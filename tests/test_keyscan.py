"""Tests for mcp-keyscan. All keys in tests/fixtures are FAKE and only shaped like real ones."""

import contextlib
import io
import json
import os
import re
import unittest
from pathlib import Path

from mcp_keyscan import cli, detect
from mcp_keyscan.locations import global_locations
from mcp_keyscan.scanner import scan

FIX = Path(__file__).parent / "fixtures"
PROJECT = FIX / "project"

FAKE_SECRET_RE = re.compile(
    r"(ghp_|sk-proj-|sk-ant-|sk_live_|hf_|AIza|AKIA|xoxb-|ntn_|BSA|FAKE)[A-Za-z0-9_\-]{6,}"
)


def all_fixture_secrets() -> set[str]:
    """Every FAKE secret-looking token present in the fixtures."""
    out = set()
    for p in FIX.rglob("*"):
        if p.is_file():
            for m in FAKE_SECRET_RE.finditer(p.read_text()):
                out.add(m.group(0))
    out.add("FAKEpassw0rd99")
    return out


def run(argv):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, buf.getvalue() + err.getvalue()


class TestDetect(unittest.TestCase):
    def test_providers(self):
        cases = {
            "sk-proj-FAKEfake1234FAKEfake5678FAKEfake90ab": "openai",
            "sk-ant-api03-FAKEfakeFAKEfakeFAKEfakeFAKE-test": "anthropic",
            "ghp_FAKE0000aaaaBBBBccccDDDDeeeeFFFF1111": "github",
            "github_pat_FAKE0000aaaaBBBBccccDD_eeeeFFFF1111gggg": "github",
            "AKIAFAKEFAKEFAKE1234": "aws",
            "AIzaFAKEfakeFAKEfakeFAKEfakeFAKEfake123": "google",
            "xoxb-FAKE000000-FAKE000000-fakeFAKEfake": "slack",
            "sk_live_FAKE0fake1FAKE2fake3": "stripe",
            "hf_FAKE0fakeFAKE1fakeFAKE2fakeFAKE3fa": "huggingface",
        }
        for value, prov in cases.items():
            hit = detect.classify(value, "X")
            self.assertIsNotNone(hit, value[:4])
            self.assertEqual(hit.provider, prov)
            self.assertEqual(hit.severity, "high")

    def test_placeholders_ignored(self):
        for v in ["${OPENAI_API_KEY}", "${env:GITHUB_TOKEN}", "${input:tok}", "$TOKEN", "%API_KEY%",
                  "<token>", "your-api-key-here", "sk-xxxxxxxxxxxxxxxxxxxxxxxx", "op://vault/item/field",
                  "Bearer ${env:REMOTE_TOKEN}", "{{ secrets.KEY }}", "", "changeme", "AKIAIOSFODNN7EXAMPLE"]:
            self.assertIsNone(detect.classify(v, "API_KEY"), v)

    def test_non_secrets_ignored(self):
        for k, v in [("AWS_REGION", "eu-central-1"), ("GH_HOST", "github.com"), ("TOKEN_URL", "https://a.invalid/t"),
                     ("PROJECT_ID", "3f2b8c1e-9a7d-4e6f-b5c4-1d2e3f4a5b6c"), ("LOG_LEVEL", "debug"),
                     ("API_KEY_FILE", "/run/secrets/key"), ("MODEL", "claude-sonnet-4-5")]:
            self.assertIsNone(detect.classify(v, k), k)

    def test_generic_by_name_and_entropy(self):
        self.assertEqual(detect.classify("FAKEz9Y8x7W6v5U4t3S2r1Q0", "MY_SERVICE_SECRET").severity, "medium")
        self.assertEqual(detect.classify("FAKEq8Zr2LmX9vT4pK7wN3sB6yH1jJ", "SOMETHING").severity, "low")

    def test_redact(self):
        self.assertEqual(detect.redact("sk-proj-FAKEfake1234"), "sk-p…(20 chars)")
        self.assertEqual(detect.redact("short12"), "****(7 chars)")


class TestScan(unittest.TestCase):
    def setUp(self):
        self.res = scan([PROJECT])
        self.by = {(Path(f.file).name, f.server, f.key): f for f in self.res.findings}

    def test_expected_findings(self):
        keys = {(f.server, f.key) for f in self.res.findings}
        expected = {
            ("github", "env.GITHUB_PERSONAL_ACCESS_TOKEN"),
            ("openai-tools", "args[2](after --api-key)"),
            ("remote-anthropic", "headers.Authorization"),
            ("aws", "env.AWS_ACCESS_KEY_ID"),
            ("aws", "env.AWS_SECRET_ACCESS_KEY"),
            ("slack", "env.SLACK_BOT_TOKEN"),
            ("stripe", "args[2](api-key)"),
            ("hf", "url"),
            ("hf", "headers.X-Custom-Token"),
            ("gemini", "env.GEMINI_API_KEY"),
            ("db", "args[0]"),
            ("notion", "NOTION_TOKEN"),
            ("(dotenv)", "ANTHROPIC_API_KEY"),
            ("(dotenv)", "MY_SERVICE_SECRET"),
        }
        self.assertEqual(keys, expected)

    def test_no_placeholder_findings(self):
        servers = {f.server for f in self.res.findings}
        self.assertNotIn("safe-one", servers)
        self.assertNotIn("ref-only", servers)
        self.assertNotIn("gh-input", servers)
        self.assertFalse(any(f.key in ("DEBUG", "PLACEHOLDER_KEY", "env.AWS_REGION") for f in self.res.findings))

    def test_clean_project(self):
        self.assertEqual(scan([FIX / "clean"]).findings, [])

    def test_global_locations_with_fake_home(self):
        home = FIX / "home"
        locs = global_locations(home=home, env={}, platform="linux")
        paths = {loc.path for loc in locs}
        self.assertIn(home / ".codeium" / "windsurf" / "mcp_config.json", paths)
        self.assertIn(home / ".cursor" / "mcp.json", paths)
        self.assertIn(home / ".config" / "Claude" / "claude_desktop_config.json", paths)
        win = {l.path for l in global_locations(home=home, env={"APPDATA": "C:/AppData/Roaming"}, platform="win32")}
        self.assertIn(Path("C:/AppData/Roaming") / "Claude" / "claude_desktop_config.json", win)
        mac = {l.path for l in global_locations(home=home, env={}, platform="darwin")}
        self.assertIn(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", mac)
        res = scan([FIX / "clean"], include_global=True, home=home)
        self.assertEqual([(f.server, f.key) for f in res.findings], [("brave", "env.BRAVE_API_KEY")])
        self.assertTrue(res.findings[0].file.startswith("~/"))

    def test_claude_json_nested_projects(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".claude.json"
            p.write_text(json.dumps({"projects": {"/some/dir": {"mcpServers": {
                "x": {"command": "y", "env": {"OPENAI_API_KEY": "sk-proj-FAKEfake1234FAKEfake5678FAKEfake90ab"}}}}}}))
            res = scan([p])
            self.assertEqual([(f.server, f.key, f.client) for f in res.findings],
                             [("x", "env.OPENAI_API_KEY", "Claude Code")])


class TestCLI(unittest.TestCase):
    def assert_no_secret(self, text):
        for s in all_fixture_secrets():
            self.assertNotIn(s, text, f"secret starting {s[:4]} leaked")
            # nothing beyond the first 4 characters may appear
            self.assertNotIn(s[:9], text, f"more than 4 chars of {s[:4]} leaked")

    def test_exit_codes(self):
        self.assertEqual(run(["scan", str(PROJECT)])[0], 1)
        self.assertEqual(run(["scan", str(FIX / "clean")])[0], 0)
        self.assertEqual(run(["scan", str(PROJECT), "--min-severity", "high"])[0], 1)
        self.assertEqual(run([str(FIX / "clean")])[0], 0)  # bare PATH = scan
        self.assertEqual(run(["fix", str(PROJECT)])[0], 2)  # write mode refused

    def test_table_never_prints_secrets(self):
        code, out = run(["scan", str(PROJECT), "--list-files"])
        self.assertIn("ghp_…(40 chars)", out)
        self.assert_no_secret(out)

    def test_json_output(self):
        code, out = run(["scan", str(PROJECT), "--json"])
        data = json.loads(out)
        self.assertEqual(data["summary"]["total"], len(data["findings"]))
        self.assertTrue(all({"file", "server", "key", "provider", "severity", "preview"} <= set(f) for f in data["findings"]))
        self.assert_no_secret(out)

    def test_fix_dry_run(self):
        code, out = run(["fix", "--dry-run", str(PROJECT)])
        self.assertEqual(code, 1)
        self.assertIn("${env:GITHUB_PERSONAL_ACCESS_TOKEN}", out)
        self.assertIn("${GEMINI_API_KEY}", out)          # Claude Code style in .mcp.json
        self.assertIn('"Authorization": "Bearer ${env:ANTHROPIC_API_KEY}"', out)
        self.assertIn("mintcall add-credential", out)
        self.assert_no_secret(out)
        code, out = run(["fix", "--dry-run", "--json", str(PROJECT)])
        self.assertTrue(json.loads(out)["dry_run"])
        self.assert_no_secret(out)

    def test_fix_does_not_modify_files(self):
        before = {p: p.read_bytes() for p in PROJECT.rglob("*") if p.is_file()}
        run(["fix", "--dry-run", str(PROJECT)])
        after = {p: p.read_bytes() for p in PROJECT.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
