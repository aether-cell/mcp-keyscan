"""Command line interface: `mcp-keyscan scan [PATH...]` and `mcp-keyscan fix --dry-run`."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .detect import SEVERITY_ORDER
from .scanner import Finding, ScanResult, scan

MINTCALL_URL = "https://github.com/aether-cell/mintcall"

# Default upstream origin per provider, for the mintcall add-credential hint.
RECIPIENTS = {
    "openai": ("https://api.openai.com", "Authorization", "Bearer {secret}"),
    "anthropic": ("https://api.anthropic.com", "x-api-key", "{secret}"),
    "github": ("https://api.github.com", "Authorization", "Bearer {secret}"),
    "google": ("https://generativelanguage.googleapis.com", "x-goog-api-key", "{secret}"),
    "slack": ("https://slack.com", "Authorization", "Bearer {secret}"),
    "stripe": ("https://api.stripe.com", "Authorization", "Bearer {secret}"),
    "huggingface": ("https://huggingface.co", "Authorization", "Bearer {secret}"),
    "xai": ("https://api.x.ai", "Authorization", "Bearer {secret}"),
}
DEFAULT_ENV = {
    "openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "github": "GITHUB_TOKEN",
    "aws": "AWS_ACCESS_KEY_ID", "google": "GOOGLE_API_KEY", "slack": "SLACK_BOT_TOKEN",
    "stripe": "STRIPE_SECRET_KEY", "huggingface": "HF_TOKEN",
}


# ---------------------------------------------------------------- output

def _filter(res: ScanResult, min_sev: str) -> list[Finding]:
    floor = SEVERITY_ORDER[min_sev]
    return [f for f in res.findings if SEVERITY_ORDER[f.severity] >= floor]


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for r in rows:
        widths = [max(w, len(c)) for w, c in zip(widths, r)]
    widths = [min(w, 60) for w in widths]

    def fmt(r: list[str]) -> str:
        cells = [(c if len(c) <= w else c[: w - 1] + "…").ljust(w) for c, w in zip(r, widths)]
        return "  ".join(cells).rstrip()

    lines = [fmt(headers), fmt(["-" * w for w in widths])]
    lines += [fmt(r) for r in rows]
    return "\n".join(lines)


def print_report(res: ScanResult, findings: list[Finding], out=None) -> None:
    out = out or sys.stdout
    if not findings:
        print(f"mcp-keyscan: no plaintext secrets found in {len(res.scanned)} config file(s).", file=out)
    else:
        rows = [[f.severity.upper(), f.file + (f":{f.line}" if f.line else ""), f.server, f.key,
                 f.provider, f.preview] for f in findings]
        print(_table(rows, ["SEVERITY", "FILE", "SERVER", "KEY", "PROVIDER", "PREVIEW"]), file=out)
        counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
        print(f"\n{len(findings)} finding(s) in {len({f.file for f in findings})} file(s) "
              f"(high={counts['high']} medium={counts['medium']} low={counts['low']}); "
              f"scanned {len(res.scanned)} config file(s). Values are never printed.", file=out)
        print("Next: `mcp-keyscan fix --dry-run` shows env-var references to use instead.\n"
              f"Keep the real keys out of agent configs with a local credential broker such as mintcall: {MINTCALL_URL}",
              file=out)
    for e in res.errors:
        print(f"warning: {e}", file=sys.stderr)


def to_json(res: ScanResult, findings: list[Finding]) -> str:
    return json.dumps({
        "tool": "mcp-keyscan",
        "version": __version__,
        "scanned_files": res.scanned,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            **{s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")},
        },
        "errors": res.errors,
        "suggestion": f"Move secrets into a credential broker such as mintcall ({MINTCALL_URL}).",
    }, indent=2)


# ---------------------------------------------------------------- fix --dry-run

def _env_name(f: Finding) -> str:
    cand = f._env_name
    if cand and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cand) and cand.upper() == cand:
        return cand
    if f.provider in DEFAULT_ENV:
        return DEFAULT_ENV[f.provider]
    base = cand or f.key.split(".")[-1]
    base = re.sub(r"\[.*?\]|\(.*?\)", "", base) or "SECRET"
    server = "" if f.server in ("-", "(dotenv)", "(settings)") else f.server + "_"
    name = re.sub(r"[^A-Za-z0-9]+", "_", server + base).strip("_").upper()
    if not re.search(r"(KEY|TOKEN|SECRET|PASSWORD)$", name):
        name += "_TOKEN"
    if name[0].isdigit():
        name = "_" + name
    return name


def _reference(f: Finding, var: str) -> tuple[str, str]:
    """Client-appropriate env reference + a note on whether the client expands it."""
    c = f.client
    if c in ("Cursor", "VS Code"):
        extra = " VS Code can also prompt once via ${input:ID} with \"password\": true." if c == "VS Code" else ""
        return "${env:%s}" % var, f"{c} expands ${{env:VAR}} from the environment it was launched with.{extra}"
    if c.startswith("Claude Code"):
        return "${%s}" % var, "Claude Code expands ${VAR} (and ${VAR:-default}) in .mcp.json."
    if c == "dotenv":
        return "", "Delete the line; load it at runtime from your broker or OS keychain instead of a file."
    if c == "Claude Desktop":
        return "${%s}" % var, ("Claude Desktop may not expand env references; remove the key from `env` "
                               "and start the server through a wrapper that injects it (see mintcall's MCP wrapper).")
    return "${%s}" % var, f"Check that {c} expands env references; if not, inject the key with a wrapper/broker."


def fix_plan(findings: list[Finding]) -> list[dict]:
    plan = []
    for f in findings:
        var = _env_name(f)
        ref, note = _reference(f, var)
        last = f.key.split(".")[-1]
        if f.client == "dotenv":
            replacement = f"remove `{f.key}=…` from the file"
        elif ".headers." in f".{f.key}" and last.lower() == "authorization":
            replacement = f'"{last}": "Bearer {ref}"'
        elif "args[" in f.key:
            replacement = f"args element -> {ref}  (or move it to env.{var} = {ref})"
        else:
            replacement = f'"{last}": "{ref}"'
        rec = RECIPIENTS.get(f.provider)
        name = var.lower().replace("_", "-")
        if rec:
            mint = (f'mintcall add-credential {name} --recipient {rec[0]} '
                    f'--header {rec[1]} --format "{rec[2]}"')
        else:
            mint = f"mintcall add-credential {name} --recipient https://<api-origin>"
        plan.append({
            "file": f.file, "line": f.line, "server": f.server, "key": f.key,
            "provider": f.provider, "severity": f.severity, "current": f.preview,
            "replace_with": replacement, "env_var": var, "note": note,
            "mintcall": mint, "rotate": True,
        })
    return plan


def print_fix(plan: list[dict], out=None) -> None:
    out = out or sys.stdout
    if not plan:
        print("mcp-keyscan fix: nothing to do.", file=out)
        return
    print("mcp-keyscan fix --dry-run: no files are modified (v0 has no write mode).\n", file=out)
    for i, p in enumerate(plan, 1):
        where = p["file"] + (f":{p['line']}" if p["line"] else "")
        print(f"[{i}] {p['severity'].upper()} {where}  server={p['server']}  {p['key']}", file=out)
        print(f"    current : {p['current']} (redacted)", file=out)
        print(f"    replace : {p['replace_with']}", file=out)
        print(f"    env var : export {p['env_var']} from your shell/keychain, or keep it in a broker", file=out)
        print(f"    note    : {p['note']}", file=out)
        print(f"    mintcall: {p['mintcall']}", file=out)
        print("    rotate  : this key was stored in plaintext; rotate it at the provider.\n", file=out)
    print(f"mintcall (local per-call credential broker): {MINTCALL_URL}", file=out)


# ---------------------------------------------------------------- main

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", metavar="PATH",
                   help="files or directories to scan recursively (default: known client locations + current project)")
    p.add_argument("--global", dest="include_global", action="store_true",
                   help="also scan known per-user client config locations when PATH is given")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                   help="report (and fail on) findings at or above this severity (default: low)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mcp-keyscan",
        description="Find plaintext secrets in AI-agent / MCP client config files. Never prints secret values.",
    )
    ap.add_argument("--version", action="version", version=f"mcp-keyscan {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan and report findings (exit 1 if any)")
    _add_common(s)
    s.add_argument("--list-files", action="store_true", help="also list every config file that was scanned")
    f = sub.add_parser("fix", help="show how each finding would be replaced (requires --dry-run in v0)")
    _add_common(f)
    f.add_argument("--dry-run", action="store_true", help="print the plan; do not modify files")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("scan", "fix", "-h", "--help", "--version"):
        argv = ["scan", *argv]
    args = ap.parse_args(argv)

    paths = [Path(p) for p in args.paths] or None
    res = scan(paths, include_global=args.include_global or None)
    findings = _filter(res, args.min_severity)

    if args.cmd == "fix":
        if not args.dry_run:
            print("mcp-keyscan fix: v0 only supports --dry-run (no files are ever written).", file=sys.stderr)
            return 2
        plan = fix_plan(findings)
        if args.json:
            print(json.dumps({"tool": "mcp-keyscan", "version": __version__, "dry_run": True, "plan": plan}, indent=2))
        else:
            print_fix(plan)
        return 1 if findings else 0

    if args.json:
        print(to_json(res, findings))
    else:
        if getattr(args, "list_files", False):
            for s in res.scanned:
                print(f"scanned: {s}")
            print()
        print_report(res, findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
