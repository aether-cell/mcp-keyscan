"""Parse config files and turn secret hits into redacted findings."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import detect
from .locations import Location, PROJECT_FILES, global_locations, is_dotenv, walk

# Keys whose value is a map (or Continue-style list) of MCP server entries.
SERVER_CONTAINERS = {"mcpServers", "servers", "context_servers", "mcp_servers", "modelContextProtocolServers"}
# Fields inside a server entry that never carry secrets.
SAFE_FIELDS = {"command", "type", "transport", "cwd", "disabled", "autoApprove", "alwaysAllow",
               "timeout", "name", "description", "version", "schema", "envFile", "trust", "tools",
               "includeTools", "excludeTools", "enabled", "startup_timeout_sec", "tool_timeout_sec"}


@dataclass
class Finding:
    file: str
    client: str
    server: str
    key: str          # dotted location inside the server entry, e.g. env.GITHUB_TOKEN
    provider: str
    severity: str
    rule: str
    preview: str      # redacted: first 4 chars + length, never the value
    line: int | None = None
    _env_name: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        return d


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- parsing

def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code / Zed settings are JSONC)."""
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_structured(path: Path, text: str) -> Any | None:
    suffix = path.suffix.lower()
    if suffix == ".toml":
        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:
            return None
        try:
            return tomllib.loads(text)
        except Exception:
            return None
    if suffix in (".json", "") or path.name.endswith(".json"):
        try:
            return json.loads(text)
        except ValueError:
            try:
                return json.loads(strip_jsonc(text))
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------- scanning

class _Collector:
    def __init__(self, file_label: str, client: str, text: str):
        self.file_label = file_label
        self.client = client
        self.text = text
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str]] = set()

    def _line_of(self, value: str) -> int | None:
        idx = self.text.find(value)
        return None if idx < 0 else self.text.count("\n", 0, idx) + 1

    def add(self, server: str, key: str, hit: detect.Hit, env_name: str = "") -> None:
        sig = (server, key, hit.value)
        if sig in self._seen:
            return
        self._seen.add(sig)
        self.findings.append(Finding(
            file=self.file_label, client=self.client, server=server, key=key,
            provider=hit.provider, severity=hit.severity, rule=hit.rule,
            preview=detect.redact(hit.value), line=self._line_of(hit.value), _env_name=env_name,
        ))


def _iter_servers(container: Any) -> Iterable[tuple[str, dict]]:
    if isinstance(container, dict):
        for name, entry in container.items():
            if isinstance(entry, dict):
                yield str(name), entry
    elif isinstance(container, list):  # Continue: list of {name: ..., ...}
        for i, entry in enumerate(container):
            if isinstance(entry, dict):
                yield str(entry.get("name", f"#{i}")), entry


_FLAG_EQ = re.compile(r"^(-{0,2}[A-Za-z][\w.\-]*)=(.+)$", re.S)
_HEADER_ARG = re.compile(r"^([A-Za-z][\w\-]*)\s*:\s*(.+)$", re.S)


def _scan_args(col: _Collector, server: str, args: list, prefix: str) -> None:
    for i, a in enumerate(args):
        if not isinstance(a, str):
            continue
        loc = f"{prefix}[{i}]"
        m = _FLAG_EQ.match(a)
        if m and "://" not in m.group(1):
            name = m.group(1).lstrip("-")
            hit = detect.classify(m.group(2), name)
            if hit:
                col.add(server, f"{loc}({name})", hit, env_name=name)
            continue
        m = _HEADER_ARG.match(a)
        if m and "://" not in a:
            hit = detect.classify(m.group(2), m.group(1))
            if hit:
                col.add(server, f"{loc}(header {m.group(1)})", hit)
            continue
        prev = args[i - 1] if i > 0 and isinstance(args[i - 1], str) else ""
        if prev.startswith("-") and "=" not in prev:
            name = prev.lstrip("-")
            hit = detect.classify(a, name, allow_entropy=detect._sensitive_name(name))
            if hit:
                col.add(server, f"{loc}(after {prev})", hit, env_name=name)
            continue
        hit = detect.classify(a, None, allow_entropy=False)
        if hit:
            col.add(server, loc, hit)


def _scan_entry(col: _Collector, server: str, node: Any, path: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            k = str(k)
            if not path and k in SAFE_FIELDS:
                continue
            if isinstance(v, str):
                in_map = bool(path) and path[-1] in ("env", "headers", "environment", "http_headers", "env_vars")
                hit = detect.classify(v, k, allow_entropy=in_map or detect._sensitive_name(k))
                if hit:
                    col.add(server, ".".join(path + [k]), hit, env_name=k if in_map and path[-1] != "headers" else "")
            elif isinstance(v, list) and k == "args":
                _scan_args(col, server, v, ".".join(path + [k]))
            else:
                _scan_entry(col, server, v, path + [k])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                hit = detect.classify(v, path[-1] if path else None, allow_entropy=False)
                if hit:
                    col.add(server, ".".join(path) + f"[{i}]", hit)
            else:
                _scan_entry(col, server, v, path + [f"[{i}]"])


def _walk_doc(col: _Collector, node: Any, path: list[str]) -> None:
    """Find server containers anywhere (e.g. ~/.claude.json projects.<dir>.mcpServers,
    VS Code settings 'mcp.servers'); provider-regex-scan everything else."""
    if isinstance(node, dict):
        for k, v in node.items():
            k = str(k)
            if k in SERVER_CONTAINERS and isinstance(v, (dict, list)):
                for name, entry in _iter_servers(v):
                    _scan_entry(col, name, entry, [])
            elif k in ("env", "environment") and isinstance(v, dict):
                # e.g. Claude Code settings.json top-level "env" block
                for ek, ev in v.items():
                    if isinstance(ev, str):
                        hit = detect.classify(ev, str(ek))
                        if hit:
                            col.add("(settings)", ".".join(path + [k, str(ek)]), hit, env_name=str(ek))
            elif isinstance(v, str):
                hit = detect.classify(v, k, allow_entropy=False) if detect._sensitive_name(k) else None
                if hit is None:
                    hits = detect.provider_scan(v)
                    hit = hits[0] if hits else None
                if hit:
                    col.add("-", ".".join(path + [k]), hit)
            else:
                _walk_doc(col, v, path + [k])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                for hit in detect.provider_scan(v):
                    col.add("-", ".".join(path) + f"[{i}]", hit)
            else:
                _walk_doc(col, v, path + [f"[{i}]"])


_KV_LINE = re.compile(r"""^\s*(?:export\s+)?(?:-\s+)?["']?([A-Za-z_][\w.\-]*)["']?\s*[:=]\s*(.*?)\s*$""")


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    # strip trailing inline comment for unquoted values
    return re.split(r"\s+#", v, maxsplit=1)[0].strip()


def _scan_lines(col: _Collector, text: str, dotenv: bool) -> None:
    """Line-based fallback for .env, YAML (Continue) and TOML without tomllib."""
    server = "(dotenv)" if dotenv else "-"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        if not dotenv:
            m = re.match(r"^\s*-\s*name\s*:\s*(.+)$", line)
            if m:
                server = _unquote(m.group(1))
                continue
            m = re.match(r"^\s*\[(?:mcp_servers|mcpServers)\.([^\]]+)", line)
            if m:
                server = m.group(1).split(".")[0].strip("\"'")
                continue
        m = _KV_LINE.match(line)
        if m and m.group(2):
            key, val = m.group(1), _unquote(m.group(2))
            hit = detect.classify(val, key, allow_entropy=True)
            if hit:
                col.add(server, key, hit, env_name=key)
                continue
        for hit in detect.provider_scan(line):
            col.add(server, "(line)", hit)


def scan_file(path: Path, client: str, display: str | None = None) -> tuple[list[Finding], str | None]:
    label = display or str(path)
    try:
        raw = path.read_bytes()
    except OSError as e:
        return [], f"{label}: cannot read ({e.strerror or type(e).__name__})"
    if b"\x00" in raw[:4096]:
        return [], None  # binary
    text = raw.decode("utf-8", errors="replace")
    col = _Collector(label, client, text)
    if is_dotenv(path.name):
        _scan_lines(col, text, dotenv=True)
    else:
        doc = load_structured(path, text)
        if doc is not None:
            _walk_doc(col, doc, [])
        else:
            _scan_lines(col, text, dotenv=False)
    return col.findings, None


def display_path(p: Path, home: Path | None = None) -> str:
    home = home or Path.home()
    try:
        return "~/" + p.resolve().relative_to(home.resolve()).as_posix()
    except (ValueError, OSError):
        return str(p)


def scan(paths: list[Path] | None = None, include_global: bool | None = None,
         home: Path | None = None) -> ScanResult:
    """paths=None: known global locations + project files in cwd.
    paths given: recursive walk of each path (plus globals if include_global)."""
    res = ScanResult()
    targets: list[tuple[str, Path]] = []
    if not paths:
        include_global = True if include_global is None else include_global
        cwd = Path.cwd()
        targets += [(client, cwd / rel) for client, rel in PROJECT_FILES]
        cont = cwd / ".continue" / "mcpServers"
        if cont.is_dir():
            targets += [("Continue", p) for p in sorted(cont.iterdir()) if p.is_file()]
    else:
        for p in paths:
            p = Path(p).expanduser()
            if not p.exists():
                res.errors.append(f"{p}: does not exist")
                continue
            targets += list(walk(p))
    if include_global:
        targets += [(loc.client, loc.path) for loc in global_locations(home=home)]

    seen: set[Path] = set()
    for client, p in targets:
        try:
            if not p.is_file():
                continue
            rp = p.resolve()
        except OSError:
            continue
        if rp in seen:
            continue
        seen.add(rp)
        label = display_path(p, home)
        findings, err = scan_file(p, client, label)
        res.scanned.append(label)
        res.findings.extend(findings)
        if err:
            res.errors.append(err)
    res.findings.sort(key=lambda f: (-detect.SEVERITY_ORDER[f.severity], f.file, f.server, f.key))
    return res
