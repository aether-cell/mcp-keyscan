"""Known MCP / AI-agent config file locations, per client and platform.

Sources (checked 2026-10): each client's MCP docs. Paths drift between
releases; anything missing can still be scanned with `mcp-keyscan scan PATH`.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    client: str
    path: Path


def _app_config_dirs(home: Path, env: dict[str, str], platform: str) -> list[Path]:
    """Per-user application config roots (where Electron apps keep settings)."""
    if platform == "darwin":
        return [home / "Library" / "Application Support"]
    if platform.startswith("win"):
        roots = []
        if env.get("APPDATA"):
            roots.append(Path(env["APPDATA"]))
        else:
            roots.append(home / "AppData" / "Roaming")
        return roots
    xdg = env.get("XDG_CONFIG_HOME")
    return [Path(xdg) if xdg else home / ".config"]


def global_locations(home: Path | None = None, env: dict[str, str] | None = None,
                     platform: str | None = None) -> list[Location]:
    env = dict(os.environ if env is None else env)
    home = Path(home) if home else Path.home()
    platform = platform or sys.platform
    app_dirs = _app_config_dirs(home, env, platform)
    local_appdata = Path(env["LOCALAPPDATA"]) if env.get("LOCALAPPDATA") else home / "AppData" / "Local"
    xdg = Path(env["XDG_CONFIG_HOME"]) if env.get("XDG_CONFIG_HOME") else home / ".config"

    locs: list[Location] = []

    def add(client: str, p: Path) -> None:
        locs.append(Location(client, p))

    for root in app_dirs:
        # Claude Desktop
        add("Claude Desktop", root / "Claude" / "claude_desktop_config.json")
        add("Claude Desktop", root / "Claude-3p" / "claude_desktop_config.json")
        # VS Code (+ Insiders, VSCodium) user mcp.json, settings.json and extension storage
        for code in ("Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"):
            user = root / code / "User"
            if code in ("Code", "Code - Insiders", "VSCodium"):
                add("VS Code", user / "mcp.json")
                add("VS Code", user / "settings.json")
            gs = user / "globalStorage"
            add("Cline", gs / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json")
            add("Roo Code", gs / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json")
        # Zed on Windows / older macOS builds
        add("Zed", root / "Zed" / "settings.json")
        # Devin Desktop (Windsurf successor) on Windows
        if platform.startswith("win"):
            add("Windsurf / Devin Desktop", root / "devin" / "mcp_config.json")

    # Claude Code
    add("Claude Code", home / ".claude.json")
    add("Claude Code", home / ".claude" / "settings.json")
    add("Claude Code", home / ".claude" / "settings.local.json")
    add("Claude Desktop", home / ".claude" / "claude_desktop_config.json")
    # Cursor
    add("Cursor", home / ".cursor" / "mcp.json")
    # Windsurf / Devin Desktop
    add("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json")
    add("Windsurf / Devin Desktop", xdg / "devin" / "mcp_config.json")
    # Zed
    add("Zed", xdg / "zed" / "settings.json")
    if platform.startswith("win"):
        add("Zed", local_appdata / "Zed" / "settings.json")
    # Continue
    add("Continue", home / ".continue" / "config.yaml")
    add("Continue", home / ".continue" / "config.json")
    mcp_dir = home / ".continue" / "mcpServers"
    if mcp_dir.is_dir():
        for p in sorted(mcp_dir.iterdir()):
            if p.suffix.lower() in (".yaml", ".yml", ".json"):
                add("Continue", p)
    # Cline CLI
    cline_override = env.get("CLINE_MCP_SETTINGS_PATH")
    if cline_override:
        add("Cline", Path(os.path.expanduser(cline_override)))
    add("Cline", home / ".cline" / "data" / "settings" / "cline_mcp_settings.json")
    # Other common agent clients
    add("Gemini CLI", home / ".gemini" / "settings.json")
    add("Codex", home / ".codex" / "config.toml")
    add("LM Studio", home / ".lmstudio" / "mcp.json")
    add("Amazon Q", home / ".aws" / "amazonq" / "mcp.json")
    add("Amazon Q", home / ".aws" / "amazonq" / "default.json")
    add("Copilot", home / ".copilot" / "mcp-config.json")

    # De-duplicate while keeping order
    seen: set[Path] = set()
    out = []
    for loc in locs:
        if loc.path not in seen:
            seen.add(loc.path)
            out.append(loc)
    return out


# Project-relative config files (checked in the current directory by default).
PROJECT_FILES: list[tuple[str, str]] = [
    ("Claude Code / portable", ".mcp.json"),
    ("Cursor", ".cursor/mcp.json"),
    ("VS Code", ".vscode/mcp.json"),
    ("VS Code", ".vscode/settings.json"),
    ("Roo Code", ".roo/mcp.json"),
    ("Gemini CLI", ".gemini/settings.json"),
    ("Codex", ".codex/config.toml"),
    ("Amazon Q", ".amazonq/mcp.json"),
    ("Amazon Q", ".amazonq/default.json"),
    ("Claude Code", ".claude/settings.json"),
    ("Claude Code", ".claude/settings.local.json"),
    ("Generic", "mcp.json"),
    ("dotenv", ".env"),
]

CANDIDATE_NAMES = {
    "mcp.json", ".mcp.json", "mcp_config.json", "mcp-config.json", "claude_desktop_config.json",
    "cline_mcp_settings.json", "mcp_settings.json", ".claude.json",
}
SETTINGS_PARENTS = {".vscode", ".gemini", ".claude", "zed", "Zed", "User"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".cache", "site-packages", ".npm", ".cargo"}


def is_dotenv(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def classify_path(p: Path) -> str | None:
    """Return a client label if this file looks like an agent/MCP config file."""
    name, parent = p.name, p.parent.name
    if name in CANDIDATE_NAMES:
        return client_for(p)
    if name in ("settings.json", "settings.local.json") and parent in SETTINGS_PARENTS:
        return client_for(p)
    if parent == "mcpServers" and p.parent.parent.name == ".continue" and p.suffix.lower() in (".yaml", ".yml", ".json"):
        return "Continue"
    if parent == ".continue" and name in ("config.yaml", "config.json"):
        return "Continue"
    if parent == ".codex" and name == "config.toml":
        return "Codex"
    if is_dotenv(name):
        return "dotenv"
    return None


def client_for(p: Path) -> str:
    s = p.as_posix()
    rules = [
        ("claude_desktop_config.json", "Claude Desktop"), ("/.claude.json", "Claude Code"),
        ("/.claude/", "Claude Code"), ("/.cursor/", "Cursor"), ("/.vscode/", "VS Code"),
        ("windsurf", "Windsurf"), ("/devin/", "Windsurf / Devin Desktop"), ("/zed/", "Zed"),
        ("/Zed/", "Zed"), ("/.continue/", "Continue"), ("cline_mcp_settings", "Cline"),
        ("roo-cline", "Roo Code"), ("/.roo/", "Roo Code"), ("/.gemini/", "Gemini CLI"),
        ("/.codex/", "Codex"), ("/amazonq/", "Amazon Q"), ("/.amazonq/", "Amazon Q"),
        ("/.lmstudio/", "LM Studio"), ("/User/mcp.json", "VS Code"), ("/User/settings.json", "VS Code"),
        ("/.copilot/", "Copilot"),
    ]
    if s.endswith("/.mcp.json") or s == ".mcp.json":
        return "Claude Code / portable"
    for needle, client in rules:
        if needle in s:
            return client
    if is_dotenv(p.name):
        return "dotenv"
    return "Generic"


def walk(root: Path, max_bytes: int = 5_000_000):
    """Yield (client, path) for candidate files under root (or root itself if a file)."""
    root = Path(root)
    if root.is_file():
        yield (classify_path(root) or client_for(root)), root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            client = classify_path(p)
            if not client:
                continue
            try:
                if p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield client, p
