"""Secret detection rules. Pure functions, no I/O.

Nothing in this module ever returns or logs a full secret except
`Hit.value`, which callers must only pass to `redact()`.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Hit:
    provider: str
    severity: str
    rule: str
    value: str  # the secret itself: only ever pass to redact()


# Order matters: more specific prefixes first (sk-ant- before sk-).
PROVIDER_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("anthropic", "high", "anthropic-key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai", "high", "openai-key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("github", "high", "github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github", "high", "github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("aws", "high", "aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google", "high", "google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("slack", "high", "slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("slack", "high", "slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}")),
    ("stripe", "high", "stripe-live-key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}")),
    ("stripe", "low", "stripe-test-key", re.compile(r"\b(?:sk|rk)_test_[0-9A-Za-z]{16,}")),
    ("huggingface", "high", "huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("private-key", "high", "pem-private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
]

# Key-name hints used for the provider guess on generic findings.
NAME_HINTS = [
    ("anthropic", "anthropic"), ("claude", "anthropic"), ("openai", "openai"),
    ("github", "github"), ("gh_", "github"), ("aws", "aws"), ("gemini", "google"),
    ("google", "google"), ("slack", "slack"), ("stripe", "stripe"),
    ("huggingface", "huggingface"), ("hf_", "huggingface"), ("brave", "brave"),
    ("tavily", "tavily"), ("notion", "notion"), ("linear", "linear"),
    ("supabase", "supabase"), ("perplexity", "perplexity"), ("exa_", "exa"),
    ("firecrawl", "firecrawl"), ("groq", "groq"), ("mistral", "mistral"),
    ("xai", "xai"), ("grok", "xai"), ("gitlab", "gitlab"), ("jira", "atlassian"),
    ("atlassian", "atlassian"), ("sentry", "sentry"), ("postgres", "postgres"),
    ("database", "database"), ("openrouter", "openrouter"), ("cloudflare", "cloudflare"),
]

SENSITIVE_NAME = re.compile(
    r"(api[_\-]?key|apikey|secret|token|passw(?:or)?d|passwd|\bpwd\b|auth|credential|"
    r"private[_\-]?key|access[_\-]?key|bearer|session|cookie|(?:^|[_\-])pat$|client[_\-]?secret)",
    re.IGNORECASE,
)
NON_SECRET_SUFFIX = re.compile(
    r"([_\-](url|uri|path|file|dir|endpoint|host|type|mode|header|name|id|ttl|expiry|expires|enabled|scope|scopes))$",
    re.IGNORECASE,
)

_PLACEHOLDER_FULL = [
    re.compile(r"^\$\{[^}]*\}$"),          # ${VAR} ${env:VAR} ${input:x}
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),  # $VAR
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),  # %VAR%
    re.compile(r"^\{\{.*\}\}$"),
    re.compile(r"^<[^>]*>$"),
    re.compile(r"^\[[^\]]*\]$"),
]
_PLACEHOLDER_WORDS = (
    "your_", "your-", "yourkey", "your key", "xxxx", "changeme", "change_me", "change-me",
    "placeholder", "example", "replace", "dummy", "redacted", "****", "insert", "_here",
    "-here", "todo", "<", "...", "…",
)
_REFERENCE_PREFIXES = (
    "op://", "mintcall:", "vault:", "keychain:", "env:", "secret://", "secrets://",
    "arn:aws:secretsmanager", "bws://", "doppler://", "file:",
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_placeholder(v: str) -> bool:
    s = v.strip().strip("'\"")
    if len(s) < 6:
        return True
    if any(p.match(s) for p in _PLACEHOLDER_FULL):
        return True
    if "${" in s or "{{" in s or "$(" in s:
        return True  # contains a variable reference / interpolation
    low = s.lower()
    if low.startswith(_REFERENCE_PREFIXES):
        return True
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    if len(set(s.replace("-", "").replace("_", ""))) <= 2:
        return True  # "aaaaaaa", "0000-0000"
    return False


def redact(v: str) -> str:
    """First 4 chars + length; values of 8 chars or less show no characters."""
    n = len(v)
    if n <= 8:
        return f"****({n} chars)"
    return f"{v[:4]}…({n} chars)"


def guess_provider_from_name(name: str | None) -> str:
    low = (name or "").lower()
    for needle, prov in NAME_HINTS:
        if needle in low:
            return prov
    return "unknown"


def _strip_scheme(v: str) -> str:
    m = re.match(r"^(?:bearer|token|basic|apikey|api-key)\s+(.+)$", v.strip(), re.IGNORECASE)
    return m.group(1).strip() if m else v.strip()


def _looks_like_non_secret(v: str) -> bool:
    low = v.lower()
    if " " in v.strip():
        return True
    if low in ("true", "false", "null", "none", "yes", "no"):
        return True
    if re.fullmatch(r"[\d.:\-]+", v):
        return True  # numbers, versions, ports, dates
    if v.startswith(("/", "~", "./", "../", "\\")) or re.match(r"^[A-Za-z]:[\\/]", v):
        return True  # file paths
    if re.fullmatch(r"@?[a-z0-9][a-z0-9._\-]*(/[a-z0-9._\-]+)*(@[\w.\-]+)?", v) and not re.search(r"\d.*[a-z]|[a-z].*\d", v):
        return True  # package names like @scope/pkg
    return False


def _sensitive_name(name: str | None) -> bool:
    if not name:
        return False
    return bool(SENSITIVE_NAME.search(name)) and not NON_SECRET_SUFFIX.search(name)


def _high_entropy(v: str) -> bool:
    if len(v) < 24 or " " in v:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", v):
        return False  # UUIDs are usually ids
    if "/" in v and v.count("/") > 2:
        return False  # paths
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return classes >= 3 and entropy(v) >= 4.0


def provider_scan(text: str) -> list[Hit]:
    """Provider-specific regexes only; used for free text and non-server JSON fields."""
    hits: list[Hit] = []
    seen: set[str] = set()
    for prov, sev, rule, rx in PROVIDER_RULES:
        for m in rx.finditer(text):
            val = m.group(0)
            if any(val in s or s in val for s in seen):
                continue
            if is_placeholder(val):
                continue
            seen.add(val)
            hits.append(Hit(prov, sev, rule, val))
    return hits


def classify(value: str, key_name: str | None = None, allow_entropy: bool = True) -> Hit | None:
    """Decide whether one config value is a plaintext secret."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    v = _strip_scheme(raw)
    if is_placeholder(v):
        return None

    hits = provider_scan(v)
    if hits:
        return hits[0]

    if "://" in v:
        return _classify_url(v)

    if _sensitive_name(key_name) and len(v) >= 12 and not _looks_like_non_secret(v):
        if entropy(v) >= 3.0 and re.search(r"[A-Za-z]", v) and re.search(r"\d", v):
            return Hit(guess_provider_from_name(key_name), "medium", "sensitive-key-name", v)

    if allow_entropy and _high_entropy(v) and not _looks_like_non_secret(v):
        return Hit(guess_provider_from_name(key_name), "low", "high-entropy", v)
    return None


def _classify_url(v: str) -> Hit | None:
    try:
        parts = urlsplit(v)
    except ValueError:
        return None
    if parts.password and not is_placeholder(parts.password):
        return Hit(guess_provider_from_name(f"{parts.scheme} {parts.hostname}"), "medium", "url-credentials", parts.password)
    for k, qv in parse_qsl(parts.query, keep_blank_values=False):
        if _sensitive_name(k) or k.lower() in ("key", "access_token", "code", "sig"):
            hit = classify(qv, k, allow_entropy=False)
            if hit:
                hit.rule = "url-query-" + hit.rule
                return hit
    return None
