#!/usr/bin/env python3
"""mcp-transport-guard: offline transport-attribution guard for MCP server configs.

The guard answers one question per MCP server entry:
    "which transport will a client actually use, and does the file say so?"

It models the transport decision that Codex Security's `mcp add` performs in
sdk/typescript/src/cli-mcp.ts (line 56, `if (/^https?:\\/\\//u.test(value)) ...`).
URI schemes are case-insensitive (RFC 3986 §3.1), but that regex is not, so a
mixed/upper-case HTTP(S) URL falls through to the *stdio command* branch.
The guard finds entries already in that state and can rewrite them to the
explicit `url` form (`--fix`), verifying the rewrite is idempotent.

No network, no third-party dependencies. Python 3.11+ (tomllib).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable

VERSION = "1.0.0"
HTTP_URL = re.compile(r"^https?://")
ANY_SCHEME_URL = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")

JSON_SERVER_KEYS = ("mcpServers", "servers", "amp.mcpServers")


class InputError(Exception):
    """Usage or malformed input; exit code 2."""


@dataclass
class Entry:
    file: str
    group: str
    name: str
    value: dict[str, Any]
    path: str  # group.name, for messages

    @property
    def command(self) -> Any:
        return self.value.get("command")

    @property
    def url(self) -> Any:
        return self.value.get("url")

    @property
    def declared_type(self) -> Any:
        return self.value.get("type")


@dataclass
class Finding:
    code: str
    severity: str
    file: str
    server: str
    field: str
    message: str
    witness: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "file": self.file,
            "server": self.server,
            "field": self.field,
            "message": self.message,
            "witness": self.witness,
        }


def classify(value: str) -> str:
    """Return the transport a client following the upstream regex picks."""
    text = value.strip()
    if HTTP_URL.match(text):
        return "http"
    scheme = ANY_SCHEME_URL.match(text)
    if scheme and scheme.group(1).lower() in {"http", "https"}:
        return "stdio_command_scheme_case_trap"
    if scheme:
        return "stdio_command_other_scheme"
    return "stdio_command"


def _scheme(text: str) -> str:
    m = SCHEME.match(text.strip())
    return m.group(1) if m else ""


def _scheme_span(text: str) -> list[int]:
    m = SCHEME.match(text.strip())
    return [0, len(m.group(1))] if m else []


def load_json(path: str) -> tuple[dict[str, Any], str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise InputError(f"no such file: {path}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InputError(f"{path}: invalid JSON: {exc}")
    if not isinstance(data, dict):
        raise InputError(f"{path}: top-level JSON must be an object")
    for key in JSON_SERVER_KEYS:
        if key in data:
            if not isinstance(data[key], dict):
                raise InputError(f"{path}: {key} must be an object")
            return data, key
    return data, ""


def load_toml(path: str) -> tuple[dict[str, Any], str]:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        raise InputError("TOML input needs Python 3.11+ (tomllib)")
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        raise InputError(f"no such file: {path}")
    except tomllib.TOMLDecodeError as exc:
        raise InputError(f"{path}: invalid TOML: {exc}")
    if not isinstance(data, dict):
        raise InputError(f"{path}: top-level TOML must be a table")
    return data, "mcp_servers"


def entries(path: str) -> list[Entry]:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".toml":
        data, group = load_toml(path)
    elif ext == ".json":
        data, group = load_json(path)
    else:
        raise InputError(f"{path}: only .json and .toml configs are supported")
    if not group:
        raise InputError(
            f"{path}: no MCP server table found (expected one of {', '.join(JSON_SERVER_KEYS)})"
        )
    table = data.get(group, {})
    if not isinstance(table, dict):
        raise InputError(f"{path}: {group} must be an object")
    out: list[Entry] = []
    for name, value in table.items():
        if not isinstance(value, dict):
            raise InputError(f"{path}: server {name!r} must be an object")
        out.append(Entry(path, group, name, value, f"{group}.{name}"))
    return out


def check_entry(entry: Entry) -> list[Finding]:
    findings: list[Finding] = []
    cmd = entry.command
    url = entry.url
    declared = entry.declared_type

    if isinstance(cmd, str) and cmd.strip():
        transport = classify(cmd)
        scheme = _scheme(cmd)
        if transport == "stdio_command_scheme_case_trap":
            findings.append(
                Finding(
                    "MCP001",
                    "high",
                    entry.file,
                    entry.name,
                    "command",
                    "HTTP(S) URL sits in `command` with a non-lowercase scheme; "
                    "the upstream transport test is case-sensitive, so this entry "
                    "is launched as an executable instead of used as a URL",
                    {
                        "value": cmd,
                        "scheme": scheme,
                        "upstream_test": HTTP_URL.pattern,
                        "minimal_flip": {
                            "range": _scheme_span(cmd),
                            "to": scheme.lower(),
                            "then_transport": "http",
                        },
                        "rfc3986": "section 3.1: schemes are case-insensitive",
                    },
                )
            )
        elif transport == "stdio_command_other_scheme":
            findings.append(
                Finding(
                    "MCP002",
                    "medium",
                    entry.file,
                    entry.name,
                    "command",
                    "`command` holds a URL with scheme {!r}; only http/https are "
                    "translated to a URL transport, every other scheme is executed "
                    "as a program".format(scheme),
                    {"value": cmd, "scheme": scheme},
                )
            )
    if isinstance(url, str) and url.strip():
        if not HTTP_URL.match(url.strip()):
            findings.append(
                Finding(
                    "MCP003",
                    "medium",
                    entry.file,
                    entry.name,
                    "url",
                    "`url` does not start with a lowercase http(s):// scheme",
                    {"value": url, "scheme": _scheme(url)},
                )
            )
    if isinstance(cmd, str) and cmd.strip() and isinstance(url, str) and url.strip():
        findings.append(
            Finding(
                "MCP004",
                "high",
                entry.file,
                entry.name,
                "command+url",
                "both `command` and `url` are present; transport depends on client "
                "precedence rules instead of the config",
                {"command": cmd, "url": url},
            )
        )
    if isinstance(declared, str):
        wanted = declared.lower()
        has_url = isinstance(url, str) and bool(url.strip())
        if wanted in {"http", "sse"} and not has_url:
            findings.append(
                Finding(
                    "MCP005",
                    "high",
                    entry.file,
                    entry.name,
                    "type",
                    f"type={declared!r} declares a remote transport but no `url` is set",
                    {"type": declared},
                )
            )
        if wanted == "stdio" and has_url:
            findings.append(
                Finding(
                    "MCP006",
                    "high",
                    entry.file,
                    entry.name,
                    "type",
                    "type='stdio' declares a local process but a `url` is set",
                    {"type": declared, "url": url},
                )
            )
    if isinstance(cmd, str) and not cmd.strip():
        findings.append(
            Finding(
                "MCP007",
                "medium",
                entry.file,
                entry.name,
                "command",
                "`command` is present but empty",
                {"value": cmd},
            )
        )
    return findings


def fix_entry(entry: Entry) -> bool:
    """Rewrite a case-trapped URL command into the explicit url transport."""
    cmd = entry.command
    if not (isinstance(cmd, str) and cmd.strip()):
        return False
    if classify(cmd) != "stdio_command_scheme_case_trap":
        return False
    if isinstance(entry.url, str) and entry.url.strip():
        return False  # ambiguous on purpose; do not guess
    text = cmd.strip()
    scheme = _scheme(text)
    # RFC 3986: the scheme is case-insensitive; path and query stay byte-identical.
    canonical = scheme.lower() + text[len(scheme):]
    entry.value.pop("command", None)
    entry.value.pop("args", None)
    entry.value["url"] = canonical
    entry.value["type"] = "http"
    return True


def run(files: Iterable[str]) -> dict[str, Any]:
    all_entries: list[Entry] = []
    findings: list[Finding] = []
    parsed: list[str] = []
    seen: set[str] = set()
    for path in files:
        if path in seen:
            continue
        seen.add(path)
        if path.lower().endswith(".toml"):
            data, group = load_toml(path)
        else:
            data, group = load_json(path)
        if not group:
            raise InputError(f"{path}: no MCP server table found")
        parsed.append(path)
        for name, value in data.get(group, {}).items():
            all_entries.append(Entry(path, group, name, value, f"{group}.{name}"))
    for entry in all_entries:
        findings.extend(check_entry(entry))
    return {
        "tool": "mcp-transport-guard",
        "version": VERSION,
        "files": parsed,
        "summary": {
            "files": len(parsed),
            "servers": len(all_entries),
            "findings": len(findings),
            "by_severity": _severity_counts(findings),
        },
        "findings": [f.as_dict() for f in findings],
        "fixed": 0,
        "ok": not findings,
    }


def _severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"mcp-transport-guard {report['version']}",
        f"files={report['summary']['files']} servers={report['summary']['servers']} "
        f"findings={report['summary']['findings']} fixed={report['fixed']}",
    ]
    for f in report["findings"]:
        lines.append(
            f"{f['severity'].upper():6} {f['code']} {f['file']}:{f['server']}.{f['field']} {f['message']}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-transport",
        description="Offline transport-attribution guard for MCP server configs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="report transport findings")
    check.add_argument("files", nargs="+")
    check.add_argument("--json", action="store_true", help="machine-readable report")
    check.add_argument("--fail-on", choices=("low", "medium", "high"), default=None)
    fix = sub.add_parser("fix", help="rewrite case-trapped URL commands (JSON only)")
    fix.add_argument("files", nargs="+")
    fix.add_argument("--json", action="store_true")
    fix.add_argument("--write", action="store_true", help="apply changes in place")
    fix.add_argument("--dry-run", action="store_true", help="report the planned rewrite")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "check":
            report = run(args.files)
            out = json.dumps(report, indent=2, sort_keys=True) if args.json else render_text(report)
            print(out)
            threshold = args.fail_on
            if threshold:
                order = {"low": 0, "medium": 1, "high": 2}
                hit = any(order[f["severity"]] >= order[threshold] for f in report["findings"])
                return 1 if hit else 0
            return 0 if report["ok"] else 1
        if args.cmd == "fix":
            if not (args.write or args.dry_run):
                raise InputError("fix needs --write or --dry-run")
            fixes: list[dict[str, Any]] = []
            for path in args.files:
                if path.lower().endswith(".toml"):
                    raise InputError("fix is JSON-only; edit TOML manually")
                data, group = load_json(path)
                changed = 0
                for name, value in data.get(group, {}).items():
                    ent = Entry(path, group, name, value, f"{group}.{name}")
                    before = value.get("command")
                    if fix_entry(ent):
                        changed += 1
                        fixes.append(
                            {
                                "file": path,
                                "server": name,
                                "from": {"command": before},
                                "to": {"url": ent.value.get("url"), "type": ent.value.get("type")},
                            }
                        )
                if args.write and changed:
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump(data, fh, indent=2)
                        fh.write("\n")
            report = run(args.files)
            report["fixed"] = len(fixes) if args.write else 0
            report["planned_fixes"] = fixes
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print(render_text(report))
                for fx in fixes:
                    print(f"FIX {fx['file']}:{fx['server']} command -> url {fx['to']['url']}")
            if report["ok"] and not fixes:
                return 0
            if args.write:
                return 0 if report["ok"] else 1
            return 1
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())