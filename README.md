# mcp-transport-guard

Offline transport-attribution guard for MCP server configs — catch the entry a client will silently launch as an executable because its URL scheme is not lowercase.

Why now: MCP clients are multiplying (Cursor, Claude Code, Codex, VS Code), each accepts a slightly different config shape, and a one-character case change can turn a remote server into a local command. This guard makes that decision explicit before it runs.

Upstream: https://github.com/openai/codex-security

## What the upstream does, and what it misses

`codex-security` has an `mcp add` command that writes MCP server entries for 20+ agents
(`sdk/typescript/src/cli-mcp.ts`). Its transport decision is one line:

```ts
if (/^https?:\/\//u.test(value)) return { url: value, type: "http" };
```

URI schemes are case-insensitive ([RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986#section-3.1)),
but this regex is not. A registration with `HTTPS://…` exits 0 and is saved as
`{"command": "HTTPS://…"}` — a local executable, not a URL. The upstream issue documents
five schemes through the real CLI registration flow:

- Issue: https://github.com/openai/codex-security/issues/2636 (open, 2026-11-13, full repro + cause)
- Source: https://github.com/openai/codex-security/blob/f26b669b56a4423abd773c81f6c6c9c2ebadc42a/sdk/typescript/src/cli-mcp.ts
- Upstream workaround in the issue: lowercase the scheme before registration.

The issue is about one writer. The same shape exists in configs those writers leave behind,
so the check belongs at the config boundary, not only inside one CLI.

## What this tool does

Reads MCP server configs (`*.json`, `*.toml`) and, for every entry, reports the transport a
client following the upstream rule will actually pick, and why it differs from what the file
appears to declare:

| Code | Severity | Meaning |
| --- | --- | --- |
| `MCP001` | high | HTTP(S) URL in `command` with a non-lowercase scheme → launched as executable; witness gives the exact scheme range and the minimal lowercase flip |
| `MCP002` | medium | `command` holds a URL with a non-http(s) scheme |
| `MCP003` | medium | `url` does not start with lowercase `http(s)://` |
| `MCP004` | high | both `command` and `url` set (transport follows client precedence) |
| `MCP005` | high | `type` says remote (`http`/`sse`) but no `url` |
| `MCP006` | high | `type` says `stdio` but a `url` is set |
| `MCP007` | medium | empty `command` |

`fix --write` migrates a case-trapped JSON entry to the explicit form the upstream writer
emits for a correctly-cased URL: `url` = scheme lowercased (path/query byte-identical),
`type` = `"http"`, `command`/`args` removed. Applying it twice changes nothing.

It does **not** launch servers, resolve DNS, read credentials, or validate schemas end-to-end.
It does not model client-specific precedence beyond the documented upstream rule.

## Install

Python 3.11+ (uses stdlib `tomllib`). No third-party dependencies, no network.

```bash
git clone git@github-linmoxi33:linmoxi33/codex-security-mcp-transport.git
cd codex-security-mcp-transport
python3 bin/mcp-transport check examples/in/cursor-mcp.json
```

## Usage

```bash
# report (text), exit 1 when findings exist
python3 bin/mcp-transport check examples/in/cursor-mcp.json examples/in/codex-config.toml

# machine-readable report
python3 bin/mcp-transport check examples/in/cursor-mcp.json --json

# only fail on high-severity findings
python3 bin/mcp-transport check .cursor/mcp.json --json --fail-on high

# preview / apply the migration
python3 bin/mcp-transport fix .cursor/mcp.json --dry-run --json
python3 bin/mcp-transport fix .cursor/mcp.json --write --json
```

`--json` prints one object with `summary`, `findings` (each with `code`, `severity`, `file`,
`server`, `field`, `witness`) and, for `fix`, `planned_fixes`/`fixed`. Example output is
committed at `examples/out/cursor-mcp.report.json`; it was produced by running the command
above, not hand-written.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | check: no findings; fix: nothing left to report after the rewrite (or nothing to do) |
| `1` | check: findings exist (or `--fail-on` threshold hit); fix: remaining findings / pending dry-run changes |
| `2` | usage or input error (missing file, invalid JSON/TOML, unknown server table, TOML write attempted) |

### Real run on the committed examples

```
$ python3 bin/mcp-transport check examples/in/cursor-mcp.json examples/in/codex-config.toml
files=2 servers=8 findings=4 fixed=0
HIGH   MCP001 examples/in/cursor-mcp.json:remote-notes.command ...
HIGH   MCP004 examples/in/cursor-mcp.json:ambiguous-docs.command+url ...
HIGH   MCP001 examples/in/codex-config.toml:web-fetch.command ...
HIGH   MCP005 examples/in/codex-config.toml:stale-type.type ...
```

Both `MCP001` witnesses point at the scheme range `[0, 5]` / `[0, 4]`; lowercasing exactly
that range flips the classified transport to `http`, which is the minimality claim the test
suite asserts.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

19 tests, no network: classification of lowercase/upper/mixed/other schemes, each rule,
the minimal-flip witness, JSON parseability, exit codes 0/1/2, TOML input, `--fail-on`
thresholds, `fix --write` round-trip and idempotence, `fix --dry-run` leaving the file
untouched.

## 本轮创新

First tool to put the **transport decision itself** under test at the config boundary:
it encodes RFC 3986 scheme case-insensitivity as a machine-checkable attribution, emits a
character-range witness (`range`, `to`, `then_transport`) that proves the minimal flip, and
migrates the entry to the exact shape the upstream writer produces for a correct URL.
Existing MCP config tools are writers (`add-mcp`, 321★) or secret scanners (`mcp-audit`);
none classify an entry as executable-vs-remote or ship a minimal witness. It is not a
wrapper around `codex-security`: it never invokes the CLI and never needs network or a login.

## 与同类项目的差异

Searched before writing (`gh search repos "mcp config"`, `gh search code "mcpServerConfig"`):

- `neon-solutions/add-mcp` (321★): installs/writes MCP configs; no transport attribution, no guard.
- `apisec-inc/mcp-audit` (166★): scans configs for exposed secrets; different failure mode.
- `getagentseal/agentseal` (383★): agent security toolkit; does not model the scheme-case branch.
- No repo matching the core function (`classify MCP entry as executable vs URL`) was found.

This project is independent: it does not fork or vendor upstream code, and only depends on
the publicly documented behaviour of the upstream regex.

## Limits

- The rule set models the upstream `mcp add` writer; other clients may differ. `MCP002`
  and `MCP003` are defensive, not proof of a specific client bug.
- Only `mcpServers`, `servers`, `amp.mcpServers` (JSON) and `[mcp_servers.*]` (TOML) are read.
- `fix` is JSON-only; TOML edits are left to the user.
- No credential, secret, or endpoint liveness checks; the guard is fully offline.

## License

MIT. See `LICENSE`.