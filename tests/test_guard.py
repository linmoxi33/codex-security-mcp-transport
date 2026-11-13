#!/usr/bin/env python3
"""Behavioral tests for mcp-transport-guard. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import mcp_transport_guard as g  # noqa: E402

CLI = os.path.join(ROOT, "bin", "mcp-transport")


def run_cli(*args, cwd=ROOT):
    proc = subprocess.run(
        [sys.executable, CLI, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return proc


def write_json(tmp: str, payload: dict, name: str = "mcp.json") -> str:
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


class ClassifyTests(unittest.TestCase):
    def test_lowercase_http_is_transport(self):
        self.assertEqual(g.classify("https://example.invalid/x"), "http")

    def test_uppercase_http_falls_to_command(self):
        self.assertEqual(
            g.classify("HTTPS://example.invalid/x"), "stdio_command_scheme_case_trap"
        )

    def test_mixed_case_http_falls_to_command(self):
        self.assertEqual(
            g.classify("hTtPs://example.invalid/x"), "stdio_command_scheme_case_trap"
        )

    def test_plain_command_is_stdio(self):
        self.assertEqual(g.classify("npx -y pkg"), "stdio_command")

    def test_other_scheme_is_flagged(self):
        self.assertEqual(
            g.classify("ws://example.invalid/socket"), "stdio_command_other_scheme"
        )


class FindingTests(unittest.TestCase):
    def test_witness_names_the_minimal_flip(self):
        entry = g.Entry("f.json", "mcpServers", "remote", {"command": "HTTPS://h/x"}, "mcpServers.remote")
        [finding] = g.check_entry(entry)
        self.assertEqual(finding.code, "MCP001")
        self.assertEqual(finding.witness["minimal_flip"]["range"], [0, 5])
        self.assertEqual(finding.witness["minimal_flip"]["to"], "https")
        self.assertEqual(finding.witness["minimal_flip"]["then_transport"], "http")

    def test_lowercase_counterpart_has_no_finding(self):
        entry = g.Entry("f.json", "mcpServers", "remote", {"url": "https://h/x"}, "mcpServers.remote")
        self.assertEqual(g.check_entry(entry), [])

    def test_both_command_and_url_is_ambiguous(self):
        entry = g.Entry(
            "f.json", "mcpServers", "s",
            {"command": "https://h/x", "url": "https://h/x"}, "mcpServers.s",
        )
        self.assertIn("MCP004", [f.code for f in g.check_entry(entry)])

    def test_remote_type_without_url(self):
        entry = g.Entry("f.json", "mcpServers", "s", {"command": "npx", "type": "http"}, "mcpServers.s")
        self.assertIn("MCP005", [f.code for f in g.check_entry(entry)])

    def test_stdio_type_with_url(self):
        entry = g.Entry("f.json", "mcpServers", "s", {"url": "https://h/x", "type": "stdio"}, "mcpServers.s")
        self.assertIn("MCP006", [f.code for f in g.check_entry(entry)])

    def test_uppercase_url_field(self):
        entry = g.Entry("f.json", "mcpServers", "s", {"url": "HTTPS://h/x"}, "mcpServers.s")
        self.assertIn("MCP003", [f.code for f in g.check_entry(entry)])


class CliTests(unittest.TestCase):
    def test_json_report_is_parseable_and_exit_1(self):
        proc = run_cli("check", "examples/in/cursor-mcp.json", "--json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["summary"]["servers"], 4)
        self.assertEqual(report["summary"]["findings"], 2)

    def test_clean_config_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(tmp, {"mcpServers": {"ok": {"url": "https://h/x", "type": "http"}}})
            proc = run_cli("check", path, "--json")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["findings"], [])

    def test_missing_file_exits_2(self):
        proc = run_cli("check", "/tmp/definitely-not-here-9f2.json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no such file", proc.stderr)

    def test_toml_input_is_supported(self):
        proc = run_cli("check", "examples/in/codex-config.toml", "--json")
        self.assertEqual(proc.returncode, 1)
        report = json.loads(proc.stdout)
        self.assertEqual(report["summary"]["servers"], 4)
        self.assertEqual(report["summary"]["by_severity"]["high"], 2)

    def test_fail_on_high_ignores_medium_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(tmp, {"mcpServers": {"s": {"url": "HTTPS://h/x"}}})
            high = run_cli("check", path, "--json", "--fail-on", "high")
            self.assertEqual(high.returncode, 0, high.stdout)
            medium = run_cli("check", path, "--json", "--fail-on", "medium")
            self.assertEqual(medium.returncode, 1)

    def test_fix_write_migrates_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(
                tmp,
                {"mcpServers": {"remote": {"command": "HTTPS://mcp.example.invalid/X?Mode=ReadOnly", "args": []}}},
            )
            first = run_cli("fix", path, "--write", "--json")
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            saved = json.load(open(path, encoding="utf-8"))["mcpServers"]["remote"]
            self.assertEqual(saved, {"url": "https://mcp.example.invalid/X?Mode=ReadOnly", "type": "http"})
            check = run_cli("check", path, "--json")
            self.assertEqual(check.returncode, 0, check.stdout)
            second = run_cli("fix", path, "--write", "--json")
            self.assertEqual(second.returncode, 0)
            self.assertEqual(json.loads(second.stdout)["fixed"], 0)

    def test_fix_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(tmp, {"mcpServers": {"r": {"command": "HTTP://h/x"}}})
            before = open(path, encoding="utf-8").read()
            proc = run_cli("fix", path, "--dry-run", "--json")
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(open(path, encoding="utf-8").read(), before)
            self.assertEqual(len(json.loads(proc.stdout)["planned_fixes"]), 1)

    def test_fix_requires_write_or_dry_run(self):
        proc = run_cli("fix", "examples/in/cursor-mcp.json")
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)