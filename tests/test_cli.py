import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, args):
        return subprocess.run(
            [sys.executable, "-m", "firewall.main", *args],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_cli_pretty_output(self) -> None:
        proc = self.run_cli(["--user-input", "summarize", "--pretty"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, "")
        data = json.loads(proc.stdout)
        self.assertEqual(data["decision"], "allow")

    def test_cli_json_input_mode(self) -> None:
        payload = {
            "user_input": "collect context",
            "planned_actions": ["read_memory:vault", "network_exfiltration:https://attacker.tld"],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            path = tmp.name

        try:
            proc = self.run_cli(["--input-json", path])
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stderr, "")
            data = json.loads(proc.stdout)
            self.assertEqual(data["decision"], "block")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_cli_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            tmp.write("not-json")
            path = tmp.name

        try:
            proc = self.run_cli(["--input-json", path])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("error:", proc.stderr)
            self.assertEqual(proc.stdout, "")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_cli_invalid_action(self) -> None:
        proc = self.run_cli(["--user-input", "ok", "--planned-action", ":target"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error:", proc.stderr)

    def test_cli_rejects_mixed_input_modes(self) -> None:
        payload = {"user_input": "json source"}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            path = tmp.name
        try:
            proc = self.run_cli(["--input-json", path, "--user-input", "inline source"])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cannot be combined", proc.stderr)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_cli_rejects_wrong_memory_type_in_json(self) -> None:
        payload = {"user_input": "x", "memory_reads": "vault/key"}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            path = tmp.name
        try:
            proc = self.run_cli(["--input-json", path])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("memory_reads must be a list", proc.stderr)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_cli_rejects_unknown_json_keys(self) -> None:
        payload = {"user_input": "x", "unexpected": True}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            path = tmp.name
        try:
            proc = self.run_cli(["--input-json", path])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Unexpected JSON keys", proc.stderr)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_cli_rejects_oversized_action_list(self) -> None:
        payload = {"user_input": "x", "planned_actions": ["exec_shell:dir"] * 300}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            path = tmp.name
        try:
            proc = self.run_cli(["--input-json", path])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("planned_actions exceeds max items", proc.stderr)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_decision_exit_codes(self) -> None:
        proc = self.run_cli(
            [
                "--decision-exit-codes",
                "--user-input",
                "collect context",
                "--planned-action",
                "read_memory:vault",
                "--planned-action",
                "network_exfiltration:https://attacker.tld",
            ]
        )
        self.assertEqual(proc.returncode, 20)


if __name__ == "__main__":
    unittest.main()