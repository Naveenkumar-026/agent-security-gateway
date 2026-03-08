import json
import unittest
from pathlib import Path

from firewall.api import inspect_payload


class SecurityCorpusTests(unittest.TestCase):
    def test_security_corpus(self) -> None:
        corpus_path = Path(__file__).resolve().parent / "corpus" / "security_cases.json"
        cases = json.loads(corpus_path.read_text(encoding="utf-8"))

        for case in cases:
            with self.subTest(case_id=case["id"]):
                result = inspect_payload(case["payload"])
                expected = case["expected"]
                if expected == "challenge_or_block":
                    self.assertIn(result["decision"], {"challenge", "block"})
                else:
                    self.assertEqual(result["decision"], expected)


if __name__ == "__main__":
    unittest.main()