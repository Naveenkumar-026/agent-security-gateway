import unittest

from firewall.config import RedactionConfig
from firewall.redaction import OutputRedactor


class RedactionTests(unittest.TestCase):
    def test_secret_and_entropy_masking_deterministic(self) -> None:
        redactor = OutputRedactor(RedactionConfig(enabled=True, mask_pii=False))
        raw = "api_key=SECRET123 token A1b2C3d4E5f6G7h8I9j0K1l2"
        first = redactor.redact_text(raw)
        second = redactor.redact_text(raw)

        self.assertTrue(first.redacted)
        self.assertEqual(first.sanitized_text, second.sanitized_text)
        self.assertNotIn("SECRET123", first.sanitized_text)
        self.assertIn("[REDACTED:secret:", first.sanitized_text)
        self.assertIn("[REDACTED:high_entropy:", first.sanitized_text)

    def test_pii_masking_configurable(self) -> None:
        with_pii = OutputRedactor(RedactionConfig(enabled=True, mask_pii=True))
        without_pii = OutputRedactor(RedactionConfig(enabled=True, mask_pii=False))

        raw = "email alice@example.com phone 415-555-1234"
        masked = with_pii.redact_text(raw)
        unmasked = without_pii.redact_text(raw)

        self.assertIn("[REDACTED:pii_email:", masked.sanitized_text)
        self.assertIn("[REDACTED:pii_phone:", masked.sanitized_text)
        self.assertIn("alice@example.com", unmasked.sanitized_text)
        self.assertIn("415-555-1234", unmasked.sanitized_text)

    def test_max_items_cap_is_deterministic(self) -> None:
        cfg = RedactionConfig(enabled=True, mask_pii=False, max_masked_items_per_output=1)
        redactor = OutputRedactor(cfg)
        raw = "api_key=SECRET123 token=ABCDEF1234567890XYZ"
        result = redactor.redact_text(raw)

        self.assertTrue(result.redacted)
        self.assertEqual(len(result.events), 1)


if __name__ == "__main__":
    unittest.main()
