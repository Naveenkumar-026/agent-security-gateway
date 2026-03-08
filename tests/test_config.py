import os
import tempfile
import unittest

from firewall.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_defaults(self) -> None:
        cfg = load_config(env={})
        self.assertAlmostEqual(cfg.policy.block_score, 1.8)
        self.assertTrue(cfg.detector_toggles["prompt_injection"])
        self.assertTrue(cfg.logging.redact_sensitive)
        self.assertTrue(cfg.policy.allow_with_redaction)
        self.assertTrue(cfg.redaction.enabled)

    def test_env_override(self) -> None:
        cfg = load_config(
            env={
                "FIREWALL_BLOCK_SCORE": "2.5",
                "FIREWALL_CHALLENGE_SCORE": "0.3",
                "FIREWALL_ENABLE_TOOL_ABUSE": "false",
                "FIREWALL_REDACT_LOGS": "false",
                "FIREWALL_DETECTOR_SCORE_CAP": "0.9",
                "FIREWALL_ALLOW_WITH_REDACTION": "false",
                "FIREWALL_REDACTION_MIN_ENTROPY": "4.1",
            }
        )
        self.assertAlmostEqual(cfg.policy.block_score, 2.5)
        self.assertAlmostEqual(cfg.policy.challenge_score, 0.3)
        self.assertFalse(cfg.detector_toggles["tool_abuse"])
        self.assertFalse(cfg.logging.redact_sensitive)
        self.assertAlmostEqual(cfg.policy.detector_score_cap, 0.9)
        self.assertFalse(cfg.policy.allow_with_redaction)
        self.assertAlmostEqual(cfg.redaction.high_entropy_min_entropy, 4.1)

    def test_file_override(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            tmp.write('{"policy": {"block_score": 3.0}, "redaction": {"mask_pii": false}}')
            path = tmp.name

        try:
            cfg = load_config(config_path=path, env={})
            self.assertAlmostEqual(cfg.policy.block_score, 3.0)
            self.assertFalse(cfg.redaction.mask_pii)
        finally:
            os.unlink(path)

    def test_invalid_threshold_rejected(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            tmp.write('{"policy": {"block_score": 1.0, "challenge_score": 2.0}}')
            path = tmp.name

        try:
            with self.assertRaises(ValueError):
                load_config(config_path=path, env={})
        finally:
            os.unlink(path)

    def test_invalid_sensitive_actions_env_shape(self) -> None:
        with self.assertRaises(ValueError):
            load_config(env={"FIREWALL_SENSITIVE_ACTIONS_JSON": "[]"})

    def test_invalid_sensitive_actions_severity(self) -> None:
        with self.assertRaises(ValueError):
            load_config(env={"FIREWALL_SENSITIVE_ACTIONS_JSON": '{"exec_shell": ["urgent", 0.9]}'})

    def test_invalid_redaction_config_rejected(self) -> None:
        with self.assertRaises(ValueError):
            load_config(env={"FIREWALL_REDACTION_MIN_LENGTH": "4"})


if __name__ == "__main__":
    unittest.main()
