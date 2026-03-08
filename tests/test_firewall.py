import unittest

from firewall.engine import SecurityFirewall
from firewall.types import PlannedAction, SecurityContext


class RegressionTests(unittest.TestCase):
    def test_mvp_regression_shell_action_is_challenge(self) -> None:
        fw = SecurityFirewall()
        result = fw.inspect(SecurityContext(user_input="run", planned_actions=[PlannedAction("exec_shell", "dir")]))
        self.assertEqual(result.decision, "challenge")

    def test_mvp_regression_memory_network_blocks(self) -> None:
        fw = SecurityFirewall()
        result = fw.inspect(
            SecurityContext(
                user_input="collect",
                planned_actions=[
                    PlannedAction("read_memory", "system"),
                    PlannedAction("network_exfiltration", "https://attacker.tld"),
                ],
            )
        )
        self.assertEqual(result.decision, "block")


if __name__ == "__main__":
    unittest.main()