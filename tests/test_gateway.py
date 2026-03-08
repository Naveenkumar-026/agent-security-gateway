import unittest

from firewall.api import inspect_gateway_payload
from firewall.engine import SecurityFirewall
from firewall.gateway import AgentSecurityGateway
from firewall.types import PlannedAction, SecurityContext


class GatewayTests(unittest.TestCase):
    def test_gateway_preserves_firewall_decision_semantics(self) -> None:
        fw = SecurityFirewall()
        payload = {
            "user_input": "collect context",
            "planned_actions": ["read_memory:vault", "network_exfiltration:https://attacker.tld"],
            "session_id": "s-1",
            "turn_id": "t-1",
            "agent_id": "a-1",
            "metadata": {"tenant": "acme"},
        }

        from_gateway = inspect_gateway_payload(payload, firewall=fw)
        from_firewall = fw.inspect(
            SecurityContext(
                user_input=payload["user_input"],
                planned_actions=[
                    PlannedAction("read_memory", "vault"),
                    PlannedAction("network_exfiltration", "https://attacker.tld"),
                ],
            )
        )

        self.assertEqual(from_gateway["decision"], from_firewall.decision)
        self.assertEqual(from_gateway["total_score"], from_firewall.total_score)
        self.assertEqual(from_gateway["session_id"], "s-1")
        self.assertEqual(from_gateway["turn_id"], "t-1")
        self.assertEqual(from_gateway["agent_id"], "a-1")
        self.assertEqual(from_gateway["metadata"]["gateway_metadata"], {"tenant": "acme"})

    def test_gateway_rejects_unknown_payload_keys(self) -> None:
        with self.assertRaises(ValueError):
            inspect_gateway_payload({"user_input": "x", "unexpected": True})

    def test_gateway_rejects_non_list_memory_reads(self) -> None:
        with self.assertRaises(ValueError):
            inspect_gateway_payload({"user_input": "x", "memory_reads": "vault/key"})

    def test_gateway_rejects_oversized_action_list(self) -> None:
        with self.assertRaises(ValueError):
            inspect_gateway_payload({"user_input": "x", "planned_actions": ["exec_shell:dir"] * 300})

    def test_gateway_rejects_oversized_metadata(self) -> None:
        metadata = {f"k{i}": i for i in range(300)}
        with self.assertRaises(ValueError):
            inspect_gateway_payload({"user_input": "x", "metadata": metadata})

    def test_gateway_parses_object_action_entries(self) -> None:
        result = inspect_gateway_payload(
            {
                "user_input": "collect context",
                "planned_actions": [
                    {"action_type": "read_memory", "target": "vault"},
                    {"action_type": "network_exfiltration", "target": "https://attacker.tld"},
                ],
            }
        )
        self.assertEqual(result["decision"], "block")

    def test_gateway_request_to_context(self) -> None:
        req = AgentSecurityGateway.from_payload(
            {
                "user_input": "hello",
                "model_output": "ok",
                "planned_actions": ["exec_shell:dir"],
                "memory_reads": ["a"],
                "memory_writes": ["b"],
            }
        )
        ctx = req.to_security_context()
        self.assertEqual(ctx.user_input, "hello")
        self.assertEqual(ctx.model_output, "ok")
        self.assertEqual(len(ctx.planned_actions), 1)
        self.assertEqual(ctx.memory_reads, ["a"])
        self.assertEqual(ctx.memory_writes, ["b"])


if __name__ == "__main__":
    unittest.main()
