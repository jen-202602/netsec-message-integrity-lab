"""Communication and tampering scenarios through the normal entry points."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
import subprocess
import sys
import unittest

from lab.actors import Endpoint
from lab.cli import main
from lab.crypto import hmac_sha256
from lab.protocol import Message
from lab.simulation import Simulation


class ScenarioTests(unittest.TestCase):
    def test_normal_and_tampered_delivery_with_each_defense(self) -> None:
        for sender in ("Alice", "Bob"):
            for defense in ("none", "hmac"):
                for attack in ("none", "tamper"):
                    with self.subTest(sender=sender, defense=defense, attack=attack):
                        replacement = "转账 900 元" if attack == "tamper" else None
                        simulation = Simulation(
                            attack=attack, defense=defense, tampered_content=replacement
                        )
                        events = simulation.send(sender, "转账 100 元")
                        receiver = simulation.bob if sender == "Alice" else simulation.alice
                        original = events[0].message
                        forwarded = next(event.message for event in events if event.action == "forward")
                        self.assertEqual(original.content, "转账 100 元")
                        self.assertEqual(forwarded.content, replacement or original.content)
                        self.assertEqual(original.auth_tag, forwarded.auth_tag)
                        self.assertEqual(bool(original.auth_tag), defense == "hmac")
                        rejected = attack == "tamper" and defense == "hmac"
                        if rejected:
                            self.assertEqual(events[-1].action, "reject_auth")
                            self.assertEqual(receiver.inbox, [])
                        else:
                            self.assertEqual(events[-1].action, "receive")
                            self.assertEqual(receiver.inbox, [forwarded])
                            self.assertEqual(
                                any(event.action == "verify_pass" for event in events),
                                defense == "hmac",
                            )

    def test_default_flow_preserves_event_order(self) -> None:
        events = Simulation().send("Alice", "hello")
        self.assertEqual([event.action for event in events], ["send", "intercept", "forward", "receive"])
        self.assertEqual([event.actor for event in events], ["Alice", "Evil", "Evil", "Bob"])

    def test_bidirectional_sequences_and_session_isolation(self) -> None:
        simulation = Simulation(defense="hmac")
        simulation.send("Alice", "first")
        simulation.send("Bob", "reply")
        simulation.send("Alice", "second")
        self.assertEqual([message.sequence for message in simulation.bob.inbox], [1, 2])
        self.assertEqual(simulation.alice.inbox[0].sequence, 1)
        self.assertTrue(all(message.session_id == simulation.session_id for message in simulation.bob.inbox))
        self.assertNotEqual(simulation.session_id, Simulation().session_id)

    def test_normal_traffic_after_rejection(self) -> None:
        simulation = Simulation(attack="tamper", defense="hmac", tampered_content="evil")
        self.assertEqual(simulation.send("Alice", "first")[-1].action, "reject_auth")
        simulation.evil.tampered_content = None
        self.assertEqual(simulation.send("Alice", "second")[-1].action, "receive")
        self.assertEqual([message.content for message in simulation.bob.inbox], ["second"])
        self.assertEqual(simulation.bob.inbox[0].sequence, 2)
        self.assertEqual(simulation.send("Bob", "reply")[-1].action, "receive")

    def test_missing_modified_truncated_and_wrong_key_tags_are_rejected(self) -> None:
        sender = Endpoint("Alice", key=b"shared key")
        receiver = Endpoint("Bob", key=b"shared key")
        message = sender.create_message("demo", "Bob", "hello")
        bad_tags = (
            b"", message.auth_tag[:-1], message.auth_tag + b"\x00",
            bytes([message.auth_tag[0] ^ 1]) + message.auth_tag[1:],
            hmac_sha256(b"wrong key", message.to_bytes()),
        )
        for tag in bad_tags:
            with self.subTest(tag=tag):
                self.assertFalse(receiver.receive(replace(message, auth_tag=tag)))
                self.assertEqual(receiver.inbox, [])
        self.assertTrue(receiver.receive(message))
        self.assertEqual(receiver.inbox, [message])

    def test_empty_content_and_unicode(self) -> None:
        for content in ("", '你好\n"消息" 🔒'):
            with self.subTest(content=content):
                simulation = Simulation(defense="hmac")
                self.assertEqual(simulation.send("Alice", content)[-1].action, "receive")
                self.assertEqual(simulation.bob.inbox[0].content, content)
        simulation = Simulation(attack="tamper", defense="hmac", tampered_content="")
        events = simulation.send("Alice", "original")
        self.assertEqual(events[-1].action, "reject_auth")
        self.assertEqual(events[-1].message.content, "")

    def test_identical_replacement_preserves_authentication(self) -> None:
        simulation = Simulation(attack="tamper", defense="hmac", tampered_content="same")
        events = simulation.send("Alice", "same")
        self.assertEqual(events[-1].action, "receive")
        self.assertNotIn("tamper", [event.action for event in events])

    def test_authentication_tag_is_excluded_from_authentication_input(self) -> None:
        sender = Endpoint("Alice", key=b"shared key")
        message = sender.create_message("demo", "Bob", "hello")
        self.assertEqual(message.auth_tag, hmac_sha256(b"shared key", message.to_bytes()))
        self.assertEqual(message.to_bytes(), replace(message, auth_tag=b"").to_bytes())
        self.assertNotIn("auth_tag", json.loads(message.to_bytes()))
        self.assertNotIn("shared key", repr(sender))
        with self.assertRaises(TypeError):
            replace(message, auth_tag="invalid")

    def test_invalid_configuration_and_messages(self) -> None:
        for options in (
            {"attack": "unknown"}, {"defense": "unknown"}, {"attack": "tamper"},
            {"attack": "tamper", "tampered_content": 3}, {"tampered_content": "evil"},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                Simulation(**options)
        simulation = Simulation(defense="hmac")
        with self.assertRaises(ValueError):
            simulation.send("Evil", "hello")
        with self.assertRaises(TypeError):
            simulation.send("Alice", None)
        self.assertEqual(simulation.send("Alice", "valid")[0].message.sequence, 1)
        with self.assertRaises(ValueError):
            simulation.alice.receive(Message("demo", "Alice", "Bob", 1, "wrong recipient"))


class CliScenarioTests(unittest.TestCase):
    def test_cli_attack_and_defense_combinations(self) -> None:
        for sender in ("Alice", "Bob"):
            for defense in ("none", "hmac"):
                for attack in ("none", "tamper"):
                    with self.subTest(sender=sender, defense=defense, attack=attack):
                        output = io.StringIO()
                        with redirect_stdout(output):
                            result = main([
                                "--sender", sender, "--message", "转账 100 元",
                                "--attack", attack, "--defense", defense,
                            ])
                        self.assertEqual(result, 0)
                        expected = "已拒绝" if defense == "hmac" and attack == "tamper" else "已接收"
                        self.assertIn(expected, output.getvalue())
                        self.assertIn("转账 100 元", output.getvalue())
                        if attack == "tamper":
                            self.assertIn("转账 900 元", output.getvalue())

    def test_cli_custom_and_empty_replacement(self) -> None:
        for replacement in ("", '伪造正文\n"下一行"'):
            with self.subTest(replacement=replacement):
                output = io.StringIO()
                with redirect_stdout(output):
                    main(["--attack", "tamper", "--tampered-message", replacement])
                self.assertIn(json.dumps(replacement, ensure_ascii=False), output.getvalue())
                self.assertIn("已接收", output.getvalue())

    def test_invalid_cli_options(self) -> None:
        for arguments in (
            ["--attack", "unknown"], ["--defense", "unknown"], ["--sender", "Evil"],
            ["--tampered-message", "evil"],
        ):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_script_and_module_entry_points(self) -> None:
        environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        for entry in (["main.py"], ["-m", "lab.cli"]):
            with self.subTest(entry=entry):
                result = subprocess.run(
                    [sys.executable, *entry, "--attack", "tamper", "--defense", "hmac"],
                    capture_output=True, text=True, encoding="utf-8", env=environment,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("HMAC 认证失败，拒绝接收", result.stdout)
                self.assertIn("已拒绝", result.stdout)


if __name__ == "__main__":
    unittest.main()
