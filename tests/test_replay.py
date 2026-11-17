"""Replay prevention, state consistency, and command-line demonstrations."""

from contextlib import redirect_stdout
from dataclasses import replace
import io
import os
import subprocess
import sys
import unittest

from lab.actors import Endpoint, Evil
from lab.cli import main
from lab.crypto import hmac_sha256
from lab.simulation import Simulation


class ReplayTests(unittest.TestCase):
    def test_replay_under_all_defenses_and_directions(self) -> None:
        for sender in ("Alice", "Bob"):
            for defense in ("none", "hmac", "hmac-replay"):
                with self.subTest(sender=sender, defense=defense):
                    simulation = Simulation(attack="replay", defense=defense)
                    sent = simulation.send(sender, "转账 100 元")
                    original = sent[0].message
                    events = simulation.replay()
                    self.assertEqual(events[0].action, "replay")
                    self.assertIs(events[0].message, original)
                    receiver = simulation.bob if sender == "Alice" else simulation.alice
                    if defense == "hmac-replay":
                        self.assertEqual(events[-1].action, "reject_replay")
                        self.assertEqual(receiver.inbox, [original])
                    else:
                        self.assertEqual(events[-1].action, "receive")
                        self.assertEqual(receiver.inbox, [original, original])
                    if defense != "none":
                        self.assertIn("verify_pass", [event.action for event in events])

    def test_repeated_rejection_and_later_normal_bidirectional_traffic(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        simulation.send("Alice", "first")
        for _ in range(3):
            self.assertEqual(simulation.replay(0)[-1].action, "reject_replay")
        self.assertEqual(simulation.send("Alice", "second")[-1].action, "receive")
        self.assertEqual(simulation.send("Bob", "reply")[-1].action, "receive")
        self.assertEqual(simulation.replay()[-1].action, "reject_replay")
        self.assertEqual([message.sequence for message in simulation.bob.inbox], [1, 2])
        self.assertEqual([message.sequence for message in simulation.alice.inbox], [1])

    def test_old_session_with_valid_tag_is_rejected_before_sequence_update(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        old_sender = Endpoint("Alice", key=simulation.alice.key)
        old_message = old_sender.create_message("previous-session", "Bob", "old")
        simulation.evil.forward(old_message)
        events = simulation.replay()
        self.assertEqual(events[-1].action, "reject_session")
        self.assertIn("verify_pass", [event.action for event in events])
        self.assertEqual(simulation.bob.inbox, [])
        self.assertEqual(simulation.send("Alice", "current")[-1].action, "receive")
        self.assertEqual(simulation.bob.inbox[0].sequence, 1)

    def test_invalid_authentication_cannot_poison_sequence_state(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        message = simulation.alice.create_message(simulation.session_id, "Bob", "first")
        forged = replace(message, sequence=1_000_000)
        self.assertEqual(simulation.bob.receive_status(forged), "reject_auth")
        self.assertEqual(simulation.bob.receive_status(message), "receive")
        self.assertEqual(simulation.bob.receive_status(message), "reject_replay")
        wrong_session = replace(message, session_id="wrong-session", sequence=2_000_000)
        self.assertEqual(simulation.bob.receive_status(wrong_session), "reject_auth")
        self.assertEqual(simulation.send("Alice", "second")[-1].action, "receive")

    def test_authenticated_wrong_session_cannot_poison_sequence_state(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        message = simulation.alice.create_message("old-session", "Bob", "old")
        message = replace(message, sequence=1_000_000)
        message = replace(message, auth_tag=hmac_sha256(simulation.alice.key, message.to_bytes()))
        self.assertEqual(simulation.bob.receive_status(message), "reject_session")
        self.assertEqual(simulation.send("Alice", "valid")[-1].action, "receive")

    def test_gaps_are_accepted_and_late_messages_are_rejected(self) -> None:
        sender = Endpoint("Alice", key=b"key")
        receiver = Endpoint("Bob", key=b"key", anti_replay=True, session_id="current")
        messages = [sender.create_message("current", "Bob", str(index)) for index in range(3)]
        self.assertTrue(receiver.receive(messages[0]))
        self.assertTrue(receiver.receive(messages[2]))
        self.assertFalse(receiver.receive(messages[1]))
        self.assertEqual(receiver.inbox, [messages[0], messages[2]])

    def test_older_history_selection_and_empty_cache(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        with self.assertRaises(ValueError):
            simulation.replay()
        simulation.send("Alice", "first")
        simulation.send("Alice", "second")
        self.assertEqual(simulation.replay(0)[0].message.content, "first")
        self.assertEqual(simulation.replay(0)[-1].action, "reject_replay")
        self.assertEqual(len(simulation.evil.history), 2)
        with self.assertRaises(IndexError):
            simulation.replay(99)
        self.assertEqual(len(simulation.bob.inbox), 2)

    def test_cache_contains_actual_forwarded_message(self) -> None:
        simulation = Simulation(attack="tamper", defense="hmac-replay", tampered_content="evil")
        events = simulation.send("Alice", "original")
        cached = simulation.evil.history[0]
        self.assertEqual(cached.content, "evil")
        self.assertEqual(cached.auth_tag, events[0].message.auth_tag)
        self.assertEqual(simulation.replay()[-1].action, "reject_auth")
        simulation.evil.tampered_content = None
        self.assertEqual(simulation.send("Alice", "normal")[-1].action, "receive")
        self.assertEqual(simulation.bob.inbox[0].sequence, 2)

    def test_fresh_endpoint_sessions_reset_receiving_state(self) -> None:
        sender = Endpoint("Alice", key=b"same key")
        old = sender.create_message("old", "Bob", "old message")
        old_receiver = Endpoint("Bob", key=b"same key", anti_replay=True, session_id="old")
        self.assertTrue(old_receiver.receive(old))
        new_receiver = Endpoint("Bob", key=b"same key", anti_replay=True, session_id="new")
        self.assertEqual(new_receiver.receive_status(old), "reject_session")
        new_sender = Endpoint("Alice", key=b"same key")
        fresh = new_sender.create_message("new", "Bob", "fresh")
        self.assertTrue(new_receiver.receive(fresh))
        self.assertEqual(fresh.sequence, 1)

    def test_invalid_replay_configuration(self) -> None:
        for options in ({"anti_replay": True}, {"anti_replay": True, "key": b"key"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                Endpoint("Bob", **options)
        with self.assertRaises(ValueError):
            Simulation(attack="replay", tampered_content="evil")
        self.assertEqual(Evil().history, [])


class ReplayCliTests(unittest.TestCase):
    def test_replay_cli_with_each_defense_and_direction(self) -> None:
        for sender in ("Alice", "Bob"):
            for defense in ("none", "hmac", "hmac-replay"):
                with self.subTest(sender=sender, defense=defense):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(main([
                            "--sender", sender, "--message", "转账 100 元",
                            "--attack", "replay", "--defense", defense,
                        ]), 0)
                    result = output.getvalue()
                    self.assertIn("结果：" + ("Bob" if sender == "Alice" else "Alice") + " 已接收", result)
                    if defense == "hmac-replay":
                        self.assertIn("重复或过期序号，拒绝接收", result)
                        self.assertIn("收件箱消息数 1", result)
                    else:
                        self.assertIn("收件箱消息数 2", result)
                        self.assertNotIn("已拒绝", result)

    def test_replay_script_and_module_entry_points(self) -> None:
        environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        for entry in (["main.py"], ["-m", "lab.cli"]):
            with self.subTest(entry=entry):
                result = subprocess.run(
                    [sys.executable, *entry, "--attack", "replay", "--defense", "hmac-replay"],
                    capture_output=True, text=True, encoding="utf-8", env=environment,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("收件箱消息数 1", result.stdout)
                self.assertIn("重复或过期序号，拒绝接收", result.stdout)


if __name__ == "__main__":
    unittest.main()
