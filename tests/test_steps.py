"""Ensure each step executes its corresponding operation lazily."""

import unittest

from lab.actors import Endpoint
from lab.simulation import Simulation


class StepExecutionTests(unittest.TestCase):
    def test_send_and_authentication_steps_do_not_deliver_early(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        steps = simulation.send_steps("Alice", "hello")
        self.assertEqual(simulation.evil.history, [])
        self.assertEqual(simulation.bob.inbox, [])
        self.assertEqual(next(steps).action, "send")
        self.assertEqual(simulation.evil.history, [])
        self.assertEqual(next(steps).action, "intercept")
        self.assertEqual(simulation.evil.history, [])
        self.assertEqual(next(steps).action, "forward")
        self.assertEqual(len(simulation.evil.history), 1)
        self.assertEqual(simulation.bob.inbox, [])
        self.assertEqual(next(steps).action, "verify_pass")
        self.assertEqual(simulation.bob.inbox, [])
        self.assertEqual(next(steps).action, "receive")
        self.assertEqual(len(simulation.bob.inbox), 1)
        with self.assertRaises(StopIteration):
            next(steps)

    def test_tamper_occurs_after_interception(self) -> None:
        simulation = Simulation(attack="tamper", defense="hmac", tampered_content="evil")
        steps = simulation.send_steps("Alice", "original")
        self.assertEqual(next(steps).message.content, "original")
        self.assertEqual(next(steps).message.content, "original")
        tamper = next(steps)
        self.assertEqual(tamper.action, "tamper")
        self.assertEqual(tamper.message.content, "evil")
        self.assertEqual([event.action for event in steps], ["forward", "reject_auth"])
        self.assertEqual(simulation.bob.inbox, [])

    def test_replay_steps_share_receiver_state(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        simulation.send("Alice", "hello")
        steps = simulation.replay_steps()
        self.assertEqual(next(steps).action, "replay")
        self.assertEqual(next(steps).action, "forward")
        self.assertEqual(next(steps).action, "verify_pass")
        self.assertEqual(next(steps).action, "reject_replay")
        self.assertEqual(len(simulation.bob.inbox), 1)

    def test_discarding_pending_steps_does_not_update_inbox(self) -> None:
        simulation = Simulation(defense="hmac-replay")
        steps = simulation.send_steps("Alice", "cancelled")
        while next(steps).action != "verify_pass":
            pass
        steps.close()
        self.assertEqual(simulation.bob.inbox, [])
        self.assertEqual(simulation.send("Alice", "next")[-1].action, "receive")
        self.assertEqual(simulation.bob.inbox[0].sequence, 2)

    def test_boolean_receiving_interface_still_runs_all_steps(self) -> None:
        sender = Endpoint("Alice", key=b"key")
        receiver = Endpoint("Bob", key=b"key", anti_replay=True, session_id="session")
        message = sender.create_message("session", "Bob", "hello")
        steps = receiver.receive_steps(message)
        self.assertEqual(next(steps), "verify_pass")
        self.assertEqual(receiver.inbox, [])
        steps.close()
        self.assertTrue(receiver.receive(message))
        self.assertFalse(receiver.receive(message))

    def test_synchronous_and_stepwise_event_sequences_match(self) -> None:
        for defense in ("none", "hmac", "hmac-replay"):
            for attack in ("none", "tamper"):
                with self.subTest(defense=defense, attack=attack):
                    replacement = "evil" if attack == "tamper" else None
                    synchronous = Simulation(attack=attack, defense=defense, tampered_content=replacement)
                    stepwise = Simulation(attack=attack, defense=defense, tampered_content=replacement)
                    expected = synchronous.send("Bob", "original")
                    actual = tuple(stepwise.send_steps("Bob", "original"))
                    self.assertEqual(
                        [(event.actor, event.action, event.message.content) for event in expected],
                        [(event.actor, event.action, event.message.content) for event in actual],
                    )


if __name__ == "__main__":
    unittest.main()
