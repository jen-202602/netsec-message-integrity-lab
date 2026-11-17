"""Widget integration checks using a withdrawn Tk window when available."""

import time
import unittest
from unittest.mock import patch

try:
    import tkinter as tk
except ImportError:
    tk = None


@unittest.skipIf(tk is None, "Tkinter is unavailable")
class GuiTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"Tk display is unavailable: {error}")
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        from lab.gui import LabApp

        self.app = LabApp(self.root)
        self.root.update_idletasks()

    def finish_steps(self) -> None:
        for _ in range(20):
            if self.app._pending is None:
                return
            self.app.advance()
        self.fail("scenario did not finish within 20 steps")

    def test_prepare_and_single_step_keep_inbox_unchanged(self) -> None:
        self.app.prepare_button.invoke()
        self.assertEqual(self.app.events, [])
        self.assertEqual(self.app.simulation.bob.inbox, [])
        self.assertEqual(str(self.app.attack_box["state"]), "disabled")
        self.app.step_button.invoke()
        self.assertEqual(self.app.events[-1].action, "send")
        self.assertEqual(self.app.simulation.bob.inbox, [])
        self.finish_steps()
        self.assertEqual(len(self.app.simulation.bob.inbox), 1)
        self.assertEqual(str(self.app.attack_box["state"]), "readonly")
        self.assertEqual(len(self.app.log.get_children()), len(self.app.events))

    def test_gui_scenarios_for_all_modes(self) -> None:
        from lab.gui import ATTACKS, DEFENSES

        for attack in ATTACKS:
            for defense in DEFENSES:
                with self.subTest(attack=attack, defense=defense):
                    self.app.attack.set(attack)
                    self.app.defense.set(defense)
                    self.app.reset_session()
                    self.app.prepare_send()
                    self.finish_steps()
                    protected = DEFENSES[defense] != "none"
                    if ATTACKS[attack] == "tamper" and protected:
                        self.assertEqual(self.app.events[-1].action, "reject_auth")
                        self.assertEqual(len(self.app.simulation.bob.inbox), 0)
                    elif ATTACKS[attack] == "replay" and DEFENSES[defense] == "hmac-replay":
                        self.assertEqual(self.app.events[-1].action, "reject_replay")
                        self.assertEqual(len(self.app.simulation.bob.inbox), 1)
                    else:
                        self.assertEqual(self.app.events[-1].action, "receive")
                        expected = 2 if ATTACKS[attack] == "replay" else 1
                        self.assertEqual(len(self.app.simulation.bob.inbox), expected)

    def test_manual_replay_and_direction_change(self) -> None:
        self.app.defense.set("HMAC + 防重放")
        self.app.reset_session()
        self.app.prepare_send()
        self.finish_steps()
        self.app.replay_button.invoke()
        self.finish_steps()
        self.assertEqual(self.app.events[-1].action, "reject_replay")
        session = self.app.simulation.session_id
        self.app.sender.set("Bob")
        self.app.prepare_send()
        self.finish_steps()
        self.assertEqual(self.app.simulation.session_id, session)
        self.assertEqual(self.app.simulation.alice.inbox[0].sequence, 1)

    def test_reset_discards_partial_send_and_cancels_timer(self) -> None:
        self.app.play_button.invoke()
        self.assertTrue(self.app._playing)
        timer = self.app._timer
        old_session = self.app.simulation.session_id
        self.app.reset_session()
        self.assertNotEqual(self.app.simulation.session_id, old_session)
        self.assertIsNone(self.app._pending)
        self.assertIsNone(self.app._timer)
        self.assertFalse(self.app._playing)
        self.assertNotIn(timer, self.root.tk.call("after", "info"))
        self.assertEqual(self.app.events, [])
        self.assertEqual(self.app.simulation.bob.inbox, [])
        self.assertEqual(self.app.simulation.evil.history, [])

    def test_pause_and_resume_preserve_progress(self) -> None:
        self.app.play_button.invoke()
        self.app.pause_button.invoke()
        before = list(self.app.events)
        self.root.update()
        self.assertEqual(self.app.events, before)
        self.assertEqual(str(self.app.step_button["state"]), "normal")
        self.finish_steps()
        self.assertEqual(self.app.events[-1].action, "receive")
        self.assertEqual(len(self.app.simulation.bob.inbox), 1)

    def test_autoplay_completes_through_tk_event_loop(self) -> None:
        self.app.attack.set("重放消息")
        self.app.defense.set("HMAC + 防重放")
        self.app.reset_session()
        with patch("lab.gui.PLAY_INTERVAL_MS", 1):
            self.app.play_button.invoke()
            deadline = time.monotonic() + 5
            while self.app._pending is not None and time.monotonic() < deadline:
                self.root.update()
                time.sleep(0.005)
        self.assertIsNone(self.app._pending)
        self.assertFalse(self.app._playing)
        self.assertEqual(self.app.events[-1].action, "reject_replay")
        self.assertEqual(len(self.app.simulation.bob.inbox), 1)

    def test_changing_scenario_starts_a_new_session(self) -> None:
        session = self.app.simulation.session_id
        self.app.attack.set("篡改正文")
        self.app.attack_box.event_generate("<<ComboboxSelected>>")
        self.assertNotEqual(self.app.simulation.session_id, session)
        self.assertEqual(str(self.app.tampered_input["state"]), "normal")
        self.assertEqual(self.app.simulation.evil.tampered_content, "转账 900 元")


if __name__ == "__main__":
    unittest.main()
