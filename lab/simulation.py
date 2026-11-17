"""Route messages through Evil and expose communication events to clients."""

from dataclasses import dataclass
import secrets

from .actors import Endpoint, Evil
from .protocol import Message, PARTICIPANTS


@dataclass(frozen=True)
class Event:
    actor: str
    action: str
    message: Message


class Simulation:
    def __init__(
        self,
        *,
        attack: str = "none",
        defense: str = "none",
        tampered_content: str | None = None,
    ) -> None:
        if attack not in ("none", "tamper", "replay"):
            raise ValueError("attack must be none, tamper, or replay")
        if defense not in ("none", "hmac", "hmac-replay"):
            raise ValueError("defense must be none, hmac, or hmac-replay")
        if attack == "tamper" and not isinstance(tampered_content, str):
            raise ValueError("tamper attack requires a string tampered_content")
        if attack != "tamper" and tampered_content is not None:
            raise ValueError("tampered_content requires the tamper attack")
        self.session_id = secrets.token_hex(16)
        # Model a shared key distributed through a trusted channel before this session.
        key = secrets.token_bytes(32) if defense != "none" else None
        anti_replay = defense == "hmac-replay"
        self.alice = Endpoint("Alice", key=key, anti_replay=anti_replay, session_id=self.session_id)
        self.bob = Endpoint("Bob", key=key, anti_replay=anti_replay, session_id=self.session_id)
        self.evil = Evil(tampered_content=tampered_content)
        self._endpoints = {"Alice": self.alice, "Bob": self.bob}

    def send(self, sender: str, content: str) -> tuple[Event, ...]:
        if sender not in PARTICIPANTS:
            raise ValueError("sender must be Alice or Bob")
        recipient = "Bob" if sender == "Alice" else "Alice"
        message = self._endpoints[sender].create_message(
            self.session_id, recipient, content
        )
        events = [Event(sender, "send", message), Event("Evil", "intercept", message)]
        forwarded = self.evil.forward(message)
        if forwarded.content != message.content:
            events.append(Event("Evil", "tamper", forwarded))
        return tuple(events) + self._deliver(forwarded)

    def replay(self, index: int = -1) -> tuple[Event, ...]:
        message = self.evil.replay(index)
        return (Event("Evil", "replay", message),) + self._deliver(message)

    def _deliver(self, message: Message) -> tuple[Event, ...]:
        """Use the same receiver checks for original and replayed traffic."""
        events = [Event("Evil", "forward", message)]
        receiver = self._endpoints[message.recipient]
        status = receiver.receive_status(message)
        if receiver.key is not None and status != "reject_auth":
            events.append(Event(receiver.name, "verify_pass", message))
        events.append(Event(receiver.name, status, message))
        return tuple(events)
