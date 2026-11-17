"""Route messages through Evil and expose communication events to clients."""

from dataclasses import dataclass
from collections.abc import Iterator
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
        return tuple(self.send_steps(sender, content))

    def send_steps(self, sender: str, content: str) -> Iterator[Event]:
        """Execute one communication action for each iterator advancement."""
        if sender not in PARTICIPANTS:
            raise ValueError("sender must be Alice or Bob")
        recipient = "Bob" if sender == "Alice" else "Alice"
        message = self._endpoints[sender].create_message(
            self.session_id, recipient, content
        )
        yield Event(sender, "send", message)
        yield Event("Evil", "intercept", message)
        forwarded = self.evil.forward(message)
        if forwarded.content != message.content:
            yield Event("Evil", "tamper", forwarded)
        yield from self._deliver_steps(forwarded)

    def replay(self, index: int = -1) -> tuple[Event, ...]:
        return tuple(self.replay_steps(index))

    def replay_steps(self, index: int = -1) -> Iterator[Event]:
        message = self.evil.replay(index)
        yield Event("Evil", "replay", message)
        yield from self._deliver_steps(message)

    def _deliver_steps(self, message: Message) -> Iterator[Event]:
        """Use the same receiver checks for original and replayed traffic."""
        yield Event("Evil", "forward", message)
        receiver = self._endpoints[message.recipient]
        for status in receiver.receive_steps(message):
            yield Event(receiver.name, status, message)
