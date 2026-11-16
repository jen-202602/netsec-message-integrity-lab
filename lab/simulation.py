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
    def __init__(self) -> None:
        self.session_id = secrets.token_hex(16)
        self.alice = Endpoint("Alice")
        self.bob = Endpoint("Bob")
        self.evil = Evil()
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
        events.append(Event("Evil", "forward", forwarded))
        self._endpoints[forwarded.recipient].receive(forwarded)
        events.append(Event(forwarded.recipient, "receive", forwarded))
        return tuple(events)
