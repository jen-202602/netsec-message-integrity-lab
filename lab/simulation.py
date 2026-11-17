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
        if attack not in ("none", "tamper"):
            raise ValueError("attack must be none or tamper")
        if defense not in ("none", "hmac"):
            raise ValueError("defense must be none or hmac")
        if attack == "tamper" and not isinstance(tampered_content, str):
            raise ValueError("tamper attack requires a string tampered_content")
        if attack == "none" and tampered_content is not None:
            raise ValueError("tampered_content requires the tamper attack")
        self.session_id = secrets.token_hex(16)
        # Model a shared key distributed through a trusted channel before this session.
        key = secrets.token_bytes(32) if defense == "hmac" else None
        self.alice = Endpoint("Alice", key=key)
        self.bob = Endpoint("Bob", key=key)
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
        events.append(Event("Evil", "forward", forwarded))
        receiver = self._endpoints[forwarded.recipient]
        accepted = receiver.receive(forwarded)
        if accepted:
            if receiver.key is not None:
                events.append(Event(receiver.name, "verify_pass", forwarded))
            events.append(Event(receiver.name, "receive", forwarded))
        else:
            events.append(Event(receiver.name, "reject_auth", forwarded))
        return tuple(events)
