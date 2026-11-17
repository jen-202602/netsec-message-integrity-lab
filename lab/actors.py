"""Alice and Bob own their inboxes; Evil controls message forwarding."""

from dataclasses import dataclass, field, replace

from .crypto import hmac_sha256, verify_hmac_sha256
from .protocol import Message, PARTICIPANTS


@dataclass
class Endpoint:
    name: str
    key: bytes | None = field(default=None, repr=False)
    inbox: list[Message] = field(default_factory=list, init=False)
    _next_sequence: int = field(default=1, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.name not in PARTICIPANTS:
            raise ValueError("endpoint name must be Alice or Bob")
        if self.key is not None and not isinstance(self.key, bytes):
            raise TypeError("key must be bytes or None")

    def create_message(self, session_id: str, recipient: str, content: str) -> Message:
        message = Message(
            session_id=session_id,
            sender=self.name,
            recipient=recipient,
            sequence=self._next_sequence,
            content=content,
        )
        if self.key is not None:
            message = replace(message, auth_tag=hmac_sha256(self.key, message.to_bytes()))
        self._next_sequence += 1
        return message

    def receive(self, message: Message) -> bool:
        if message.recipient != self.name:
            raise ValueError("message is addressed to another endpoint")
        if self.key is not None and not verify_hmac_sha256(
            self.key, message.to_bytes(), message.auth_tag
        ):
            return False
        self.inbox.append(message)
        return True


@dataclass
class Evil:
    """Replace the body during forwarding while retaining the original tag."""

    tampered_content: str | None = None

    def forward(self, message: Message) -> Message:
        if self.tampered_content is not None:
            return replace(message, content=self.tampered_content)
        return message
