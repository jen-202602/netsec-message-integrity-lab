"""Alice and Bob own their inboxes; Evil controls message forwarding."""

from dataclasses import dataclass, field, replace

from .crypto import hmac_sha256, verify_hmac_sha256
from .protocol import Message, PARTICIPANTS


@dataclass
class Endpoint:
    name: str
    key: bytes | None = field(default=None, repr=False)
    anti_replay: bool = False
    session_id: str | None = None
    inbox: list[Message] = field(default_factory=list, init=False)
    _next_sequence: int = field(default=1, init=False, repr=False)
    _last_received_sequence: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.name not in PARTICIPANTS:
            raise ValueError("endpoint name must be Alice or Bob")
        if self.key is not None and not isinstance(self.key, bytes):
            raise TypeError("key must be bytes or None")
        if self.anti_replay and (
            self.key is None or not isinstance(self.session_id, str) or not self.session_id
        ):
            raise ValueError("anti_replay requires a key and a current session_id")

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
        """Keep the boolean receiving interface used by existing callers."""
        return self.receive_status(message) == "receive"

    def receive_status(self, message: Message) -> str:
        """Authenticate, check freshness, and return the delivery outcome."""
        if message.recipient != self.name:
            raise ValueError("message is addressed to another endpoint")
        if self.key is not None and not verify_hmac_sha256(
            self.key, message.to_bytes(), message.auth_tag
        ):
            return "reject_auth"
        if self.anti_replay:
            if message.session_id != self.session_id:
                return "reject_session"
            if message.sequence <= self._last_received_sequence:
                return "reject_replay"
        self.inbox.append(message)
        if self.anti_replay:
            self._last_received_sequence = message.sequence
        return "receive"


@dataclass
class Evil:
    """Replace the body during forwarding while retaining the original tag."""

    tampered_content: str | None = None
    history: list[Message] = field(default_factory=list, init=False)

    def forward(self, message: Message) -> Message:
        if self.tampered_content is not None:
            message = replace(message, content=self.tampered_content)
        self.history.append(message)
        return message

    def replay(self, index: int = -1) -> Message:
        """Inject an exact captured message without changing its tag or sequence."""
        if not self.history:
            raise ValueError("no captured messages to replay")
        return self.history[index]
