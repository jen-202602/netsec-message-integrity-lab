"""Alice and Bob own their inboxes; Evil controls message forwarding."""

from dataclasses import dataclass, field

from .protocol import Message, PARTICIPANTS


@dataclass
class Endpoint:
    name: str
    inbox: list[Message] = field(default_factory=list, init=False)
    _next_sequence: int = field(default=1, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.name not in PARTICIPANTS:
            raise ValueError("endpoint name must be Alice or Bob")

    def create_message(self, session_id: str, recipient: str, content: str) -> Message:
        message = Message(
            session_id=session_id,
            sender=self.name,
            recipient=recipient,
            sequence=self._next_sequence,
            content=content,
        )
        self._next_sequence += 1
        return message

    def receive(self, message: Message) -> None:
        if message.recipient != self.name:
            raise ValueError("message is addressed to another endpoint")
        self.inbox.append(message)


class Evil:
    """Forward messages unchanged during the first development stage."""

    def forward(self, message: Message) -> Message:
        return message
