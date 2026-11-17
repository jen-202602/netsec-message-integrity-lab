"""Message fields and deterministic encoding shared by all participants."""

from dataclasses import dataclass, field
import json


PARTICIPANTS = ("Alice", "Bob")


@dataclass(frozen=True)
class Message:
    session_id: str
    sender: str
    recipient: str
    sequence: int
    content: str
    auth_tag: bytes = b""
    version: int = field(default=1, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id:
            raise ValueError("session_id must be a non-empty string")
        if self.sender not in PARTICIPANTS or self.recipient not in PARTICIPANTS:
            raise ValueError("sender and recipient must be Alice or Bob")
        if self.sender == self.recipient:
            raise ValueError("sender and recipient must be different")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")
        if not isinstance(self.auth_tag, bytes):
            raise TypeError("auth_tag must be bytes")

    def to_bytes(self) -> bytes:
        """Encode authenticated fields, excluding the tag itself."""
        fields = {
            "version": self.version,
            "session_id": self.session_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "sequence": self.sequence,
            "content": self.content,
        }
        return json.dumps(
            fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
