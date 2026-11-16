"""Command-line controls and readable communication logs."""

import argparse
import json

from .protocol import PARTICIPANTS
from .simulation import Event, Simulation


ACTION_LABELS = {
    "send": "发送",
    "intercept": "截获",
    "forward": "原样转发",
    "receive": "接收并存入收件箱",
}


def format_event(event: Event) -> str:
    message = event.message
    content = json.dumps(message.content, ensure_ascii=False)
    return (
        f"[{event.actor}] {ACTION_LABELS[event.action]} | "
        f"{message.sender} -> {message.recipient} | "
        f"序号 {message.sequence} | 正文 {content}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="中间人攻击与防御实验器 · 正常通信")
    parser.add_argument("--sender", choices=PARTICIPANTS, default="Alice", help="发送方")
    parser.add_argument("--message", help="消息正文，默认向接收方发送问候")
    args = parser.parse_args(argv)

    recipient = "Bob" if args.sender == "Alice" else "Alice"
    content = args.message if args.message is not None else f"你好，{recipient}！"
    simulation = Simulation()
    print(f"会话 {simulation.session_id}")
    print("模式：正常通信，Evil 原样转发")
    for event in simulation.send(args.sender, content):
        print(format_event(event))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
