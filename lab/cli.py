"""Command-line controls and readable communication logs."""

import argparse
import json

from .protocol import PARTICIPANTS
from .simulation import Event, Simulation


ACTION_LABELS = {
    "send": "发送",
    "intercept": "截获",
    "tamper": "篡改正文",
    "replay": "重放已缓存消息，保留会话、序号和标签",
    "forward": "转发",
    "verify_pass": "HMAC 认证通过",
    "reject_auth": "HMAC 认证失败，拒绝接收",
    "reject_session": "会话标识不匹配，拒绝接收",
    "reject_replay": "重复或过期序号，拒绝接收",
    "receive": "接收并存入收件箱",
}


def format_event(event: Event) -> str:
    message = event.message
    content = json.dumps(message.content, ensure_ascii=False)
    tag = f" | HMAC {message.auth_tag.hex()}" if message.auth_tag else ""
    return (
        f"[{event.actor}] {ACTION_LABELS[event.action]} | "
        f"{message.sender} -> {message.recipient} | "
        f"序号 {message.sequence} | 正文 {content}{tag}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="中间人攻击与防御实验器 · 篡改、重放与防御")
    parser.add_argument("--sender", choices=PARTICIPANTS, default="Alice", help="发送方")
    parser.add_argument("--message", help="消息正文，默认向接收方发送问候")
    parser.add_argument("--gui", action="store_true", help="启动图形界面")
    parser.add_argument("--attack", choices=("none", "tamper", "replay"), default="none", help="攻击方式")
    parser.add_argument("--defense", choices=("none", "hmac", "hmac-replay"), default="none", help="防御方式")
    parser.add_argument("--tampered-message", help="Evil 替换的正文，篡改模式默认使用“转账 900 元”")
    args = parser.parse_args(argv)
    if args.tampered_message is not None and args.attack != "tamper":
        parser.error("--tampered-message 需要 --attack tamper")

    recipient = "Bob" if args.sender == "Alice" else "Alice"
    content = args.message if args.message is not None else f"你好，{recipient}！"
    tampered_content = args.tampered_message
    if args.attack == "tamper" and tampered_content is None:
        tampered_content = "转账 900 元"
    if args.gui:
        from .gui import launch

        return launch(
            sender=args.sender, message=content, attack=args.attack,
            defense=args.defense, tampered_content=tampered_content,
        )
    simulation = Simulation(
        attack=args.attack, defense=args.defense, tampered_content=tampered_content
    )
    print(f"会话 {simulation.session_id}")
    attack_label = {"none": "原样转发", "tamper": "篡改正文", "replay": "重放消息"}[args.attack]
    defense_label = {
        "none": "无认证", "hmac": "HMAC-SHA-256", "hmac-replay": "HMAC-SHA-256 + 防重放"
    }[args.defense]
    print(f"模式：{attack_label} | 防御：{defense_label}")
    events = simulation.send(args.sender, content)
    for event in events:
        print(format_event(event))
    result = "已接收" if events[-1].action == "receive" else "已拒绝"
    print(f"结果：{recipient} {result}")
    if args.attack == "replay":
        print("重放阶段：Evil 再次发送刚才缓存的消息")
        replay_events = simulation.replay()
        for event in replay_events:
            print(format_event(event))
        replay_result = "已接收" if replay_events[-1].action == "receive" else "已拒绝"
        receiver = simulation.bob if recipient == "Bob" else simulation.alice
        print(f"重放结果：{recipient} {replay_result} | 收件箱消息数 {len(receiver.inbox)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
