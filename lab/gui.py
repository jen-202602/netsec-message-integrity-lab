"""Tkinter controls for step-by-step communication and attack experiments."""

from collections.abc import Iterator
import json
import tkinter as tk
from tkinter import messagebox, ttk

from .cli import ACTION_LABELS
from .protocol import Message
from .simulation import Event, Simulation


ATTACKS = {"正常转发": "none", "篡改正文": "tamper", "重放消息": "replay"}
DEFENSES = {"无防御": "none", "HMAC 认证": "hmac", "HMAC + 防重放": "hmac-replay"}
BACKGROUND = "#f3f5f7"
INK = "#162d40"
TEAL = "#087f78"
ORANGE = "#b86024"
RED = "#b63a40"
PLAY_INTERVAL_MS = 700


class LabApp(ttk.Frame):
    def __init__(
        self, root: tk.Tk, *, sender: str = "Alice", message: str = "转账 100 元",
        attack: str = "none", defense: str = "none", tampered_content: str | None = None,
    ) -> None:
        super().__init__(root, padding=18)
        self.root = root
        root.title("消息完整性实验室 · 中间人攻击与防御")
        width = min(1180, root.winfo_screenwidth() - 60)
        height = min(820, root.winfo_screenheight() - 90)
        root.geometry(f"{width}x{height}")
        root.minsize(min(1000, width), min(650, height))
        root.configure(background=BACKGROUND)
        self.pack(fill="both", expand=True)
        self._pending: Iterator[Event] | None = None
        self._timer: str | None = None
        self._playing = False
        self._replay_after_send = False
        self.events: list[Event] = []
        self.original_message: Message | None = None
        self._active_actor = ""
        self.sender = tk.StringVar(value=sender)
        self.attack = tk.StringVar(value=next(label for label, value in ATTACKS.items() if value == attack))
        self.defense = tk.StringVar(value=next(label for label, value in DEFENSES.items() if value == defense))
        self.status = tk.StringVar()
        self.session_label = tk.StringVar()
        self._configure_style()
        self._build_layout(message, tampered_content)
        self.reset_session()
        root.protocol("WM_DELETE_WINDOW", self.close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", font=("Microsoft YaHei UI", 10), foreground=INK)
        style.configure("TFrame", background=BACKGROUND)
        style.configure("TLabel", background=BACKGROUND)
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 19, "bold"))
        style.configure("Section.TLabel", font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("Muted.TLabel", foreground="#566c7c")
        style.configure("TButton", padding=(10, 5))
        style.configure("Primary.TButton", background=TEAL, foreground="white")
        style.map("Primary.TButton", background=[("active", "#06645f"), ("disabled", "#b4c6c4")])
        style.configure("Treeview", rowheight=30, background="white", fieldbackground="white")
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 10, "bold"), padding=6)

    def _build_layout(self, message: str, tampered_content: str | None) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)
        ttk.Label(self, text="消息完整性实验室", style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(self, textvariable=self.session_label, style="Muted.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(6, 14)
        )
        sidebar = ttk.Frame(self)
        sidebar.grid(row=2, column=0, sticky="ns", padx=(0, 20))
        sidebar.rowconfigure(0, weight=1)
        control_canvas = tk.Canvas(sidebar, width=244, background=BACKGROUND, highlightthickness=0)
        control_canvas.grid(row=0, column=0, sticky="ns")
        sidebar_scroll = ttk.Scrollbar(sidebar, orient="vertical", command=control_canvas.yview)
        sidebar_scroll.grid(row=0, column=1, sticky="ns")
        control_canvas.configure(yscrollcommand=sidebar_scroll.set)
        controls = ttk.Frame(control_canvas)
        control_canvas.create_window((0, 0), window=controls, anchor="nw", width=240)
        controls.bind("<Configure>", lambda event: control_canvas.configure(scrollregion=control_canvas.bbox("all")))
        controls.columnconfigure(0, weight=1)
        ttk.Label(controls, text="实验设置", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.sender_box = self._combo(controls, 1, "发送方", self.sender, ("Alice", "Bob"))
        self.sender_box.bind("<<ComboboxSelected>>", lambda event: self._draw_roles())
        self.attack_box = self._combo(controls, 3, "攻击方式", self.attack, tuple(ATTACKS))
        self.defense_box = self._combo(controls, 5, "防御方式", self.defense, tuple(DEFENSES))
        self.attack_box.bind("<<ComboboxSelected>>", self.reset_session)
        self.defense_box.bind("<<ComboboxSelected>>", self.reset_session)
        ttk.Label(controls, text="发送正文").grid(row=7, column=0, sticky="w", pady=(10, 5))
        self.message_input = self._text(controls, height=2, width=24)
        self.message_input.grid(row=8, column=0, sticky="ew")
        self.message_input.insert("1.0", message)
        ttk.Label(controls, text="Evil 替换正文").grid(row=9, column=0, sticky="w", pady=(10, 5))
        self.tampered_input = self._text(controls, height=2, width=24)
        self.tampered_input.grid(row=10, column=0, sticky="ew")
        self.tampered_input.insert("1.0", tampered_content if tampered_content is not None else "转账 900 元")
        self.prepare_button = ttk.Button(controls, text="准备发送", command=self.prepare_send)
        self.prepare_button.grid(row=11, column=0, sticky="ew", pady=(12, 4))
        self.replay_button = ttk.Button(controls, text="重放最新缓存", command=self.prepare_replay)
        self.replay_button.grid(row=12, column=0, sticky="ew", pady=4)
        ttk.Button(controls, text="重置会话", command=self.reset_session).grid(
            row=13, column=0, sticky="ew", pady=4
        )
        ttk.Label(
            controls, text="切换攻击或防御将新建会话。\n发送方可在同一会话内切换。",
            style="Muted.TLabel", wraplength=230,
        ).grid(row=14, column=0, sticky="w", pady=(8, 0))

        workspace = ttk.Frame(self)
        workspace.grid(row=2, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(6, weight=1)
        self.canvas = tk.Canvas(workspace, height=120, background="white", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="ew")
        self.canvas.bind("<Configure>", lambda event: self._draw_roles())
        self.status_widget = ttk.Label(workspace, textvariable=self.status, style="Section.TLabel", wraplength=740)
        self.status_widget.grid(row=1, column=0, sticky="w", pady=(14, 10))
        toolbar = ttk.Frame(workspace)
        toolbar.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        self.step_button = ttk.Button(toolbar, text="单步执行", command=self.advance, style="Primary.TButton")
        self.step_button.pack(side="left", padx=(0, 8))
        self.play_button = ttk.Button(toolbar, text="自动播放", command=self.play)
        self.play_button.pack(side="left", padx=(0, 8))
        self.pause_button = ttk.Button(toolbar, text="暂停", command=self.pause)
        self.pause_button.pack(side="left")
        ttk.Label(toolbar, text="每步间隔 700 ms", style="Muted.TLabel").pack(side="right")
        comparison = ttk.Frame(workspace)
        comparison.grid(row=3, column=0, sticky="ew")
        comparison.columnconfigure((0, 1), weight=1, uniform="messages")
        ttk.Label(comparison, text="原始消息", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(comparison, text="当前消息", style="Section.TLabel").grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.original_text = self._text(comparison, height=5, width=26)
        self.current_text = self._text(comparison, height=5, width=26)
        self.original_text.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.current_text.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(8, 0))
        ttk.Label(workspace, text="通信事件", style="Section.TLabel").grid(
            row=5, column=0, sticky="w", pady=(18, 8)
        )
        log_frame = ttk.Frame(workspace)
        log_frame.grid(row=6, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = ttk.Treeview(log_frame, columns=("actor", "action", "sequence", "content"), show="headings", height=6)
        for column, title, width in (
            ("actor", "角色", 60), ("action", "行为", 230), ("sequence", "序号", 50), ("content", "正文", 200),
        ):
            self.log.heading(column, text=title)
            self.log.column(column, width=width, minwidth=45, stretch=column in ("action", "content"))
        self.log.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scrollbar.set)
        self.log.tag_configure("reject", foreground=RED)
        self.log.tag_configure("attack", foreground=ORANGE)
        self.log.tag_configure("accept", foreground=TEAL)

    def _combo(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, values: tuple) -> ttk.Combobox:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(10, 5))
        box = ttk.Combobox(parent, textvariable=variable, values=values, state="readonly", width=24)
        box.grid(row=row + 1, column=0, sticky="ew")
        return box

    def _text(self, parent: ttk.Frame, **options) -> tk.Text:
        return tk.Text(
            parent, **options, wrap="word", font=("Microsoft YaHei UI", 10),
            background="white", foreground=INK, relief="solid", borderwidth=1,
            highlightthickness=0, padx=10, pady=8,
        )

    def reset_session(self, event=None) -> None:
        self.pause()
        self._pending = None
        self._replay_after_send = False
        attack = ATTACKS[self.attack.get()]
        self.simulation = Simulation(
            attack=attack, defense=DEFENSES[self.defense.get()],
            tampered_content=self.tampered_input.get("1.0", "end-1c") if attack == "tamper" else None,
        )
        self.events.clear()
        self.original_message = None
        self._active_actor = ""
        self.session_label.set(f"会话  {self.simulation.session_id}")
        self.status.set("准备发送后，单步推进或自动播放通信过程")
        self.status_widget.configure(foreground=INK)
        self.log.delete(*self.log.get_children())
        self._set_text(self.original_text, "等待发送")
        self._set_text(self.current_text, "等待发送")
        self._draw_roles()
        self._sync_controls()

    def prepare_send(self) -> None:
        if self._pending is not None:
            return
        self.simulation.evil.tampered_content = (
            self.tampered_input.get("1.0", "end-1c") if ATTACKS[self.attack.get()] == "tamper" else None
        )
        self._pending = self.simulation.send_steps(self.sender.get(), self.message_input.get("1.0", "end-1c"))
        self._replay_after_send = ATTACKS[self.attack.get()] == "replay"
        self.status.set("已准备，点击单步执行或自动播放")
        self.status_widget.configure(foreground=INK)
        self._sync_controls()

    def prepare_replay(self) -> None:
        if self._pending is not None or not self.simulation.evil.history:
            return
        self._pending = self.simulation.replay_steps()
        self._replay_after_send = False
        self.status.set("已准备缓存重放，点击单步执行或自动播放")
        self.status_widget.configure(foreground=INK)
        self._sync_controls()

    def advance(self) -> None:
        if self._pending is None:
            return
        try:
            event = next(self._pending)
        except StopIteration:
            self._pending = None
            self.pause()
            self._sync_controls()
            return
        except (ValueError, TypeError) as error:
            self._pending = None
            self.pause()
            self._sync_controls()
            messagebox.showerror("实验无法继续", str(error), parent=self.root)
            return
        self._show_event(event)
        if event.action == "receive" or event.action.startswith("reject_"):
            if self._replay_after_send:
                self._pending = self.simulation.replay_steps()
                self._replay_after_send = False
                self.status.set(self.status.get() + " · 下一步开始重放")
            else:
                self._pending = None
                self.pause()
        self._sync_controls()

    def play(self) -> None:
        if self._playing:
            return
        if self._pending is None:
            self.prepare_send()
        self._playing = True
        self._sync_controls()
        self._tick()

    def _tick(self) -> None:
        self._timer = None
        self.advance()
        if self._playing and self._pending is not None:
            self._timer = self.root.after(PLAY_INTERVAL_MS, self._tick)

    def pause(self) -> None:
        if self._timer is not None:
            self.root.after_cancel(self._timer)
            self._timer = None
        self._playing = False
        self._sync_controls()

    def close(self) -> None:
        self.pause()
        self.root.destroy()

    def _show_event(self, event: Event) -> None:
        self.events.append(event)
        self._active_actor = event.actor
        if event.action in ("send", "replay"):
            self.original_message = event.message
        self._set_text(self.original_text, self._message_details(self.original_message))
        self._set_text(self.current_text, self._message_details(event.message))
        color, tag = INK, ""
        if event.action.startswith("reject_"):
            color, tag = RED, "reject"
        elif event.action in ("tamper", "replay"):
            color, tag = ORANGE, "attack"
        elif event.action in ("verify_pass", "receive"):
            color, tag = TEAL, "accept"
        self.status.set(f"{event.actor} · {ACTION_LABELS[event.action]}")
        self.status_widget.configure(foreground=color)
        item = self.log.insert("", "end", values=(
            event.actor, ACTION_LABELS[event.action], event.message.sequence,
            json.dumps(event.message.content, ensure_ascii=False),
        ), tags=(tag,))
        self.log.see(item)
        self._draw_roles()

    def _message_details(self, message: Message | None) -> str:
        if message is None:
            return "等待发送"
        tag = message.auth_tag.hex() or "未启用"
        return (
            f"{message.sender} → {message.recipient}  ·  序号 {message.sequence}\n"
            f"{json.dumps(message.content, ensure_ascii=False)}\nHMAC  {tag}"
        )

    def _set_text(self, widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _sync_controls(self) -> None:
        busy = self._pending is not None
        for box in (self.sender_box, self.attack_box, self.defense_box):
            box.configure(state="disabled" if busy else "readonly")
        self.message_input.configure(state="disabled" if busy else "normal")
        self.tampered_input.configure(state="normal" if not busy and ATTACKS[self.attack.get()] == "tamper" else "disabled")
        self.prepare_button.configure(state="disabled" if busy else "normal")
        has_cache = hasattr(self, "simulation") and bool(self.simulation.evil.history)
        self.replay_button.configure(state="normal" if not busy and has_cache else "disabled")
        self.step_button.configure(state="normal" if busy and not self._playing else "disabled")
        self.play_button.configure(state="disabled" if self._playing else "normal")
        self.pause_button.configure(state="normal" if self._playing else "disabled")

    def _draw_roles(self) -> None:
        self.canvas.delete("all")
        width = max(self.canvas.winfo_width(), 600)
        centers = (width * 0.17, width * 0.5, width * 0.83)
        for left, right in zip(centers, centers[1:]):
            self.canvas.create_line(left + 64, 53, right - 64, 53, fill="#92a8b7", width=2, arrow="both")
        counts = {"Alice": len(self.simulation.alice.inbox), "Evil": len(self.simulation.evil.history), "Bob": len(self.simulation.bob.inbox)}
        for name, center in zip(("Alice", "Evil", "Bob"), centers):
            active = self._active_actor == name
            color = ORANGE if name == "Evil" else TEAL
            self.canvas.create_rectangle(
                center - 61, 17, center + 61, 88, fill=color if active else "#edf3f5", outline=""
            )
            self.canvas.create_text(center, 39, text=name, fill="white" if active else INK, font=("Microsoft YaHei UI", 14, "bold"))
            label = "缓存" if name == "Evil" else "收件箱"
            self.canvas.create_text(center, 66, text=f"{label}  {counts[name]}", fill="white" if active else "#566c7c", font=("Microsoft YaHei UI", 10))
        direction = f"{self.sender.get()} → Evil → {'Bob' if self.sender.get() == 'Alice' else 'Alice'}"
        self.canvas.create_text(width / 2, 108, text=direction, fill="#566c7c", font=("Microsoft YaHei UI", 10))


def launch(**options) -> int:
    root = tk.Tk()
    LabApp(root, **options)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
