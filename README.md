# netsec-message-integrity-lab

《计算机网络安全技术》课程实验一，中间人攻击与防御实验器。

项目使用 Python 单进程模拟 Alice、Bob 和 Evil 之间的消息传递，逐步实现消息篡改、完整性认证、重放攻击及其防御，并提供图形化演示。

## 当前进度

已完成第一阶段的正常文本通信，以及第二阶段的密码算法与单元测试。

- Alice 和 Bob 可以互相发送消息，各自维护发送序号和收件箱。
- Evil 位于通信链路中，接收并原样转发消息。
- 命令行展示发送、截获、转发、接收四个步骤。
- 消息包含协议版本、会话标识、发送方、接收方、序号和正文，使用确定性的 UTF-8 JSON 编码。
- 自行实现 SHA-256、HMAC-SHA-256 和完整认证标签验证。
- 算法测试包含固定标准向量、边界输入、独立标准库对照和篡改检测。

后续阶段将把认证接入通信链路，实现篡改攻防、重放攻防，以及 GUI 和单步执行。

## 运行环境

- Python 3.10 或更高版本。
- 当前阶段使用 Python 标准库，可直接启动。

在项目根目录执行以下命令。Windows 也可使用 `py -3` 代替 `python`。

```powershell
python main.py
```

默认由 Alice 向 Bob 发送问候消息，Evil 原样转发，Bob 将消息存入收件箱。

自定义消息或发送方向。

```powershell
python main.py --message "转账 100 元"
python main.py --sender Bob --message "收到，Alice！"
python main.py --help
```

也可通过模块入口启动。

```powershell
python -m lab.cli --sender Alice --message "你好，Bob！"
```

每次启动创建独立会话，因此会话标识每次不同，首次发送的序号为 1。CLI 的一次运行发送一条消息。Python 接口可以在同一会话中连续、双向发送。

```python
from lab.simulation import Simulation

simulation = Simulation()
simulation.send("Alice", "你好，Bob！")
simulation.send("Bob", "收到，Alice！")
simulation.send("Alice", "下一条消息")
assert [message.sequence for message in simulation.bob.inbox] == [1, 2]
assert simulation.alice.inbox[0].content == "收到，Alice！"
```

## 算法测试

在项目根目录执行全部测试。

```powershell
python -m unittest discover -v
```

也可分别运行两种算法的测试。

```powershell
python -m unittest tests.test_sha256 -v
python -m unittest tests.test_hmac_sha256 -v
```

当前共 13 个测试方法，包含参数化子用例。已在 Python 3.10.9 下全部通过。测试依据、用例和验证环境见 [算法与测试说明](docs/crypto.md)。

算法接口接收 `bytes`，SHA-256 和 HMAC 均返回 32 字节结果。文本显式使用 UTF-8 编码，展示十六进制结果时调用 `.hex()`。

```python
from lab.crypto import sha256, hmac_sha256, verify_hmac_sha256

data = "转账 100 元".encode("utf-8")
key = b"shared lab demonstration key"
digest = sha256(data)
tag = hmac_sha256(key, data)
print(digest.hex())
assert verify_hmac_sha256(key, data, tag)
assert not verify_hmac_sha256(key, "转账 900 元".encode("utf-8"), tag)
```

## 目录结构

```text
main.py             程序入口
lab/
    __init__.py
    protocol.py     消息结构与编码
    actors.py       通信端点与 Evil 转发行为
    simulation.py   会话和通信流程
    cli.py          命令行参数与日志显示
    crypto/
        __init__.py      算法公共接口
        sha256.py        自行实现 SHA-256
        hmac_sha256.py   自行实现 HMAC 及标签验证
tests/
    __init__.py
    test_sha256.py       SHA-256 测试
    test_hmac_sha256.py  HMAC 测试
docs/
    protocol.md     协议、角色和阶段设计说明
    crypto.md       算法实现与测试依据、结果
```

## 开发步骤

1. 消息协议、角色模型和命令行正常通信。
2. 自行实现 SHA-256、HMAC-SHA-256，使用标准向量和独立实现对照测试。
3. 实现 Evil 篡改消息，以及 HMAC 完整性认证。
4. 实现重放攻击，加入会话标识与序号检查。
5. 实现 GUI、单步执行和通信过程可视化。
6. 整理算法测试、场景验证、实验说明与提交压缩包。

## 开发记录

- 第一阶段采用消息经过 Evil 的单进程通信模型，并用命令行验证正常传输。协议细节见 [协议说明](docs/protocol.md)。
- 第二阶段按规范实现消息填充、32 位运算、压缩函数和 HMAC 内外层摘要。重点处理 56 字节填充边界、超过 64 字节的密钥归一化，以及完整标签长度检查。13 个测试方法全部通过，并复查两个方向的 CLI 正常通信。
- AI 辅助使用 Codex（GPT-6），参与需求整理、方案设计、代码与说明编写。阶段验证覆盖命令行入口、消息编码、连续双向发送和参数错误处理，后续按阶段补充验证记录。
