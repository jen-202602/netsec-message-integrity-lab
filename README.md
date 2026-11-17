# netsec-message-integrity-lab

《计算机网络安全技术》课程实验一，中间人攻击与防御实验器。

项目使用 Python 单进程模拟 Alice、Bob 和 Evil 之间的消息传递，逐步实现消息篡改、完整性认证、重放攻击及其防御，并提供图形化演示。

## 当前进度

已完成正常通信、自行实现的密码算法、篡改与重放攻防，以及第五阶段的 GUI、单步执行和通信可视化。

- Alice 和 Bob 可以互相发送消息，各自维护发送序号和收件箱。
- Evil 位于通信链路中，可以转发、篡改并缓存消息，再次注入历史消息。
- 命令行展示发送、截获、篡改、转发、认证和接收或拒绝的过程。
- 消息包含协议版本、会话标识、发送方、接收方、序号和正文，使用确定性的 UTF-8 JSON 编码。
- 自行实现 SHA-256、HMAC-SHA-256 和完整认证标签验证。
- 算法测试包含固定标准向量、边界输入、独立标准库对照和篡改检测。
- 启用 HMAC 后，接收方验证全部消息字段的认证标签，通过后才写入收件箱。
- 启用完整防御后，接收方依次检查认证标签、当前会话与递增序号，拒绝重复和旧会话消息。
- Tkinter 图形界面支持场景选择、真实单步执行、自动播放、暂停、缓存重放和会话重置。
- 可视化显示当前角色、双方收件箱数量、Evil 缓存数量、消息正文与认证标签对照。

已整理独立实验说明与最终验收记录，并提供提交材料打包命令。

## 运行环境

- Python 3.10 或更高版本。
- 当前阶段使用 Python 标准库，可直接启动。
- GUI 需要 Python 的 Tkinter/Tcl/Tk 组件和可用桌面环境。可运行 `python -m tkinter` 检查。

## 图形界面

在项目根目录执行以下命令启动。

```powershell
python main.py --gui
```

也可预选攻防场景，或直接通过 GUI 模块入口启动。

```powershell
python main.py --gui --attack replay --defense hmac-replay --message "转账 100 元"
python -m lab.gui
```

1. 选择发送方、攻击方式和防御方式，填写正文。篡改模式还可填写 Evil 的替换正文。
2. 点击“准备发送”，再点击“单步执行”逐步推进，观察角色高亮、正文与标签变化、收件箱计数。
3. 点击“自动播放”以 700 ms 的间隔推进。“暂停”保留当前进度，随后可继续单步或自动播放。
4. 重放模式会在首次投递完成后继续重放该消息。一次实验完成后，也可点击“重放最新缓存”准备重放，再单步或自动推进。
5. 切换发送方可在同一会话内反向通信。切换攻击或防御方式将创建新会话并清空记录。“重置会话”也会取消当前执行与定时器、清空双方收件箱和缓存。

右侧显示通信路径、当前状态、原始与当前消息对照，以及完整事件列表。设置区域高度不足时，可用其右侧滚动条查看下方按钮。消息对照区支持鼠标滚动查看较长内容。

单步执行会在迭代器每次推进时执行对应操作。准备发送和发送步骤均保持接收方收件箱为空，HMAC 验证通过后还可暂停，继续到“接收”时才写入收件箱。

## 命令行

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

每次启动创建独立会话，因此会话标识每次不同，首次发送的序号为 1。CLI 默认发送一条消息，重放模式会在正常发送后追加一次历史消息重放。Python 接口可以在同一会话中连续、双向发送。

```python
from lab.simulation import Simulation

simulation = Simulation()
simulation.send("Alice", "你好，Bob！")
simulation.send("Bob", "收到，Alice！")
simulation.send("Alice", "下一条消息")
assert [message.sequence for message in simulation.bob.inbox] == [1, 2]
assert simulation.alice.inbox[0].content == "收到，Alice！"
```

## 篡改攻击与 HMAC 防御

使用同一正文依次运行以下四种场景，观察接收方的结果。

```powershell
python main.py --message "转账 100 元"
python main.py --message "转账 100 元" --attack tamper
python main.py --message "转账 100 元" --defense hmac
python main.py --message "转账 100 元" --attack tamper --defense hmac
```

| 场景 | Bob 的结果 |
| --- | --- |
| 正常通信，无认证 | 接收“转账 100 元” |
| 篡改通信，无认证 | 接收被 Evil 替换的“转账 900 元” |
| 正常通信，启用 HMAC | 认证通过，接收“转账 100 元” |
| 篡改通信，启用 HMAC | 认证失败，拒绝接收，收件箱保持为空 |

篡改模式默认替换为“转账 900 元”。可以用 `--tampered-message` 自定义替换正文，并通过 `--sender Bob` 演示反向通信。

```powershell
python main.py --sender Bob --message "同意支付 100 元" --attack tamper --tampered-message "同意支付 900 元" --defense hmac
```

启用 HMAC 时，模拟器生成一个随机的 32 字节密钥并交给双方，表示通信前已完成可信的密钥分发。Evil 获得消息和认证标签。篡改保留原标签，因此接收方对修改后的正文验证失败。两端日志中的标签可用来核对传输前后的变化。

相同正文替换后字节内容保持一致时，认证仍会通过。篡改实验请选择与原消息不同的正文。CLI 用退出码 0 表示实验执行完成，攻击结果由输出中的“已接收”或“已拒绝”表示。

Python 接口同样支持场景选择。

```python
from lab.simulation import Simulation

simulation = Simulation(attack="tamper", defense="hmac", tampered_content="转账 900 元")
events = simulation.send("Alice", "转账 100 元")
assert events[-1].action == "reject_auth"
assert simulation.bob.inbox == []
```

## 重放攻击与防御（Bonus）

重放模式先正常发送并缓存一条消息，再让 Evil 原样发送同一消息，保留正文、会话、序号和标签。依次运行以下命令可以比较三种防御模式。

```powershell
python main.py --message "转账 100 元" --attack replay
python main.py --message "转账 100 元" --attack replay --defense hmac
python main.py --message "转账 100 元" --attack replay --defense hmac-replay
```

| 防御模式 | 首次发送 | 重放消息 | Bob 最终收件箱 |
| --- | --- | --- | --- |
| `none` | 接收 | 接收 | 2 条相同消息 |
| `hmac` | 认证通过并接收 | 认证通过并接收 | 2 条相同消息 |
| `hmac-replay` | 认证通过并接收 | 认证通过，因序号重复拒绝 | 1 条消息 |

`hmac-replay` 同时启用 HMAC 和防重放，也可与 `--attack none` 或 `--attack tamper` 组合。`--sender Bob` 可切换发送方向。

接收方将会话标识与本地当前会话比较，并保存对端已接收的最大序号。新消息的序号必须严格大于该值，允许跳号。低于最大值的迟到消息也会被拒绝。认证或会话检查失败时，序号状态保持原值。

Python 接口通过 `send()` 发送，通过 `replay()` 单独注入缓存消息。`replay()` 默认选择最新消息，也可传入历史消息索引。

```python
from lab.simulation import Simulation

simulation = Simulation(defense="hmac-replay")
simulation.send("Alice", "转账 100 元")
events = simulation.replay(0)
assert events[-1].action == "reject_replay"
assert len(simulation.bob.inbox) == 1
assert simulation.send("Alice", "后续正常消息")[-1].action == "receive"
```

空缓存重放抛出 `ValueError`，越界索引抛出 `IndexError`。重新创建模拟器会建立新会话，并重置发送、接收序号和历史缓存。

## 测试

在项目根目录执行全部测试。

```powershell
python -m unittest discover -v
```

也可按算法或场景分别运行测试。

```powershell
python -m unittest tests.test_sha256 -v
python -m unittest tests.test_hmac_sha256 -v
python -m unittest tests.test_scenarios -v
python -m unittest tests.test_replay -v
python -m unittest tests.test_steps -v
python -m unittest tests.test_gui -v
```

当前共 51 个测试方法，其中算法测试 13 个、通信与篡改场景测试 13 个、重放测试 12 个、单步执行测试 6 个、GUI 集成测试 7 个，包含参数化子用例。已在 Windows、Python 3.10.9、Tk 8.6 下全部通过。GUI 测试使用隐藏窗口，缺少 Tk 或可用显示环境时会报告跳过，其余测试照常执行。测试依据见 [算法与测试说明](docs/crypto.md)，场景验收见 [协议说明](docs/protocol.md)。

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
    gui.py          Tkinter 场景控制与通信可视化
    crypto/
        __init__.py      算法公共接口
        sha256.py        自行实现 SHA-256
        hmac_sha256.py   自行实现 HMAC 及标签验证
tests/
    __init__.py
    test_sha256.py       SHA-256 测试
    test_hmac_sha256.py  HMAC 测试
    test_scenarios.py    攻防场景与 CLI 测试
    test_replay.py       重放攻击、防御与状态一致性测试
    test_steps.py        惰性单步执行与收件箱更新测试
    test_gui.py          GUI 控件、暂停、自动播放与重置测试
docs/
    protocol.md     协议、角色和阶段设计说明
    crypto.md       算法实现与测试依据、结果
    experiment-report.md  独立实验说明
    validation.txt        最终环境、CLI 场景与运行输出
    test-results.txt      解压副本的完整测试输出
scripts/
    package_submission.py 提交材料打包脚本
```

## 提交材料

[实验说明](docs/experiment-report.md) 覆盖运行环境与操作、通信及攻防原理、算法测试依据与结果、开发阶段和 AI 辅助说明。最终复现从程序包独立解压目录执行，以 `python -S` 禁用第三方 site-packages，复用本机 Python 与 Tcl/Tk 运行时。51 个测试方法及 18 个 CLI 场景通过，记录见 [完整测试输出](docs/test-results.txt) 和 [场景验收记录](docs/validation.txt)。

在项目根目录执行以下命令生成提交材料。

```powershell
python scripts/package_submission.py
```

输出位于 `dist/submission/`。

| 文件 | 内容 |
| --- | --- |
| `program.zip` | 源代码、测试、README、技术说明、验收记录和打包脚本 |
| `experiment-report.md` | 独立实验说明，Markdown 格式 |
| `netsec-message-integrity-submission.zip` | 包含上述两部分的总提交包 |

解压 `program.zip` 后进入 `netsec-message-integrity-lab` 目录，按本文启动和测试。打包脚本校验压缩包完整性及文件内容。源文件或说明更新后重新运行脚本，可生成对应的新提交包。生成物遵循已有 `dist/` 忽略规则。

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
- 第三阶段在消息对象中加入认证标签，标签独立于认证输入，避免自引用。Evil 通过转发链路修改正文，接收方在写入收件箱前验证标签。26 个测试方法全部通过，覆盖两个发送方向、攻防组合、错误标签和拒收后的正常通信。
- 第四阶段增加 Evil 的转发历史和重放入口，统一正常消息与重放消息的接收处理。先认证、再检查会话与序号，最后更新接收状态，防止伪造高序号影响后续通信。38 个测试方法全部通过，覆盖三种防御模式、旧会话、序号间隙、迟到消息和重放拒绝后的正常双向通信。
- 第五阶段将发送、转发、认证和接收拆分为惰性迭代步骤，同步接口通过消费同一迭代器完成，GUI 按步驱动实际状态。增加 Tkinter 界面，处理播放定时器取消、切换场景时的会话重置和小屏幕滚动设置区。51 个测试方法全部通过，覆盖九种 GUI 攻防组合和真实事件循环播放。测试窗口创建后处理待执行布局事件，避免销毁后的主题事件提示。
- 第六阶段按实验原文核对实现和提交要求，整理独立实验说明、标准测试依据和实际验收输出。从程序包解压副本以 `python -S` 运行，51 个测试方法、18 个 CLI 场景及 README 示例全部通过，打包脚本校验两部分材料的内容与完整性。
- AI 辅助使用 Codex（GPT-6），参与需求整理、方案设计、代码与说明编写。阶段验证覆盖命令行入口、消息编码、连续双向发送和参数错误处理，后续按阶段补充验证记录。
