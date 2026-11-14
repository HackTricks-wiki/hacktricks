# E2EE 即时通讯应用中的送达回执侧信道攻击

{{#include ../banners/hacktricks-training.md}}

现代端到端加密（E2EE）即时通讯应用必须使用送达回执，因为客户端需要知道密文何时已解密，以便丢弃 ratcheting 状态和临时密钥。服务器只转发不透明数据块，因此设备确认（双勾）由接收方在成功解密后发出。测量攻击者触发的操作与相应送达回执之间的往返时间（RTT），会暴露高分辨率的计时信道，leak 设备状态、在线状态，还可能被用于隐蔽 DoS。多设备“client-fanout”部署会放大这种泄漏，因为每台已注册设备都会解密探测消息并返回自己的回执。<sup>[[1]](#references)</sup>

## 送达回执来源与用户可见信号

选择始终会发出送达回执、但不会在受害者界面上留下痕迹的消息类型。下表总结了经实测确认的行为：<sup>[[1]](#references)</sup>

| Messenger | 操作 | 送达回执 | 受害者通知 | 备注 |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | 文本消息 | ● | ● | 始终会引起注意 → 仅适用于引导判断状态。 |
| | 表情回应 | ● | ◐（仅在回应受害者的消息时） | 自我回应和移除回应都不会显示。 |
| | 编辑 | ● | 取决于平台的静默推送 | 编辑时间窗口约为 20 分钟；过期后仍会确认。 |
| | 为所有人删除 | ● | ○ | UI 允许约 60 小时内操作，但之后发送的数据包仍会收到确认。 |
| **Signal** | 文本消息 | ● | ● | 与 WhatsApp 有相同限制。 |
| | 表情回应 | ● | ◐ | 受害者看不到自我回应。 |
| | 编辑/删除 | ● | ○ | 服务器强制执行约 48 小时的时间窗口，最多允许编辑 10 次，但延迟发送的数据包仍会收到确认。 |
| **Threema** | 文本消息 | ● | ● | 多设备回执会被汇总，因此每次探测只能看到一个 RTT。 |

图例：● = 始终，◐ = 有条件，○ = 从不。取决于平台的 UI 行为已在备注中说明。必要时可关闭已读回执，但 WhatsApp 或 Signal 均无法关闭送达回执。<sup>[[1]](#references)</sup>

## 攻击者目标与模型

* **G1 – 设备指纹识别：** 统计每次探测收到的回执数量，对 RTT 聚类以推断操作系统/客户端（Android、iOS 或桌面端），并监视在线/离线状态变化。
* **G2 – 行为监控：** 将高频 RTT 序列（约 1 Hz 时较稳定）作为时间序列，推断屏幕开关、应用前台/后台状态、通勤与工作时间等。
* **G3 – 资源耗尽：** 持续发送静默探测，让受害者的每台设备上的无线电和 CPU 保持唤醒状态，消耗电量/流量并降低视频通话质量。<sup>[[1]](#references)</sup>

以下两种威胁行为者足以描述这种滥用面：<sup>[[1]](#references)</sup>

1. **可疑的联系人：** 已经与受害者共享聊天，并滥用自我回应、移除回应，或针对现有消息 ID 重复编辑/删除。
2. **可疑的陌生人：** 注册一个一次性账号，并发送引用本地对话中从未存在过的消息 ID 的回应；WhatsApp 和 Signal 仍会解密并确认这些消息，即使 UI 会丢弃状态变更，因此不需要预先建立对话。

## 原始协议访问工具

使用能够充分暴露底层 E2EE 协议的客户端，以便在 UI 限制之外构造受支持的数据包并记录精确时间戳；任意消息 ID 是否可用，需要针对每种实现进行检查：

* **WhatsApp：** [whatsmeow](https://github.com/tulir/whatsmeow)（Go，WhatsApp Web 多设备 API）记录了发送和接收送达回执的方式；[Cobalt](https://github.com/Auties00/Cobalt)（非官方 Java/Kotlin Web 和移动 API）记录了回应、编辑和删除等消息操作。请使用其文档中说明的 API，而不要假设所有内部帧都已开放。<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal：** [signal-cli](https://github.com/AsamK/signal-cli) 提供 CLI、JSON-RPC 和 D-Bus 接口；[libsignal-service-java](https://github.com/signalapp/libsignal-service-java) 则是用于与 Signal 通信的 Java 库。<sup>[[5]](#references)[[7]](#references)</sup> 当前 `signal-cli` 语法使用 `sendReaction RECIPIENT --target-author --target-timestamp`；保持运行 `receive` 或 `daemon`，以便持续处理协议更新。<sup>[[6]](#references)</sup> 自我回应切换示例：
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema：**Careless Whisper 论文中的测量发现，送达回执会在设备间同步，因此即使在多设备设置中，每条消息也只会暴露一条回执。<sup>[[1]](#references)</sup>
* **Turnkey PoCs：**[device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) 提供 WhatsApp/Signal 后端，默认使用静默删除探测，并通过滚动中位数阈值（`RTT < 0.9 * median`）标记 `active` 与 `standby`。<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) 是一个更轻量、以 WhatsApp 为先的 CLI，支持 `--delay`、`--concurrent`、CSV/Prometheus 导出器，以及适配 Grafana 的输出。<sup>[[9]](#references)</sup> 应将两者视为侦察辅助工具，而非协议参考；关键在于，一旦能够访问原始客户端，所需代码就少得惊人。

无法使用自定义工具时，官方客户端或浏览器开发者工具仍可触发静默操作并暴露加密流量的时序信息；原始 API 可消除 UI 延迟，并允许执行无效操作。<sup>[[1]](#references)</sup>

## 诡异的伴随操作：静默采样循环

1. 在聊天中选一条你发送过的历史消息，这样受害者就不会看到“reaction”气泡发生变化。
2. 在一个可见的 emoji 和空的 reaction payload 之间交替切换（在 WhatsApp protobuf 中编码为 `""`，或在 signal-cli 中使用 `--remove`）。每次发送都会得到设备 ack，即使受害者的 UI 没有任何变化。
3. 记录发送时间和每条送达回执的到达时间。像下面这样以 1 Hz 运行的循环，可以无限期获取各设备的 RTT 轨迹：
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. 由于 WhatsApp/Signal 接受无限次 reaction 更新，攻击者无需发布新的聊天内容，也不必担心编辑时限。<sup>[[1]](#references)</sup>

## 陌生人探测：探测任意电话号码

1. 注册一个新的 WhatsApp/Signal 账号，并获取目标号码的公开身份密钥（会在会话设置期间自动完成）。
2. 构造一个引用随机 `message_id` 的 reaction 数据包，该 ID 从未被任何一方见过；论文报告称，WhatsApp 和 Signal 都会接受此类 reaction，并仍会生成送达回执。<sup>[[1]](#references)</sup>
3. 即使不存在聊天线程，也发送该数据包。受害者设备会解密数据包，因找不到对应的基础消息而丢弃状态更改，但仍会确认收到密文，并向攻击者发送设备回执。
4. 持续重复此操作，以建立 RTT 序列，无需事先建立对话，也不会显示通知。<sup>[[1]](#references)</sup>

如果你需要先确认哪些号码已注册，或想大规模预先收集设备清单，可将此方法与[联系人发现 / 注册 oracle](../pentesting-web/registration-vulnerabilities.md)结合使用，而不是手动猜测随机的 E.164 号码范围。

已发表的联系人发现研究说明了这在实际操作中的意义：借助准确的电话前缀表和适度资源，研究人员在进行定向探测前，能够查询 WhatsApp 上约 `10%` 的美国手机号码，以及 Signal 上 `100%` 的美国手机号码。<sup>[[11]](#references)</sup> 实际上，先筛选出活跃账号，可以让静默探测预算集中在确实会解密数据包的号码上。

较新的 WhatsApp 版本还提供了 `Settings -> Privacy -> Advanced -> Block unknown account messages`。<sup>[[10]](#references)</sup> 将其视为吞吐量限制：tracker 文档称，WhatsApp 会拦截来自未知账号的大量消息，但并未披露阈值，因此无法完全阻止探测 reaction。<sup>[[8]](#references)</sup>

## 将编辑和删除操作重复用作隐蔽触发器

* **重复删除：** 一条消息被“为所有人删除”一次后，引用相同 `message_id` 的后续删除数据包不会影响 UI，但每台设备仍会解密并确认收到。
* **超出时限的操作：** WhatsApp 在 UI 中将删除时限设为约 60 小时、编辑时限设为约 20 分钟；Signal 的时限约为 48 小时。即使超出这些时限，构造的协议消息也会在受害者设备上被静默忽略，但回执仍会发送，因此攻击者可以在对话结束很久后继续探测。
* **无效载荷：** 论文报告称，无效消息仍可能得到确认；畸形消息正文或已清除 ID 的具体行为取决于实现，因此依赖此行为前应先测试。<sup>[[1]](#references)</sup>

## 多设备放大与指纹识别

* 在 WhatsApp 和 Signal 上，每台关联设备（手机、桌面应用、浏览器 companion）都会独立解密探测并返回自己的 ack。统计每次探测收到的回执数量，即可得知设备的确切数量。<sup>[[1]](#references)</sup>
* 如果设备处于离线状态，其回执会进入队列，并在重新连接时发送。因此，回执间隔会 leak 在线 / 离线周期，甚至能泄露通勤时间（例如，外出期间桌面端回执会停止）。
* RTT 分布因平台和环境而异，因为 OS、型号、客户端和网络状况都会影响时序。可对 RTT 聚类（例如使用中位数 / 方差特征进行 k-means），将设备标记为“Android 手机”“iOS 手机”“Electron 桌面端”等。
* 由于发送方必须在加密前获取接收方的密钥清单，攻击者也可以观察新设备何时配对；设备数量突然增加或出现新的 RTT 聚类，都能作为强烈信号。<sup>[[1]](#references)</sup>

**通过排队的回执进行指纹识别：** 在目标设备离线时，发送若干个具有不同消息 ID 的探测。设备重新连接后，关联返回的送达回执中的 ID，并检查这些回执是分别发送还是合并在同一条回执中，以及合并后的 ID 是否保留或颠倒发送顺序。在测试的客户端中，WhatsApp Android/iOS 会分别返回送达回执，而 Web、Windows 和 macOS 会将其合并；macOS 会颠倒合并后的顺序。Signal Desktop 会合并回执，而其移动客户端不会。即使 RTT 分布重叠，也可以据此识别重新连接的客户端。不要将送达回执与已读回执混淆，两者的合并规则不同。<sup>[[1]](#references)</sup>

如需了解另一种无需送达消息、可读取 **服务器端 prekey 补充**的 WhatsApp 探测方法，请参阅 [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md)。

## 采样频率、排队与合并回执

* **WhatsApp 的突发容忍度：** 已发表的测量结果显示，WhatsApp 可接受每 `50 ms` 一次探测的静默 reaction 突发流量，且没有明显的服务器端排队。这适用于短时间校准、快速统计设备数量，或迅速加大 drain attack 的强度。
* **Signal 的长期排队：** Signal 可以承受短时突发流量，但持续每秒发送多个探测时会开始排队。进行长期监控时，将频率控制在约 `1 Hz`（或更低），确保每条回执反映的是设备当前状态，而非积压队列的排空情况。
* **重新连接造成的干扰：** 设备重新上线时，部分客户端会批量处理或快速发送多条延迟回执。应将这类回执突发视为状态转换标记，而不是独立的 RTT 样本，否则你的聚类 / `active` 与 `idle` 分类器会对重新连接噪声过拟合。<sup>[[1]](#references)</sup>

## 从 RTT 轨迹推断行为

1. 以 ≥1 Hz 的频率采样，以捕捉 OS 调度效应。使用 WhatsApp 的 iOS 设备上，RTT <1 秒与屏幕亮起 / 前台运行高度相关，RTT >1 秒则与屏幕关闭 / 后台节流相关。
2. 构建简单的分类器（阈值判断或双簇 k-means），将每个 RTT 标记为“active”或“idle”。汇总这些标签形成连续时段，以推断就寝时间、通勤时间、工作时间，或桌面 companion 的活跃时段。
3. 同时向每台设备发送探测并进行关联，以观察用户何时从手机切换到桌面端、companion 何时离线，以及应用是否受到推送或持久套接字的速率限制。
4. 在真实网络环境中，避免使用单一的硬编码 `1 s` 阈值。先用一个较短的预热窗口校准每台设备，并保持滚动基线（例如，device-activity-tracker PoC 使用 `threshold = 0.9 * median RTT`），避免 Wi-Fi / 蜂窝网络的波动导致分类器失效。<sup>[[1]](#references)[[8]](#references)</sup>

## 根据送达 RTT 推断位置

同一种时序原语也可用于推断接收者所在位置，而不仅仅是判断其是否活跃。`Hope of Delivery` 研究表明，利用已知接收者位置对应的 RTT 分布进行训练后，攻击者可以仅凭送达确认来判断受害者的位置：<sup>[[2]](#references)</sup>

* 在目标处于多个已知地点（家中、办公室、校园、国家 A 与国家 B 等）时，建立基线。
* 针对每个地点，收集大量普通消息 RTT，并提取中位数、方差或百分位区间等简单特征。
* 发起真实攻击时，将新的探测序列与训练得到的聚类进行比较。论文报告称，即使是同一城市内的位置通常也可以区分；在 3 个地点的场景中，准确率可达 `>80%`。
* 如果攻击者控制发送方环境，并在相似网络条件下进行探测，效果最佳，因为测得的路径包含接收者的接入网络、唤醒延迟和 messenger 基础设施。<sup>[[2]](#references)</sup>

与上述静默 reaction / 编辑 / 删除攻击不同，位置推断不需要无效消息 ID 或隐蔽的状态更改数据包。普通消息和正常送达确认就足够，因此隐蔽性较低，但适用于更多 messenger。

## 隐蔽的资源耗尽

由于每次静默探测都必须解密并确认，持续发送 reaction 切换、无效编辑或“为所有人删除”数据包会造成应用层 DoS：<sup>[[1]](#references)</sup>

* 迫使无线电 / 调制解调器每秒都进行收发 → 明显消耗电池，闲置手机尤其如此。
* 产生上行 / 下行流量，消耗移动数据套餐，并可能影响视频通话等对延迟敏感的功能。<sup>[[1]](#references)</sup>
* 大型无效载荷会增加处理负担，但论文报告称，密码运算本身对电池消耗的影响微乎其微。<sup>[[1]](#references)</sup>
* 在 WhatsApp 上，无效 reaction 可接受的数据远超普通 emoji 所暗示的大小：已发表的测量发现，服务器端接受的每条 reaction 数据量最高约为 `1 MB`。
* 当正文超过约 `30 bytes` 后，超大 reaction 不再产生可靠的送达回执，但仍会在丢弃前被转发和处理。需要 ACK 时，应保持 reaction 正文很小；只有在目标是纯粹耗尽资源或进行隐蔽单向传输时，才扩大正文。
* 公开测量中，此模式产生的受害者流量约为 `3.7 MB/s`（`~13.3 GB/h`）。



## References

- [1] [Careless Whisper：利用静默送达回执监控移动即时通讯应用的用户](https://arxiv.org/html/2411.11194v4)
- [2] [送达希望：从移动即时通讯应用中提取用户位置](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [如何拦截大量未知消息 | WhatsApp 帮助中心](https://faq.whatsapp.com/3379690015658337)
- [11] [所有号码都在美国：移动通讯应用中联系人发现的大规模滥用](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
