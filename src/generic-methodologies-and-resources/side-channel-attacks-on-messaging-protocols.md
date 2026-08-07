# E2EE Messengers 中的送达回执 Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

现代端到端加密（E2EE）messenger 必须支持送达回执，因为客户端需要知道密文何时已被解密，以便丢弃 ratcheting 状态和 ephemeral keys。服务器只转发不透明 blob，因此设备确认（双勾）会在接收方成功解密后发送。测量攻击者触发的操作与相应送达回执之间的往返时间（RTT），会暴露一个高分辨率 timing channel，从而 leak 设备状态、在线状态，并可被滥用于 covert DoS。多设备的 "client-fanout" 部署会放大该泄露，因为每个已注册设备都会解密 probe 并返回自己的回执。<sup>[[1]](#references)</sup>

## 送达回执来源与用户可见信号

选择始终发送送达回执、但不会在受害者界面产生 UI 痕迹的消息类型。下表总结了经过实证确认的行为：<sup>[[1]](#references)</sup>

| Messenger | 操作 | 送达回执 | 受害者通知 | 备注 |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | 文本消息 | ● | ● | 始终会产生噪声 → 仅适合用于 bootstrap state。 |
| | Reaction | ● | ◐（仅在对受害者消息作出 reaction 时） | Self-reactions 和 removals 保持静默。 |
| | Edit | ● | 取决于平台的 silent push | Edit window ≈20 分钟；过期后仍会被 ack。 |
| | Delete for everyone | ● | ○ | UI 允许约 60 小时，但之后的数据包仍会被 ack。 |
| **Signal** | 文本消息 | ● | ● | 与 WhatsApp 存在相同限制。 |
| | Reaction | ● | ◐ | Self-reactions 对受害者不可见。 |
| | Edit/Delete | ● | ○ | 服务器执行约 48 小时的 window，最多允许 10 次 edit，但延迟数据包仍会被 ack。 |
| **Threema** | 文本消息 | ● | ● | 多设备回执会被聚合，因此每个 probe 只能看到一个 RTT。 |

图例：● = 始终，◐ = 有条件，○ = 从不。平台相关的 UI 行为已在行内注明。如有需要，可以禁用 read receipts，但 WhatsApp 或 Signal 无法关闭 delivery receipts。<sup>[[1]](#references)</sup>

## 攻击者目标与模型

* **G1 – Device fingerprinting：** 统计每个 probe 到达的回执数量，对 RTT 进行聚类以推断 OS/client（Android、iOS 或 desktop），并监视 online/offline 状态变化。
* **G2 – Behavioural monitoring：** 将高频 RTT 序列（约 1 Hz 时较稳定）作为 time-series，推断屏幕开关、app 位于 foreground/background、通勤与工作时间等。
* **G3 – Resource exhaustion：** 通过发送持续不断的 silent probe，让每台受害者设备的 radio/CPU 保持唤醒，消耗 battery/data，并降低 VoIP/RTC 质量。<sup>[[1]](#references)</sup>

两个 threat actor 足以描述该滥用面：<sup>[[1]](#references)</sup>

1. **Creepy companion：** 已经与受害者共享 chat，并滥用 self-reactions、reaction removals，或针对现有 message ID 的重复 edits/deletes。
2. **Spooky stranger：** 注册 burner account，并发送引用本地 conversation 中从未存在的 message ID 的 reactions；即使 UI 丢弃了状态变化，WhatsApp 和 Signal 仍会解密并确认这些数据包，因此无需事先建立 conversation。

## 用于 raw protocol access 的 tooling

依赖能够暴露底层 E2EE protocol 的客户端，以便在 UI 限制之外构造数据包、指定任意 `message_id`，并记录精确时间戳：

* **WhatsApp：** [whatsmeow](https://github.com/tulir/whatsmeow)（Go、WhatsApp Web protocol）或 [Cobalt](https://github.com/Auties00/Cobalt)（面向 mobile）允许你发送 raw `ReactionMessage`、`ProtocolMessage`（edit/delete）和 `Receipt` frame，同时保持 double-ratchet 状态同步。<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal：** [signal-cli](https://github.com/AsamK/signal-cli) 结合 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)，通过 CLI/API 暴露所有消息类型。<sup>[[5]](#references)[[7]](#references)</sup> 当前 `signal-cli` syntax 使用 `sendReaction RECIPIENT --target-author --target-timestamp`；保持 `receive` 或 `daemon` 运行，以便实际收集 delivery receipts。<sup>[[6]](#references)</sup> Self-reaction toggle 示例：
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema：** Android client 的 source 说明了 delivery receipts 在离开设备前如何被 consolidated，这解释了为什么该 side channel 在此处的 bandwidth 可以忽略不计。<sup>[[1]](#references)</sup>
* **Turnkey PoCs：** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) 提供 WhatsApp/Signal backends，默认使用 silent delete probes，并通过 rolling-median threshold（`RTT < 0.9 * median`）标记 `active` 与 `standby`。<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) 是一个更轻量、优先支持 WhatsApp 的 CLI，提供 `--delay`、`--concurrent`、CSV/Prometheus exporters 以及适合 Grafana 的 output。<sup>[[9]](#references)</sup> 应将二者视为 reconnaissance helpers，而不是 protocol references；重要结论是，一旦具备 raw client access，所需代码非常少。

如果无法使用 custom tooling，仍可以从 WhatsApp Web 或 Signal Desktop 触发 silent actions，并 sniff encrypted websocket/WebRTC channel，但 raw APIs 可以移除 UI 延迟，并允许执行 invalid operations。

## Creepy companion：silent sampling loop

1. 选择 chat 中由你发送的任意历史消息，这样受害者永远不会看到 "reaction" balloons 发生变化。
2. 在 visible emoji 和 empty reaction payload 之间交替切换（在 WhatsApp protobufs 中编码为 `""`，或在 signal-cli 中使用 `--remove`）。每次 transmission 都会产生 device ack，尽管受害者的 UI 没有变化。
3. 记录发送时间和每个 delivery receipt 的到达时间。如下所示的 1 Hz loop 可以无限期生成每台设备的 RTT traces：
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. 由于 WhatsApp/Signal 接受 unlimited reaction updates，攻击者无需发布新的 chat 内容，也不必担心 edit windows。<sup>[[1]](#references)</sup>

## Spooky stranger：探测任意 phone numbers

1. 注册一个新的 WhatsApp/Signal account，并获取目标号码的 public identity keys（在 session setup 期间自动完成）。
2. 构造引用随机 `message_id` 的 reaction/edit/delete packet，该 ID 从未被任何一方见过（WhatsApp 接受任意 `key.id` GUID；Signal 使用 millisecond timestamps）。
3. 即使不存在 thread，也发送该 packet。受害者设备会解密它，无法匹配 base message，丢弃状态变化，但仍会确认传入的 ciphertext，并将 device receipts 发回攻击者。
4. 持续重复，以构建 RTT series，同时完全不出现在受害者的 chat list 中。<sup>[[1]](#references)</sup>

如果首先需要发现哪些号码已注册，或希望大规模预先建立 device inventories，可以将此流程与 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) 串联，而不是手动猜测随机的 E.164 ranges。

已发表的 contact-discovery work 说明了其实际意义：借助准确的 phone-prefix tables 和适度资源，研究人员在转向 targeted probing 前，能够查询 WhatsApp 上约 `10%` 的美国 mobile numbers，以及 Signal 上 `100%` 的号码。<sup>[[11]](#references)</sup> 实践中，先筛选 live accounts，可以将 silent-probe budget 集中到实际会解密数据包的号码上。

近期 WhatsApp builds 还暴露了 `Settings -> Privacy -> Advanced -> Block unknown account messages`。<sup>[[10]](#references)</sup> 应将其视为 throughput limiter，而不是修复措施：它主要会影响持续的 stranger-only flooding；一旦你已经是 known contact，该设置就无关紧要。

## 将 edits 和 deletes 复用为 covert triggers

* **Repeated deletes：** 一条消息首次被 delete-for-everyone 后，后续引用同一 `message_id` 的 delete packets 不会产生 UI 效果，但每台设备仍会解密并确认它们。
* **Out-of-window operations：** WhatsApp 在 UI 中执行约 60 小时的 delete / 约 20 分钟的 edit windows；Signal 执行约 48 小时。超出这些 window 的 crafted protocol messages 会在受害者设备上被静默忽略，但 receipts 仍会被传输，因此攻击者可以在 conversation 结束很久后无限期探测。
* **Invalid payloads：** 格式错误的 edit bodies，或引用已 purge messages 的 deletes，会引发相同的行为——解密加 receipt，且不会产生任何用户可见 artefacts。<sup>[[1]](#references)</sup>

## Multi-device amplification 与 fingerprinting

* 每台 associated device（phone、desktop app、browser companion）都会独立解密 probe 并返回自己的 ack。统计每个 probe 的 receipts 数量，可以揭示准确的 device count。
* 如果某台设备处于 offline，其 receipt 会排队，并在重新连接时发送。因此，间隔会 leak online/offline cycles，甚至 leak commuting schedules（例如 desktop receipts 会在出行期间停止）。
* 由于 OS power management 和 push wakeups 的差异，不同 platform 的 RTT distributions 不同。对 RTT 进行聚类（例如对 median/variance features 使用 k-means），即可标记 “Android handset”、“iOS handset”、“Electron desktop” 等。
* 由于 sender 必须先获取 recipient 的 key inventory 才能进行加密，攻击者还可以监视何时有新设备被 paired；device count 突然增加或出现新的 RTT cluster，是强 indicator。<sup>[[1]](#references)</sup>

## Sampling cadence、queueing 与 stacked receipts

* **WhatsApp burst tolerance：** 已发表的 measurements 报告称，WhatsApp 接受 silent-reaction bursts 的速度可达到每个 probe `50 ms`，且没有明显的 server-side queueing。这对短期 calibration bursts、快速 device counting 或快速提升 drain attack 速度很有用。
* **Signal long-run queueing：** Signal 可以容忍短时 bursts，但 sustained multi-probe-per-second traffic 开始出现 queueing。对于长期 monitoring，应将 cadence 保持在约 `1 Hz`（或更低），使每个 receipt 仍反映当前 device state，而不是 backlog drain。
* **Reconnect artefacts：** 设备重新 online 时，一些客户端会 batch 或快速 flush 多个 delayed receipts。应将这些 receipt bursts 视为 state-transition marker，而不是独立的 RTT samples，否则 clustering / `active` 与 `idle` classifier 会对 reconnect noise 过拟合。<sup>[[1]](#references)</sup>

## 从 RTT traces 推断行为

1. 以 ≥1 Hz 的频率进行 sampling，以捕获 OS scheduling effects。在 iOS 上使用 WhatsApp 时，<1 s 的 RTT 与 screen-on/foreground 强相关，而 >1 s 通常对应 screen-off/background throttling。
2. 构建简单的 classifiers（thresholding 或 two-cluster k-means），将每个 RTT 标记为 "active" 或 "idle"。将 labels 聚合成 streaks，以推导就寝时间、通勤、工作时间，或 desktop companion 处于 active 的时间。
3. 对每台设备同时进行 probes，以观察用户何时从 mobile 切换到 desktop、companions 何时 offline，以及 app 是否因 push 或 persistent socket 而受到 rate limiting。
4. 在真实 network 中，避免使用单一硬编码的 `1 s` threshold。为每台设备通过短 warm-up window 进行 bootstrap，并保持 rolling baseline（例如 `threshold = 0.9 * median RTT`），以避免 Wi-Fi/cellular drift 破坏 classifier。<sup>[[1]](#references)</sup>

## 从 delivery RTT 推断位置

相同的 timing primitive 不仅可以推断 recipient 是否 active，还可以复用于推断其所在位置。`Hope of Delivery` work 表明，在已知 receiver locations 上训练 RTT distributions 后，攻击者可以仅根据 delivery confirmations 对受害者位置进行分类：<sup>[[2]](#references)</sup>

* 在目标位于多个已知地点时建立 baseline（家、办公室、校园、国家 A 与国家 B 等）。
* 对每个 location 收集大量 normal message RTT，并提取 median、variance 或 percentile buckets 等简单 features。
* 在实际 attack 期间，将新的 probe series 与训练得到的 clusters 进行比较。论文报告称，即使是同一城市内的地点通常也可以区分；在 3-location setting 中，准确率可达到 `>80%`。
* 当攻击者控制 sender environment，并在相似的 network conditions 下进行 probes 时，该方法效果最佳，因为测量路径包含 recipient access network、wake-up latency 和 messenger infrastructure。<sup>[[2]](#references)</sup>

与上述 silent reaction/edit/delete attacks 不同，location inference 不需要 invalid message IDs 或 stealthy state-changing packets。带有 normal delivery confirmations 的 plain messages 就足够了，因此其代价是 stealth 较低，但在不同 messengers 中的适用范围更广。

## Stealthy resource exhaustion

由于每个 silent probe 都必须被解密并确认，持续发送 reaction toggles、invalid edits 或 delete-for-everyone packets 会造成 application-layer DoS：<sup>[[1]](#references)</sup>

* 强制 radio/modem 每秒进行 transmit/receive → 会产生明显的 battery drain，尤其是在 idle handsets 上。
* 生成不受计量的 upstream/downstream traffic，在混入 TLS/WebSocket noise 的同时消耗 mobile data plans。
* 占用 crypto threads，并在 VoIP、video calls 等对 latency 敏感的功能中引入 jitter，尽管用户从未看到 notifications。
* 在 WhatsApp 中，invalid reactions 接受的数据远多于普通 emoji 所暗示的大小：已发表的 measurements 发现，server-side acceptance 每个 reaction 最高约为 `1 MB`。
* 当 body 大小超过约 `30 bytes` 后，oversized reactions 不再产生可靠的 delivery receipts，但在被 discard 前仍会被转发和处理。需要 ACKs 时，应保持 reaction bodies 很小；只有在目标是 pure drain 或 covert one-way transport 时才将其增大。
* Public measurements 在此模式下达到了约 `3.7 MB/s`（`~13.3 GB/h`）的 victim traffic。

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
