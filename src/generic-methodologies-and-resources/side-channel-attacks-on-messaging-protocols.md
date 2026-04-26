# E2EE Messengers 中的 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts 在现代端到端加密（E2EE）messengers 中是强制性的，因为客户端需要知道 ciphertext 何时被解密，这样它们才能丢弃 ratcheting state 和 ephemeral keys。server 只转发 opaque blobs，所以设备确认（double checkmarks）由接收方在成功解密后发出。测量 attacker 触发的动作与对应 delivery receipt 之间的 round-trip time（RTT），会暴露一个高分辨率 timing channel，泄露 device state、online presence，并可被滥用于 covert DoS。多设备 “client-fanout” 部署会放大这种泄露，因为每个已注册设备都会解密 probe 并返回自己的 receipt。

## Delivery receipt sources vs. user-visible signals

选择那些总会发出 delivery receipt、但不会在受害者端显示 UI 痕迹的 message types。下表总结了实测确认的行为：

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 总是有噪声 → 只适合用于 bootstrap state。 |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions 和 removals 保持静默。 |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; 过期后仍会 ack。 |
| | Delete for everyone | ● | ○ | UI 允许约 60 h，但更晚的 packets 仍会 ack。 |
| **Signal** | Text message | ● | ● | 限制与 WhatsApp 相同。 |
| | Reaction | ● | ◐ | Self-reactions 对受害者不可见。 |
| | Edit/Delete | ● | ○ | server 强制约 48 h 窗口，最多允许 10 次 edits，但晚到的 packets 仍会 ack。 |
| **Threema** | Text message | ● | ● | Multi-device receipts 会被聚合，因此每个 probe 只会暴露一个 RTT。 |

图例：● = always，◐ = conditional，○ = never。平台相关的 UI 行为已在行内注明。必要时可关闭 read receipts，但 WhatsApp 或 Signal 中无法关闭 delivery receipts。

## Attacker goals and models

* **G1 – Device fingerprinting:** 统计每个 probe 到达多少 receipts，按 RTT 聚类推断 OS/client（Android vs iOS vs desktop），并观察 online/offline 转换。
* **G2 – Behavioural monitoring:** 将高频 RTT 序列（≈1 Hz 是稳定的）视为 time-series，并推断屏幕开/关、app 前台/后台、通勤 vs 工作时间等。
* **G3 – Resource exhaustion:** 通过发送永不结束的 silent probes，让每个受害设备的 radio/CPU 保持唤醒，耗尽电池/data 并降低 VoIP/RTC 质量。

要描述这种滥用面，只需要两类 threat actor：

1. **Creepy companion:** 已经与受害者共享聊天，并滥用 self-reactions、reaction removals 或与现有 message IDs 绑定的 repeated edits/deletes。
2. **Spooky stranger:** 注册一个 burner account，并发送引用本地对话中从未存在过的 message IDs 的 reactions；即使 UI 会丢弃该状态变更，WhatsApp 和 Signal 仍会解密并确认，因此不需要事先存在对话。

## Tooling for raw protocol access

依赖能暴露底层 E2EE protocol 的 clients，这样你就可以在 UI 约束之外构造 packets，指定任意 `message_id`s，并记录精确时间戳：

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)（Go, WhatsApp Web protocol）或 [Cobalt](https://github.com/Auties00/Cobalt)（mobile-oriented）可让你发出原始 `ReactionMessage`、`ProtocolMessage`（edit/delete）和 `Receipt` frames，同时保持 double-ratchet state 同步。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) 结合 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) 可通过 CLI/API 暴露每种 message type。self-reaction toggle 示例：
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android client 的 source 文档说明了 delivery receipts 在离开设备前如何被 consolidate，这也解释了为什么该 side channel 的带宽几乎可以忽略。
* **Turnkey PoCs:** 公开项目如 `device-activity-tracker` 和 `careless-whisper-python` 已经自动化了 silent delete/reaction probes 和 RTT classification。把它们当作现成的侦察助手，而不是 protocol references；有趣之处在于，它们确认了只要能直接访问 raw client，这个 attack 在操作上就很简单。

当没有自定义 tooling 时，你仍然可以从 WhatsApp Web 或 Signal Desktop 触发 silent actions，并嗅探加密的 websocket/WebRTC channel，但 raw APIs 可以移除 UI 延迟并允许无效操作。

## Creepy companion: silent sampling loop

1. 选择聊天中任何一条你自己发过的历史消息，这样受害者就不会看到“reaction”气泡变化。
2. 在可见 emoji 和空 reaction payload 之间交替切换（在 WhatsApp protobufs 中编码为 `""`，或在 signal-cli 中使用 `--remove`）。每次传输都会产生 device ack，尽管受害者端没有任何 UI delta。
3. 记录发送时间和每个 delivery receipt 的到达时间。如下所示的 1 Hz loop 可以无限期地产生按设备划分的 RTT traces：
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. 因为 WhatsApp/Signal 接受无限次 reaction updates，attacker 永远不需要发布新的聊天内容，也不用担心 edit windows。

## Spooky stranger: probing arbitrary phone numbers

1. 注册一个新的 WhatsApp/Signal 账户，并获取目标号码的 public identity keys（在 session setup 期间会自动完成）。
2. 构造一个 reaction/edit/delete packet，引用一个任一方都从未见过的随机 `message_id`（WhatsApp 接受任意 `key.id` GUIDs；Signal 使用 millisecond timestamps）。
3. 即使不存在任何 thread，也照样发送该 packet。受害者设备会解密它、无法匹配 base message、丢弃状态变更，但仍会确认传入的 ciphertext，并把 device receipts 发回给 attacker。
4. 持续重复，以构建 RTT series，而不会出现在受害者的 chat list 中。

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 当一条消息被 delete-for-everyone 一次后，后续引用同一 `message_id` 的 delete packets 不会产生 UI 效果，但每个设备仍会解密并确认它们。
* **Out-of-window operations:** WhatsApp 在 UI 中强制约 60 h 的 delete / 约 20 min 的 edit 窗口；Signal 强制约 48 h。窗口之外构造的 protocol messages 会在受害设备上被静默忽略，但 receipts 仍会传输，因此 attacker 可以在对话结束很久之后仍持续 probe。
* **Invalid payloads:** 格式错误的 edit bodies，或引用已被 purge 的消息的 deletes，会触发相同行为——解密加 receipt，零用户可见痕迹。

## Multi-device amplification & fingerprinting

* 每个关联设备（phone、desktop app、browser companion）都会独立解密 probe 并返回自己的 ack。统计每个 probe 的 receipts 数量即可暴露准确的设备数量。
* 如果某个设备离线，它的 receipt 会被排队，并在重新连接时发出。因此，间隙会泄露 online/offline 循环，甚至通勤安排（例如，desktop receipts 在出行期间停止）。
* 由于 OS power management 和 push wakeups 的存在，不同平台的 RTT 分布不同。对 RTT 做聚类（例如使用中位数/方差特征进行 k-means）来标记“Android handset”、“iOS handset”、“Electron desktop”等。
* 因为 sender 在加密前必须先获取接收者的 key inventory，attacker 还能观察新设备何时被配对；设备数量突然增加或出现新的 RTT cluster，都是强 संकेत。

## Behaviour inference from RTT traces

1. 以 ≥1 Hz 采样，以捕获 OS scheduling effects。在 iOS 上使用 WhatsApp 时，<1 s 的 RTT 往往与 screen-on/foreground 强相关，而 >1 s 则与 screen-off/background throttling 相关。
2. 构建简单分类器（thresholding 或 two-cluster k-means），将每个 RTT 标记为 "active" 或 "idle"。把标签聚合成 streaks，以推导 bedtime、commute、work hours，或 desktop companion 何时活跃。
3. 将指向每个设备的 simultaneous probes 进行相关分析，观察用户何时从 mobile 切换到 desktop，何时 companions offline，以及 app 是被 push 还是 persistent socket 限流。

## Location inference from delivery RTT

同样的 timing primitive 也可以被改用来推断接收者在哪里，而不仅仅是他们是否 active。`Hope of Delivery` 的工作表明，在已知接收位置的 RTT distributions 上训练后，attacker 之后就能仅凭 delivery confirmations 对受害者位置进行分类：

* 为同一目标在多个已知地点建立 baseline（home、office、campus、country A vs country B 等）。
* 对每个 location，收集大量正常 message RTT，并提取 median、variance 或 percentile buckets 等简单特征。
* 在真实 attack 期间，将新的 probe series 与训练得到的 clusters 进行比较。论文报告称，即使是同一城市内的位置，通常也能区分开，在 3-location 场景下准确率可达 `>80%`。
* 当 attacker 控制 sender environment，并在相似网络条件下 probe 时，效果最好，因为测量路径包含接收者 access network、wake-up latency 和 messenger infrastructure。

与上面的 silent reaction/edit/delete attacks 不同，location inference 不需要无效的 message IDs 或隐蔽的状态修改 packets。普通 message 只要有正常的 delivery confirmations 就足够，因此代价是更低的隐蔽性，但适用范围更广，适用于更多 messengers。

## Stealthy resource exhaustion

因为每个 silent probe 都必须被解密并确认，持续发送 reaction toggles、invalid edits 或 delete-for-everyone packets 会造成 application-layer DoS：

* 强制 radio/modem 每秒进行发送/接收 → 明显的电池消耗，尤其是在闲置手机上。
* 生成未计费的 upstream/downstream traffic，在融入 TLS/WebSocket 噪声的同时消耗 mobile data plans。
* 占用 crypto threads，并在 latency-sensitive features（VoIP、video calls）中引入 jitter，即使用户从未看到任何 notification。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
