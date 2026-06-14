# E2EE Messengers 中的 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts 在现代端到端加密（E2EE）messengers 中是强制性的，因为客户端需要知道某个 ciphertext 何时被解密，这样它们才能丢弃 ratcheting state 和 ephemeral keys。Server 转发的是 opaque blobs，所以 device acknowledgements（double checkmarks）会在接收方成功解密后发出。测量攻击者触发的动作与对应 delivery receipt 之间的 round-trip time（RTT），会暴露一个高分辨率 timing channel，从而泄露 device state、online presence，并可被滥用于 covert DoS。多设备 "client-fanout" 部署会放大这种泄露，因为每个已注册 device 都会解密 probe 并返回自己的 receipt。

## Delivery receipt sources vs. user-visible signals

选择总是会触发 delivery receipt、但不会在受害者端显示 UI artifacts 的 message types。下表总结了经过实测确认的行为：

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 总是会有噪声 → 只能用于 bootstrap state。 |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions 和 removals 保持静默。 |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min；过期后仍会 ack。 |
| | Delete for everyone | ● | ○ | UI 允许约 60 h，但更晚的 packets 仍会被 ack。 |
| **Signal** | Text message | ● | ● | 与 WhatsApp 相同的限制。 |
| | Reaction | ● | ◐ | Self-reactions 对受害者不可见。 |
| | Edit/Delete | ● | ○ | Server 强制约 48 h 窗口，允许最多 10 次 edits，但晚到的 packets 仍会被 ack。 |
| **Threema** | Text message | ● | ● | Multi-device receipts 会被聚合，因此每个 probe 只会显现一个 RTT。 |

图例：● = always，◐ = conditional，○ = never。平台相关的 UI 行为已在行内注明。必要时可关闭 read receipts，但 WhatsApp 或 Signal 中无法关闭 delivery receipts。

## Attacker goals and models

* **G1 – Device fingerprinting:** 统计每个 probe 到达多少 receipts，对 RTT 做聚类以推断 OS/client（Android vs iOS vs desktop），并观察 online/offline 变化。
* **G2 – Behavioural monitoring:** 将高频 RTT 序列（≈1 Hz 很稳定）视为 time-series，推断 screen on/off、app foreground/background、通勤 vs 工作时段等。
* **G3 – Resource exhaustion:** 通过持续发送永不结束的 silent probes，让每个受害 device 的 radio/CPU 保持唤醒，耗尽 battery/data 并降低 VoIP/RTC 质量。

只需要两类 threat actor 就足以描述这种 abuse surface：

1. **Creepy companion:** 已经与受害者共享一个 chat，并滥用 self-reactions、reaction removals，或与现有 message IDs 绑定的重复 edits/deletes。
2. **Spooky stranger:** 注册一个 burner account，并发送引用本地 conversation 中从未存在过的 message IDs 的 reactions；即使 UI 丢弃了 state change，WhatsApp 和 Signal 仍会解密并确认它们，因此不需要事先存在对话。

## Tooling for raw protocol access

依赖能够暴露底层 E2EE protocol 的 clients，这样你就可以在 UI 约束之外构造 packets、指定任意 `message_id`s，并记录精确 timestamps：

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)（Go, WhatsApp Web protocol）或 [Cobalt](https://github.com/Auties00/Cobalt)（mobile-oriented）允许你发送原始 `ReactionMessage`、`ProtocolMessage`（edit/delete）和 `Receipt` frames，同时保持 double-ratchet state 同步。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) 结合 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) 可通过 CLI/API 暴露每种 message type。当前 `signal-cli` 语法使用 `sendReaction RECIPIENT --target-author --target-timestamp`；保持 `receive` 或 `daemon` 运行，这样 delivery receipts 才会被真正收集。self-reaction toggle 示例：
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client 的 source 记录了 delivery receipts 在离开 device 前如何被整合，这解释了为何该 side channel 的带宽几乎可以忽略。
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) 提供 WhatsApp/Signal backends，默认使用 silent delete probes，并通过滚动中位数阈值（`RTT < 0.9 * median`）标记 `active` vs `standby`。[careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) 是一个更轻量、以 WhatsApp 为先的 CLI，支持 `--delay`、`--concurrent`、CSV/Prometheus exporters，以及适合 Grafana 的输出。把两者都视为 reconnaissance helpers，而不是 protocol references；真正重要的启示是：一旦具备 raw client access，所需代码量非常少。

当无法使用自定义 tooling 时，你仍然可以从 WhatsApp Web 或 Signal Desktop 触发 silent actions，并嗅探加密的 websocket/WebRTC channel，但 raw APIs 能移除 UI delays 并允许无效操作。

## Creepy companion: silent sampling loop

1. 在聊天中挑选你自己曾发送过的任意历史 message，这样受害者就永远看不到 "reaction" 气泡变化。
2. 在可见 emoji 与空 reaction payload 之间交替（在 WhatsApp protobufs 中编码为 `""`，或在 signal-cli 中使用 `--remove`）。每次传输都会产生一个 device ack，尽管受害者端没有任何 UI 差异。
3. 记录发送时间和每个 delivery receipt 的到达时间。如下所示的 1 Hz loop 可以无限期地产生每个 device 的 RTT traces：
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. 由于 WhatsApp/Signal 允许无限次 reaction updates，攻击者无需发布新的 chat content，也无需担心 edit windows。

## Spooky stranger: probing arbitrary phone numbers

1. 注册一个新的 WhatsApp/Signal account，并获取目标号码的 public identity keys（在 session setup 期间会自动完成）。
2. 构造一个引用随机 `message_id` 的 reaction/edit/delete packet，该 `message_id` 从未被任一方见过（WhatsApp 接受任意 `key.id` GUIDs；Signal 使用毫秒级 timestamps）。
3. 即使不存在任何 thread 也照样发送该 packet。受害者 devices 会解密它，匹配不到 base message，丢弃 state change，但仍会确认进入的 ciphertext，将 device receipts 发回给攻击者。
4. 持续重复即可构建 RTT series，而无需在受害者的 chat list 中留下任何痕迹。

如果你首先需要发现哪些号码已注册，或者想要大规模预先填充 device inventories，可以把这一步与 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) 串联起来，而不是手动猜测随机 E.164 ranges。

已公开的 contact-discovery 研究表明了这在 operational 上为何重要：借助准确的 phone-prefix tables 和适度资源，研究人员能够在转向定向 probing 之前，对 WhatsApp 上约 `10%` 的美国 mobile numbers 以及 Signal 上 `100%` 的号码进行查询。实际上，先预过滤 live accounts 可以让 silent-probe 预算集中在那些确实会解密 packets 的号码上。

最近的 WhatsApp builds 还暴露了 `Settings -> Privacy -> Advanced -> Block unknown account messages`。把它视为吞吐限制器，而不是修复：它主要影响持续性的 stranger-only flooding，而一旦你已经是已知 contact，它就不再相关。

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 某个 message 一旦被 delete-for-everyone 过，之后引用同一个 `message_id` 的 delete packets 不会再有 UI 效果，但每个 device 仍会解密并确认它们。
* **Out-of-window operations:** WhatsApp 在 UI 中强制约 60 h 的 delete / 约 20 min 的 edit windows；Signal 强制约 48 h。超出这些窗口的 crafted protocol messages 会在受害 device 上被静默忽略，但 receipts 仍会被传输，因此攻击者可以在对话结束很久之后继续无限 probing。
* **Invalid payloads:** 格式错误的 edit bodies，或引用已经被清除消息的 deletes，会触发相同行为——解密加 receipt，零 user-visible artefacts。

## Multi-device amplification & fingerprinting

* 每个关联 device（phone、desktop app、browser companion）都会独立解密 probe，并返回自己的 ack。统计每个 probe 的 receipts 数量即可揭示精确的 device count。
* 如果某个 device offline，它的 receipt 会被排队，并在重新连接时发出。因此，空缺会泄露 online/offline 周期，甚至通勤时间表（例如旅行期间 desktop receipts 停止）。
* 由于 OS power management 和 push wakeups 不同，RTT 分布会随 platform 而异。对 RTT 做聚类（例如在 median/variance 特征上使用 k-means）即可标记 “Android handset”、“iOS handset”、“Electron desktop” 等。
* 因为发送方在加密前必须先获取接收方的 key inventory，攻击者还可以观察何时配对了新 device；device count 的突然增加或出现新的 RTT cluster 都是强信号。

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** 已公开的测量结果显示，WhatsApp 接受 silent-reaction bursts 的速度快到每 `50 ms` 一个 probe，而没有明显的 server-side queueing。这对于短暂校准、快速 device counting，或快速启动 drain attack 都很有用。
* **Signal long-run queueing:** Signal 能容忍短 burst，但在持续的每秒多 probe traffic 下会开始 queueing。对于长期监控，请将 cadence 保持在约 `1 Hz`（或更低），这样每个 receipt 仍反映当前 device state，而不是 backlog drain。
* **Reconnect artefacts:** 当 device 重新 online 时，某些 clients 会批量处理或快速清空多个延迟 receipts。应把这些 receipt bursts 视为 state-transition marker，而不是独立的 RTT samples，否则你的聚类 / `active` vs `idle` classifier 会过拟合 reconnect noise。

## Behaviour inference from RTT traces

1. 以 ≥1 Hz 进行采样以捕捉 OS scheduling effects。在 iOS 上使用 WhatsApp 时，<1 s 的 RTT 通常与 screen-on/foreground 强相关，而 >1 s 则与 screen-off/background throttling 相关。
2. 构建简单的 classifiers（thresholding 或 two-cluster k-means），将每个 RTT 标记为 "active" 或 "idle"。把这些标签聚合成 streaks，就能推导出 bedtime、commutes、work hours，或 desktop companion 何时活跃。
3. 将同时发往每个 device 的 probes 进行相关分析，以观察用户何时从 mobile 切换到 desktop、companion 何时 offline，以及 app 是否受 push 或 persistent socket 的 rate limit 影响。
4. 在真实网络中，不要使用单一硬编码的 `1 s` threshold。先用短 warm-up window 为每个 device 建立基线，再维持滚动基线（例如 `threshold = 0.9 * median RTT`），这样 Wi-Fi/cellular drift 就不会破坏你的 classifier。

## Location inference from delivery RTT

同样的 timing primitive 也可以被重新用于推断接收方在哪里，而不仅仅是他们是否活跃。`Hope of Delivery` 研究表明：基于已知接收位置的 RTT distributions 进行训练后，攻击者之后仅凭 delivery confirmations 就能对受害者的位置进行分类：

* 在受害者位于几个已知地点时建立 baseline（家、办公室、校园、国家 A vs 国家 B 等）。
* 针对每个地点，收集大量正常 message RTT，并提取 median、variance 或 percentile buckets 等简单特征。
* 在真正攻击时，将新的 probe series 与训练得到的 clusters 进行比较。论文报告称，即使是同一城市内的位置，通常也可以被区分，在 3-location 场景下准确率超过 `80%`。
* 当攻击者控制 sender 环境并在相似网络条件下 probing 时，这种方法效果最好，因为测量路径包含了接收方 access network、wake-up latency 和 messenger 基础设施。

与上面的 silent reaction/edit/delete attacks 不同，location inference 不需要无效的 message IDs 或隐蔽的状态变更 packets。普通 messages 加正常 delivery confirmations 就足够了，因此其代价是更低的 stealth，但适用范围更广，跨 messenger 都可用。

## Stealthy resource exhaustion

因为每个 silent probe 都必须被解密并确认，持续发送 reaction toggles、invalid edits，或 delete-for-everyone packets 会造成 application-layer DoS：

* 强制 radio/modem 每秒收发一次 → 可见的 battery drain，尤其是在空闲 handset 上。
* 产生不计费的 upstream/downstream traffic，在 TLS/WebSocket noise 中伪装传输，同时消耗 mobile data plans。
* 占用 crypto threads，并在对 latency-sensitive features（VoIP、video calls）造成 jitter，尽管用户从未看到通知。
* 在 WhatsApp 上，invalid reactions 可接受的数据量远超普通 emoji 的直觉：已公开的测量发现 server-side acceptance 最高可达每个 reaction 约 `1 MB`。
* 当 body 大到约 `30 bytes` 以上时，超大 reactions 不再产生可靠的 delivery receipts，但在被丢弃前仍会被转发和处理。当你需要 ACKs 时，保持 reaction bodies 很小；只有在目标是纯粹 drain 或 covert one-way transport 时才把它们放大。
* 已公开的测量在这种模式下达到了受害者流量约 `3.7 MB/s`（`~13.3 GB/h`）。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
