# E2EE Messenger 中的 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts 在现代端到端加密（E2EE）messengers 中是强制性的，因为客户端需要知道 ciphertext 何时被解密，这样它们才能丢弃 ratcheting state 和 ephemeral keys。服务器只转发 opaque blobs，因此设备确认（双勾）是在接收方成功解密后发出的。测量攻击者触发的动作与相应 delivery receipt 之间的 round-trip time（RTT），会暴露一个高分辨率 timing channel，泄漏 device state、online presence，并可被滥用于 covert DoS。多设备 “client-fanout” 部署会放大这种泄漏，因为每个已注册设备都会解密 probe 并返回自己的 receipt。

## Delivery receipt sources vs. user-visible signals

选择那些总会发出 delivery receipt、但不会在受害者界面上显示 UI 痕迹的消息类型。下表总结了实测确认的行为：

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 总是有噪声 → 只适合用于 bootstrap state。 |
| | Reaction | ● | ◐（仅当对受害者消息做 reaction 时） | 自己的 reaction 和移除操作保持静默。 |
| | Edit | ● | Platform-dependent silent push | Edit window 约 20 min；即使过期后仍会 ack’d。 |
| | Delete for everyone | ● | ○ | UI 允许约 60 h，但更晚的 packets 仍会 ack’d。 |
| **Signal** | Text message | ● | ● | 与 WhatsApp 相同的限制。 |
| | Reaction | ● | ◐ | 自己的 reaction 对受害者不可见。 |
| | Edit/Delete | ● | ○ | Server 强制约 48 h 窗口，允许最多 10 次 edits，但延迟 packets 仍会 ack’d。 |
| **Threema** | Text message | ● | ● | 多设备 receipts 会被聚合，因此每个 probe 只会看到一个 RTT。 |

图例：● = always，◐ = conditional，○ = never。平台相关的 UI 行为已在内联注明。如有需要可关闭 read receipts，但 WhatsApp 或 Signal 里无法关闭 delivery receipts。

## Attacker goals and models

* **G1 – Device fingerprinting:** 统计每个 probe 到达的 receipts 数量，按 RTT 聚类推断 OS/client（Android vs iOS vs desktop），并观察 online/offline 切换。
* **G2 – Behavioural monitoring:** 将高频 RTT 序列（≈1 Hz 足够稳定）视为 time-series，推断屏幕开/关、app 前台/后台、通勤 vs 工作时间等。
* **G3 – Resource exhaustion:** 通过发送永不结束的 silent probes，持续唤醒每个受害设备的 radio/CPU，耗电耗流量并降低 VoIP/RTC 质量。

描述这种滥用面，两个威胁模型就足够了：

1. **Creepy companion:** 已经与受害者共享聊天，并滥用 self-reactions、reaction removals 或与现有 message IDs 绑定的重复 edits/deletes。
2. **Spooky stranger:** 注册一个 burner account，发送引用本地对话中从未存在过的 message IDs 的 reactions；即使 UI 会丢弃该状态变化，WhatsApp 和 Signal 仍会解密并确认它，因此不需要先前对话。

## Tooling for raw protocol access

依赖能暴露底层 E2EE protocol 的客户端，这样你就可以在 UI 约束之外构造 packets、指定任意 `message_id`s，并记录精确时间戳：

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)（Go，WhatsApp Web protocol）或 [Cobalt](https://github.com/Auties00/Cobalt)（移动端导向）可以让你发出原始 `ReactionMessage`、`ProtocolMessage`（edit/delete）和 `Receipt` frames，同时保持 double-ratchet state 同步。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) 结合 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) 可通过 CLI/API 暴露所有 message type。当前 `signal-cli` 语法使用 `sendReaction RECIPIENT --target-author --target-timestamp`；保持 `receive` 或 `daemon` 运行，这样 delivery receipts 才会被真正收集。示例 self-reaction toggle：
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client 的源码说明了 delivery receipts 在离开设备前如何被合并，这也解释了为什么这里的 side channel 几乎没有 bandwidth。
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) 提供 WhatsApp/Signal backends，默认使用 silent delete probes，并用 rolling-median threshold（`RTT < 0.9 * median`）区分 `active` 与 `standby`。[careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) 是更轻量的、以 WhatsApp 为先的 CLI，带有 `--delay`、`--concurrent`、CSV/Prometheus exporters，以及适合 Grafana 的输出。把这两者都当作 reconnaissance helpers，而不是 protocol references；真正重要的 takeaway 是，一旦能直接访问 raw client，所需代码量其实很少。

当无法使用自定义 tooling 时，你仍然可以从 WhatsApp Web 或 Signal Desktop 触发 silent actions，并 sniff 加密的 websocket/WebRTC channel，但 raw APIs 能去掉 UI 延迟并允许无效操作。

## Creepy companion: silent sampling loop

1. 选择聊天中任意一个你自己发送过的历史消息，这样受害者就不会看到 "reaction" 气泡变化。
2. 在可见 emoji 与空 reaction payload 之间交替（在 WhatsApp protobufs 中编码为 `""`，或在 signal-cli 中使用 `--remove`）。每次传输都会产生 device ack，即使受害者端没有任何 UI 变化。
3. 记录发送时间和每个 delivery receipt 的到达时间。像下面这样的 1 Hz loop 可以无限期地为每个设备生成 RTT traces：
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. 由于 WhatsApp/Signal 接受无限次 reaction updates，攻击者无需发布新的聊天内容，也不必担心 edit windows。

## Spooky stranger: probing arbitrary phone numbers

1. 注册一个新的 WhatsApp/Signal 账户，并获取目标号码的 public identity keys（会在 session setup 时自动完成）。
2. 构造一个引用随机 `message_id` 的 reaction/edit/delete packet，这个 `message_id` 对任一方都从未见过（WhatsApp 接受任意 `key.id` GUIDs；Signal 使用 millisecond timestamps）。
3. 即使不存在任何 thread 也发送该 packet。受害设备会解密它，匹配不到 base message，丢弃状态变化，但仍会确认进入的 ciphertext，并把 device receipts 回传给攻击者。
4. 持续重复，以在受害者聊天列表中完全不出现的情况下构建 RTT series。

如果你首先需要发现哪些号码已注册，或想要大规模预先填充 device inventories，可以把这与 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) 串联起来，而不是手工猜测随机 E.164 ranges。

最新的 WhatsApp builds 还暴露了 `Settings -> Privacy -> Advanced -> Block unknown account messages`。把它当作 throughput limiter，而不是修复：它主要影响持续的 stranger-only flooding；一旦你已经是已知联系人，它就不再相关。

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 某个消息一旦被 delete-for-everyone，后续引用相同 `message_id` 的 delete packets 不再产生 UI 效果，但每个 device 仍会解密并确认它们。
* **Out-of-window operations:** WhatsApp 在 UI 中强制约 60 h 的 delete / 约 20 min 的 edit 窗口；Signal 强制约 48 h。超出这些窗口构造的 protocol messages 会在受害设备上被静默忽略，但 receipts 仍会传输，因此攻击者即使在对话结束很久之后也能无限期探测。
* **Invalid payloads:** 格式错误的 edit bodies，或引用已被清除消息的 deletes，都会触发相同行为——解密加 receipt，零 user-visible artefacts。

## Multi-device amplification & fingerprinting

* 每个关联设备（手机、desktop app、browser companion）都会独立解密 probe 并返回自己的 ack。统计每个 probe 的 receipts 数量即可得到准确的 device count。
* 如果某个设备离线，它的 receipt 会被排队并在重新连接时发出。因此，空档会泄漏 online/offline cycles，甚至通勤时间表（例如，旅行期间 desktop receipts 会停止）。
* 由于 OS power management 和 push wakeups，不同 platform 的 RTT distributions 会不同。对 RTT 做聚类（例如，基于 median/variance features 的 k-means）即可标注为 “Android handset”、“iOS handset”、“Electron desktop”等。
* 因为 sender 在加密前必须获取 recipient 的 key inventory，攻击者还可以观察新设备何时被配对；device count 的突然增加或出现新的 RTT cluster 都是强信号。

## Behaviour inference from RTT traces

1. 以 ≥1 Hz 采样来捕捉 OS scheduling effects。在 iOS 上的 WhatsApp 中，<1 s 的 RTT 强相关于屏幕开启/前台，>1 s 则通常表示屏幕关闭/后台节流。
2. 构建简单分类器（阈值法或双簇 k-means），把每个 RTT 标成 "active" 或 "idle"。将这些标签聚合成 streaks，可推导就寝时间、通勤、工作时间，或 desktop companion 何时活跃。
3. 将同时向每个 device 发起的 probes 做相关分析，观察用户何时从 mobile 切换到 desktop、companion 何时离线，以及 app 是受 push 还是 persistent socket 的 rate limiting。
4. 在真实网络中，不要使用单一硬编码的 `1 s` threshold。先用短 warm-up window 对每个 device 做 bootstrap，再维护 rolling baseline（例如，`threshold = 0.9 * median RTT`），这样 Wi-Fi/cellular drift 就不会让分类器失效。

## Location inference from delivery RTT

同样的 timing primitive 也可以改用来推断接收者在哪里，而不仅仅是他们是否活跃。`Hope of Delivery` 这项工作表明：在已知接收位置上训练 RTT distributions，之后攻击者就能仅凭 delivery confirmations 对受害者的位置进行分类：

* 在同一个目标处于多个已知地点时建立 baseline（家里、办公室、校园、国家 A vs 国家 B 等）。
* 对每个 location，收集大量正常消息 RTT，并提取 median、variance 或 percentile buckets 等简单 features。
* 在真实攻击期间，把新的 probe series 与训练好的 clusters 比较。论文报告称，即使是同一城市内的位置，通常也能区分开，在 3-location 场景下准确率可超过 `80%`。
* 这在攻击者控制 sender environment 并在相似网络条件下进行 probes 时效果最佳，因为测得的路径包含 recipient access network、wake-up latency 和 messenger infrastructure。

与上面的 silent reaction/edit/delete attacks 不同，location inference 不需要无效 message IDs 或隐蔽的状态变更 packets。普通消息和正常 delivery confirmations 就足够了，因此代价是 stealth 较低，但适用性更广，适用于更多 messengers。

## Stealthy resource exhaustion

因为每个 silent probe 都必须被解密并确认，持续发送 reaction toggles、invalid edits 或 delete-for-everyone packets 会造成 application-layer DoS：

* 强迫 radio/modem 每秒都进行收发 → 明显耗电，尤其在空闲手持设备上。
* 生成未计量的上行/下行流量，在混入 TLS/WebSocket 噪声的同时消耗移动数据套餐。
* 占用 crypto threads，并在对延迟敏感的功能（VoIP、video calls）中引入 jitter，尽管用户根本看不到通知。
* 在 WhatsApp 中，invalid reactions 可接受的数据远超普通 emoji 的直觉大小：已发布测量发现，server-side acceptance 每个 reaction 最高约可达 `1 MB`。
* 当 body 增长到大约 `30 bytes` 以上时，超大的 reactions 就不再产生可靠的 delivery receipts，但它们仍会在被丢弃前被转发和处理。需要 ACKs 时保持 reaction bodies 很小；只有在目标是纯耗尽或 covert one-way transport 时才把它们增大。
* 公开测量在这种模式下达到约 `3.7 MB/s`（`~13.3 GB/h`）的受害者流量。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
