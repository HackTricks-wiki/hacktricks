# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts 在现代 end-to-end encrypted (E2EE) messengers 中是必须的，因为客户端需要知道 ciphertext 何时被解密，以便丢弃 ratcheting state 和 ephemeral keys。服务器转发 opaque blobs，因此设备确认（双勾）在接收方成功解密后发出。在攻击者触发的操作与相应 delivery receipt 之间测量 round-trip time (RTT) 会暴露高分辨率的 timing channel，能够 leak 设备状态、在线存在性，并可被滥用于 covert DoS。多设备的 "client-fanout" 部署会放大信息泄露，因为每个注册设备都会解密探针并返回自己的 receipt。

## Delivery receipt sources vs. user-visible signals

选择总是发出 delivery receipt 但不会在受害者端产生 UI 痕迹的 message types。下面的表格总结了实证确认的行为：

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

图例： ● = always, ◐ = conditional, ○ = never。平台相关的 UI 行为在行内标注。若需要可以禁用 read receipts，但在 WhatsApp 或 Signal 中无法关闭 delivery receipts。

## Attacker goals and models

* **G1 – Device fingerprinting:** 统计每次探针到达的 receipts 数量，聚类 RTTs 以推断 OS/client（Android vs iOS vs desktop），并监视在线/离线转换。
* **G2 – Behavioural monitoring:** 将高频 RTT 序列（≈1 Hz 是稳定的）视为时间序列，推断屏幕开/关、app 前台/后台、通勤与工作时间等行为。
* **G3 – Resource exhaustion:** 通过发送永无止境的 silent probes 保持每台受害设备的 radios/CPUs 唤醒，消耗电池/数据并劣化 VoIP/RTC 质量。

两类威胁行为者足以描述滥用面：

1. **Creepy companion：** 已与受害者共享聊天，滥用 self-reactions、reaction removals 或反复的 edits/deletes（绑定到现有 message IDs）。
2. **Spooky stranger：** 注册一次性账号并发送引用在本地会话中从未存在的 message IDs 的 reactions；WhatsApp 和 Signal 仍会解密并确认它们，尽管 UI 丢弃了状态更改，因此不需要事先对话。

## Tooling for raw protocol access

依赖那些暴露底层 E2EE 协议的客户端，这样你可以在 UI 约束之外构造数据包、指定任意 `message_id`s，并记录精确时间戳：

* **WhatsApp：** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) 或 [Cobalt](https://github.com/Auties00/Cobalt) (面向移动) 允许你发送原始的 `ReactionMessage`, `ProtocolMessage` (edit/delete), 和 `Receipt` 帧，同时保持 double-ratchet state 同步。
* **Signal：** [signal-cli](https://github.com/AsamK/signal-cli) 结合 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) 通过 CLI/API 暴露每种 message type。示例自我反应切换：
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema：** Android 客户端的源码说明了 delivery receipts 在离开设备前如何被合并，这解释了为何该侧信道的带宽可忽略不计。

当自定义工具不可用时，你仍可以从 WhatsApp Web 或 Signal Desktop 触发 silent actions 并嗅探加密的 websocket/WebRTC 通道，但原始 API 可以去除 UI 延迟并允许非法操作。

## Creepy companion: silent sampling loop

1. 选择你在聊天中发送过的任意历史消息，这样受害者不会看到 “reaction” 气泡变化。
2. 在可见 emoji 与空 reaction payload（在 WhatsApp protobuf 中编码为 `""` 或在 signal-cli 中使用 `--remove`）之间交替。每次传输都会产生设备 ack，尽管对受害者没有 UI 差异。
3. 记录发送时间和每个 delivery receipt 到达时间。像下面这样的 1 Hz 循环可以无限期地给出每设备的 RTT 跟踪：
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. 因为 WhatsApp/Signal 接受无限的 reaction 更新，攻击者无需发布新的聊天内容或担心编辑窗口。

## Spooky stranger: probing arbitrary phone numbers

1. 注册一个新的 WhatsApp/Signal 账号并获取目标号码的 public identity keys（在会话设置期间会自动完成）。
2. 构造一个引用任意从未被任一方见过的 `message_id` 的 reaction/edit/delete 数据包（WhatsApp 接受任意 `key.id` GUID；Signal 使用毫秒时间戳）。
3. 发送该数据包，尽管不存在线程。受害设备会解密它、无法匹配基消息、丢弃状态更改，但仍会确认收到的 ciphertext，将设备 receipts 发回攻击者。
4. 持续重复以构建 RTT 序列，同时永远不会出现在受害者的聊天列表中。

## Recycling edits and deletes as covert triggers

* **Repeated deletes：** 一条消息被删除-for-everyone 一次后，后续引用相同 `message_id` 的 delete 包不会有 UI 效果，但每台设备仍会解密并确认它们。
* **Out-of-window operations：** WhatsApp 在 UI 中强制约 ~60 h 的删除 / ~20 min 的编辑窗口；Signal 强制约 ~48 h。构造的协议消息在这些窗口外在受害设备上被静默忽略，但 receipts 仍会被传输，因此攻击者可以在对话结束很久之后无限期探测。
* **Invalid payloads：** 损坏的 edit body 或引用已被清除消息的 delete 会产生相同的行为——解密并发送 receipt，但没有用户可见的痕迹。

## Multi-device amplification & fingerprinting

* 每个关联设备（手机、桌面 app、浏览器 companion）会独立解密探针并返回自己的 ack。统计每次探针的 receipts 数量即可揭示确切的设备数量。
* 如果某设备离线，其 receipt 会排队并在重新连接时发出。因此间隙会 leak 在线/离线周期，甚至通勤日程（例如桌面 receipt 在出行期间停止）。
* RTT 分布因平台而异，受 OS 电源管理和 push 唤醒影响。对 RTT 进行聚类（例如基于中位数/方差特征的 k-means）可标记为 “Android handset”, “iOS handset”, “Electron desktop” 等。
* 因为发送者在加密前必须检索接收方的 key inventory，攻击者还可以观察到何时配对了新设备；设备数量突然增加或新的 RTT 聚类是强烈的指示器。

## Behaviour inference from RTT traces

1. 以 ≥1 Hz 采样以捕捉 OS 调度效应。在 iOS 上的 WhatsApp 中，<1 s 的 RTT 强烈相关于屏幕开启/前台，>1 s 相关于屏幕关闭/后台节流。
2. 构建简单的分类器（阈值或二类 k-means）将每个 RTT 标记为 "active" 或 "idle"。将标签聚合为连续段以推断就寝时间、通勤、工作时间，或何时桌面 companion 处于活动状态。
3. 同步探测每台设备并关联它们，可以看到用户何时从移动设备切换到桌面、何时 companions 下线，以及应用是被 push 限速还是由持久 socket 限制。

## Stealthy resource exhaustion

因为每个 silent probe 都必须被解密并确认，持续发送 reaction 切换、无效的 edits 或 delete-for-everyone 数据包会造成应用层 DoS：

* 强制 radio/modem 每秒发送/接收 → 在空闲手机上会有明显电池消耗。
* 产生未计费的上/下行流量，消耗移动数据计划，同时混入 TLS/WebSocket 噪声中不易被察觉。
* 占用 crypto 线程并在延迟敏感功能（VoIP、视频通话）中引入抖动，即便用户从未看到通知。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
