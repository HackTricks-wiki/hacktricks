# WhatsApp Prekey Bundle 耗尽与补充侧信道

{{#include ../banners/hacktricks-training.md}}

WhatsApp 会为每台设备存储一个 identity key、一个 signed prekey，以及一组 one-time prekey 储备。获取设备的 bundle 会消耗服务器端存储的一个 one-time prekey，即使请求方没有发送任何消息也是如此。这让拥有 WhatsApp 账户和目标电话号码的攻击者可以进行一种**服务器端**探测，不同于[客户端送达回执计时](side-channel-attacks-on-messaging-protocols.md)。缺少 one-time prekey 也会削弱新建会话*初始*消息的前向保密性，但其本身不会暴露明文。<sup>[[1]](#references)[[2]](#references)</sup>

## 检查目标的设备 bundles

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) 可作为 WhatsApp companion session 配对，并支持**手动**查询设备和 prekey。将它与测试账户配对，然后使用其交互式 `target`、`devices`、`prekey`（主设备）和 `combine`（所有设备）命令。发布的 artifact 刻意省略了自动耗尽和服务器阻塞功能。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

对于每个响应，记录设备 JID、bundle 时间戳 `t`、signed-prekey ID `skey.id`，以及是否存在一次性 `key.id`。设备 ID `0` 是手机；非零 ID 是 companion。在论文测试的实现中，初始 signed-prekey ID 也能区分部分客户端：Android 从 `0` 开始，iOS 和 macOS 使用随机值，WhatsApp Web 和 Windows Desktop 从 `1` 开始。应将其视为实现指纹，而非不可变的协议规则。<sup>[[1]](#references)</sup>

## 将补充行为变成在线状态 oracle

先在自己控制的设备上校准：反复请求其 bundle，直到服务器不再返回一次性 `key`，并记录最后的时间戳和 key ID。对于目标设备，重复耗尽操作，并在设定的间隔后重新查询：如果出现新的 one-time key 且 bundle 时间戳前进，说明该设备上传了新的一批 key。在报告的 WhatsApp 测试中，剩余 key 少于 11 个时，服务器会提示补充，客户端会上传 812 个新 key。对每个设备 JID 分别执行此流程，以区分手机和 companion。补充延迟只能**暗示**设备处于离线状态：后台调度、网络中断和客户端特有的补充延迟都可能导致相同的观察结果。与 receipt RTT 不同，此探测不需要已送达的 ciphertext 或受害者一侧的确认。<sup>[[1]](#references)[[2]](#references)</sup>

每次查询都会消耗一个 one-time key，因此要持续运行 oracle，需要能够反复获取 prekey 的自定义客户端；公开的 artifact 仅演示了手动查询。将储备 key 保持为空，可能导致其他用户在建立新 session 时不使用 one-time prekey。这会降低初始消息的前向保密性，直到发生新的 ratchet 步骤；但要利用录制的 ciphertext，还需要获取 E2EE ciphertext，并在之后攻陷相关的长期和中期私钥。现有已建立的 session 不会自动降级。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo：调查 WhatsApp 握手机制中的安全与隐私问题](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [X3DH 密钥协商协议](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
