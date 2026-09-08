# Privacy Operating Systems

{{#include ../banners/hacktricks-training.md}}

以隐私为重点的操作系统可以减少 routing 和 persistence 方面的错误，但任何系统都无法弥补可识别行为或已被入侵的硬件。

## 选择隔离模型

| System | Best fit | Persistence | Network enforcement | Main tradeoff |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | 偶尔进行匿名 Web 浏览 | 浏览器状态通常仅限当前会话 | 仅浏览器流量 | 其他应用和主机仍在 Tor 之外 |
| **Tails** | 便携、无痕的单一用途会话 | 可选的加密 Persistent Storage | Internet 流量强制通过 Tor | 重启和工作流不便；固件/硬件信任问题 |
| **Whonix** | 需要强制 Tor 路由的持久化应用 | 持久化 VMs | Gateway/Workstation 分离 | 主机/hypervisor 和身份混用问题仍然存在 |
| **Qubes-Whonix** | 面向高级用户的强隔离 | 按 qube 分离 | 专用 network qubes 和 Whonix | 硬件要求高且操作复杂 |

## Tails

Tails 可从可移动介质独立启动，通过 Tor 路由 Internet 流量，并且设计目标是尽量减少本地状态。其自身的警告强调：它无法防护已被入侵的 BIOS/firmware/hardware、身份识别信息泄露、文件 metadata，或能够关联通信两端的强大观察者。<sup>[[1]](#references)</sup>

### 单一用途的 Tails 工作流

1. 在受信任且已更新的计算机上从官方网站下载 Tails，并按照官方 verification/install 流程操作。
2. 仅使用受支持的 USB drive 启动 Tails；不要同时将其用作常规文件传输 drive。
3. 在由你实际控制的硬件上启动。live OS 无法抵御硬件 keylogger 或恶意 firmware。
4. 除非工作流确实需要，否则保持 Persistent Storage 禁用。如果启用，只持久化必要的类别，并使用强 passphrase。
5. 连接到合法网络。如果 captive portal 不可避免，请仅使用 Tails' Unsafe Browser 处理 portal，不要披露任何不必要的身份信息，完成后立即关闭，并在进行任何敏感活动前连接到 Tor。<sup>[[2]](#references)</sup>
6. 如果 direct Tor visibility 或 blocking 很重要，请配置 Tor bridge。
7. 每个会话只执行**一种上下文身份/目的**。Tails 建议在不应关联的活动之间重新启动。<sup>[[1]](#references)</sup>
8. 在发布文件前检查并清理文件。不要在可能绕过预期上下文的应用中打开下载的 active documents。
9. 完成后完全关机，并确保 USB 在物理上安全。

## Whonix

Whonix 将 Tor-routing **Gateway** 与 **Workstation** 分离，Workstation 中的应用无法直接获知外部 IP。这可以有效减少 proxy/DNS 错误，但主机、hypervisor、行为和文档仍可能暴露身份。Whonix 明确警告，不要将一个 workstation 用于多个身份，也不要混合 anonymous 和 non-anonymous 活动。<sup>[[3]](#references)</sup>

### 隔离工作流

1. 从官方来源验证 Whonix image 和 virtualization platform。
2. 使用前修补 host、hypervisor、Gateway 和 Workstation。
3. 为每个身份或 engagement 克隆一个全新的 Workstation；一旦引入包含身份信息的状态，绝不要再克隆 VM。
4. 不要让 personal accounts、host shared folders、clipboard synchronization、USB devices 以及 time/location data 进入 Workstation。
5. 使用 snapshots 进行恢复，不要将其替代 backups 或 identity separation。
6. 确认 Gateway 停止后，Workstation 无法访问 Internet。
7. 对于风险特别高的文件，使用 disposable VM/qube，并且只导出经过清理的结果。

## Qubes OS 和 Qubes-Whonix

Qubes 通过基于 Xen 的 qubes，利用 compartmentalization 实现安全。其设计限制了一个 domain 中的 compromise 自动影响其他 domain，但位于**同一** qube 内的应用彼此并不隔离。<sup>[[4]](#references)</sup> Disposable qubes 可为不受信任的网站、文件和设备提供全新的状态。<sup>[[5]](#references)</sup>

一种实用的布局：
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
规则：

- 为每个 qube 指定一个信任级别和身份用途。
- 将 secrets 保存在离线 vault qube 中，并使用明确的 qube 间复制/文件操作。
- 在 disposables 中打开未经请求的文件和链接。
- 仅通过 Whonix 或专用 VPN qube 路由指定的 qube。
- 清晰标记窗口，并在敏感操作期间停止无关的 qube。
- 不要认为两个 qube 就能防止关联；如果它们共享账户、内容、时间安排或支付信息，仍然可能被关联。

## 验证与维护

- 按照官方说明验证安装程序的签名/校验和。
- 先更新模板，然后重启依赖它们的 qube/VM。
- 确认 network-deny 行为、DNS、IPv6、时钟、剪贴板、共享目录和 USB 分配。
- 检查 Persistent Storage 和 VM snapshots 中是否存在旧的身份相关数据。
- 对 seeds/keys 保留加密的离线备份，并在隔离环境中测试恢复。
- 在怀疑遭到 compromise 后重建 compartment；仅更改其 egress IP 并不足够。

## References

- [1] [Tails — 警告：Tails 安全但并非万能](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — 使用 captive portal 登录网络](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix 和 Tor 的局限性](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — 安全设计目标](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — 如何使用 disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
