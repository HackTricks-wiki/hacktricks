# 隐私操作系统

注重隐私的操作系统可以减少 routing 和 persistence 错误，但没有任何系统能够弥补可识别行为或已被入侵的硬件。

## 选择隔离模型

| 系统 | 最适合 | Persistence | Network enforcement | 主要权衡 |
|---|---|---|---|---|
| **维护良好的 OS 上的 Tor Browser** | 偶尔进行 anonymous web browsing | Browser state 通常仅限当前 session | 仅 Browser traffic | 其他应用和主机仍在 Tor 之外 |
| **Tails** | 便携、amnesic、单一用途的 sessions | 可选的加密 Persistent Storage | Internet traffic 强制通过 Tor | 重启和工作流不便；firmware/hardware trust |
| **Whonix** | 需要强制 Tor routing 的持久化应用 | Persistent VMs | Gateway/Workstation split | Host/hypervisor 和 identity mixing 仍然存在 |
| **Qubes-Whonix** | 面向高级用户的强 compartment separation | Per-qube | Dedicated network qubes 和 Whonix | 硬件要求和操作复杂度 |

## Tails

Tails 可独立从 removable media 启动，通过 Tor routing Internet traffic，并且设计目标是尽量不留下本地 state。其自身的 warnings 强调：它无法防御已被入侵的 BIOS/firmware/hardware、identifying disclosures、file metadata，或能够关联两端的强大 observer。<sup>[[1]](#references)</sup>

### 单一用途的 Tails 工作流

1. 在受信任且已更新的计算机上从官方网站下载 Tails，并遵循官方的 verification/install 流程。
2. 仅使用受支持的 USB drive 启动 Tails；不要同时将其作为通用 file-transfer drive 使用。
3. 在你实际控制的硬件上启动。live OS 无法抵御 hardware keylogger 或恶意 firmware。
4. 除非工作流确实需要，否则保持 Persistent Storage disabled。如果启用，只持久化必要的 categories，并使用强 passphrase。
5. 连接到合法网络。如果 captive portal 无法避免，仅将 Tails' Unsafe Browser 用于该 portal，不要披露任何不必要的 identity，完成后立即关闭，并在进行任何 sensitive activity 之前连接到 Tor。<sup>[[2]](#references)</sup>
6. 如果 direct Tor visibility 或 blocking 很重要，请配置 Tor bridge。
7. 每个 session 仅执行 **一种 contextual identity/purpose**。Tails 建议在不应相互关联的 activities 之间重新启动。<sup>[[1]](#references)</sup>
8. 在发布前检查并清理 files。不要在可能绕过预期 context 的 application 中打开下载的 active documents。
9. 完成后完全 shut down，并确保 USB physical security。

## Whonix

Whonix 将 Tor-routing **Gateway** 与 **Workstation** 分离；Workstation 中的 applications 无法直接获知 external IP。这能显著减少 proxy/DNS 错误，但 host、hypervisor、行为和 documents 仍可能暴露 identity。Whonix 明确警告，不要使用同一个 workstation 处理多个 identities，也不要混合 anonymous 和 non-anonymous activity。<sup>[[3]](#references)</sup>

### Compartment 工作流

1. 从官方来源验证 Whonix image 和 virtualization platform。
2. 使用前修补 host、hypervisor、Gateway 和 Workstation。
3. 为每个 identity 或 engagement 克隆一个全新的 Workstation；一旦引入了 identity-bearing state，绝不要再克隆该 VM。
4. 不要让 personal accounts、host shared folders、clipboard synchronization、USB devices 以及 time/location data 进入 Workstation。
5. 使用 snapshots 进行 recovery，不要将其作为 backups 或 identity separation 的替代方案。
6. 确认 Gateway 停止时 Workstation 无法访问 Internet。
7. 对于风险尤其高的 files，使用 disposable VM/qube，并且只导出 sanitized result。

## Qubes OS 和 Qubes-Whonix

Qubes 通过基于 Xen 的 qubes 以 compartmentalization 实现 security。其设计限制了一个 domain 中的 compromise 自动影响其他 domains，但位于**同一个** qube 内的 applications 彼此并未隔离。<sup>[[4]](#references)</sup> Disposable qubes 可为不受信任的 sites、files 和 devices 提供 fresh state。<sup>[[5]](#references)</sup>

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
- 将机密信息保存在离线 vault qube 中，并使用明确的 qube 间复制/文件操作。
- 在 disposable 中打开未经请求的文件和链接。
- 仅通过 Whonix 或专用 VPN qube 路由指定的 qube。
- 为窗口使用明显不同的标签，并在处理敏感工作时停止无关的 qube。
- 不要假设两个 qube 能防止关联分析，因为它们可能共享账户、内容、时间安排或付款信息。

## Verification and maintenance

- 按照官方说明验证 installer signatures/checksums。
- 先更新模板，然后重启依赖它们的 qube/VM。
- 确认 network-deny 行为、DNS、IPv6、时钟、剪贴板、共享目录和 USB 分配。
- 检查 Persistent Storage 和 VM snapshots 中是否存在旧的身份相关数据。
- 对 seeds/keys 保留加密的离线备份，并在隔离环境中测试恢复。
- 在怀疑遭到 compromise 后重建 compartment；仅更改其 egress IP 不足以解决问题。

## References

- [1] [Tails — 警告：Tails 是安全的，但并非万能](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — 使用 captive portal 登录网络](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix 和 Tor 的限制](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — 安全设计目标](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — 如何使用 disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
