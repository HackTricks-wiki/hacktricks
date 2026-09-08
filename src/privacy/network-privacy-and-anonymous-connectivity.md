# 网络隐私与匿名连接

网络隐私是一项路由决策，而不是完整身份。选择路径时，应先考虑哪些观察者不应能够将**源**、**目的地**、**内容**和**时间特征**关联起来。

有关每类访问路径的标准化清单——`Pros`、`Cons`、逐步 `Procedure` 和 `Detection`——请从[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)开始。本页面扩展介绍常见的可部署选项。

## 每类观察者通常可以看到什么

| 路径 | 本地网络 / ISP | 中间方 | 目的地 | 主要限制 | 相对速度 |
|---|---|---|---|---|---|
| Direct HTTPS | 源、目的地元数据、时间特征/流量量 | Hosting/CDN 看到连接 | 源 IP、浏览器/应用数据 | 不提供源 IP 隐私 | 最快 |
| Commercial VPN | 源已连接到 VPN；通常看不到目的地元数据 | VPN 看到源和目的地元数据 | VPN 出口 IP | 一个提供商成为关联点 | 通常较快 |
| Self-hosted VPN/VPS | 源已连接到 VPS | 主机/账户/支付/控制平面日志 | VPS 出口 IP | 很容易归因到租用的服务器/账户 | 通常较快 |
| Tor Browser | 源已连接到 Tor/bridge；时间特征/流量量 | 每个 Relay 只能看到有限部分 | Tor exit、浏览器数据 | 更慢；存在账户/端点/关联风险 | 中等/较慢 |
| Tails/Whonix | 类似 Tor 路径，但路由边界更强 | 具有相同的 Tor 限制 | Tor exit/应用数据 | 操作失误以及主机/硬件仍会暴露 | 中等/较慢 |
| Public guest Wi-Fi + HTTPS | 场所看到本地设备/时间特征和目的地 | 场所 ISP 看到元数据 | Guest 公共 IP | 物理/captive-portal/设备关联 | 快速/不稳定 |
| Cellular hotspot | 运营商看到订户/设备/位置和目的地 | 如使用 VPN/Tor，则看到相应信息 | 运营商、VPN 或 Tor 出口 IP | 移动订阅和位置是持久标识符 | 快速/不稳定 |
| Mixnet | 接入方看到 Mixnet 使用情况；时间特征/流量量 | 多个混合节点 | Gateway/egress | 生态仍在发展；延迟和带宽成本 | 最慢 |

HTTPS 可保护传输中的内容，但不能保护所有元数据。EFF 指出，即使页面路径、凭据和消息已加密，中间方仍可能看到域名、时间和流量大小。<sup>[[1]](#references)</sup>

## VPN：速度较快但信任集中

VPN 可用于向接入 ISP 隐藏目的地元数据、保护不可信网络上的第一跳、提供稳定的 engagement 出口地址，或访问私有网络。它**不会**使用户匿名。VPN 可以看到源连接并观察目的地元数据；账户、cookies、GPS、fingerprints 和支付信息仍然存在。<sup>[[1]](#references)</sup>

### 提供商评估清单

1. **所有权和司法管辖区：**确认法律实体、母公司、运营国家、基础设施分包商以及适用的法律程序。
2. **收集的数据：**区分账户/账单、源 IP、连接时间戳、带宽、崩溃遥测、DNS 查询和目的地日志。“不记录浏览日志”不等于“不收集数据”。
3. **保留和删除：**确认准确的保留期限，以及备份、欺诈系统和处理方是否遵循相同的计划。
4. **证据：**优先选择公开审计（包含范围、日期、发现和修复情况）、可复现/开放的客户端、透明度报告以及有记录的事件。
5. **协议和客户端：**使用维护中的 WireGuard、OpenVPN 或其他经过审查的协议；自动更新；DNS 和 IPv6 处理；kill switch；以及针对各平台的 leak 测试。
6. **商业模式：**了解免费或补贴服务如何获得资金。仅存在于应用商店并不能证明其运行值得信任。
7. **支付适配性：**替代支付方式可以减少向 VPN 暴露的账单信息，但不会抹除每次连接时 VPN 观察到的源 IP。

### 配置和验证 VPN

1. 仅从官方来源安装提供商/组织签名的客户端。
2. 除非有记录证明某条路由必须绕过 VPN，否则选择 **full tunnel**。Split tunneling 会产生关联和 leak 路径。
3. 启用 fail-closed/always-on 行为，并在重新连接期间阻断流量。
4. 通过隧道发送 DNS，并测试 IPv4 和 IPv6。只有在某协议无法安全通过隧道传输且已接受功能损失时，才禁用该协议。
5. 测试睡眠/唤醒、网络切换、captive-portal 登录、隧道崩溃和 hotspot tethering。NCSC 警告，在某些平台上，tethered 客户端可能绕过手机的 VPN。<sup>[[2]](#references)</sup>
6. 使用组织控制的测试端点，记录观测到的 IPv4、IPv6、DNS resolver 和连接时间。不要将敏感 engagement 暴露给随机的“leak test”网站。
7. 在客户端、OS、网络或策略发生变化后重新测试。

## Tor Browser：更强的 Web 不可关联性

Tor 通过多个 Relay 构建 circuit，因此通常没有单个 Relay 同时知道源和目的地。目的地看到的是 Tor exit，而不是用户的 IP；本地网络通常只能看到 Tor 连接。<sup>[[3]](#references)</sup> Tor 面向低延迟 TCP 应用设计，因此速度较慢，并且无法保证抵御能够关联两端流量的对手。<sup>[[4]](#references)</sup>

### 安全的 Tor Browser 工作流

1. 仅从 Tor Project 或官方镜像下载 Tor Browser，并在可能时验证签名。
2. 使用 **Tor Browser**，不要使用指向 Tor SOCKS 端口的普通浏览器。普通浏览器可能泄露 DNS/WebRTC 和可识别状态。<sup>[[5]](#references)</sup>
3. 保持默认的尺寸、字体、扩展和隐私设置。额外 add-ons 可能使浏览器更具唯一性。<sup>[[6]](#references)</sup>
4. 在能够接受更高页面损坏率时，选择 **Safer** 或 **Safest** 安全级别。
5. 当直接 Tor 被阻断，或普通 Relay IP 会造成不可接受的本地可见性时，使用 bridge。Bridge 可降低被轻易识别的概率，但不能消除流量分析。<sup>[[7]](#references)</sup>
6. 不要登录可识别身份的账户、提供可识别信息，也不要在外部联网应用中打开下载的活动文档。
7. 为每个身份使用独立的会话/上下文。“New circuit”不等同于清除浏览器/应用身份；应适当使用 **New Identity** 或重启隔离环境。
8. 优先使用经过身份验证的 HTTPS 或经过身份验证的 onion service。Tor exit 可以观察未加密的 HTTP 流量。

### Tor 加 VPN

组合使用并不会自动更安全。Tor 之前使用 VPN，可能向 ISP 隐藏直接的 Tor Relay 连接，但 VPN 会看到源；VPN 之前使用 Tor，则 VPN 会稳定地看到 Tor 之后的活动，并可能缩小匿名集合。错误配置可能引入 leak。Tor Project 建议仅在高级且明确的威胁模型下使用此类组合。<sup>[[8]](#references)</sup>

## 公共和 Guest Wi-Fi

现代 HTTPS 意味着被动监听的附近用户通常无法读取正确加密的 Web 内容，但 Guest Wi-Fi 并不提供匿名性。场所可以记录关联时间、设备标识符、captive-portal 数据、目的地和 DHCP 详情；摄像头、购买记录、交通记录和现场观察都可能识别用户。伪造的相似名称 hotspot 还可能窃取 portal 凭据或操纵未加密流量。<sup>[[9]](#references)</sup>

### 合法的 Guest 网络工作流

1. 仅使用为 Guest 提供的网络，或网络所有者明确授权使用的网络。向工作人员确认准确的 SSID 和 portal 流程。
2. 到达前更新端点和 travel router。禁用文件/打印机共享、入站发现、自动加入和已记忆网络探测。
3. 启用 OS 的私有/随机 Wi-Fi 地址。当前 Apple 系统可在开放/弱网络上使用轮换地址；现代 Android 的随机化通常按 SSID 持久存在。这只会减少一个本地标识符。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. 在特权工作站和 Guest 网络之间，优先使用组织控制的 travel router 或低信任 bridge 设备。这可以集中管理 firewall/VPN 策略，但不会向场所隐藏 router。<sup>[[12]](#references)</sup>
5. 仅通过指定的低信任设备/浏览器完成 captive portal。对于所谓的匿名上下文，绝不要输入个人凭据或重复使用的凭据。建立连接后关闭 portal 浏览器。
6. 在敏感活动前启动 full-tunnel VPN 或 Tor，并确认 fail-closed 行为。
7. 使用后忘记该网络，并查看 portal 账户/数据保留策略。

{% hint style="danger" %}
破解邻居的 Wi-Fi、绕过 portal、使用泄露的 Guest 凭据、克隆其他 Guest 的访问权限，或在咖啡馆隐藏 Raspberry Pi，都是未经授权的活动，而不是隐私技术。安全的替代方案是合法的 Guest 网络、客户批准的站点，或经物业所有者书面同意后放置并回收的有记录 drop node。
{% endhint %}

## Travel routers

Travel router 可以将工作站与恶意本地广播隔离、强制执行 firewall、提供一致的内部 SSID，并自动重新连接 VPN。它**不是**匿名的：上游可以看到其无线身份和流量时间特征，其 VPN 提供商可以看到隧道源。

- 使用受支持的 OpenWrt/vendor firmware，并移除未使用的服务。
- 通过 Ethernet 或带有唯一密码的专用管理 SSID 进行管理。
- 禁用 WAN 侧管理、UPnP、WPS、文件共享和未经请求的入站流量。
- 仅在受支持且获准的情况下使用随机化/私有 WAN MAC。
- 在 router 上强制执行 VPN 策略，包括 DNS 和 IPv6，并在隧道失败时阻断 egress。
- 不要假设 phone hotspot 会让 tethered 设备通过手机的 VPN 隧道；应进行测试。

## Cellular、SIM 和 eSIM

Cellular 很方便，但并不匿名。运营商会保留订户/设备标识符，以及根据网络接入情况推导出的位置信息；eSIM 仍然是移动订阅。Prepaid 并不可靠地意味着未注册——各国要求不同且会变化。<sup>[[13]](#references)</sup>

在操作层面：

- 使用独立且受支持的设备来减少个人数据暴露，而不是制造虚构的订户身份。
- 如果威胁模型包含共址分析，不要让“独立”设备持续与个人手机一起携带。
- 禁用未使用的 cellular、Wi-Fi、Bluetooth 和位置访问；关机比 UI 开关提供更强的无线边界。
- 将敏感流量置于批准的 VPN/Tor 路径中，同时认识到运营商仍知道订阅/设备位置和隧道端点。
- 向国家监管机构或当地法律顾问确认当前的注册和保留规则；不要依赖在线“匿名 SIM 国家”列表。

## DNS 和 TLS 元数据

- **DoH/DoT/DoQ** 会加密客户端与 resolver 之间的 DNS，防止本地进行简单读取或修改，但 resolver 仍能看到查询和传输标识符。它们只是转移信任，并不提供匿名性。<sup>[[14]](#references)</sup>
- **ODoH** 添加 proxy，使 resolver 无需了解客户端 IP，前提是 proxy 和目标不会串通。流量分析明确不在其范围内。<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** 可以在客户端、DNS 和服务器支持时，保护 TLS 握手中的内部服务器名称。目的地 IP、时间特征、流量量和端点仍然可见。<sup>[[16]](#references)</sup>
- 在正确配置的 VPN 或 Tor 环境中，DNS 应遵循该环境支持的路径。额外添加独立 resolver 可能产生新的观察者或 fingerprint。

### 加密 DNS/ECH 验证工作流

1. 确定 DNS 由 VPN/Tor 环境、OS 还是应用控制。在**一个**预期层中配置它，而不是堆叠互不相关的 resolver。
2. 根据其公开的隐私/保留策略选择 resolver，并在平台支持时启用严格的加密模式。机会式 fallback 可能会静默返回明文。
3. 查询你控制的权威测试 zone 下的唯一子域；确认权威日志看到的是预期的递归 resolver。
4. 在获得授权的情况下，仅捕获测试设备的流量。确认接入网络无法读取明文 DNS，同时认识到它可以看到加密 resolver/隧道端点。
5. 测试被阻断/不可达的加密 resolver。通过条件应是选定的 fail-closed 或有记录的 fallback 行为，而不是意外的明文查询。
6. 对于 ECH，使用受控且启用 ECH 的主机，并检查客户端/服务器诊断，以确认**内部** ClientHello 已被接受。仅提供 HTTPS 记录不能证明 ECH 成功。
7. 在网络变化、captive portal、浏览器更新和 VPN 重连后重复测试。记录由哪个组件负责 DNS/ECH，避免后续管理员创建绕过路径。

## Mixnets

Nym 或 Katzenpost 等 Mixnet 会添加固定大小的数据包、延迟、重新排序和 cover traffic，以抵抗时间关联。这些特性会产生延迟和带宽成本，而独立的部署规模证据仍然有限。将当前的 consumer Mixnet 视为**新兴/高延迟选项**，而不是 Tor/VPN 更快或有保证的替代方案。<sup>[[17]](#references)</sup>

### 评估工作流

1. 确认维护中的客户端和确切支持的应用；不要通过未记录的 proxy 强制任意浏览器/系统流量。
2. 阅读当前威胁模型，了解 entry、mix nodes、gateway、destination 和串通假设。
3. 从官方签名来源安装到独立的测试隔离环境中，并仅使用无害的自有端点。
4. 测量传递延迟、消息大小限制、可靠性、重传，以及 gateway 不可用时的行为。
5. 检查本地流量和自有端点，以确认预期路径和源。检查回复是否使用相同的隐私设计。
6. 测试关机/故障：应用不得静默 fallback 到直接 Internet 访问。
7. 不要仅为提速而禁用 cover traffic、减少延迟或选择异常的固定路径；这些变化可能使声明的匿名模型失效。
8. 在具体部署、独立分析和操作可靠性达到相应后果等级之前，将其保持为实验性方案。

## Network preflight checklist

- [ ] 授权范围涵盖接入网络、目标、日期和源基础设施。
- [ ] 端点不包含无关身份或活动同步会话。
- [ ] IPv4、IPv6、DNS 和重连行为符合计划。
- [ ] 目的地只能看到预期的 egress。
- [ ] 已在不使用敏感流量的情况下测试 captive portal 和 hotspot 行为。
- [ ] 已禁用本地共享/发现和自动加入网络。
- [ ] 已接受观察者表以及残余流量关联风险。
- [ ] 提供商策略、保留期限和紧急联系方式均为最新。

有关 split-knowledge relays、route-enforced workloads、pluggable transports、onion services、I2P 和 disposable remote browsers，请继续阅读[Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)。

## References

- [1] [EFF — 选择适合你的 VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — 设备安全指南：Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor 提供的隐私和匿名保护](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor 简介](https://spec.torproject.org/intro/)
- [5] [Tor Project — 将 Tor 与其他浏览器配合使用](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser 中的 Plugins 和 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — 解除 Tor 的阻断](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — 将 Tor Browser 与 VPN 配合使用](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — 公共 Wi-Fi 网络安全吗？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple 设备的 Wi-Fi 隐私](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — 实现 MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstations 原则](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — 强制 SIM 注册：政策和监管视角](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators 建议](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — 威胁模型](https://katzenpost.network/docs/threat_model/)
