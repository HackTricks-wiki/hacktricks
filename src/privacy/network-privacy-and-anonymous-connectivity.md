# 网络隐私与匿名连接

{{#include ../banners/hacktricks-training.md}}

网络隐私是一项路由决策，而不是完整的身份保护。选择路径时，应询问哪些观察者不应能够将**源**、**目标**、**内容**和**时间**关联起来。

有关每类访问路径的标准化清单——`Pros`、`Cons`、分步的 `Procedure` 和 `Detection`——请从 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) 开始。本页面扩展介绍常见的可部署选项。

## 每类观察者通常能看到什么

| 路径 | 本地网络 / ISP | 中间方 | 目标 | 主要限制 | 相对速度 |
|---|---|---|---|---|---|
| Direct HTTPS | 源、目标元数据、时间 | Hosting/CDN 看到连接 | 源 IP、浏览器/应用数据 | 不提供源 IP 隐私 | 最快 |
| Commercial VPN | 源连接到 VPN；通常看不到目标元数据 | VPN 看到源和目标元数据 | VPN 出口 IP | 一个 provider 成为关联点 | 通常较快 |
| Self-hosted VPN/VPS | 源连接到 VPS | Host/account/payment/control-plane 日志 | VPS 出口 IP | 容易归因到租用的服务器/账户 | 通常较快 |
| Tor Browser | 源连接到 Tor/bridge；时间/流量大小 | 每个 relay 只能看到有限部分 | Tor exit、浏览器数据 | 较慢；存在账户/端点/关联风险 | 中等/慢 |
| Tails/Whonix | 类似 Tor 路径，但路由边界更强 | 具有相同的 Tor 限制 | Tor exit/应用数据 | 操作错误以及主机/硬件仍然存在 | 中等/慢 |
| Public guest Wi-Fi + HTTPS | 场所看到本地设备/时间和目标 | 场所 ISP 看到元数据 | Guest public IP | 物理/captive-portal/设备关联 | 快/不稳定 |
| Cellular hotspot | Carrier 看到订阅者/设备/位置及目标 | 如果使用 VPN/Tor，则看到相应连接 | Carrier、VPN 或 Tor 出口 IP | 移动订阅和位置是持久标识符 | 快/不稳定 |
| Mixnet | 接入方看到 Mixnet 使用情况、时间/流量大小 | 多个 mixing 节点 | Gateway/egress | 生态仍在发展；存在延迟和带宽成本 | 最慢 |

HTTPS 可保护传输中的内容，但不能保护所有元数据。EFF 指出，即使页面路径、凭据和消息已加密，域名、时间和流量大小仍可能对中间方可见。<sup>[[1]](#references)</sup>

## VPN：快速隐私与集中的信任

VPN 可用于向接入 ISP 隐藏目标元数据、保护不受信任网络上的第一跳、提供稳定的 engagement egress 地址，或访问私有网络。它**不会**让用户匿名。VPN 能看到源连接，并可观察目标元数据；账户、cookies、GPS、fingerprints 和支付信息仍然存在。<sup>[[1]](#references)</sup>

### Provider 评估清单

1. **所有权和司法管辖区：** 确认法律实体、母公司、运营国家、基础设施 subcontractors 以及适用的法律程序。
2. **收集的数据：** 匘蛛 account/billing、源 IP、连接时间戳、带宽、崩溃 telemetry、DNS queries 和 destination logs。“No browsing logs”并不意味着“不收集数据”。
3. **保留和删除：** 查找精确的保存期限，并确认 backups、fraud systems 和 processors 是否遵循相同时间表。
4. **证据：** 优先选择公开审计（包含范围、日期、发现结果和修复情况）、可复现/open clients、transparency reports 以及有记录的事件。
5. **Protocol 和 client：** 使用受维护的 WireGuard、OpenVPN 或其他经过审查的 protocol；启用自动更新；处理 DNS 和 IPv6；启用 kill switch；并进行各平台的 leak tests。
6. **商业模式：** 了解免费或补贴服务的资金来源。出现在 app store 中本身并不是可信运营的证据。
7. **支付适配性：** 替代支付方式可以减少向 VPN 暴露的账单信息，但不会抹去每次连接时观察到的源 IP。

### 配置和验证 VPN

1. 从官方来源安装 provider/organization 的签名 client。
2. 除非有记录在案的路由必须绕过 VPN，否则选择 **full tunnel**。Split tunneling 会产生关联和 leak 路径。
3. 启用 fail-closed/always-on 行为，并在重新连接期间阻断流量。
4. 通过 tunnel 发送 DNS，并测试 IPv4 和 IPv6。只有在某个 protocol 无法安全地通过 tunnel 传输且接受功能损失时，才禁用该 protocol。
5. 测试休眠/唤醒、网络切换、captive-portal 登录、tunnel 崩溃和 hotspot tethering。NCSC 警告，在某些平台上，tethered clients 可能绕过手机的 VPN。<sup>[[2]](#references)</sup>
6. 使用 organization-controlled test endpoint 记录观察到的 IPv4、IPv6、DNS resolver 和连接时间。不要将敏感 engagement 暴露给随机的“leak test”网站。
7. 在 client、OS、网络或 policy 发生变化后重新测试。

## Tor Browser：更强的 Web 不可关联性

Tor 通过多个 relays 构建 circuit，因此通常没有单个 relay 同时知道源和目标。目标看到的是 Tor exit，而不是用户的 IP；本地网络通常看到的是 Tor 连接。<sup>[[3]](#references)</sup> Tor 面向低延迟 TCP 应用设计，因此速度较慢，并且无法保证防御能够关联两端的 adversary。<sup>[[4]](#references)</sup>

### 安全的 Tor Browser 工作流

1. 仅从 Tor Project 或官方 mirror 下载 Tor Browser，并在可能时验证 signature。
2. 使用 **Tor Browser**，不要使用指向 Tor SOCKS port 的普通浏览器。普通浏览器可能泄露 DNS/WebRTC 和识别状态。<sup>[[5]](#references)</sup>
3. 保持默认的尺寸、字体、extensions 和隐私设置。额外 add-ons 可能使浏览器更加独特。<sup>[[6]](#references)</sup>
4. 在可以接受更高 breakage 的情况下，选择 **Safer** 或 **Safest** security level。
5. 当 direct Tor 被阻断，或普通 relay IP 会造成不可接受的本地可见性时，使用 bridge。Bridges 可降低被轻易识别的概率，但无法消除 traffic analysis。<sup>[[7]](#references)</sup>
6. 不要登录可识别身份的账户、提供可识别身份的信息，或在外部联网应用中打开下载的 active documents。
7. 为每个身份使用独立的 session/context。“New circuit”不等同于清除浏览器/应用身份；应适当使用 **New Identity** 或重启隔离环境。
8. 优先使用 authenticated HTTPS 或 authenticated onion service。Tor exit 可以观察未加密的 HTTP 流量。

### Tor 加 VPN

组合使用并不会自动更安全。Tor 之前使用 VPN，可能向 ISP 隐藏 direct Tor relay connections，但 VPN 会看到源；Tor 之后使用 VPN，则 VPN 会稳定看到 Tor 后的活动，并可能缩小 anonymity set。错误配置可能引入 leaks。Tor Project 仅建议在高级且明确的 threat models 下使用此类组合。<sup>[[8]](#references)</sup>

## 公共和访客 Wi-Fi

现代 HTTPS 意味着被动邻居通常无法读取正确加密的 Web 内容，但 guest Wi-Fi 并不提供匿名性。场所可以记录关联时间、设备标识符、captive-portal 数据、目标和 DHCP 详情；摄像头、购买记录、交通信息和物理观察都可能识别用户。同名或类似名称的 fake hotspot 还可能窃取 portal credentials 或篡改未加密流量。<sup>[[9]](#references)</sup>

### 合法 guest-network 工作流

1. 仅使用向访客提供的网络，或网络所有者明确授权使用的网络。向工作人员询问准确的 SSID 和 portal 流程。
2. 在到达前更新 endpoint 和 travel router。禁用文件/打印机共享、入站发现、自动加入和 remembered-network probing。
3. 启用 OS 的 private/randomized Wi-Fi address。当前 Apple 系统可以在开放/弱网络上使用 rotating addresses；现代 Android randomization 通常按 SSID 持久化。这样只会减少一个本地标识符。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. 在 privileged workstation 与 guest network 之间，优先使用 organization-controlled travel router 或 low-trust bridge device。这可以集中 firewall/VPN policy，但不会向场所隐藏该 router。<sup>[[12]](#references)</sup>
5. 仅通过指定的 low-trust device/browser 完成 captive portal。不要为所谓的 anonymous context 输入个人凭据或复用的凭据。建立连接后关闭 portal browser。
6. 在敏感活动前启动 full-tunnel VPN 或 Tor，并确认 fail-closed 行为。
7. 使用后忘记该网络，并查看 portal 账户/数据保留 policy。

{% hint style="danger" %}
破解邻居的 Wi-Fi、绕过 portal、使用泄露的访客凭据、克隆其他访客的访问权限，或将 Raspberry Pi 藏在咖啡馆中，都是未经授权的活动，而不是隐私技术。安全的等价做法是使用合法的 guest network、经 client 批准的站点，或在 property owner 书面同意下放置并回收的 documented drop node。
{% endhint %}

## Travel routers

Travel router 可以将 workstation 与恶意的本地 broadcasts 隔离，强制执行 firewall，提供一致的内部 SSID，并自动重新连接 VPN。它**不是**匿名的：上游可以看到其 radio identity 和流量时间，VPN provider 可以看到 tunnel source。

- 使用受支持的 OpenWrt/vendor firmware，并移除未使用的 services。
- 通过 Ethernet 或具有唯一密码的 dedicated management SSID 进行管理。
- 禁用 WAN-side administration、UPnP、WPS、文件共享和未经请求的入站流量。
- 仅在受支持且获准的情况下使用 randomized/private WAN MAC。
- 在 router 上强制执行 VPN policy，包括 DNS 和 IPv6，并在 tunnel 失败时阻断 egress。
- 不要假定 phone hotspot 会通过手机的 VPN 为 tethered devices 建立 tunnel；应进行测试。

## Cellular、SIM 和 eSIM

Cellular 便捷但不匿名。运营商会维护订阅者/设备标识符，以及根据网络接入推导出的位置；eSIM 仍然是移动订阅。Prepaid 并不可靠地意味着未注册——要求因国家而异且会变化。<sup>[[13]](#references)</sup>

在操作层面：

- 使用独立且受支持的设备，以减少个人数据暴露，而不是创建虚假的订阅者身份。
- 如果 co-location 属于 threat model，不要将“独立”设备持续与个人手机一起携带。
- 禁用未使用的 cellular、Wi-Fi、Bluetooth 和 location access；关机比 UI toggles 提供更强的 radio boundary。
- 将敏感流量放入获批准的 VPN/Tor path，同时认识到 carrier 仍然知道订阅/设备位置和 tunnel endpoint。
- 向 national regulator 或 local counsel 核实当前的注册和保留规则；不要依赖在线“anonymous SIM countries”列表。

## DNS 和 TLS 元数据

- **DoH/DoT/DoQ** 会加密 client 与 resolver 之间的 DNS，防止简单的本地读取或修改，但 resolver 仍然可以看到 queries 和 transport identifiers。它们会转移信任，但不提供匿名性。<sup>[[14]](#references)</sup>
- **ODoH** 添加 proxy，使 resolver 无需了解 client IP，前提是 proxy 和 target 不串通。Traffic analysis 明确不在其范围内。<sup>[[15]](#references)</sup>
- 当 client、DNS 和 server 支持时，**TLS Encrypted Client Hello (ECH)** 可以保护 TLS handshake 中的 inner server name。Destination IP、时间、流量大小和 endpoint 仍然可见。<sup>[[16]](#references)</sup>
- 在正确配置的 VPN 或 Tor 环境中，DNS 应遵循该环境支持的路径。添加独立 resolver 可能产生新的 observer 或 fingerprint。

### Encrypted-DNS/ECH 验证工作流

1. 确定 DNS 由 VPN/Tor environment、OS 还是 application 控制。在**一个**预期层中配置，而不是叠加无关的 resolvers。
2. 根据其公开的 privacy/retention policy 选择 resolver，并在平台支持时启用 strict encrypted mode。Opportunistic fallback 可能静默地回退到明文。
3. 查询你控制的 authoritative test zone 下的唯一 subdomain；确认 authoritative log 看到的是预期的 recursive resolver。
4. 在获得授权的情况下，仅捕获 test device 的流量。确认接入网络无法读取明文 DNS，同时认识到它仍可看到 encrypted resolver/tunnel endpoint。
5. 测试被阻断/不可达的 encrypted resolver。通过条件应是所选的 fail-closed 或 documented fallback 行为，而不是意外的明文查询。
6. 对于 ECH，使用受控的 ECH-enabled host，并检查 client/server diagnostics，确认 **inner** ClientHello 已被接受。仅提供 HTTPS record 并不能证明 ECH 成功。
7. 在网络变化、captive portals、browser updates 和 VPN reconnects 后重复测试。记录哪个 component 负责 DNS/ECH，以免后续管理员创建 bypass。

## Mixnets

Nym 或 Katzenpost 等 Mixnets 添加固定大小的数据包、延迟、重新排序和 cover traffic，以抵抗 timing correlation。这些特性会带来延迟和带宽成本，并且独立的部署规模证据有限。应将当前 consumer mixnets 视为**新兴/高延迟选项**，而不是 Tor/VPN 的更快或有保证的替代品。<sup>[[17]](#references)</sup>

### 评估工作流

1. 确认受维护的 client 和确切支持的 application；不要通过 undocumented proxy 强制任意 browser/system traffic。
2. 阅读当前 threat model，了解 entry、mix nodes、gateway、destination 和 collusion assumptions。
3. 从官方签名来源安装到独立的 test compartment 中，并仅使用 benign owned endpoint。
4. 测量 delivery latency、message-size limits、reliability、retransmission，以及 gateway 不可用时的行为。
5. 检查本地流量和 owned endpoint，以确认预期路径和 source。检查 replies 是否使用相同的 privacy design。
6. 测试 shutdown/failure：application 不得静默回退到 direct Internet access。
7. 不要仅为提速而禁用 cover traffic、减少 delays 或选择 unusual fixed routes；这些变化可能使声明的 anonymity model 失效。
8. 在特定 deployment、独立分析和操作可靠性达到相应后果等级之前，保持其 experimental 状态。

## 网络 preflight 清单

- [ ] Authorization 覆盖 access network、target、日期和 source infrastructure。
- [ ] Endpoint 不包含无关身份或活动中的 sync sessions。
- [ ] IPv4、IPv6、DNS 和 reconnect 行为符合计划。
- [ ] Destination 只能看到预期的 egress。
- [ ] Captive portal 和 hotspot 行为已在无敏感流量的情况下测试。
- [ ] 本地 sharing/discovery 和自动加入网络已禁用。
- [ ] Observer table 和剩余的 traffic-correlation risk 已被接受。
- [ ] Provider policy、retention 和 emergency contact 均为最新。

有关 split-knowledge relays、route-enforced workloads、pluggable transports、onion services、I2P 和 disposable remote browsers，请继续阅读 [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)。

## References

- [1] [EFF — 选择适合你的 VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — 设备安全指南：Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor 提供的隐私和匿名保护](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor 简介](https://spec.torproject.org/intro/)
- [5] [Tor Project — 在其他浏览器中使用 Tor](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser 中的 Plugins 和 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — 解除 Tor 阻断](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — 将 Tor Browser 与 VPN 配合使用](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — 公共 Wi-Fi 网络安全吗？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple 设备的 Wi-Fi 隐私](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — 实现 MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — 安全 Privileged Access Workstations 原则](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — 强制 SIM 注册：政策和监管视角](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators 建议](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
