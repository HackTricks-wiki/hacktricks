# 网络隐私与 Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

网络隐私是一项路由决策，而不是完整的身份保护。选择路径时，应先明确哪些观察者不应能够关联 **source**、**destination**、**content** 和 **timing**。

对于每种 access-path family 的标准化清单——`Pros`、`Cons`、逐步的 `Procedure` 和 `Detection`——请从 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) 开始。本页面扩展介绍常见的可部署选项。

## 每类观察者通常可以看到什么

| 路径 | 本地网络 / ISP | 中间方 | 目标 | 主要限制 | 相对速度 |
|---|---|---|---|---|---|
| 直接 HTTPS | Source、destination 元数据、timing/流量量 | Hosting/CDN 可看到连接 | Source IP、浏览器/应用数据 | 不提供 source-IP 隐私 | 最快 |
| Commercial VPN | Source 已连接到 VPN；通常看不到 destination 元数据 | VPN 可看到 source 和 destination 元数据 | VPN egress IP | 一个 provider 成为关联点 | 通常较快 |
| Self-hosted VPN/VPS | Source 已连接到 VPS | Host/账户/支付/控制面板日志 | VPS egress IP | 很容易归因到租用的服务器/账户 | 通常较快 |
| Tor Browser | Source 已连接到 Tor/bridge；timing/流量量 | 每个 relay 只能看到有限部分 | Tor exit、浏览器数据 | 较慢；存在账户/endpoint/关联风险 | 中等/较慢 |
| Tails/Whonix | 类似 Tor 路径，但具有更强的路由边界 | 具有相同的 Tor 限制 | Tor exit/应用数据 | 操作失误以及主机/硬件仍会暴露信息 | 中等/较慢 |
| 公共访客 Wi-Fi + HTTPS | 场所可看到本地设备/timing 和目标 | 场所 ISP 可看到元数据 | Guest public IP | 存在实体/captive-portal/设备关联 | 快/不稳定 |
| Cellular hotspot | Carrier 可看到订户/设备/位置及目标 | 若使用 VPN/Tor，则可看到相应信息 | Carrier、VPN 或 Tor egress IP | 移动订阅和位置是持久标识符 | 快/不稳定 |
| Mixnet | Access 可看到 mixnet 的使用情况、timing/流量量 | 多个 mixing node | Gateway/egress | 生态仍在发展；存在延迟和带宽成本 | 最慢 |

HTTPS 可保护传输中的 content，但不能保护所有元数据。EFF 指出，即使页面路径、凭据和消息已加密，域名、时间和流量大小仍可能对中间方可见。<sup>[[1]](#references)</sup>

## VPN：快速隐私与集中的信任

VPN 可用于向 access ISP 隐藏 destination 元数据、保护不受信任网络中的第一跳、提供稳定的 engagement egress 地址，或访问私有网络。它**不会**使用户匿名。VPN 可看到 source 连接并观察 destination 元数据；账户、cookies、GPS、fingerprints 和支付信息仍然存在。<sup>[[1]](#references)</sup>

### Provider 评估清单

1. **所有权和司法管辖区：**确定法律实体、母公司、运营国家、基础设施分包商以及适用的法律程序。
2. **收集的数据：**区分账户/账单、source IP、连接时间戳、带宽、崩溃 telemetry、DNS 查询和 destination 日志。“不记录浏览日志”不代表“不收集数据”。
3. **保留和删除：**确认具体的保留时长，以及备份、反欺诈系统和处理方是否遵循相同的时间表。
4. **证据：**优先选择公开审计（包含范围、日期、发现和修复情况）、可复现/open clients、透明度报告以及记录在案的事件。
5. **协议和客户端：**使用受维护的 WireGuard、OpenVPN 或其他经过审查的协议；启用自动更新；确认 DNS 和 IPv6 处理、kill switch 以及各平台的 leak 测试。
6. **商业模式：**了解免费或补贴服务的资金来源。仅出现在应用商店中，并不能证明其运营可信。
7. **支付适配性：**替代支付方式可以减少向 VPN 暴露的账单信息，但不会消除每次连接时被观察到的 source IP。

### 配置和验证 VPN

1. 从官方来源安装 provider/组织签名的客户端。
2. 除非有文档明确要求绕过 VPN，否则选择 **full tunnel**。Split tunneling 会产生关联和 leak 路径。
3. 启用 fail-closed/always-on 行为，并在重新连接期间阻断流量。
4. 通过 tunnel 发送 DNS，并测试 IPv4 和 IPv6。只有在某协议无法安全通过 tunnel 传输且已接受功能损失时，才禁用该协议。
5. 测试睡眠/唤醒、网络切换、captive-portal 登录、tunnel 崩溃和 hotspot tethering。NCSC 警告，在某些平台上，tethered clients 可能绕过手机的 VPN。<sup>[[2]](#references)</sup>
6. 使用组织控制的测试 endpoint 记录观测到的 IPv4、IPv6、DNS resolver 和连接 timing。不要将敏感 engagement 暴露给随机的“leak test”网站。
7. 在客户端、OS、网络或策略发生变化后重新测试。

### Hostile-LAN routing bypasses

VPN 可能仍显示为“已连接”，但部分数据包会绕过 VPN，因为操作系统会在 VPN 加密数据包**之前**选择路由。TunnelCrack 展示了利用常见路由例外的两种方式：**LocalNet** 使 Internet destination 看起来位于直接连接的子网中，而 **ServerIP** 则伪造 VPN-gateway 解析结果，使目标地址继承 VPN transport 所需的明文网络例外。这些属于客户端/路由故障，并不是对 WireGuard、OpenVPN、IPsec 或 TLS 的破解；HTTPS payload 仍保持端到端加密，但本地观察者可以恢复 destination/timing 元数据以及任何明文协议数据。<sup>[[18]](#references)</sup>

TunnelVision 通过 DHCP option 121 使用相同的预加密原语。恶意或遭入侵的 DHCP server 可以安装一条比 VPN 的 catch-all route 更具体的 classless route，从而为任意主机或范围选择物理接口。VPN control channel 可以保持活动状态，因此仅在 tunnel 断开时触发的 kill switch 可能不会启动，而单一的公共“IP leak”检查也可能无法发现选择性 bypass。<sup>[[19]](#references)</sup>

只允许物理接口上的 DHCP 和经过身份验证的 VPN transport 通过的 packet-filter kill switch 应能将其转变为 fail-closed 行为，但有针对性的 route injection 仍可能产生选择性拒绝服务的 side channel。对于高影响的 Linux workloads，优先使用更强的 [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload)，其中 application namespace 没有物理接口或明文网络默认路由。<sup>[[19]](#references)</sup>

#### Owned-lab verification

在自有 AP、DHCP server、VPN endpoint 和 destination 上测试确切的客户端/OS/版本；由于路由和 packet-filter 实现具有平台特定性，针对整个产品的结论很快会过时。在 endpoint 本身和测试 server 上同时进行 capture——仅凭 egress-IP 网站无法证明每个 destination 都遵循 tunnel。<sup>[[18]](#references)[[19]](#references)</sup>

1. 连接 VPN，记录 VPN-server 地址，并保存所有 IPv4/IPv6 routing table 和 policy-routing rule。在 Windows 上使用 `route print`；在 macOS 上使用 `netstat -rn`；在 Linux 上使用下面的命令。
2. 查询若干自有 destination IP 的 selected route。除文档明确说明的 VPN transport endpoint 外，next hop/interface 必须是 tunnel。
3. 对于 TunnelVision，在受控 DHCP 网络上续租，并且**仅针对自有测试 destination**安装 option 121 route。通过标准是流量仍经 tunnel 传输或被阻断——绝不能作为 destination traffic 从物理接口发出。
4. 对于 LocalNet，为客户端分配一个仅用于实验室的公共文档子网，例如 `203.0.113.0/24`，并将自有测试 destination 放入其中。验证启用 LAN access 不会导致 Internet 类 destination 绕过 tunnel。
5. 对于 ServerIP，在 VPN 连接前，让受控 DNS 将自有 VPN hostname 解析为自有测试 destination，同时让实验室 gateway 将 VPN transport 转发到真正的自有 VPN endpoint。客户端不得将发往伪造地址的无关 application traffic 排除在 tunnel 外。
6. 在“local network access”启用和禁用两种情况下重复测试，并覆盖重新连接、睡眠/唤醒、网络切换以及 VPN-process crash。分别测试 IPv4、IPv6 和 DNS。
7. 检查物理接口上的 capture。其中应包含 DHCP 和发往 VPN server 的加密数据包，而不应包含直接发往自有测试 destination 的数据包。同时确认被拒绝的 bypass 不会在用户提示或 connectivity repair 后悄悄恢复。
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser：更强的 Web 不可关联性

Tor 通过多个 relay 建立 circuit，因此通常没有任何单个 relay 同时知道源和目的地。目的地看到的是 Tor exit，而不是用户的 IP；本地网络通常看到的是 Tor 连接。<sup>[[3]](#references)</sup> Tor 针对低延迟 TCP 应用而设计，因此速度较慢，并且无法保证防御能够关联两端流量的对手。<sup>[[4]](#references)</sup>

### 安全的 Tor Browser 工作流程

1. 仅从 Tor Project 或官方 mirror 下载 Tor Browser，并在可能时验证签名。
2. 使用 **Tor Browser**，不要使用指向 Tor SOCKS 端口的普通浏览器。普通浏览器可能泄露 DNS/WebRTC 和可识别状态。<sup>[[5]](#references)</sup>
3. 保持默认的大小、字体、扩展和隐私设置。额外的 add-ons 可能使浏览器更加独特。<sup>[[6]](#references)</sup>
4. 在可以接受更高程度的功能失效时，选择 **Safer** 或 **Safest** 安全级别。
5. 当 direct Tor 被阻断，或普通 relay IP 会造成不可接受的本地可见性时，使用 bridge。Bridge 可降低被轻易识别的可能性，但无法消除 traffic analysis。<sup>[[7]](#references)</sup>
6. 不要登录可识别身份的账户、提供可识别身份的信息，或在外部联网应用中打开下载的 active documents。
7. 为每个身份使用单独的 session/context。“New circuit”并不等同于擦除浏览器/应用身份；应适当使用 **New Identity** 或重启隔离环境。
8. 优先使用经过身份验证的 HTTPS 或经过身份验证的 onion service。Tor exit 可以观察未加密的 HTTP 流量。

### Tor 加 VPN

组合使用并不会自动更安全。Tor 之前使用 VPN，可能会向 ISP 隐藏 direct Tor relay 连接，但 VPN 可以看到源；VPN 之前使用 Tor，会让 VPN 稳定地看到 Tor 之后的活动，并可能缩小 anonymity set。配置错误可能引入 leak。Tor Project 建议仅在高级且明确的 threat model 下使用此类组合。<sup>[[8]](#references)</sup>

## 公共和访客 Wi-Fi

现代 HTTPS 意味着被动监听的附近人员通常无法读取正确加密的 Web 内容，但访客 Wi-Fi 并不提供 anonymity。场所可以记录关联时间、设备标识符、captive portal 数据、目的地和 DHCP 详情；摄像头、购买记录、交通记录和实体观察都可能识别用户。同名仿冒 hotspot 还可能捕获 portal 凭据或操纵未加密流量。<sup>[[9]](#references)</sup>

### 合法的访客网络工作流程

1. 仅使用提供给访客的网络，或使用所有者明确授权的网络。向工作人员询问确切的 SSID 和 portal 流程。
2. 在到达前更新 endpoint 和 travel router。禁用文件/打印机共享、入站发现、自动加入和已记忆网络探测。
3. 启用操作系统的私有/随机化 Wi-Fi 地址。当前 Apple 系统可以在开放/弱安全网络上使用轮换地址；现代 Android 的随机化通常按 SSID 持久化。此举只能减少一个本地标识符。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. 优先在特权工作站和访客网络之间使用组织控制的 travel router 或低信任 bridge device。这样可以集中管理 firewall/VPN 策略，但不会将 router 对场所隐藏。<sup>[[12]](#references)</sup>
5. 仅通过指定的低信任 device/browser 完成 captive portal。对于所谓 anonymous context，绝不要输入个人凭据或重复使用的凭据。建立连接后关闭 portal browser。
6. 在敏感活动前启动 full-tunnel VPN 或 Tor，并确认 fail-closed 行为。
7. 使用后忘记该网络，并查看 portal 账户/数据保留政策。

{% hint style="danger" %}
破解邻居的 Wi-Fi、绕过 portal、使用泄露的访客凭据、克隆其他访客的访问权限，或在咖啡馆隐藏 Raspberry Pi，都是未经授权的活动，而不是隐私技术。安全的等价方案是合法的访客网络、经客户批准的站点，或经物业所有者书面同意后放置并回收的、具有文档记录的 drop node。
{% endhint %}

## Travel routers

Travel router 可以将工作站与恶意本地广播隔离，强制执行 firewall，提供一致的内部 SSID，并自动重新连接 VPN。它**不是** anonymous：上游可以看到其无线电身份和流量时序，而其 VPN provider 可以看到 tunnel source。

- 使用受支持的 OpenWrt/vendor firmware，并移除未使用的服务。
- 通过 Ethernet 或具有唯一密码的专用 management SSID 进行管理。
- 禁用 WAN-side administration、UPnP、WPS、文件共享和未经请求的入站流量。
- 仅在受支持且获准的情况下使用随机化/私有 WAN MAC。
- 在 router 上强制执行 VPN 策略，包括 DNS 和 IPv6，并在 tunnel 失败时阻止 egress。
- 不要假设 phone hotspot 会通过手机的 VPN 为 tethered devices 建立 tunnel；应进行测试。

## Cellular、SIM 和 eSIM

Cellular 很方便，但并不 anonymous。运营商会维护 subscriber/device identifiers，并根据网络接入信息推导位置；eSIM 仍然是移动订阅。Prepaid 并不可靠地意味着未注册——要求因国家而异，也会发生变化。<sup>[[13]](#references)</sup>

在实际操作中：

- 使用单独且受支持的 device，以减少个人数据暴露，而不是创建虚构的 subscriber。
- 如果共址属于 threat model，不要让“单独的”device 始终与个人手机一起携带。
- 禁用未使用的 cellular、Wi-Fi、Bluetooth 和 location access；关机相比 UI 开关能提供更强的无线电边界。
- 将敏感流量置于获准的 VPN/Tor 路径中，同时应认识到 carrier 仍然知道订阅/设备位置和 tunnel endpoint。
- 向国家监管机构或当地法律顾问确认当前的注册和保留规则；不要依赖网上的“anonymous SIM 国家”列表。

## DNS 和 TLS metadata

- **DoH/DoT/DoQ** 会加密 client 与 resolver 之间的 DNS，防止简单的本地读取或修改，但 resolver 仍然可以看到查询和传输标识符。它们改变的是信任对象；并不提供 anonymity。<sup>[[14]](#references)</sup>
- **ODoH** 会加入 proxy，使 resolver 无需获知 client IP，前提是 proxy 和 target 不串通。Traffic analysis 明确不在其范围内。<sup>[[15]](#references)</sup>
- 当 client、DNS 和 server 都支持时，**TLS Encrypted Client Hello (ECH)** 可以保护 TLS handshake 中的内部 server name。Destination IP、时序、流量大小和 endpoint 仍然可见。<sup>[[16]](#references)</sup>
- 在正确配置的 VPN 或 Tor 环境中，DNS 应遵循该环境支持的路由。添加单独的 resolver 可能创建新的 observer 或 fingerprint。

### Encrypted-DNS/ECH 验证工作流程

1. 确定 DNS 由 VPN/Tor 环境、操作系统还是应用控制。在**一个**预期层中进行配置，而不是堆叠互不相关的 resolver。
2. 根据 resolver 发布的隐私/保留政策进行选择，并在平台支持时启用 strict encrypted mode。机会式 fallback 可能会静默返回 plaintext。
3. 查询你控制的 authoritative test zone 下的唯一子域名；确认 authoritative log 看到的是预期的 recursive resolver。
4. 在获得授权的情况下，仅捕获测试 device 的流量。确认接入网络无法读取 plaintext DNS，同时认识到它可以看到 encrypted resolver/tunnel endpoint。
5. 测试被阻断/不可达的 encrypted resolver。通过条件应是选定的 fail-closed 或文档化 fallback 行为，而不是意外的 clear query。
6. 对于 ECH，使用受控的 ECH-enabled host，并检查 client/server diagnostics，以确认 **inner** ClientHello 已被接受。仅提供 HTTPS record 并不能证明 ECH 成功。
7. 在网络变化、captive portal、浏览器更新和 VPN 重连后重复测试。记录哪个组件负责 DNS/ECH，以避免后续管理员创建 bypass。

## Mixnets

Nym 或 Katzenpost 等 Mixnets 会加入固定大小的数据包、延迟、重新排序和 cover traffic，以抵抗时序关联。这些属性会带来延迟和带宽成本，而独立的部署规模证据有限。应将当前的 consumer mixnets 视为**新兴/高延迟选项**，而不是 Tor/VPN 的更快或有保证的替代品。<sup>[[17]](#references)</sup>

### 评估工作流程

1. 识别受维护的 client 及其确切支持的应用；不要通过未记录的 proxy 强行传输任意浏览器/系统流量。
2. 阅读当前的 threat model，了解 entry、mix nodes、gateway、destination 和 collusion 假设。
3. 从官方签名 source 安装到单独的测试 compartment 中，并且只使用无害的自有 endpoint。
4. 测量交付延迟、消息大小限制、可靠性、重传，以及 gateway 不可用时的行为。
5. 检查本地流量和自有 endpoint，以确认预期路径和 source。检查回复是否使用相同的隐私设计。
6. 测试 shutdown/failure：应用不得静默 fallback 到 direct Internet access。
7. 不要仅为提高速度而禁用 cover traffic、减少延迟或选择不常见的固定路由；这些更改可能使声明的 anonymity model 失效。
8. 在特定部署、独立分析和运行可靠性达到相应后果等级之前，将其保持为实验性方案。

## Network preflight checklist

- [ ] Authorization 覆盖 access network、target、日期和 source infrastructure。
- [ ] Endpoint 不包含无关身份或活动中的 sync sessions。
- [ ] IPv4、IPv6、DNS 和 reconnect 行为符合计划。
- [ ] 受控的 DHCP/local-subnet route injection 无法将测试流量移至物理接口。
- [ ] Destination 只能看到预期的 egress。
- [ ] Captive portal 和 hotspot 行为已在不使用敏感流量的情况下完成测试。
- [ ] 本地共享/发现和自动加入网络功能已禁用。
- [ ] Observer table 和剩余的 traffic-correlation 风险已获接受。
- [ ] Provider policy、保留策略和 emergency contact 均为最新。

关于 split-knowledge relays、route-enforced workloads、pluggable transports、onion services、I2P 和 disposable remote browsers，请继续阅读 [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)。



## References

- [1] [EFF — 选择适合你的 VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — 设备安全指南：Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor 提供的隐私和匿名保护](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor 简介](https://spec.torproject.org/intro/)
- [5] [Tor Project — 将 Tor 与其他浏览器结合使用](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser 中的 Plugins 和 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — 解除 Tor 阻断](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — 将 Tor Browser 与 VPN 结合使用](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — 公共 Wi-Fi 网络安全吗？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple 设备的 Wi-Fi 隐私](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — 实现 MAC 随机化](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — 安全特权访问工作站原则](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — 强制 SIM 注册：政策和监管视角](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators 的建议](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue 等 — 绕过 Tunnels：滥用路由表泄露 VPN Client 流量](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision：攻击者如何解除基于路由的 VPN 的隐藏以造成完全 VPN Leak](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
