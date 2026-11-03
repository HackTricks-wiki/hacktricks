# 网络隐私与匿名连接

{{#include ../banners/hacktricks-training.md}}

网络隐私是一项路由选择，而不是完整的身份保护。选择路径时，应考虑哪些观察者不应将**源、目的地、内容和时序**关联起来。

如需查看规范化清单——每种访问路径类别的 `Pros`、`Cons`、分步 `Procedure` 和 `Detection`——请从[匿名互联网访问技术目录](anonymous-internet-access-techniques.md)开始。本页将详细介绍常见且可部署的选项。

## 各观察者通常能看到什么

| 路径 | 本地网络 / ISP | 中间方 | 目的地 | 主要限制 | 相对速度 |
|---|---|---|---|---|---|
| 直接 HTTPS | 源、目的地元数据、时序/流量 | 托管商/CDN 可看到连接 | 源 IP、浏览器/应用数据 | 无源 IP 隐私保护 | 最快 |
| 商业 VPN | 源连接到 VPN；通常看不到目的地元数据 | VPN 可看到源和目的地元数据 | VPN 出口 IP | 一个服务商会成为关联点 | 通常较快 |
| 自托管 VPN/VPS | 源连接到 VPS | 主机/账户/支付/控制平面日志 | VPS 出口 IP | 容易被归因到租用的服务器/账户 | 通常较快 |
| Tor Browser | 源连接到 Tor/bridge；时序/流量 | 各中继只能看到有限信息 | Tor 出口、浏览器数据 | 速度较慢；有账户/终端/关联风险 | 中等/较慢 |
| Tails/Whonix | 类似的 Tor 路径，但路由边界更严格 | 同样受 Tor 的限制 | Tor 出口/应用数据 | 操作失误以及主机/硬件仍会带来风险 | 中等/较慢 |
| 公共访客 Wi-Fi + HTTPS | 场所可看到本地设备/时序和目的地 | 场所的 ISP 可看到元数据 | 访客公共 IP | 存在实体位置/强制门户/设备关联风险 | 快/不定 |
| 蜂窝热点 | 运营商可看到用户/设备/位置和目的地 | 若使用 VPN/Tor，则为 VPN/Tor | 运营商、VPN 或 Tor 出口 IP | 移动订阅和位置是持久标识符 | 快/不定 |
| Mixnet | 接入方可看到 mixnet 使用情况；时序/流量 | 多个混合节点 | 网关/出口 | 生态仍在发展；延迟和带宽成本较高 | 最慢 |

HTTPS 可保护传输中的内容，但无法隐藏所有元数据。EFF 指出，即使网页路径、凭据和消息都已加密，中间方仍可能看到域名、时间和流量大小。<sup>[[1]](#references)</sup>

加密覆盖网络并不自动等同于匿名网络：Yggdrasil 的直接对等节点可以看到彼此的 IP 地址。<sup>[[20]](#references)</sup>它的[用户空间转发和 SOCKS 传输](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack)是一种隧道选项，而不是源匿名层。<sup>[[20]](#references)[[21]](#references)</sup>

## VPN：快速隐私保护，但信任集中

VPN 可用于向接入 ISP 隐藏目的地元数据、保护不可信网络上的第一跳、提供稳定的项目出口地址，或访问私有网络。但它**不会**让用户匿名。VPN 可看到源连接和目的地元数据；账户、cookies、GPS、指纹和支付信息仍然存在。<sup>[[1]](#references)</sup>

### 服务商评估清单

1. **所有权和司法管辖区：**确认法律实体、母公司、运营国家、基础设施分包商，以及适用的法律程序。
2. **收集的数据：**区分账户/账单信息、源 IP、连接时间戳、带宽、崩溃遥测、DNS 查询和目的地日志。“不记录浏览日志”不代表“没有数据”。
3. **保留和删除：**查明具体保留时长，以及备份、反欺诈系统和数据处理商是否遵循相同的时间表。
4. **证据：**优先选择公开审计（注明范围、日期、发现和修复措施）、可复现/开源客户端、透明度报告和有记录的安全事件。
5. **协议和客户端：**使用维护中的 WireGuard、OpenVPN 或其他经过审查的协议；确认有自动更新、DNS 和 IPv6 处理、kill switch，以及针对各平台的 leak 测试。
6. **商业模式：**了解免费或补贴服务的资金来源。仅仅上架应用商店，并不能证明其运营值得信任。
7. **支付方式是否合适：**替代支付方式可以减少向 VPN 服务商披露的账单信息，但无法抹去每次连接时服务商看到的源 IP。

### 配置并验证 VPN

1. 从官方来源安装服务商/组织签名的客户端。
2. 除非有已记录的路由必须绕过隧道，否则选择 **full tunnel**。Split tunneling 会产生关联和 leak 路径。
3. 启用 fail-closed/always-on 行为，并在重新连接期间阻止流量。
4. 通过隧道发送 DNS，并分别测试 IPv4 和 IPv6。只有在协议无法安全地通过隧道传输，且你接受由此造成的功能损失时，才禁用该协议。
5. 测试睡眠/唤醒、网络切换、强制门户登录、隧道崩溃和热点共享。NCSC 警告称，在某些平台上，通过手机共享网络的客户端可能绕过手机 VPN。<sup>[[2]](#references)</sup>
6. 使用组织控制的测试端点，记录观测到的 IPv4、IPv6、DNS 解析器和连接时序。不要将敏感项目暴露给随机的“leak 测试”网站。
7. 客户端、操作系统、网络或策略发生变化后，重新测试。

### 恶意局域网环境下的路由绕过

VPN 可能仍显示为“已连接”，但部分数据包会绕过隧道，因为操作系统会在 VPN 加密数据包**之前**选择路由。TunnelCrack 展示了利用常见路由例外的两种方式：**LocalNet** 使互联网目的地看起来像是位于直连子网内；**ServerIP** 则伪造 VPN 网关的解析结果，使目标地址继承 VPN 传输所需的明文网络例外。这些问题出在客户端/路由机制，并非 WireGuard、OpenVPN、IPsec 或 TLS 被破解；HTTPS 负载仍保持端到端加密，但本地观察者可以获取目的地/时序元数据以及任何明文协议数据。<sup>[[18]](#references)</sup>

TunnelVision 通过 DHCP 选项 121 使用了相同的加密前原语。恶意或遭入侵的 DHCP 服务器可以安装无类路由，其特异性高于 VPN 的兜底路由，从而为任意主机或网段选择物理接口。VPN 控制通道可能仍保持连接，因此仅在隧道断开时触发的 kill switch 可能不会启动；单次公共“IP leak”检查也可能无法发现选择性绕过。<sup>[[19]](#references)</sup>

在物理接口上仅允许 DHCP 和经过身份验证的 VPN 传输的包过滤 kill switch，应能将这种情况转为 fail-closed 行为；但有针对性的路由注入仍可能产生选择性拒绝服务侧信道。对于高影响的 Linux 工作负载，建议采用更强的[按工作负载强制路由的 network-namespace 模式](advanced-network-privacy-architectures.md#enforce-the-route-per-workload)，让应用命名空间没有物理接口，也没有明文网络默认路由。<sup>[[19]](#references)</sup>

#### 自有实验室验证

在自有 AP、DHCP 服务器、VPN 端点和目的地上，测试确切的客户端/操作系统/版本；产品整体声明很快就会过时，因为路由和包过滤的实现因平台而异。除了测试服务器，也要在端点本身抓包——仅靠一个出口 IP 网站，无法证明所有目的地流量都经过隧道。<sup>[[18]](#references)[[19]](#references)</sup>

1. 连接 VPN，记录 VPN 服务器地址，并保存所有 IPv4/IPv6 路由表和策略路由规则。在 Windows 上使用 `route print`；在 macOS 上使用 `netstat -rn`；在 Linux 上使用下文所列命令。
2. 查询到多个自有目的地 IP 的选定路由。除有记录的 VPN 传输端点外，下一跳/接口必须是隧道。
3. 对于 TunnelVision，在受控 DHCP 网络上续租，并且**仅针对自有测试目的地**安装选项 121 路由。通过测试意味着流量仍经隧道传输或被阻止，而不会作为发往目的地的流量从物理接口发出。
4. 对于 LocalNet，将客户端分配到仅用于实验室的公共文档网段，例如 `203.0.113.0/24`，并将自有测试目的地放入该网段。验证启用 LAN 访问不会导致互联网类目的地绕过隧道。
5. 对于 ServerIP，在 VPN 连接前，通过受控 DNS 将自有 VPN 主机名解析到自有测试目的地，同时让实验室网关将 VPN 传输转发到真正的自有 VPN 端点。客户端不得将发往伪造地址的无关应用流量设为例外。
6. 在“local network access”启用和禁用两种情况下重复测试，并在重新连接、睡眠/唤醒、网络切换和 VPN 进程崩溃后再次测试。分别测试 IPv4、IPv6 和 DNS。
7. 检查物理接口抓包。抓包中应包含 DHCP 和发往 VPN 服务器的加密数据包，而不应有直接发往自有测试目的地的数据包。还要确认，被拒绝的绕过流量不会在用户提示或网络修复后悄然回退到明文连接。

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

Tor 会通过多个中继建立 circuit，因此通常没有任何单个中继同时知道来源和目的地。目的地看到的是 Tor exit，而不是用户的 IP；本地网络通常看到的是 Tor 连接。<sup>[[3]](#references)</sup> Tor 是为低延迟 TCP 应用设计的，因此速度较慢，并且无法保证防御能够关联通信两端的对手。<sup>[[4]](#references)</sup>

### 安全使用 Tor Browser 的工作流程

1. 仅从 Tor Project 或官方镜像下载 Tor Browser，并尽可能验证签名。
2. 使用 **Tor Browser**，不要使用指向 Tor SOCKS 端口的普通浏览器。普通浏览器可能泄露 DNS/WebRTC 信息和可识别身份的状态。<sup>[[5]](#references)</sup>
3. 保留默认的窗口大小、字体、扩展和隐私设置。额外的附加组件可能让浏览器更容易被识别。<sup>[[6]](#references)</sup>
4. 在可以接受由此导致的网站功能异常时，选择 **Safer** 或 **Safest** 安全级别。
5. 直接使用 Tor 受到阻止，或普通中继 IP 会造成不可接受的本地可见性时，使用 bridge。bridge 可以降低被轻易识别的概率，但无法消除流量分析。<sup>[[7]](#references)</sup>
6. 不要登录可识别身份的账户、提供可识别身份的信息，也不要在联网的外部应用程序中打开已下载的活动文档。
7. 为每个身份使用单独的会话/上下文。“New circuit”不等同于清除浏览器/应用程序身份；请酌情使用 **New Identity** 或重启隔离环境。
8. 优先使用经过身份验证的 HTTPS 或经过身份验证的 onion service。Tor exit 可以观察未加密的 HTTP 流量。

### Tor 加 VPN

将两者结合使用并不一定更安全。先连接 VPN 再使用 Tor，可能会让 ISP 看不到直接连接 Tor relay 的行为，但 VPN 会看到来源；先使用 Tor 再连接 VPN，会让 VPN 稳定地看到 Tor 之后的活动，并可能缩小匿名集。配置错误可能导致 leak。Tor Project 仅建议在高级且明确的威胁模型下使用此类组合。<sup>[[8]](#references)</sup>

## 公共和访客 Wi-Fi

现代 HTTPS 意味着被动监听的附近用户通常无法读取正确加密的 Web 内容，但访客 Wi-Fi 不等于匿名。场所可以记录关联时间、设备标识符、captive portal 数据、目的地和 DHCP 详情；摄像头、购物记录、交通信息和现场观察也可能识别用户。名称相似的假热点还可能窃取 portal 凭据或篡改未加密流量。<sup>[[9]](#references)</sup>

### 合法使用访客网络的工作流程

1. 仅使用面向访客开放的网络，或已获得所有者明确授权的网络。向工作人员确认准确的 SSID 和 portal 流程。
2. 到达前更新终端和 travel router。禁用文件/打印机共享、入站发现、自动加入和已保存网络探测。
3. 启用操作系统的私有/随机 Wi-Fi 地址。当前 Apple 系统可在开放/弱安全网络上使用轮换地址；现代 Android 通常会按 SSID 使用持久化随机地址。这只能减少一个本地标识符。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. 优先在具有较高权限的工作站和访客网络之间，使用由组织控制的 travel router 或低信任 bridge 设备。这能集中管理防火墙/VPN 策略，但不会让场所看不到 router。<sup>[[12]](#references)</sup>
5. 仅通过指定的低信任设备/浏览器完成 captive portal 验证。不要在所谓的匿名上下文中输入个人凭据或重复使用的凭据。建立连接后关闭 portal 浏览器。
6. 在进行敏感活动前启动全隧道 VPN 或 Tor，并确认故障时会阻止流量外泄。
7. 使用后忘记该网络，并查看 portal 账户/数据保留政策。

{% hint style="danger" %}
破解邻居的 Wi-Fi、绕过 portal、使用泄露的访客凭据、克隆其他访客的访问权限，或将 Raspberry Pi 藏在咖啡馆中，都是未经授权的活动，并非隐私技术。安全的替代方案是合法的访客网络、客户批准的现场，或在获得物业所有者书面同意后部署并回收的、有文档记录的 drop node。
{% endhint %}

## Travel router

travel router 可以将工作站与不可信的本地广播隔离、强制执行防火墙策略、提供一致的内部 SSID，并自动重新连接 VPN。它**不**能实现匿名：上游网络可以看到它的无线电身份和流量时间；VPN 提供商可以看到隧道来源。

- 使用受支持的 OpenWrt/厂商固件，并移除未使用的服务。
- 通过 Ethernet 或使用独特密码的专用管理 SSID 进行管理。
- 禁用 WAN 侧管理、UPnP、WPS、文件共享和未经请求的入站流量。
- 仅在受支持且获准的情况下使用随机/私有 WAN MAC。
- 在 router 上强制执行 VPN 策略，包括 DNS 和 IPv6，并在隧道故障时阻止出站流量。
- 不要假设手机热点会让连接到手机的设备通过手机的 VPN 建立隧道；请进行测试。

## 蜂窝网络、SIM 和 eSIM

蜂窝网络很方便，但并不匿名。运营商会保留订户/设备标识符，以及根据网络接入情况推断的位置；eSIM 仍然是移动订阅。预付费并不一定意味着无需注册——不同国家的要求各不相同，也会发生变化。<sup>[[13]](#references)</sup>

操作建议：

- 使用单独且受支持的设备来减少个人数据暴露，而不是伪造订户身份。
- 如果威胁模型包含共址分析，不要在随身携带个人手机的同时持续携带一台“独立”设备。
- 禁用未使用的蜂窝网络、Wi-Fi、Bluetooth 和位置访问；关机比通过 UI 开关更能切断无线电连接。
- 通过获准的 VPN/Tor 路径传输敏感流量，同时意识到运营商仍知道订阅/设备的位置和隧道端点。
- 向国家监管机构或当地法律顾问核实当前的注册和数据保留规定；不要依赖网上的“匿名 SIM 国家”列表。

## DNS 和 TLS 元数据

- **DoH/DoT/DoQ** 会加密客户端与解析器之间的 DNS 通信，防止简单的本地读取或篡改，但解析器仍能看到查询和传输标识符。它们转移了信任，但不提供匿名性。<sup>[[14]](#references)</sup>
- **ODoH** 会加入一个代理，使解析器无需获知客户端 IP；前提是代理和目标不会串通。流量分析明确不在其保护范围内。<sup>[[15]](#references)</sup>
- 当客户端、DNS 和服务器都支持 **TLS Encrypted Client Hello (ECH)** 时，它可以保护 TLS 握手中的内部服务器名称。目的地 IP、时间、流量大小和端点仍然可见。<sup>[[16]](#references)</sup>
- 在正确配置的 VPN 或 Tor 环境中，DNS 应通过该环境支持的路径传输。添加单独的解析器可能会引入新的观察者或指纹。

### 加密 DNS/ECH 验证工作流程

1. 确定 DNS 由 VPN/Tor 环境、操作系统还是应用程序控制。在**一个**预期层配置，而不是叠加互不相关的解析器。
2. 根据解析器公布的隐私/数据保留政策进行选择，并在平台支持时启用严格的加密模式。机会式回退可能会悄然改用明文。
3. 查询你控制的权威测试区域下的唯一子域名；确认权威日志中看到的是预期的递归解析器。
4. 在获得授权的情况下，仅捕获测试设备的流量。确认接入网络无法读取明文 DNS，同时认识到它仍能看到加密解析器/隧道端点。
5. 测试加密解析器被阻止或无法访问时的情况。通过条件应是所选的故障时阻断行为或已记录的回退行为，而不是意外发送明文查询。
6. 对于 ECH，使用启用了 ECH 的受控主机，并检查客户端/服务器诊断信息，确认**内部** ClientHello 已被接受。仅提供 HTTPS 记录并不能证明 ECH 成功。
7. 在网络变更、使用 captive portal、浏览器更新和 VPN 重新连接后重复测试。记录由哪个组件负责 DNS/ECH，避免后续管理员意外创建绕过路径。

## Mixnet

Nym 或 Katzenpost 等 mixnet 会通过固定大小的数据包、延迟、重新排序和掩护流量来抵御时间关联。这些特性会增加延迟并消耗带宽，而且大规模独立部署的证据有限。应将当前面向消费者的 mixnet 视为**新兴/高延迟选项**，而非更快或有保障的 Tor/VPN 替代方案。<sup>[[17]](#references)</sup>

### 评估工作流程

1. 找到维护中的客户端，并确认确切支持的应用程序；不要通过未记录的代理强行转发任意浏览器/系统流量。
2. 阅读当前威胁模型，了解入口、mix node、gateway、目的地和串通假设。
3. 从官方签名来源安装到单独的测试隔离环境中，并且只使用无害且由你拥有的端点。
4. 测量传输延迟、消息大小限制、可靠性、重传情况，以及 gateway 不可用时的行为。
5. 检查本地流量和你拥有的端点，以确认预期路径和来源。检查回复是否采用相同的隐私设计。
6. 测试关闭/故障情况：应用程序不得悄然回退到直接访问 Internet。
7. 不要仅为提高速度而禁用掩护流量、缩短延迟或选择不寻常的固定路由；这些变更可能使所声明的匿名模型失效。
8. 在特定部署、独立分析和运行可靠性达到与潜在后果相称的水平之前，继续将其视为实验性方案。

## 网络预检清单

- [ ] 授权范围涵盖接入网络、目标、日期和来源基础设施。
- [ ] 终端不包含无关身份或活动的同步会话。
- [ ] IPv4、IPv6、DNS 和重新连接行为符合计划。
- [ ] 受控的 DHCP/本地子网路由注入无法将测试流量引导至物理接口。
- [ ] 目的地只会看到预期的出口。
- [ ] 已在不传输敏感流量的情况下测试 captive portal 和热点行为。
- [ ] 已禁用本地共享/发现和自动加入网络。
- [ ] 已接受观察者表和剩余的流量关联风险。
- [ ] 提供商政策、数据保留规定和紧急联系人信息均为最新。

有关拆分知识中继、强制路由的工作负载、可插拔传输、onion service、I2P 和一次性远程浏览器，请继续阅读[高级网络隐私架构](advanced-network-privacy-architectures.md)。



## References

- [1] [EFF — 选择适合你的 VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [英国 NCSC — 设备安全指南：虚拟专用网络](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor 提供的隐私和匿名保护](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor 规范 — Tor 简介](https://spec.torproject.org/intro/)
- [5] [Tor Project — 在其他浏览器中使用 Tor](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser 中的插件和附加组件](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — 解除对 Tor 的封锁](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — 将 Tor Browser 与 VPN 配合使用](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC 消费者建议 — 公共 Wi-Fi 网络安全吗？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple 平台安全 — Apple 设备的 Wi-Fi 隐私](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android 开源项目 — 实现 MAC 随机化](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [英国 NCSC — 安全特权访问工作站的原则](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — 强制 SIM 注册：政策和监管观点](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS 隐私服务运营商建议](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — 基于 HTTPS 的无感知 DNS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS 加密客户端问候](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — 威胁模型](https://katzenpost.network/docs/threat_model/)
- [18] [Xue 等 — 绕过隧道：利用路由表泄露 VPN 客户端流量](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision：攻击者如何通过基于路由的 VPN 解密路由，从而造成 VPN leak](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil 常见问题：Yggdrasil 是匿名的吗？](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
