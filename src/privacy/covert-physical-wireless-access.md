# 隐蔽的物理与无线访问

{{#include ../banners/hacktricks-training.md}}

如需详细了解经所有者批准的实施方案，包括出站 rendezvous、电源/上行链路恢复、设备持有的最少 secrets、捕获测试，以及针对可能被发现情况的监控，请参阅 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)。

改变网络路径也可能改变表面上的物理来源。复杂的攻击者可能使用附近被入侵的系统、隐藏设备、公共访问、蜂窝回传或卫星接收器，使目标日志将来源指向远离操作员的位置。这些手段都不会消除物理、无线电或 provider 证据；它们只是将归因转移到不同的数据集中。

## 技术矩阵

| Technique | 表面来源 | 必要条件 | 高价值证据 |
|---|---|---|---|
| Nearby wireless pivot | 目标旁边的企业/住宅 | 被入侵的双宿主主机以及目标 Wi-Fi 访问权限 | 邻近主机的 endpoint 日志、RF 关联记录以及目标 RADIUS/DHCP |
| Public/guest network | 场所 NAT 或 tunnel 出口 | 合法访问或访问控制绕过 | captive portal、DHCP、AP 关联记录、CCTV 以及支付/位置记录 |
| Covert drop device | 目标或附近的有线、Wi-Fi 或 cellular 地址 | 物理放置或投递 | switchport/USB、RF、资产清单、电源以及出站 tunnel telemetry |
| Cellular router/eSIM | carrier NAT 或专用 APN | modem/SIM/subscription | IMEI/IMSI/eSIM、小区扇区、carrier 账户以及流量时序 |
| Satellite-link abuse | 波束覆盖范围内的 subscriber 地址 | 特定于协议和服务的弱点 | RF 定位、上行流、异常 RTT/routing 以及 provider 记录 |

## Nearest-neighbor attack

Volexity 记录了一起 2022 年的 APT28/GRU operation，其中攻击者与最终目标并不在同一地点。攻击者对目标的 public service 进行 password spraying，以获取有效 credentials，但 MFA 阻止了直接的 Internet login。目标的 enterprise Wi-Fi 接受这些 credentials，且不要求 MFA。攻击者入侵了目标附近的组织，找到一台具有无线连接范围的双宿主系统，并利用该系统向目标 Wi-Fi 进行 authentication。Volexity 将其命名为 **Nearest Neighbor Attack**。<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
新颖之处在于这种组合方式。无需任何 operator 前往目标地点，而面向 Internet 的 service 仍可正常执行 MFA。被攻陷的邻近设备提供物理接近条件；窃取的目标 credential 提供逻辑访问权限；目标 Wi-Fi 则成为跨越边界的路径。

### 前提条件与可见性

- 附近必须存在一个可被远程控制的系统，并且该系统具有兼容的 radio，或能够访问另一个附近的 pivot。
- 目标 SSID 必须能覆盖该系统，并且 Wi-Fi 接入必须接受可复用的 credential、certificate 或 device state。
- pivot 通常需要两条同时存在的路径：一条返回 operator，另一条进入目标 WLAN。
- 目标可能会看到新的 station MAC 和合法的 username，但看不到相应的 managed-device certificate、posture、历史记录或预期的建筑进入记录。
- 邻近 endpoint 的日志可能显示 wireless scans、新 profile、interface 变更、tunneling 和 remote-control 活动。

### 检测与防护

1. 企业 Wi-Fi 应要求 certificate-backed EAP-TLS 和 managed-device posture；不要仅因为某个在 Internet 上未通过 MFA 的 password 通过 radio 到达，就认为它足够。
2. 将 RADIUS authentication 与 MDM/NAC identity、历史 station/device binding、AP location、physical-access events 及并发 sessions 进行关联。
3. 当某个 account 首次 associate、来自异常的 AP edge、没有 managed certificate，或同一 identity 同时在其他位置处于 active 状态时发出 alert。
4. 监控能够 bridge interfaces 的 endpoint。在 Windows、Linux 和 network appliances 上，调查异常的 WLAN profiles、forwarding/NAT configuration、virtual adapters 及持久化 tunnels。
5. 通过合理的 AP 部署和 power planning，减少不必要的 signal spill。这是辅助控制措施，而不是 authentication。
6. 与邻近租户协调 incident response：最终的 radio source 本身可能就是受害者。

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) 可在不攻击邻居的情况下复现这些 observables。

## Public venues and third-party Wi-Fi

使用咖啡馆、酒店、机场或市政 Wi-Fi 会改变 destination 所看到的 IP，但不会带来 anonymity。场所或其 provider 可能保留 AP association、device MAC、DHCP lease、captive-portal account、SMS/email validation 及 flow logs。实体进入记录、CCTV、购买记录、mobile-location 和 travel records 可能将数字事件与某个人关联起来。

攻击者可能尝试通过 randomized MAC addresses、独立 device、cash 或 tunnel 来减少某一种关联线索。但跨层 correlation 仍然可能通过到达时间、重复的场所模式、radio fingerprints、portal behavior、traffic timing、camera footage 及 tunnel provider 实现。VPN 也只是将 destination 从场所日志转移到 VPN 日志；它不会消除场所知道该 device 曾经出现过这一事实。

公共接入的防御者应隔离 clients、阻止 lateral traffic，在可行时使用 WPA2/3-Enterprise 或 per-device keys，按比例保留 DHCP/RADIUS/security logs，保护 captive portals，并公布 abuse process。Red teams 只有在场所条款和 engagement 均允许时才能使用此类场所；绕过 portal、窃取 access 或 targeting 其他 guests 都不是经授权的 testing shortcut。

## Covert drop devices and warshipping

drop 是一种放置在 site 内或被送入 site 的小型 system，随后通过 outbound Ethernet、Wi-Fi 或 cellular 进行控制。“Warshipping”会将该 device 包装起来，使普通 delivery 将其带入 radio perimeter。硬件可能从 single-board computer 到 modified charger、USB peripheral、network appliance 或 battery-powered modem 不等。

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
该设备可能提供远程 foothold、执行无线测量、模拟已授权的 exercise 外设，或中继流量。它表面上的来源是本地的，但会产生物理痕迹：序列号、包装、指纹、摄像头、访问日志、功耗、USB descriptors、switchport negotiation、DHCP fingerprints、MAC OUI/randomization 行为、RF emissions，以及反复建立的 rendezvous 连接。

### 防御控制

- 维护收货室和资产清单流程；检查意外出现的电子设备，以及寄给不存在员工的包裹。
- 在有线和无线接入上使用 802.1X/NAC，禁用未使用的端口，并将未知设备置于受限的 remediation VLAN 中。
- 对新的 DHCP fingerprints、持续存在的 locally administered MAC、新的 USB network/HID devices、未经授权的 Wi-Fi Direct/Bluetooth，以及长期存在的出站 tunnels 发出告警。
- 建立 switchport、power-over-Ethernet、DNS 和 TLS 行为基线。一个没有资产记录、却定期建立加密连接的小型主机，比单独看到“Raspberry Pi OUI”更具识别价值。
- 在 exercise 期间，完成清点、标记和范围界定，进行加密，提供 remote kill，设定回收期限，并确保设备丢失不会暴露可复用的凭据。

## 蜂窝网络和 eSIM 回传

蜂窝 modem 可以绕过目标的 Internet gateway，并通过出站 rendezvous，使 drop 在 carrier NAT 后方仍然可访问。移动地址可能轮换或被共享；但 cellular operator 仍掌握有力的 subscriber 和 network 证据：SIM/eSIM 身份、IMSI、设备 IMEI、分配的地址/端口、蜂窝小区/扇区计时信息、账户/付款记录以及漫游记录。

从企业角度看，应通过 wireless/RF surveys、endpoint USB/PCI inventory、MDM restrictions、rogue-SSID monitoring 和 physical inspection，检测意外出现的 modems 和 personal hotspots。使用 cellular 进行控制的 drop，仍可能通过其本地 Ethernet/Wi-Fi 行为和 radio emissions 被发现。

对于已授权的 exercises，组织应拥有该 subscription 和 modem，将标识符记录在 controller 中，并确认 carrier/provider 条款允许相关流量。使用 prepaid label 或 cryptocurrency 购买，并不能消除基站、设备或零售记录。

## MAC randomization 和 device fingerprinting

现代系统可以为每个网络使用一个 locally administered random MAC。这会减少通过稳定的出厂 MAC 进行被动长期跟踪的风险，但无法隐藏：

- probe/association timing 以及所请求 network capabilities 的集合；
- 802.11 information elements、supported rates 和 vendor-specific behavior；
- DHCP options/hostname、IPv6 identifiers 以及 captive-portal/browser fingerprint；
- 已认证的 802.1X identity 或 certificate；
- 更高层的 account、tunnel 和 traffic pattern；或
- physical observation。

防御者不应将 MAC allowlists 用作 authentication。应将 radio identity 与 certificate/device posture 关联起来；除非其他上下文存在异常，否则应将 MAC 变化视为正常现象。

## Satellite-link hijacking

Kaspersky 记录了 Turla 利用旧式单向 DVB-S satellite Internet 中的弱点。在报告所述模型中，合法 remote subscriber 通过 terrestrial link 发送出站请求，但通过未加密的广域 satellite broadcast 接收下行数据。位于 satellite footprint 内的 actor 可以观察下行流量，选择一个活跃 subscriber IP，并安排将 C2 replies 发往该 IP。合法 subscriber 和 actor 都会收到该 broadcast；actor 提取发往所选端口的流量，而合法 subscriber 则丢弃未经请求的数据包。随后，C2 operator 似乎使用了另一个地理区域内的 satellite-provider address。<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
这属于特定协议/服务、受带宽限制的情况，不能等同于攻陷现代双向加密 satellite terminal。它也无法向能力足够强的观察者隐藏攻击者的出站请求路径。可利用的检测机会包括非对称/不可能的路由、发往未发起该流量的 subscriber 的流量、异常目标端口、provider telemetry、接收器位置/RF 调查以及 malware 配置。应利用此案例质疑“对 C2 IP 进行地理定位就等于对其 controller 进行地理定位”这一假设，而不要将其作为构建方案。

## Physical-to-digital correlation worksheet

当一个表面上位于本地的 source 存在可疑之处时，建立一条时间线：

1. 统一 AP、RADIUS、DHCP、DNS、proxy、VPN、EDR、switch 和 physical-access 的时钟；
2. 确定首次 radio association 或 link-up，而不仅是首次 alert；
3. 将 station 与 certificate、device posture、DHCP fingerprint 以及 switch/AP location 进行映射；
4. 查找附近系统上是否同时存在 remote-control/tunnel activity；
5. 根据适用的 policy/law，审查 deliveries、visitors、inventory exceptions、cameras 以及 RF findings；
6. 保全疑似设备和易失性 network state；不要盲目 power-cycle；
7. 判断表面上的 source 是由攻击者控制的 infrastructure，还是另一名 victim。

## References

- [1] [Volexity — 最近邻攻击：俄罗斯 APT 如何 weaponized 附近的 Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla：天空中的 APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — 保护 Wireless Local Area Networks 的指南](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
