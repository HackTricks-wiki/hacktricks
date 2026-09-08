# 隐蔽的物理与无线访问

如需详细的、经所有者批准的实施方案，涵盖出站 rendezvous、电源/uplink 恢复、设备持有的最小化 secrets、capture 测试以及对可能被发现情况的监控，请参见 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)。

改变 network path 也可能改变表面上的物理来源。复杂的攻击者可能使用附近的已被 compromise 的系统、隐藏设备、公共访问、蜂窝 backhaul 或 satellite receiver，使 target logs 指向远离 operator 的位置。这些方式都不会消除物理、无线电或 provider 证据；它们只是将 attribution 转移到不同的数据集中。

## 技术矩阵

| 技术 | 表面来源 | 必要条件 | 高价值证据 |
|---|---|---|---|
| 附近的 wireless pivot | target 旁边的企业/住宅 | 已被 compromise 的 dual-homed host，以及 target Wi-Fi 访问权限 | neighbor-host endpoint logs、RF association，以及 target RADIUS/DHCP |
| 公共/guest network | venue NAT 或 tunnel exit | 合法访问或 access-control bypass | captive portal、DHCP、AP association、CCTV，以及支付/位置记录 |
| 隐蔽 drop device | target/附近的 wired、Wi-Fi 或 cellular address | 物理放置或投递 | switchport/USB、RF、inventory、power，以及出站 tunnel telemetry |
| Cellular router/eSIM | carrier NAT 或 dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM、cell-sector、carrier account，以及 traffic timing |
| Satellite-link abuse | beam footprint 内的 subscriber address | 特定于协议和服务的 weakness | RF location、uplink flow、impossible RTT/routing，以及 provider records |

## Nearest-neighbor attack

Volexity 记录了 2022 年的一次 APT28/GRU operation，其中 actor 与其最终 target 位于远程位置。它对 target 的 public service 执行了 password-spraying，以获取有效 credentials，但 MFA 阻止了直接的 Internet login。Target 的 enterprise Wi-Fi 接受这些 credentials，且不要求 MFA。Actor compromise 了物理位置上靠近 target 的 organizations，找到了一个具备 wireless reach 的 dual-homed system，并使用该 system 对 target Wi-Fi 进行 authenticate。Volexity 将此称为 **Nearest Neighbor Attack**。<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
新颖之处在于组合方式。没有操作员前往目标地点，而面向 Internet 的服务的 MFA 仍然有效。被攻陷的邻居提供物理接近条件；窃取的目标凭据提供逻辑访问权限；目标 Wi-Fi 则成为跨越边界的路径。

### 前置条件与可见性

- 附近必须有一台可被远程控制的系统，并具备兼容的 radio，或能够访问另一台附近的 pivot。
- 目标 SSID 必须能覆盖该系统，并且 Wi-Fi 接入必须接受可复用的凭据、证书或设备状态。
- pivot 通常需要两条同时存在的路径：一条返回操作员，另一条进入目标 WLAN。
- 目标可能会看到新的 station MAC 和合法用户名，但看不到相应的 managed-device certificate、posture、历史记录或预期的 building entry。
- 邻居 endpoint 的日志可能显示 wireless scans、新 profile、interface 变更、tunneling 和 remote-control 活动。

### 检测与防御

1. 对 enterprise Wi-Fi 要求 certificate-backed EAP-TLS 和 managed-device posture；不要仅仅因为一个在 Internet 上未通过 MFA 的密码经由 radio 到达，就认为它足够。
2. 将 RADIUS authentication 与 MDM/NAC identity、历史 station/device binding、AP location、physical-access events 及并发会话进行关联。
3. 当某个 account 首次 associate、来自异常的 AP edge、没有 managed certificate，或同一 identity 同时在其他位置活跃时发出告警。
4. 监控具备 bridging interfaces 能力的 endpoint。在 Windows、Linux 和 network appliances 上，调查异常的 WLAN profiles、forwarding/NAT configuration、virtual adapters 及 persistent tunnels。
5. 通过合理的 AP placement 和 power planning，减少不必要的 signal spill。这是辅助控制措施，不是 authentication。
6. 与邻近租户协调 incident response：最终的 radio source 本身可能就是受害者。

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) 在不攻击邻居的情况下复现了这些 observables。

## 公共场所与第三方 Wi-Fi

使用咖啡馆、酒店、机场或市政 Wi-Fi 会改变目标看到的 IP，但不会实现匿名。场所或其 provider 可能保留 AP association、device MAC、DHCP lease、captive-portal account、SMS/email validation 及 flow logs。实体进入记录、CCTV、购买记录、移动位置和出行记录都可能将数字事件与某个人关联起来。

攻击者可能尝试通过使用 randomized MAC addresses、单独的设备、现金或 tunnel 来减少某一个关联线索。但跨层关联仍然可能通过到达时间、重复的场所模式、radio fingerprints、portal behavior、traffic timing、camera footage 及 tunnel provider 实现。VPN 也只是将目标从场所日志转移到 VPN 日志；它不会消除场所知道该设备曾在场的事实。

公共接入的防御方应隔离 clients、阻止 lateral traffic，并在可行时使用 WPA2/3-Enterprise 或 per-device keys，保留适当的 DHCP/RADIUS/security logs，保护 captive portals，并公布 abuse process。Red teams 只有在场所条款和 engagement 都允许时才能使用此类场所；绕过 portal、窃取 access 或 targeting other guests 都不是经过授权的 testing shortcut。

## Covert drop devices 与 warshipping

drop 是一种被放置或送入某个场所的小型系统，之后通过 outbound Ethernet、Wi-Fi 或 cellular 进行控制。“Warshipping”会对设备进行封装，使普通的配送过程将其带入 radio perimeter。可用 hardware 的范围从 single-board computer，到改装的 charger、USB peripheral、network appliance 或 battery-powered modem。

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
该设备可能提供远程 foothold、执行 wireless 测量、模拟经过授权的 exercise peripheral，或 relay 流量。其表面来源是本地的，但会留下物理痕迹：序列号、包装、指纹、摄像头、访问日志、功耗、USB descriptors、switchport 协商、DHCP fingerprints、MAC OUI/randomization 行为、RF emissions 以及周期性 rendezvous connections。

### 防御控制

- 维护收货室和资产清单流程；检查意外出现的电子设备，以及寄给不存在员工的包裹。
- 在有线和无线访问中使用 802.1X/NAC，禁用未使用的端口，并将未知设备置于受限的 remediation VLAN 中。
- 对新的 DHCP fingerprints、持续存在的 locally administered MAC、新的 USB network/HID 设备、未经授权的 Wi-Fi Direct/Bluetooth 以及长期存在的 outbound tunnels 发出告警。
- 建立 switchport、power-over-Ethernet、DNS 和 TLS 行为基线。一个没有资产记录、定期建立加密连接的小型主机，比单独出现“Raspberry Pi OUI”更值得关注。
- 在 exercise 期间，建立资产清单、贴标签、明确 scope、加密、提供 remote kill、设定取回期限，并确保设备丢失不会暴露可复用的凭据。

## Cellular and eSIM backhaul

Cellular modem 可以绕过目标的 Internet gateway，并通过 outbound rendezvous 让位于 carrier NAT 后方的 drop 保持可访问。移动地址可能轮换或被共享；但 cellular operator 仍拥有强有力的 subscriber 和 network 证据：SIM/eSIM identity、IMSI、设备 IMEI、分配的地址/端口、cell/sector timing、账户/支付及 roaming 记录。

从企业视角来看，应通过 wireless/RF surveys、endpoint USB/PCI inventory、MDM restrictions、rogue-SSID monitoring 和物理检查来发现意外的 modems 及 personal hotspots。使用 cellular 进行控制的 drop，仍可能通过其本地 Ethernet/Wi-Fi 行为及 radio emissions 被发现。

对于授权 exercise，组织应拥有该 subscription 和 modem，将 identifiers 与 controller 关联记录，并确认 carrier/provider 条款允许相关流量。使用 prepaid label 或 cryptocurrency 购买，并不能抹去 tower、device 或 retail 记录。

## MAC randomization and device fingerprinting

现代系统可以针对每个网络使用 locally administered random MAC。这样可以减少通过稳定的出厂 MAC 进行的被动长期跟踪，但无法隐藏：

- probe/association timing 以及请求的网络能力集合；
- 802.11 information elements、supported rates 以及 vendor-specific behavior；
- DHCP options/hostname、IPv6 identifiers 以及 captive-portal/browser fingerprint；
- 已认证的 802.1X identity 或 certificate；
- 更高层的 account、tunnel 和 traffic pattern；或
- physical observation。

防御者不应将 MAC allowlists 用作 authentication。应将 radio identity 与 certificate/device posture 关联起来，并将变化的 MAC 视为正常现象，除非其他上下文存在异常。

## Satellite-link hijacking

Kaspersky 记录了 Turla 利用旧式单向 DVB-S satellite Internet 中的弱点。在报告描述的模型中，合法 remote subscriber 通过 terrestrial link 发送 outbound requests，但通过未加密的 wide-area satellite broadcast 接收 downstream data。位于 satellite footprint 内的 actor 可以观察 downlink，选择一个活跃 subscriber IP，并安排将 C2 replies 发送到该 IP。合法 subscriber 和 actor 都会收到该 broadcast；actor 提取目标端口的流量，而合法 subscriber 丢弃 unsolicited packets。随后，C2 operator 看起来像是在使用另一个地理位置中的 satellite-provider address。<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
这属于特定协议/服务，受带宽限制，不能等同于攻破现代双向加密 satellite terminal。它也无法向能力足够强的观察者隐藏攻击者的 outbound request path。检测机会包括非对称/不可能的路由、流量发往未发起该 flow 的 subscriber、异常 destination ports、provider telemetry、receiver location/RF investigation 以及 malware configuration。利用此案例质疑“对 C2 IP 进行地理定位即可定位其控制者”这一假设，而不要将其作为构建方案。

## Physical-to-digital correlation worksheet

当一个看似本地的 source 引起怀疑时，建立一条时间线：

1. 统一 AP、RADIUS、DHCP、DNS、proxy、VPN、EDR、switch 和 physical-access 的时钟；
2. 确定首次 radio association 或 link-up，而不只是首次 alert；
3. 将 station 映射到 certificate、device posture、DHCP fingerprint 以及 switch/AP location；
4. 查找附近系统上同时发生的 remote-control/tunnel activity；
5. 根据适用的 policy/law，审查 deliveries、visitors、inventory exceptions、cameras 和 RF findings；
6. 保留疑似设备及 volatile network state；不要盲目 power-cycle；
7. 确定表面上的 source 是攻击者控制的 infrastructure，还是另一个 victim。

## References

- [1] [Volexity — 最近邻攻击：俄罗斯 APT 如何 weaponize 附近的 Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla：空中的 APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Securing Wireless Local Area Networks 指南](https://csrc.nist.gov/pubs/sp/800/153/final)
