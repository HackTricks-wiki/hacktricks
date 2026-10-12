# 隐蔽的物理与无线访问

{{#include ../banners/hacktricks-training.md}}

如需了解经所有者批准的详细实施方案，涵盖出站会合、电源/上行链路恢复、设备持有的最少机密、捕获测试以及对可能被发现情况的监控，请参阅 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)。

改变网络路径也会改变表面上的物理来源。高级攻击者可能会利用附近被入侵的系统、隐藏设备、公共接入、蜂窝回程或卫星接收器，使目标日志指向远离操作者的位置。这些方式都无法消除物理、无线电或服务提供商留下的证据；它们只是将归因线索转移到不同的数据集中。

## 技术矩阵

| 技术 | 表面来源 | 必要条件 | 高价值证据 |
|---|---|---|---|
| 邻近无线枢纽 | 目标附近的企业/住宅 | 被入侵的双宿主主机和目标 Wi-Fi 接入 | 邻近主机端点日志、RF 关联记录以及目标 RADIUS/DHCP |
| 公共/访客网络 | 场所 NAT 或隧道出口 | 合法接入或绕过访问控制 | 强制门户、DHCP、AP 关联记录、CCTV 以及付款/位置记录 |
| 隐蔽投放设备 | 目标/附近的有线、Wi-Fi 或蜂窝地址 | 物理放置或投递 | 交换机端口/USB、RF、资产清单、电源以及出站隧道遥测 |
| 蜂窝路由器/eSIM | 运营商 NAT 或专用 APN | 调制解调器/SIM/订阅 | IMEI/IMSI/eSIM、小区扇区、运营商账户以及流量时间信息 |
| 滥用卫星链路 | 波束覆盖区内的用户地址 | 特定于协议和服务的弱点 | RF 定位、上行流量、异常 RTT/路由以及服务提供商记录 |

## 邻近攻击

Volexity 记录了一起 2022 年 APT28/GRU 行动，攻击者与最终目标身处异地。攻击者对目标的公共服务进行密码喷洒以获取有效凭据，但 MFA 阻止了其直接从互联网登录。目标的企业 Wi-Fi 接受这些凭据，且未启用 MFA。攻击者入侵了与目标地理位置相近的组织，找到一台具有无线接入能力的双宿主系统，并利用该系统通过身份验证接入目标 Wi-Fi。Volexity 将此方法命名为 **Nearest Neighbor Attack**。<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

新颖之处在于这种组合方式。操作人员无需前往目标地点，而面向互联网的服务仍正常执行 MFA。被攻陷的邻近设备提供物理接近条件；被盗的目标凭据提供逻辑访问权限；目标 Wi-Fi 则成为跨越边界的路径。

### 前提条件与可见性

- 附近必须有一台可远程控制的系统，且配备兼容的无线电设备，或能够访问另一个附近的 pivot。
- 目标 SSID 必须覆盖该系统，且 Wi-Fi 接入控制必须接受可重复使用的凭据、证书或设备状态。
- pivot 通常需要两条同时存在的路径：一条连接回操作人员，另一条接入目标 WLAN。
- 目标可能会看到新的站点 MAC 和合法用户名，却看不到对应的受管设备证书、设备状态、历史记录或预期的建筑物出入记录。
- 邻近设备的端点日志可能会显示无线扫描、新建配置文件、接口变更、隧道和远程控制活动。

### 检测与防护

1. 企业 Wi-Fi 应要求基于证书的 EAP-TLS 和受管设备状态；不能仅因为密码通过无线方式提交，就认为它足以通过认证，尤其是该密码在互联网登录时未能通过 MFA。
2. 将 RADIUS 身份验证与 MDM/NAC 身份、历史站点/设备绑定关系、AP 位置、物理门禁事件和并发会话相关联。
3. 当账户首次关联、从不常见的 AP 边缘位置关联、未提供受管证书，或同一身份仍在其他位置处于活动状态时，触发告警。
4. 监控能够桥接接口的端点。在 Windows、Linux 和网络设备上，调查意外的 WLAN 配置文件、转发/NAT 配置、虚拟适配器和持久隧道。
5. 通过合理规划 AP 布局和发射功率，减少不必要的信号外溢。这只是辅助控制措施，不能代替身份验证。
6. 与邻近租户协调事件响应：最终的无线信号来源本身可能也是受害者。

[自有的双组织实验室](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) 无需攻击邻近组织，即可复现这些可观测现象。

### 验证 Windows pivot 路径

双网卡 Windows 主机不会自动桥接其接口。首先盘点其适配器、路由和 WLAN 状态，然后仅通过已批准的配置文件进行关联。`netsh wlan connect` 的 `name` 参数指定的是已安装的配置文件，而不是任意 SSID 和密码。比较关联前后的路由表，确保新的默认路由不会中断控制路径或导致结果失效。确认预期接口和路由后，再继续执行[关联后检查](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md)。<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity 发布的事件样本体现了另一个有用的区别。其内嵌的 C# 会打开 WLAN API、枚举接口、从磁盘读取 EAP XML，并在第一个无线接口上为指定配置文件调用 `WlanSetProfileEapXmlUserData`。该 API 会为现有的 802.1X 配置文件设置 EAP 用户凭据，但发布的组件既不包含 `WlanConnect`，也不包含报告中所述的发现逻辑。应将其视为配置文件配置组件，而非完整的连接器，并将生成的配置文件纳入[客户端和 supplicant 评估](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md)进行检查。<sup>[[5]](#references)[[7]](#references)</sup>

## 公共场所和第三方 Wi-Fi

使用咖啡馆、酒店、机场或市政 Wi-Fi，会改变目标看到的 IP 地址，但不会带来匿名性。场所或其服务提供商可能会保留 AP 关联记录、设备 MAC 地址、DHCP 租约、Captive Portal 账户、SMS/电子邮件验证记录和流量日志。出入记录、CCTV、购物记录、移动位置数据和旅行记录，都可能将数字活动与某个人关联起来。

攻击者可能会尝试使用随机化 MAC 地址、独立设备、现金或隧道来减少一种可追踪线索。但跨层关联仍有可能通过到达时间、重复出现的场所模式、无线电指纹、门户行为、流量时序、监控录像和隧道提供商实现。VPN 只是将目标方的日志记录从场所转移到 VPN 日志中，并不会消除场所知道设备曾到访的事实。

公共网络的防御方应隔离客户端、阻止横向流量、在可行时使用 WPA2/3-Enterprise 或每设备密钥、按比例保留 DHCP/RADIUS/安全日志、保护 Captive Portal，并公布滥用事件处理流程。红队只有在场所条款和测试约定允许时，才能使用此类场所；绕过门户、窃取访问权限或攻击其他访客，都不是获得授权的测试捷径。

## 隐蔽投放设备与 warshipping

投放设备是一种放置在现场或被送入现场的小型系统，之后通过出站以太网、Wi-Fi 或蜂窝网络进行控制。“Warshipping”会对设备进行包装，让普通投递将其带入无线电覆盖范围。硬件可以是各种设备，从单板计算机到改装的充电器、USB 外设、网络设备或电池供电的调制解调器。

操作架构：

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

该设备可能提供远程立足点、执行无线测量、模拟获准演练所用的外围设备，或中继流量。它表面上来自本地，但会留下实物痕迹：序列号、包装、指纹、摄像头、访问日志、功耗、USB 描述符、交换机端口协商、DHCP 指纹、MAC OUI/随机化行为、RF 发射，以及定期建立的 rendezvous 连接。

### 防御措施

- 建立收货室和资产盘点流程；检查意外出现的电子设备，以及寄给不存在员工的包裹。
- 在有线和无线网络上使用 802.1X/NAC，禁用未使用的端口，并将未知设备放入受限的修复 VLAN。
- 对新的 DHCP 指纹、持续使用的本地管理 MAC、新出现的 USB 网络/HID 设备、未经授权的 Wi-Fi Direct/Bluetooth，以及长期存在的出站隧道发出告警。
- 建立交换机端口、以太网供电、DNS 和 TLS 行为基线。没有资产记录、却定期建立加密连接的小型主机，比单看“Raspberry Pi OUI”更值得关注。
- 演练期间，应登记、贴标签、限定范围、加密，提供远程 kill 功能，设定取回期限，并确保设备丢失不会导致可重复使用的凭据泄露。

## 蜂窝网络和 eSIM 回传

蜂窝调制解调器可以绕过目标的 Internet 网关，并通过出站 rendezvous 让植入设备在运营商 NAT 后仍可访问。移动地址可能轮换或被共享；但蜂窝运营商仍掌握充分的用户和网络证据：SIM/eSIM 身份、IMSI、设备 IMEI、分配的地址/端口、小区/扇区时间记录，以及账户/支付和漫游记录。

从企业角度来看，可通过无线/RF 扫描、端点 USB/PCI 盘点、MDM 限制、恶意 SSID 监控和实地检查，发现意外出现的调制解调器和个人热点。即使植入设备使用蜂窝网络进行控制，也仍可能通过其本地以太网/Wi-Fi 行为及无线电发射被发现。

对于获准的演练，组织应自行持有订阅和调制解调器，在控制器中记录标识符，并确认运营商/服务提供商条款允许相关流量。预付费标签或使用加密货币购买，并不能抹去基站、设备或零售记录。

## MAC 随机化和设备指纹识别

现代系统可以为每个网络使用本地管理的随机 MAC。这会减少通过稳定的出厂 MAC 进行被动长期跟踪，但无法隐藏：

- 探测/关联时间，以及请求的网络功能集合；
- 802.11 信息元素、支持的速率和特定厂商的行为；
- DHCP 选项/主机名、IPv6 标识符和 captive portal/浏览器指纹；
- 经身份验证的 802.1X 身份或证书；
- 更高层的账户、隧道和流量模式；或
- 实地观察。

防御人员不应将 MAC 允许列表用作身份验证手段。应将无线电身份与证书/设备状态关联起来；除非其他背景信息表明存在异常，否则应将 MAC 变化视为正常情况。

## 卫星链路劫持

Kaspersky 记录了 Turla 利用旧式单向 DVB-S 卫星 Internet 的弱点。在报告所述的模式中，合法的远程用户通过地面链路发送出站请求，但通过未加密的广域卫星广播接收下行数据。处于卫星覆盖范围内的攻击者可以观察下行链路，选择一个活跃用户的 IP，并设法让 C2 回复发往该 IP。合法用户和攻击者都会收到广播；攻击者提取发往所选端口的流量，而合法用户则丢弃未经请求的数据包。随后，C2 操作者看起来像是在另一个地理区域使用卫星服务提供商的地址。<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

这是特定于协议/服务的，带宽受限，也不等同于攻陷现代双向加密卫星终端。它也无法向能力足够强的观察者隐藏攻击者的出站请求路径。检测机会包括非对称/不可能的路由、发往未发起该流量的订阅用户的流量、异常目标端口、provider telemetry、接收器位置/RF 调查以及 malware 配置。利用此案例质疑“对 C2 IP 进行地理定位就能定位其控制者”这一假设，而不要把它当作操作指南。

## Physical-to-digital correlation worksheet

当看似本地的来源令人怀疑时，建立一条时间线：

1. 统一 AP、RADIUS、DHCP、DNS、proxy、VPN、EDR、switch 和物理门禁系统的时钟；
2. 找出首次无线关联或链路启动的时间，而不只是首次告警时间；
3. 将站点映射到证书、设备安全状态、DHCP 指纹和 switch/AP 位置；
4. 检查附近系统是否同时存在远程控制/隧道活动；
5. 根据适用的 policy/law，审查投递物、访客、库存异常、摄像头录像和 RF 调查结果；
6. 保全可疑设备和易失性网络状态；不要贸然断电重启；
7. 判断表面上的来源是攻击者控制的基础设施，还是另一名受害者。

## References

- [1] [Volexity — 最近邻攻击：俄罗斯 APT 如何将附近的 Wi-Fi 网络武器化](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla：天空中的 APT 命令与控制](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — 硬件添加 (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — 无线局域网安全指南](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — 脱敏的 PowerShell/C# WLAN 配置文件代码](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData 函数](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
