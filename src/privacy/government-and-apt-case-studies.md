# 政府与 APT 案例研究

这些公开案例展示了不同的隐私技术如何在真实行动中组合使用。归因标签采用被引用调查人员或政府所使用的名称；单独依据 IP 地址、工具重叠或地缘政治匹配，无法得出确凿归因。

## APT28：远程近邻 Wi-Fi 访问

**公开发现。** Volexity 将一起 2022 年入侵事件归因于 GruesomeLarch/APT28。在通过 MFA 阻止使用已验证凭据进行 Internet 访问后，该攻击者入侵了目标附近的组织，并从一个附近的 dual-homed 主机连接到目标的企业 Wi-Fi。该 Wi-Fi 路径接受了该凭据，而无需外部访问所要求的 MFA。<sup>[[1]](#references)</sup>

**隐私影响。** 最终访问源自物理无线电范围，而中间组织是受害者。该行动无需出行，并使传统 IP 地理定位将线索指向邻近组织。

**暴露因素。** 必须将目标告警、主机/网络调查、凭据活动、接口拓扑和物理邻近性作为一条完整链路进行分析。异常之处不仅是出现了一个新 IP；而是一个合法身份通过异常的 Wi-Fi/设备上下文出现，同时附近系统遭到入侵。

**防御经验。** 对 Wi-Fi 应用基于证书/设备的访问控制，将 RADIUS 与 NAC/MDM 及物理上下文进行关联，并调查邻近基础设施，而不是假设最后一跳就是攻击者。

## APT28：GRU 重新利用犯罪组织的 Moobot 基础设施

**公开发现。** 2024 年 2 月，美国司法部描述了一个由数百台 Ubiquiti EdgeOS 路由器组成的 botnet。犯罪分子在仍保留已知默认管理员凭据的路由器上安装了 Moobot；随后 GRU Unit 26165 添加脚本和文件，将现有犯罪 botnet 转变为用于 spearphishing 和凭据窃取的间谍平台。<sup>[[2]](#references)</sup>

**隐私影响。** GRU 并未自行构建全部基础设施。借用已经遭到入侵的设备群，使无关家庭和小型办公室的地址位于攻击者与目标之间，将国家行为与犯罪活动混杂在一起，并减少了与攻击者相关的注册痕迹。

**暴露因素。** 路由器文件、malware 控制行为和非内容路由信息为调查提供了支持。此次 disruption 临时修改了防火墙规则并移除了恶意文件，而 DOJ 警告称，未更改的默认凭据可能导致再次感染。

**防御经验。** 更换不再受支持的路由器，移除暴露在 Internet 上的管理接口，更改默认凭据，进行 patch，收集边缘设备的配置/流量数据，并主动搜寻 fleet 行为。“美国住宅 IP”并不能证明操作人员来自美国。

## Volt Typhoon：KV Botnet 加上 living off the land

**公开发现。** DOJ 和一份 CISA 联合 advisory 描述称，中国国家支持的 Volt Typhoon 使用 KV Botnet，主要由遭到入侵且已达到生命周期终点的 Cisco 和 NETGEAR SOHO 路由器组成，以掩盖针对关键基础设施的活动来源于中国。在受害者内部，该攻击者偏好使用有效账户和内置管理工具；相关机构报告称，在某些环境中，访问持续时间至少达到五年。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**隐私影响。** 类 ORB 路径隐藏了源头，而 living-off-the-land 在获得访问权限后减少了新型二进制文件和 signature 机会。网络与 endpoint 隐匿相互强化。

**暴露因素。** 路由器/控制器结构、法院授权的技术收集、反复出现的活动以及跨受害者分析，比单个 IOC 更为关键。在所述案例中，重启路由器会移除易失性的 KV malware，但无法修复设备底层的 end-of-life 暴露问题。

**防御经验。** 更换 EOL edge devices，集中管理 authentication 和 network-device logs，建立管理员行为基线，限制 outbound connectivity，并跨 identity、endpoint 和 network 层搜寻行为序列。

## China-nexus ORB networks：infrastructure as a service

**公开发现。** Mandiant 描述了一个由多个 China-nexus espionage actors 使用的 ORB networks 生态系统。Provisioned networks 使用 leased VPS nodes；non-provisioned networks 使用被攻陷的 IoT 和 routers；hybrid networks 则将两者结合。ORB3/SPACEHOP 支持与 APT5/APT15 相关的活动。ORB2/FLORAHOX 结合了 administration server、leased servers、customized Tor layer 以及被攻陷的 Cisco、ASUS 和 DrayTek devices。Mandiant 评估认为，其中一些 networks 由独立人员管理，并出租给多个 APT actors。<sup>[[5]](#references)</sup>

**隐私影响。** Infrastructure 成为了一个 service boundary。单个 operator 无需维护 victim fleet，就能获得地理位置和住宅网络出口；而多个 customers 共享同一 infrastructure，则削弱了简单的 actor-to-IP 映射。Fleet 的快速轮换加速了“IOC extinction”。

**暴露因素。** Network topography、cloned server images、ports/services、controller relationships、router implants 和 lifecycle patterns 仍可用于聚类。Mandiant 报告称，一些 node IP 在某个 ORB 中存在的时间短至 31 天。

**防御经验。** 将 ORB 作为不断变化的实体进行跟踪：node roles、service fingerprints、upstream relations、scan behavior 和 rotation rhythm。IP indicator 过期后，应更新 cluster，而不是删除案件。

## PRC global espionage system：routers、trusted links 和 traffic mirroring

**公开发现。** 一份 2025 年的 multinational advisory 描述了与 Salt Typhoon、OPERATOR PANDA、RedMike、UNC5807 和 GhostEmperor 等商业报告名称重叠的活动。相关机构报告称，actors 使用 leased VPSs 和被攻陷的 intermediate routers 访问 telecommunications 和 network providers。Actors 通过 trusted provider/customer links 进行 pivot，修改 routes，建立 GRE/IPsec tunnels，使用 device containers，并启用 SPAN/RSPAN/ERSPAN 或 native packet capture 来收集 authentication 和 customer traffic。<sup>[[13]](#references)</sup>

**隐私影响。** 被攻陷的 router 同时是 relay、observation point 和 trusted network participant。Private interconnections 可以绕过针对 public Internet 设计的 controls，而 traffic mirroring 无需部署 endpoint agent 即可收集 credentials。

**暴露因素。** Configuration diffs、异常的 SNMP/SSH/web administration、新增的 static routes/tunnels、mirror sessions、Guest Shell containers、PCAP files、TACACS+/RADIUS destinations 的变化以及被禁用的 logging。该 advisory 强调，一些 intermediate routers 并不属于此前已命名的 public botnet，因此缺少已知 ORB indicators 并不能证明系统未受影响。

**防御经验。** 使用 out-of-band administration、centralized configuration/authentication logs、signed-image 和 runtime integrity checks，限制 management-interface egress，并针对 route/mirror/tunnel/AAA changes 设置 alerts。在 eviction 之前，应将疑似 compromise 的范围扩展到 trusted peers。

## UNC3886 RedPenguin：ISP routers 上的 passive backdoors

**公开发现。** Mandiant 将 Juniper MX routers 上的 custom TINYSHELL-derived backdoors 归因于 UNC3886。这些 backdoors 包括 active 和 passive implants，使用仿冒 legitimate daemons 的名称，具备 log-disabling 行为、向 trusted process 注入、SOCKS proxy 能力，以及被评估为 ORB staging nodes 的 infrastructure。Passive variants 通过 `libpcap` 检查数据包，仅在出现 magic pattern 后激活；其中一个 variant 可以切换到 trigger 中提供的 active callback。<sup>[[14]](#references)</sup>

**隐私影响。** Passive implant 没有周期性 beacon，因而难以被发现。它与真实 network appliance 共享 ports/traffic，仅短暂激活，并且可以通过 ORB relay，而不是直接连接最终 controller。

**暴露因素。** Memory analysis、磁盘上的 code 与运行中 code 之间的差异、异常的 packet-capture filters/socket behavior、仅近似模仿 legitimate daemons 的 process/file names、通过 terminal servers 进行的 administration、缺失的 logs，以及 staging nodes 与 backend controller 之间的两阶段关系。

**防御经验。** 除 filesystem/configuration evidence 外，还应获取 memory；将 processes/modules 与 known-good image 进行比对；监控 packet-capture/socket-filter 的使用；保护 management terminal servers；并更换 EOL network hardware。没有发现 outbound beacon，并不代表系统状态良好。

## APT29：Tor domain fronting

**公开发现。** MITRE 记录了 APT29 使用 `meek` Tor pluggable transport 对 C2 traffic 进行 domain-front。外层 TLS name 看起来是一个获允许的 CDN-hosted domain，而内层 HTTP host 则选择实际 route。<sup>[[6]](#references)</sup>

**隐私影响。** Filtering observer 看到的可能是常见的 front/CDN，而不是内层 destination；阻断该 destination 还可能造成 collateral damage。

**暴露因素。** CDN 可以观察到 routing mismatch；拥有 endpoint 或 lawful TLS visibility 的 defender 可以关联 process、authority、connection lifetime、byte pattern 以及后续 activity。Provider policy changes 也可能使该 technique 失效。

**防御经验。** 不要只依赖 SNI allowlisting。实施 application-aware egress，在可见时比对 TLS 和 HTTP identities，并将 network event 与发起连接的 process 关联起来。

## APT41 和其他 dead-drop resolvers

**公开发现。** MITRE 记录了 APT41 使用 GitHub、Pastebin、Microsoft TechNet、Cloudflare 和 community forums 等 legitimate sites 发布或获取 C2 information。其他与 state 相关的 tooling 也以类似方式使用 posts、documents 和 social media。<sup>[[7]](#references)</sup>

**隐私影响。** Binary 中包含的是 legitimate service/object，而不是稳定的 C2 address。该 object 可以被编辑以轮换 infrastructure，而初始 request 会混入常见的 TLS traffic。

**暴露因素。** Object 或 account identifier 是稳定的；少见的 processes 会反复 fetch 它；content 会被 decode；随后还会出现第二个 outbound connection。Provider account 和 API records 可能将 publication 与 operator 关联起来。

**防御经验。** 保留完整的 proxy paths/object IDs 以及 endpoint process lineage。仅记录“connected to GitHub”这类 domain-level event，粒度过粗。

## Turla：satellite-address C2

**公开发现。** Kaspersky 报告称，Turla 滥用了旧式单向 DVB-S Internet services 的未加密下行广播。位于 satellite footprint 内的 operator 可以选择某个 legitimate subscriber address，并接收广播给该 address 的 replies，使 C2 看起来像是托管在不同地区的 satellite provider 之后。<sup>[[8]](#references)</sup>

**隐私影响。** 表面上的 server address 无法识别 receiver，传统的 hosting seizure/WHOIS 流程也不再那么有用。

**暴露因素。** Actor 仍需要 outbound request path；routing 是 asymmetric 的；legitimate subscriber 并未发起 C2 exchange；RF/provider investigation 则可能缩小 receiving footprint。

**防御经验。** 将 geolocation 视为一种假设。验证 path symmetry、RTT、routing ownership，以及被指称的 endpoint 是否确实能够提供观察到的 service。

## Cyclops Blink 和 VPNFilter：edge devices 作为持久掩护

**公开发现。** 一份 2022 年的 NCSC/CISA/FBI/NSA advisory 描述了 Sandworm 在 WatchGuard devices 上使用的 modular Cyclops Blink malware。该 malware 作为 firmware update 持久部署，并能够添加 modules。DOJ 另行描述了更早的 APT28 VPNFilter botnet；该 botnet 感染 routers 和 NAS devices，能够进行 intelligence collection、destructive activity 和 misattribution。<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**隐私影响。** Edge appliances 持续在线，被视为 infrastructure 的可信组成部分，且通常缺乏 EDR 覆盖。Firmware persistence 可以跨越普通 restart 持续存在，并使 victim device 成为 relay 或 control point。

**暴露因素。** Firmware integrity、vendor-specific implant protocol、异常的 management exposure、configuration changes 和 outbound beaconing。Edge devices 必须作为 forensic subjects，而不能被视为透明的 plumbing。

## DPRK：identity、network 和 financial layering

**公开发现。** DOJ cases 描述了 DPRK workers 如何使用虚假或被盗的 identity material 和 VPN 获得 remote jobs，接收 cryptocurrency，拆分 transfers，交换 assets/chains，使用 NFTs 并混同 proceeds。其他 cases 描述了 OTC traders 和 front companies 如何将被盗 crypto 转换为 purchases。Treasury 和 FBI 已公开将 Lazarus/TraderTraitor proceeds 与 mixers 关联起来，并识别出重大盗窃案中的 addresses。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**隐私影响。** 这并不是“一种 private coin”。它是一条 multi-domain chain：persona 和 remote access 隐藏 worker location；crypto 转移 value；layering 打破简单的 transaction narratives；OTC traders/front companies 则连接到 goods 和 fiat。

**暴露因素。** Employer/device anomalies、重复使用的 facilitators、blockchain timing/value continuity、exchange/bridge records、sanctioned addresses、account identity 以及 shipment/company records，会重新连接这条 chain。

**防御经验。** Hiring、IAM、endpoint、payroll、blockchain 和 sanctions teams 需要共享的 case model。更多详情见 [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md)。

## Cross-case patterns

| Pattern | APT examples | Defender adaptation |
|---|---|---|
| 出口是另一个 victim | APT28/Moobot、Volt Typhoon/KV、ORBs | 调查并修复该出口；不要将其等同于 actor location |
| Controls 会因 boundary 而不同 | APT28 nearest neighbor | 让 internal/wireless access 具备与 Internet access 相同的 identity assurance |
| Legitimate service 是 routing layer | APT29、APT41 | 保留 object/path/process context，而不仅是 destination domain |
| Edge devices 缺少 telemetry | KV、Moobot、Cyclops Blink、ORBs | 集中管理 config/auth/flow logs，并验证 firmware/inventory |
| Infrastructure 是共享且短命的 | China-nexus ORBs | 对 behavior/topology 进行聚类，并随时间跟踪 role changes |
| 多个薄弱隔离层叠加 | DPRK personas + VPN + crypto + OTC | 关联 identity、device、network、payment 和 physical evidence |

## References

- [1] [Volexity — Nearest Neighbor Attack：俄罗斯 APT 如何 weaponize 附近的 Wi-Fi networks 以实现 covert access](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — 对 GRU-controlled Moobot router botnet 的 disruption](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — 对 PRC KV Botnet 的 disruption](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actors compromise 并维持对 US critical infrastructure 的 persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actors 使用 ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter disruption](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representative 因 crypto-laundering conspiracies 被起诉](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctions 和 Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — 应对 Chinese state-sponsored actors 对全球 networks 的 compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router：UNC3886 targets Juniper routers](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
