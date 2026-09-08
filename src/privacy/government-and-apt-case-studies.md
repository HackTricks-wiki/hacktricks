# 政府与 APT 案例研究

{{#include ../banners/hacktricks-training.md}}

这些公开案例展示了不同隐私技术如何在真实行动中组合使用。归因标签采用被引用调查人员或政府使用的称呼；仅凭 IP 地址、工具重叠或地缘政治关联，无法得出确凿归因。

## APT28：远程最近邻 Wi-Fi 访问

**公开发现。** Volexity 将一次 2022 年的入侵归因于 GruesomeLarch/APT28。在使用经过验证的凭据进行 Internet 访问被 MFA 阻止后，该攻击者入侵了目标附近的组织，并从一个附近的双归属主机连接到目标的企业 Wi-Fi。Wi-Fi 路径接受了该凭据，而无需外部访问所要求的 MFA。<sup>[[1]](#references)</sup>

**隐私影响。** 最终访问源自物理无线电范围内，中间组织则是受害者。该行动避免了出行，并使传统 IP 地理定位将目标指向邻近组织。

**暴露方式。** 必须将目标告警、主机/网络调查、凭据活动、接口拓扑和物理邻近性作为一条链进行分析。异常之处不仅仅是出现了一个新 IP；而是一个合法身份通过异常的 Wi-Fi/设备上下文到达，同时附近系统已被入侵。

**防御经验。** 对 Wi-Fi 应用基于证书/设备的访问控制，将 RADIUS 与 NAC/MDM 及物理上下文进行关联，并调查邻近基础设施，而不是假定最后一跳就是攻击者。

## APT28：GRU 重新利用犯罪组织的 Moobot 基础设施

**公开发现。** 2024 年 2 月，美国司法部描述了一个由数百台 Ubiquiti EdgeOS 路由器组成的 botnet。犯罪分子在仍保留已知默认管理员凭据的路由器上安装了 Moobot；随后 GRU 第 26165 部队添加脚本和文件，将现有犯罪 botnet 转变为用于 spearphishing 和凭据窃取的间谍平台。<sup>[[2]](#references)</sup>

**隐私影响。** GRU 并未自行构建全部基础设施。借用一支已遭入侵的设备群，使无关家庭和小型办公室地址处于攻击者与目标之间，将国家活动与犯罪活动混合，并减少了可归属于攻击者的注册痕迹。

**暴露方式。** 路由器文件、恶意软件控制行为和非内容路由信息支持了调查。此次 disruption 临时更改了 firewall 规则并删除了恶意文件，而 DOJ 警告称，未更改的默认凭据可能导致再次感染。

**防御经验。** 更换不再受支持的路由器，移除暴露于 Internet 的管理接口，更改默认设置，安装补丁，收集边缘设备配置/流量数据，并搜寻设备群行为。“美国住宅 IP”并不能证明操作者来自美国。

## Volt Typhoon：KV Botnet 加上 living off the land

**公开发现。** DOJ 和 CISA 联合公告描述了由中国国家支持的 Volt Typhoon 使用 KV Botnet（主要由已被入侵的停产 Cisco 和 NETGEAR SOHO 路由器组成），以隐藏针对关键基础设施活动的中国来源。在受害者环境内部，该攻击者偏好使用有效账户和内置管理工具；相关机构报告称，在某些环境中，访问持续了至少五年。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**隐私影响。** 类 ORB 路径隐藏了源头，而 living-off-the-land 在获得访问权限后减少了新型二进制文件和签名暴露机会。网络层与端点层的隐匿相互强化。

**暴露因素。** 路由器/控制器结构、法院授权的技术收集、重复活动以及跨受害者分析，比单个 IOC 更为关键。在所述案例中，重启路由器可以移除易失性的 KV malware，但无法修复设备底层的 EOL 暴露问题。

**防御经验。** 更换 EOL 边缘设备，集中管理身份验证和网络设备日志，建立管理员行为基线，限制出站连接，并跨身份、端点和网络层寻找行为序列。

## 中国关联的 ORB 网络：基础设施即服务

**公开发现。** Mandiant 描述了一个由多个中国关联间谍行为者使用的 ORB 网络生态系统。Provisioned networks 使用租用的 VPS 节点；non-provisioned networks 使用被入侵的 IoT 和路由器；hybrid networks 则将两者结合。ORB3/SPACEHOP 支持与 APT5/APT15 相关的活动。ORB2/FLORAHOX 结合了管理服务器、租用服务器、定制化 Tor 层，以及被入侵的 Cisco、ASUS 和 DrayTek 设备。Mandiant 评估认为，其中一些网络由独立运营者管理，并出租给多个 APT 行为者。<sup>[[5]](#references)</sup>

**隐私影响。** 基础设施变成了服务边界。单个运营者无需维护受害者设备群，即可获得地理位置和住宅网络出口；而多个客户共享同一基础设施，也削弱了简单的行为者到 IP 映射。设备群的快速更替加速了“IOC extinction”。

**暴露因素。** 网络拓扑、克隆的服务器镜像、端口/服务、控制器关系、路由器 implant 和生命周期模式仍可用于聚类分析。Mandiant 报告称，某些节点 IP 在 ORB 中的存活时间短至 31 天。

**防御经验。** 将 ORB 作为不断变化的实体进行跟踪：节点角色、服务指纹、上游关系、扫描行为和轮换节奏。IP indicator 过期后应更新 cluster，而不是删除案件。

## PRC 全球间谍系统：路由器、可信链路与流量镜像

**公开发现。** 一份 2025 年的多国联合 advisory 描述了与 Salt Typhoon、OPERATOR PANDA、RedMike、UNC5807 和 GhostEmperor 等商业报告名称存在重叠的活动。相关机构报告称，行为者使用租用的 VPS 和被入侵的中间路由器访问电信及网络提供商。行为者通过可信的提供商/客户链路进行 pivot，修改路由，建立 GRE/IPsec 隧道，使用设备容器，并启用 SPAN/RSPAN/ERSPAN 或原生 packet capture，以收集身份验证信息和客户流量。<sup>[[13]](#references)</sup>

**隐私影响。** 被入侵的路由器同时充当 relay、观测点和可信网络参与者。私有互连可以绕过围绕公共 Internet 设计的控制措施，而 traffic mirroring 无需部署 endpoint agent 即可收集凭据。

**暴露因素。** 配置差异、异常的 SNMP/SSH/web 管理、新增的静态路由/隧道、mirror session、Guest Shell 容器、PCAP 文件、TACACS+/RADIUS 目标变更以及被禁用的日志记录。该 advisory 强调，某些中间路由器并不属于此前公开命名的 botnet，因此缺少已知 ORB indicator 并不能证明其无罪。

**防御经验。** 使用 out-of-band 管理、集中式配置/身份验证日志、签名镜像和运行时完整性检查，限制管理接口的出站流量，并针对路由/mirror/tunnel/AAA 变更设置告警。在清除入侵前，应将调查范围扩展到所有可信对等方。

## UNC3886 RedPenguin：ISP 路由器上的被动后门

**公开发现。** Mandiant 将 EOL Juniper MX 路由器上的定制 TINYSHELL-derived backdoor 归因于 UNC3886。该套 implant 包括主动和被动 implant、仿冒合法 daemon 的名称、禁用日志的行为、向可信进程中进行 process injection、SOCKS proxy 能力，以及被评估为 ORB staging node 的基础设施。被动变体通过 `libpcap` 检查数据包，仅在检测到 magic pattern 后激活；其中一个变体还可以切换到由 trigger 提供的主动 callback。<sup>[[14]](#references)</sup>

**隐私影响。** 被动 implant 没有周期性 beacon，因而难以被发现。它与真实网络设备共享端口和流量，仅短暂激活，并且可以通过 ORB relay，而不是直接连接最终 controller。

**暴露因素。** 内存分析、磁盘代码与运行时代码之间的差异、异常的 packet-capture filters/socket 行为、仅近似仿冒合法 daemon 的进程/文件名称、通过 terminal server 进行的管理、缺失的日志，以及 staging node 与后端 controller 之间的两阶段关系。

**防御经验。** 除文件系统和配置证据外，还应获取内存；将进程/模块与已知良好镜像进行比较；监控 packet-capture/socket-filter 的使用；保护管理 terminal server；并更换 EOL 网络硬件。没有发现干净的 outbound-beacon，并不代表系统安全。

## APT29：Tor domain fronting

**公开发现。** MITRE 记录了 APT29 使用 `meek` Tor pluggable transport 对 C2 流量进行 domain-front。外层 TLS 名称看起来是一个被允许的 CDN-hosted domain，而内层 HTTP host 则选择实际路由。<sup>[[6]](#references)</sup>

**隐私影响。** 过滤观察者看到的可能是常见的 front/CDN，而不是内部目标；封锁该目标还可能造成附带损害。

**暴露因素。** CDN 可以观察到路由不匹配；拥有 endpoint 或合法 TLS 可见性的 defender 则可以关联进程、authority、连接生命周期、字节模式和后续活动。Provider policy 的变更也可能使该技术失效。

**防御经验。** 不要仅依赖 SNI allowlisting。实施 application-aware egress，在可见时比较 TLS 和 HTTP 身份，并将网络事件与发起连接的进程关联起来。

## APT41 和其他 dead-drop resolvers

**公开发现。** MITRE 记录了 APT41 使用 GitHub、Pastebin、Microsoft TechNet、Cloudflare 和社区论坛等合法网站发布或获取 C2 信息。其他与国家关联的工具也以类似方式使用帖子、文档和社交媒体。<sup>[[7]](#references)</sup>

**隐私影响。** 二进制文件包含的是合法服务/对象，而不是稳定的 C2 地址。该对象可以被编辑以轮换基础设施，而初始请求则混入常见的 TLS 流量中。

**暴露因素。** 对象或账户标识符保持稳定；少见的进程会反复获取该对象；内容会被解码；随后还会出现第二个出站连接。Provider account 和 API 记录可能将发布行为与运营者关联起来。

**防御经验。** 保存完整的 proxy 路径/对象 ID，以及 endpoint process lineage。仅记录“已连接到 GitHub”这类 domain-level 事件过于粗略。

## Turla：卫星地址 C2

**公开发现。** Kaspersky 报告称，Turla 滥用了旧式单向 DVB-S Internet 服务中未加密的下行广播。位于卫星覆盖范围内的运营者可以选择合法订阅者的地址，并接收广播到该地址的回复，使 C2 看起来像托管在另一个地区的卫星提供商之后。<sup>[[8]](#references)</sup>

**隐私影响。** 表面上的服务器地址无法识别接收者，传统的主机查封和 WHOIS 流程也因此不太有用。

**暴露因素。** 行为者仍然需要出站请求路径；路由具有非对称性；合法订阅者并未发起 C2 exchange；而 RF/provider 调查可以缩小接收范围。

**防御经验。** 将地理定位视为一种假设。验证路径对称性、RTT、路由所有权，以及被指称的 endpoint 是否确实能够提供所观察到的服务。

## Cyclops Blink 和 VPNFilter：边缘设备作为持久掩护

**公开发现。** 2022 年 NCSC/CISA/FBI/NSA advisory 描述了 Sandworm 在 WatchGuard 设备上使用模块化 Cyclops Blink malware，通过 firmware update 持久部署，并能够添加模块。DOJ 另行描述了较早的 APT28 VPNFilter botnet；该 botnet 由路由器和 NAS 设备组成，能够进行情报收集、破坏性活动和误导归因。<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**隐私影响。** 边缘设备持续在线，被视为基础设施的一部分，并且通常缺少 EDR 覆盖。Firmware persistence 可以在普通重启后继续存在，并使受害设备成为 relay 或 control point。

**暴露因素。** Firmware integrity、厂商特定的 implant protocol、异常的管理暴露、配置变更和 outbound beaconing。边缘设备必须作为 forensic subject，而不能被当作透明管道。

## DPRK：身份、网络与金融分层

**公开发现。** DOJ 案件描述了 DPRK 工作人员如何使用虚假或被盗的身份材料和 VPN 获取远程工作，接收 cryptocurrency，拆分转账，交换资产/链，使用 NFT，并将收益混同。其他案件描述了 OTC traders 和 front companies 如何将被盗 crypto 转换为商品购买。Treasury 和 FBI 已公开将 Lazarus/TraderTraitor 的收益与 mixers 关联，并识别出重大盗窃案中的地址。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**隐私影响。** 这并不是“一种 private coin”。它是一条跨域链：persona 和远程访问隐藏工作人员位置；crypto 转移价值；分层操作破坏简单的交易叙事；OTC traders/front companies 则连接商品和法定货币。

**暴露因素。** 雇主/设备异常、重复使用的 facilitators、区块链上的时间和价值连续性、exchange/bridge 记录、受制裁地址、账户身份，以及运输/公司记录，都可以重新连接这条链。

**防御经验。** 招聘、IAM、endpoint、payroll、blockchain 和 sanctions 团队需要共享案件模型。更多详情见 [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md)。

## Cross-case patterns

| 模式 | APT 示例 | Defender adaptation |
|---|---|---|
| 出口节点是另一个受害者 | APT28/Moobot、Volt Typhoon/KV、ORB | 调查并修复出口节点；不要将其等同于行为者所在位置 |
| 控制措施因边界而异 | APT28 nearest neighbor | 为内部/无线访问提供与 Internet 访问相同的身份保证 |
| 合法服务充当路由层 | APT29、APT41 | 保留对象/路径/进程上下文，而不仅是目标域名 |
| 边缘设备缺少 telemetry | KV、Moobot、Cyclops Blink、ORB | 集中配置/身份验证/流量日志，并验证 firmware/inventory |
| 基础设施共享且生命周期短 | 中国关联的 ORB | 对行为/拓扑进行 cluster，并持续跟踪角色变化 |
| 多个薄弱隔离层叠加 | DPRK persona + VPN + crypto + OTC | 关联身份、设备、网络、支付和物理证据 |

## References

- [1] [Volexity — 最近邻攻击](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — 对 GRU 控制的 Moobot 路由器 botnet 进行 disruption](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — 对 PRC KV Botnet 进行 disruption](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC 行为者入侵并持续访问美国关键基础设施](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — 中国关联间谍行为者使用 ORB 网络](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter disruption](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — 应对中国国家支持的行为者入侵全球网络](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — 路由器中的幽灵：UNC3886 瞄准 Juniper 路由器](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
