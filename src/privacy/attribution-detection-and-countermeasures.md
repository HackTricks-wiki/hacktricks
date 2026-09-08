# 归因、检测与对策

归因规避基础设施旨在使单个指标变得可弃用。防御者应保留原始证据，对关系进行建模，并搜寻在 IP、域名或 persona 发生变化后仍然存在的行为。

## 证据层级

| 证据 | 用途 | 主要注意事项 |
|---|---|---|
| 源 IP/ASN/地理位置 | 定位可见出口和提供商 | 出口可能是 relay、NAT 或受害者；地理位置仅为近似值 |
| 被动 DNS/注册信息 | 基础设施历史和共同托管关系 | 隐私/编辑和共享托管会造成缺口 |
| 证书/TLS/HTTP 指纹 | 对重复部署进行聚类 | 常见软件和模仿会造成误报 |
| 流量时序和字节形态 | 关联 relay 阶段和重复 beacon | CDN/NAT 以及有限的可见性会降低确定性 |
| Endpoint 进程/身份 | 解释连接发生的原因 | 边缘设备/IoT 上可能不存在；攻击者可能使用原生工具 |
| Cloud/CDN/API 审计 | 识别租户和基础设施控制权 | 保留期限以及提供商/法律访问权限各不相同 |
| 支付/账户/设备 | 将采购行为与个人/实体关联 | 必须考虑名义持有人、账户失陷和共享设备 |
| 查获的 implant/配置 | 暴露密钥、对端、控制器和构建关联 | 收集完整性和查获时间非常重要 |
| 人员/物理证据 | 将数字事件与地点/操作人员关联 | 具有侵入性、取决于司法管辖区，并要求严格处理 |

任何单一行都不应支撑高置信度的国家归因。使用相互竞争的假设，并说明哪项观察结果会证伪每个假设。

## 最低遥测要求

1. **DNS：** 客户端、查询、类型、应答、TTL、响应代码、resolver 和时间戳。
2. **网络流：** 源/目的地址/端口、开始/结束时间、数据包/字节数、TCP 标志和传感器位置。
3. **TLS/HTTP：** 可见时记录 SNI、证书、协商协议、客户端/服务器指纹、方法、authority/path 类别、状态和字节数。保护敏感的完整 URL。
4. **身份：** 身份验证结果、因子/证书/设备、来源、应用程序、会话 ID 和风险决策。
5. **Endpoint：** 发起进程、父进程、用户、二进制签名/哈希和目的地。
6. **边缘/网络设备：** 配置差异、管理员登录、进程/文件/固件完整性、接口和流量日志。
7. **Cloud/SaaS/CDN：** 操作者、租户/项目、API 操作、来源、对象/资源、令牌和结果。
8. **Wireless/NAC：** 站点、随机化 MAC 标志、AP、信号、EAP 身份/证书、分配的 VLAN/IP 和安全状态。

同步时钟，保留原始时区，记录 NAT/proxy 边界，并保留足够长的历史记录，以超过一个 ORB 节点的 31 天生命周期。

## 构建归因图

将观察结果表示为带类型的节点和边：
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
有用的节点包括 IP、前缀、ASN、域名、DNS account、证书/密钥、类似 JA3/JA4 的指纹、HTTP grammar、文件/配置 hash、cloud tenant、API token、email、persona、支付工具和物理设备。每条边都需要包含 `first_seen`、`last_seen`、传感器/来源、置信度，以及其属于观测结果还是推断结果。

仅凭图的密度容易产生误导：CDN 或证书颁发机构会连接许多互不相关的行为者。应提高由操作者控制的稀有关系的权重——例如相同的 API account、SSH key、origin allowlist、唯一响应正文或控制协议——而不是常见的 hosting 关系。

## ORB 和受感染路由器 hunting

### 从已观测到的 exit 开始

1. 确定该地址属于 hosting、住宅、移动、教育还是企业网络；不要丢弃住宅来源。
2. 在限定时间范围内提取历史 DNS、services/certificates、开放端口，以及已观测到的扫描/利用行为。
3. 搜索共享稀有 service fingerprints、controller destinations、证书材料或轮换时序的 peer。
4. 分类其可能的角色：access、traversal、exit/staging 或 administration。
5. 检查多个不相关的 intrusion clusters 是否使用过同一地址池；multi-tenancy 会削弱对具体行为者的直接归因，但会增强 ORB 假设。
6. 在旧 IP 消失后，跟踪符合该角色特征的新节点。

### 在网络所有者处

- 针对新暴露于 Internet 的管理服务，以及默认/legacy authentication 发出告警。
- 将路由器/防火墙/VPN 配置变更和管理员 authentication 发送到设备外部。
- 为通常很少发起会话的基础设施建立 outbound connections 基线。
- 检测新的 proxy/listener processes、tunnels、scheduled tasks、firmware changes 和异常 DNS。
- 更换已停止生命周期支持的设备；重启虽然可以移除 volatile malware，但无法修复暴露问题。
- 将管理限制在经过 authentication 的 administration plane 和已知来源内。

Mandiant 建议将 ORB infrastructure 作为不断演变的实体进行跟踪，因为短期 IP blocking 无法反映其拓扑和生命周期。<sup>[[1]](#references)</sup>

## Fast-flux 和 dynamic-DNS analytics

按 registered domain 和滑动窗口进行聚合。一个实用的评分可以结合：
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
调查具有多个独立特征的域名，而不是只依赖一个阈值。与 CDN/anti-DDoS 的允许模型进行比较，并检查权威 name-server 轮换，以区分 single flux 和 double flux。对于 DGA，加入每个客户端的 NXDOMAIN 突发、长度/字符分布、跨主机同步查询，以及生成这些查询的进程。MITRE 当前的指导同样强调高频变更、低 TTL，以及进程/网络关联。<sup>[[2]](#references)</sup>

## Domain-fronting 检测

在企业端点或同时具备两种身份的授权检查点上进行比较：
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
当 SNI 与 authority 属于无关的 tenant、该进程不是获批准的客户端、会话具有周期性或持续时间很长，且内部 origin 很少见时，应提高置信度。空 SNI 是需要记录的特征，不应自动视为恶意。ECH 可能会隐藏线路上的 SNI，因此 endpoint、DNS 以及 provider/CDN 日志变得更加重要。MITRE 同时记录了不匹配 SNI 和空 SNI 两种变体。<sup>[[3]](#references)</sup>

## Dead-drop resolver 序列检测

高信号行为是一种序列，而不是某个被阻止的域名：
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
在整个 fleet 中搜索相同的对象路径、响应哈希、API 标识符和后续目标。保存已获取的内容，因为攻击者可能会编辑或删除这些内容。限制不必要的 service API，并要求已批准的应用通过 enterprise proxy 使用网络，但要考虑 developer tools 和自动化。MITRE 在真实操作中列出了 GitHub、论坛、文档以及社交/Web 服务。<sup>[[4]](#references)</sup>

## Redirector 和可复用部署聚类

即使域名和地址发生变化，operators 也经常重新部署相同的自动化机制。可基于以下组合进行聚类：

- 证书字段/key 复用和签发时间；
- TLS 版本/cipher/扩展顺序以及服务器行为；
- 完全相同的 HTTP 状态、header 顺序、缓存行为、图标/body 和错误页面；
- 异常端口对和重定向链；
- DNS provider/name-server 模式和 TTL 时间表；
- 部署时间、运行时间和维护窗口；
- 后端 origin 暴露或完全相同的 allowlist。

单个通用 Nginx 页面只能提供较弱证据。多个罕见且相互独立的匹配，加上时间连续性，可以支持基础设施集群假设。

## Residential proxy 和 impossible-session 检测

在 IP 层之上维护 session 身份。标记以下组合：

- 同一个 session/device fingerprint 以超出合理旅行速度的方式改变国家/ASN；
- consumer IP 在每次请求间变化，而 cookies 和 TLS/browser 身份保持不变；
- 声称的本地设备与出口的延迟/时区/语言不一致；
- 一个地址交替服务于互不相关的账户群体，或表现出 backconnect proxy 行为；
- privileged session 在没有组织设备证书的情况下从 residential access 出现。

Carrier NAT、无障碍工具、企业 VPN 和旅行都会产生良性异常。应要求 step-up authentication 或进行调查，而不是仅凭“residential proxy”标签实施不可逆阻断。

## Wireless 和 covert-device 检测

将 RADIUS/NAC 与 AP 及物理环境信息关联：

1. 找出首次出现的 account-device-AP 组合；
2. 识别在没有 managed EAP certificate/posture 的情况下使用的凭据；
3. 比较并发 session 以及 badge/建筑物出现记录；
4. 检查异常微弱/边缘信号以及 AP 之间的移动；
5. 在附近的 managed endpoint 中搜索 wireless scanning、新启用的 interface bridge/NAT、virtual adapter 或 tunnel；
6. 清点新的 switchport、DHCP、USB network 和 PoE 活动；
7. 当证据支持时，执行经过授权的 RF/物理扫描。

这可以发现 APT28-style nearest-neighbor path 和 exercise drop。不得将 MAC randomization 视为身份或有罪证据。

## Financial-attribution 检测

- 保存完整且准确的 chain、token、address、transaction 和 block 标识符。
- 跟踪资金经过 change、peel chain、fan-out/in、mixer、bridge 和 service deposit 的流动，同时标注所使用的启发式方法。
- 关联时间、扣除费用后的金额、contract event、流动性以及目标链上的提现。
- 获取或保存合法的 exchange、bridge、merchant、account、device 和交付记录。
- 根据适用项目筛查当前受制裁的实体/address 及其衍生项；不要依赖旧的静态列表。
- 将 privacy-protocol 的使用视为风险背景输入，而不是不当行为的证明。

FATF 的红旗指标明确具有上下文属性：异常模式、金额/频率、地理位置、资金来源和增强匿名性的服务结合起来时才具有意义。<sup>[[5]](#references)</sup>

## Deception 和 canary

防御者可以在不试图对普通用户进行去匿名化的情况下，创建高置信度信号：

- 不应离开任何单一系统的唯一凭据或文档；
- 虚假的 administrative endpoint 和 decoy share；
- 仅嵌入受控 artifact 中的 instrumented DNS name；
- 没有任何合法用途的 canary cloud key；
- 任何 managed device 都不拥有的 decoy Wi-Fi identity。

应谨慎确定 deception 的范围并进行治理。canary 应识别对防御者自身资产的滥用，而不是收集无关的第三方流量。

## Countermeasure 优先级

1. 移除不受支持的 Internet-facing router、VPN 和 appliance。
2. 要求使用抗 phishing 的 MFA 和 device-bound certificate，包括内部/wireless access。
3. 集中保存具有足够不可变性的 identity、endpoint、DNS、flow、proxy、cloud 和 network-device 日志。
4. 限制管理面和 egress；清点每项可从外部访问的 service。
5. 监控 DNS、certificate transparency 和 cloud configuration，以发现未授权资产。
6. 保留 process-to-network 和对象级 SaaS 可见性。
7. 演练跨层调查以及与相邻 provider 的协调。
8. 跟踪基础设施集群和行为，而不仅是 IP blocklist。

## Analytical discipline

使用置信度措辞：

- **Observed：** sensor/provider 记录直接显示了该关系。
- **Strongly supported：** 多个独立观察结果相较于其他可能性更支持该结论。
- **Assessed：** 基于明确假设和证据得出的推断。
- **Unknown：** 缺少可见性，无法得出结论。

始终至少保留两个假设：actor-operated infrastructure 与 compromised/shared intermediary；单一 actor 与 multi-tenant service；蓄意规避与合法的隐私/CDN 行为。解释不确定性的能力是正确检测的一部分。

## References

- [1] [Google Cloud/Mandiant — 中国关联的间谍 actor 使用 ORB 网络](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Assets 红旗指标](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actor 入侵并维持持久访问](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — 通信基础设施的增强可见性和加固指南](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
