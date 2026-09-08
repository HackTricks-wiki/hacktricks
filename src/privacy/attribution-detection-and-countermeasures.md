# 归因、检测与对策

{{#include ../banners/hacktricks-training.md}}

归因规避基础设施旨在使单个指标可随时弃用。防御者应保留原始证据、建立关系模型，并搜寻在 IP、域名或身份变更后仍然存在的行为。

## 证据层级

| 证据 | 用途 | 主要注意事项 |
|---|---|---|
| 源 IP/ASN/地理位置 | 定位可见出口和提供商 | 出口可能是 relay、NAT 或受害者；地理位置仅为近似值 |
| 被动 DNS/注册信息 | 基础设施历史和共同托管关系 | 隐私保护/信息删改以及共享托管会造成缺口 |
| Certificate/TLS/HTTP 指纹 | 聚类重复部署 | 通用软件和仿冒会产生误报 |
| 流量时序和字节特征 | 关联 relay 阶段和重复 beacon | CDN/NAT 以及有限的可见性会降低确定性 |
| Endpoint 进程/身份 | 解释连接为何发生 | edge/IoT 设备上可能不存在；攻击者可能使用原生工具 |
| Cloud/CDN/API 审计 | 识别租户和基础设施控制权 | 保留期限以及提供商/法律访问权限各不相同 |
| 支付/账户/设备 | 将采购行为与个人/实体关联 | 必须考虑名义持有人、账户被入侵和共享设备 |
| 被扣押的 implant/configuration | 暴露密钥、对等节点、控制器和构建关联 | 采集完整性以及扣押时间十分重要 |
| 人员/物理证据 | 将数字事件与地点/操作人员关联 | 具有侵入性、取决于司法管辖区，并且需要严格处理 |

不应让任何单行证据单独支撑高置信度的国家归因。使用相互竞争的假设，并说明哪项观察结果可以证伪每个假设。

## 最低遥测要求

1. **DNS：** 客户端、查询、类型、应答、TTL、响应代码、resolver 和时间戳。
2. **网络流量：** 源/目的地址/端口、开始/结束时间、数据包/字节数、TCP flags 以及传感器位置。
3. **TLS/HTTP：** 可见时记录 SNI、证书、协商协议、客户端/服务器指纹、方法、authority/path 类别、状态和字节数。保护敏感的完整 URL。
4. **身份：** authentication 结果、factor/certificate/device、源、应用程序、session ID 和风险决策。
5. **Endpoint：** 发起进程、父进程、用户、binary signature/hash 和目的地。
6. **Edge/network device：** 配置差异、管理员登录、进程/文件/firmware 完整性、接口和流量日志。
7. **Cloud/SaaS/CDN：** 操作者、租户/项目、API 操作、源、对象/资源、token 和结果。
8. **Wireless/NAC：** 工作站、randomized-MAC 标志、AP、信号、EAP 身份/证书、分配的 VLAN/IP 和 posture。

同步时钟，保留原始时区，记录 NAT/proxy 边界，并保留足够长的历史，以超出一个 31 天 ORB 节点的生命周期。

## 构建归因图

将观察结果表示为带类型的节点和边：
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
有用的节点包括 IP、prefix、ASN、domain、DNS account、certificate/key、类似 JA3/JA4 的 fingerprint、HTTP grammar、file/config hash、cloud tenant、API token、email、persona、payment instrument 和 physical device。每条边都需要包含 `first_seen`、`last_seen`、sensor/source、confidence，以及其属于 observed 还是 inferred。

仅凭图的密度容易产生误导：CDN 或 certificate authority 会连接许多互不相关的行为者。相比常见的 hosting，应更重视罕见的、由 operator 控制的关系——例如相同的 API account、SSH key、origin allowlist、独特的 response body 或 control protocol。

## ORB and compromised-router hunting

### From an observed exit

1. 确定该地址属于 hosting、residential、mobile、education 还是 business；不要丢弃 residential sources。
2. 在限定时间范围内提取历史 DNS、services/certificates、开放端口以及已观察到的 scan/exploitation 行为。
3. 搜索共享罕见 service fingerprints、controller destinations、certificate material 或 rotation timing 的对等节点。
4. 对可能的角色进行分类：access、traversal、exit/staging 或 administration。
5. 检查多个互不相关的 intrusion clusters 是否使用了同一 pool；multi-tenancy 会削弱对直接 actor 的 attribution，但会增强 ORB hypothesis。
6. 在旧 IP 消失后，跟踪符合该角色 profile 的新节点。

### At the network owner

- 监控新的 Internet-exposed management，以及 default/legacy authentication。
- 将 router/firewall/VPN configuration changes 和 admin authentication 发送到设备外部。
- 为通常很少发起 session 的 infrastructure 建立 outbound connections 基线。
- 检测新的 proxy/listener processes、tunnels、scheduled tasks、firmware changes 和异常 DNS。
- 更换 end-of-life devices；重启虽然可以移除 volatile malware，但无法修复 exposure。
- 将 management 限制在经过 authentication 的 administration plane 和已知 sources 上。

Mandiant 建议将 ORB infrastructure 作为不断演变的实体进行跟踪，因为短期的 IP blocking 无法反映 topology 和 lifecycle。<sup>[[1]](#references)</sup>

## Fast-flux and dynamic-DNS analytics

按 registered domain 和 sliding window 进行聚合。一个实用的 score 可以结合：
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
Investigate domains with several independent features, not one threshold. 将其与 CDN/anti-DDoS allow-model 进行比较，并检查权威名称服务器轮换，以区分 single flux 与 double flux。对于 DGA，加入每个客户端的 NXDOMAIN bursts、长度/字符分布、跨主机的 synchronized queries，以及生成这些查询的进程。MITRE 当前的 guidance 同样强调高频变更、低 TTL，以及进程/网络关联。<sup>[[2]](#references)</sup>

## Domain-fronting detection

当企业 endpoint 或 authorized inspection point 同时拥有两种身份时，进行比较：
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
当 SNI 和 authority 属于无关的租户、进程不是已批准的 client、会话具有周期性或长期持续特征，且内部 origin 很少见时，应提高置信度。空 SNI 是需要记录的特征，但不应自动判定为恶意。ECH 可能会隐藏线路上的 SNI，因此 endpoint、DNS 和 provider/CDN 日志变得更加重要。MITRE 同时记录了 SNI 不匹配和 SNI 为空的变体。<sup>[[3]](#references)</sup>

## Dead-drop resolver 序列检测

高信号行为表现为一个序列，而不是单个被阻止的域名：
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
在整个 fleet 范围内搜寻相同的对象路径、响应哈希、API 标识符和后续目的地。保留已获取的内容，因为攻击者可能会编辑或删除它。限制不必要的 service API，并要求已批准的应用通过 enterprise proxy 使用服务，但要考虑 developer tools 和自动化。MITRE 在真实操作中列出了 GitHub、论坛、文档和社交/网页服务。<sup>[[4]](#references)</sup>

## Redirector 和可复用部署聚类

即使域名和地址发生变化，操作者通常仍会重新部署相同的自动化方案。可根据以下组合进行聚类：

- 证书字段/key 重用和签发时间；
- TLS 版本/cipher/扩展顺序及服务器行为；
- 完全相同的 HTTP 状态、header 顺序、缓存行为、图标/正文和错误页面；
- 异常端口对和重定向链；
- DNS provider/name server 模式和 TTL 时间表；
- 部署时间、运行时间和维护窗口；
- 后端 origin 暴露或完全相同的 allowlist。

单个通用 Nginx 页面是较弱的证据。多个罕见且相互独立的匹配，加上时间上的连续性，可以支持基础设施集群假设。

## Residential proxy 和不可能会话检测

在 IP 层之上维护会话身份。标记以下组合：

- 一个 session/device fingerprint 以超出正常旅行可能性的速度改变国家/ASN；
- consumer IP 每次请求都发生变化，而 cookies 和 TLS/browser 身份保持不变；
- 所声称的本地设备与出口节点的延迟/时区/语言不一致；
- 一个地址交替服务于无关的账户群体，或表现出 backconnect proxy 行为；
- 特权 session 在没有组织设备证书的情况下，通过 residential access 出现。

Carrier NAT、无障碍工具、企业 VPN 和旅行都会产生良性异常。应要求 step-up authentication 或进行调查，而不是仅依据“residential proxy”标签进行不可逆阻断。

## Wireless 和隐蔽设备检测

将 RADIUS/NAC 与 AP 及物理环境信息关联：

1. 找出首次出现的账户–设备–AP 组合；
2. 识别未使用受管 EAP 证书/posture 的凭据使用情况；
3. 比较并发会话与门禁/建筑物 उपस्थित情况；
4. 检查异常弱或处于边缘的信号，以及 AP 之间的移动；
5. 在附近的受管 endpoint 中搜寻 wireless scanning、新启用的接口 bridge/NAT、virtual adapter 或 tunnel；
6. 清点新的 switchport、DHCP、USB network 和 PoE 活动；
7. 当证据支持时，执行经过授权的 RF/物理扫描。

这可以同时捕获 APT28 风格的最近邻路径和演练投放设备。不得将 MAC randomization 视为身份或有罪依据。

## Financial-attribution detection

- 保留完整且精确的 chain、token、address、transaction 和 block 标识符。
- 跟踪资金经过 change、peel chain、fan-out/in、mixer、bridge 和 service deposit 的流转，同时标注所使用的启发式方法。
- 关联时间、扣除费用后的金额、contract event、流动性和目标链提现。
- 获取或保留合法的 exchange、bridge、merchant、account、device 和 delivery 记录。
- 根据适用计划筛查当前受制裁的实体/地址及其衍生对象；不要依赖旧的静态列表。
- 将 privacy-protocol 的使用视为风险上下文输入，而不是不当行为的证明。

FATF 的红旗指标明确依赖上下文：异常模式、金额/频率、地理位置、资金来源和增强匿名性的服务，需要结合起来才具有意义。<sup>[[5]](#references)</sup>

## Deception 和 canary

防御者可以创建高置信度信号，而无需尝试 deanonymize 普通用户：

- 不应离开单一系统的唯一凭据或文档；
- 虚假的管理 endpoint 和 decoy share；
- 仅嵌入受控 artifact 中的 instrumented DNS name；
- 没有任何合法用途的 canary cloud key；
- 没有任何受管设备拥有的 decoy Wi-Fi identity。

应谨慎界定 deception 的范围并进行治理。canary 应识别对防御者自身资产的滥用，而不是收集无关的第三方流量。

## Countermeasure 优先级

1. 移除不受支持的面向 Internet 的 router、VPN 和 appliance。
2. 要求使用抗 phishing 的 MFA 和设备绑定证书，包括内部/wireless access。
3. 集中管理具有足够不可变性的 identity、endpoint、DNS、flow、proxy、cloud 和 network-device 日志。
4. 限制管理面和 egress；清点每项可从外部访问的服务。
5. 监控 DNS、certificate transparency 和 cloud 配置，以发现未授权资产。
6. 保留 process-to-network 和对象级 SaaS 可见性。
7. 演练跨层调查和相邻 provider 协调。
8. 跟踪基础设施集群和行为，而不仅是 IP blocklist。

## Analytical discipline

使用置信度表述：

- **Observed：** sensor/provider 记录直接显示了该关系。
- **Strongly supported：** 多个独立观察结果相较其他解释更支持该关系。
- **Assessed：** 基于明确假设和证据得出的推断。
- **Unknown：** 缺少可见性，无法得出结论。

始终至少保留两个假设：攻击者运营的基础设施与被攻陷/共享的中间层；单一攻击者与 multi-tenant service；蓄意规避与合法的隐私/CDN 行为。解释不确定性的能力，是正确检测的一部分。

## References

- [1] [Google Cloud/Mandiant — 中国关联的间谍团伙使用 ORB 网络](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — 快速通量 DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — 虚拟资产红旗指标](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — 中国方面的攻击者入侵并维持持久访问](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — 通信基础设施增强可见性和加固指南](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
