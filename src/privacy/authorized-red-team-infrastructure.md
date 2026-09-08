# Authorized Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

对于持久部署的现场设备，请使用 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) 设计和 suspected-discovery runbook。

对于专业 red team 而言，目标是实现**受控归因**，而不是逃避问责。目标方不应轻易看到 operator 的家庭 IP 或个人账户，而 engagement owner 必须能够识别来源、停止操作、处理滥用报告、保存证据并证明授权有效。

本页面是合法 engagement 的部署基线。对于其旨在模拟的 adversary tradecraft——包括被攻陷的 ORBs、住宅 relays、fronting、dead drops 以及附近的 wireless pivots——请从 [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) 和 [Government and APT Case Studies](government-and-apt-case-studies.md) 开始，然后在 [authorized labs](authorized-adversary-emulation-labs.md) 中复现所需的 telemetry。

NIST 将 rules of engagement (ROE) 定义为预先设定的约束，用于授予开展明确定义测试活动的权限。<sup>[[1]](#references)</sup> Privacy architecture 不能扩大该权限范围。

## 选择 egress 模式

| 模式 | 最适用场景 | 目标方看到的内容 | Provider/local observer 看到的内容 | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | 大多数 assessments | Client address range | Client identity and operator access | 最强 |
| Red-team organization bastion | 可重复的受控 egress | Organization range | Hosting provider and organization | 强 |
| Engagement-specific VPS | 隔离 clients/campaigns | VPS address | Host account, billing, control-plane and access logs | 记录完整时较强 |
| Approved commercial VPN | Provider 和 ROE 允许的 research/scanning | Shared/dedicated VPN egress | VPN account and source connection | 中等 |
| Tor Browser | 需要 destination unlinkability 的 Web research | Tor exit | Local network sees Tor/bridge; destination sees Tor | 不适合 allowlisted source attribution |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network and remote tunnel provider | 纳入资产清单时较强 |
| Lawful guest Wi-Fi | 低风险 administrative/research use | Venue public IP or tunnel egress | Venue, ISP, VPN/Tor | 较弱且可通过物理方式观察 |

对于大多数工作，client-provided 或 organization-controlled 的固定 egress 比 consumer anonymity services 更安全、更快速。它还允许 defenders 根据 exercise design 对已知 source ranges 进行 allowlist、监控，或有意**不进行 allowlist**。

## ROE infrastructure annex

在部署前记录：

- 授权方和接收授权方的 legal entities；
- 确切目标和明确排除项；
- start/end times、time zone 以及允许使用的 techniques；
- source IPs、autonomous-system/provider names、domains、redirectors、mail infrastructure 以及现场设备 identifiers；
- 是否允许 phishing、C2、credential capture、wireless testing、physical access、denial-of-service、persistence 或 third-party services；
- client 和 provider approvals，包括任何 pre-notification reference；
- emergency stop phrase、24/7 client 和 provider abuse contacts，以及最大响应时间；
- 可能收集的数据类别、encryption、access、retention 和 deletion；
- evidence 和 logging requirements，包括由谁持有从 public infrastructure 到 operator 的映射；
- teardown、domain expiration、certificate revocation、credential rotation、device recovery 以及最终 attestation。

确认 public IPs 和 domains 确实由 authorizing party 控制，或已明确纳入 scope。NIST SP 800-115 建议在测试前确认 public target addresses 受该组织管辖。<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **创建 engagement account/project**：在 red-team organization 下创建，并使用准确的 billing 和 ownership details。将 roles、API keys、budgets 和 audit logs 与其他 clients 分离。
2. **检查每个 provider policy。** Cloud、VPS、CDN、domain、email 和 VPN providers 的规则各不相同。例如，AWS 允许指定的 assessments，但要求 hosted C2/covert simulations 事先获得 approval，并禁止列出的活动。<sup>[[3]](#references)</sup>
3. **分配固定的 egress addresses** 并将其写入 ROE annex。避免快速轮换 IP/resources；这会使 incident response 更复杂，并可能违反 provider policy。
4. **强化 management：** 使用 key-only SSH 或 identity-aware management plane、phishing-resistant MFA、独立 admin network、least privilege、patched images、禁止 public admin ports，以及 encrypted secret storage。
5. **创建 full-tunnel path**：从 operator endpoint 到 bastion。明确路由 DNS 和 IPv6，并在 tunnel 中断时强制 firewall deny。
6. **限制 outbound destinations 和 ports**：在可行时限制到 authorized scope。对 scanners 进行 rate-limit，并将不可逆或破坏性 techniques 置于单独的 approval gate 之后。
7. **为 accountability 而非 surveillance 进行 logging：** 记录 operator authentication、configuration changes、start/stop、source address、scoped destination 以及 tool/job identifiers。除非 exercise 有要求且受 data plan 保护，否则避免捕获 payload/credentials。
8. **通过组织拥有的 controlled endpoint 进行验证：** 检查 observed IPv4/IPv6、DNS path、reverse DNS、clock、source-port behavior、failure/reconnect 以及 provider abuse contact。
9. **安全地共享 attribution map**：将其提供给 exercise controller 或约定的 escrow contact。如果 blind detection 是测试的一部分，不要将其发布给 target team。

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPS 仅对目的地保持 pseudonymous。主机可能拥有联系、计费、身份、源 IP、API、设备、位置和使用记录；仅客户可见的 AWS CloudTrail 历史记录也可能暴露管理活动。<sup>[[4]](#references)</sup> 使用 cryptocurrency 支付 hosting 费用并不会抹除这些记录。

## Domains and certificates

- 使用由组织拥有、专用于本次 engagement 的 registrar 账户。
- 启用 registrar lock、支持时启用 DNSSEC、MFA/security keys，并且仅在获批期间启用 auto-renew。
- 使用 registration privacy 减少公开暴露，但不要虚假陈述 registrant 信息。ICANN policy 要求 registrar 收集 registration data，即使公开显示内容已被隐藏或通过代理提供。<sup>[[5]](#references)</sup>
- 避免使用非法冒充无关方的名称。Typosquatting/lookalike domains 必须获得 client 和 provider 的明确批准。
- 清点 DNS、certificates、CDN/redirector 配置，以及可能 leak operators 或 clients 的第三方 analytics。
- Teardown 时删除 records、撤销 certificates/tokens、保留约定的 evidence，并决定是否应出于防御目的保留该 domain。

## Authorized on-site drop nodes

仅当 property/network owner 和 client 明确授权其准确放置位置及行为时，Raspberry Pi 或类似 appliance 才可接受。安全计划如下：

1. 记录设备 serial、MAC/private-MAC policy、照片、owner、准确批准位置、电源来源、retrieval deadline 和 tamper contact。
2. 使用最小化的 signed image、encrypted secrets、read-only 或可恢复的 storage、host firewall、在可行时启用 automatic security updates，并且不使用 default credentials。
3. 配置仅向指定 engagement endpoint 发起 outbound-only communication。不要暴露未经 authentication 的 listener。
4. Allowlist destinations 和 capabilities。Packet capture、credential collection、wireless impersonation 和 lateral movement 均必须分别获得明确授权。
5. 使用 mutual authentication、short-lived keys、remote kill、health reporting 和 bandwidth limits。
6. 确保设备丢失或被盗不会泄露可复用的 credentials 或 client data。
7. 将 retrieval 及 secure wipe/decommission 安排到日历中；取得已签署的 recovery record。

未经 owner/operator 的书面许可，不要将硬件隐藏在咖啡馆、酒店、共享办公室、邻居的 property 或公共场所。

## Guest networks and travel routers

如果经授权的场景需要 guest access：

- 与 venue/client 核实 SSID 和 acceptable-use policy；
- 使用组织拥有的 travel router 或 low-trust bridge device，隔离 privileged workstation；
- 在 privileged workstation 之外完成 captive portals；
- 在 assessment traffic 开始前启动已批准的 tunnel；
- 确认 tethered devices 确实使用该 tunnel；
- 假设 venue 能够关联 radio association、portal、physical presence 以及 camera/payment records；
- 绝不绕过 access control、clone 其他 device、攻击 Wi-Fi 或遗留设备。

## Operational separation

- 每个 client/engagement 使用独立的 endpoint compartment、cloud project、secrets set、domain group、redirector set 和 evidence store。
- 不得在已批准的组织系统之外使用个人 email、browser sync、phone number、cloud drive、SSH/GPG key、code-signing identity 或 payment reimbursement。
- 除非 exercise design 接受 fingerprinting，否则不要在 clients 之间复用具有独特特征的 payload configuration、callback paths、certificates 或 public repositories。
- 为 infrastructure 设定 kill date 和 budget alert。被遗弃的 systems 会同时对 client 和 Internet 构成风险。
- 保留足够的内部 attribution，以便调查事故。“No logs”通常与专业 evidence 和 safety obligations 不相容。

## Blind to defenders, attributable to the controller

当 exercise objective 是衡量 detection 而不是测试 allowlist 时，target SOC 可以保持 blind，同时不使 operation 失去 accountability：

1. Exercise controller 批准每个 public source、domain、certificate 和 on-site device，但不向 SOC 提供清单。
2. Controller 将 source-to-engagement/operator map 存储在独立的 encrypted vault 中，并设置 two-person emergency access。
3. 每个 operator job 都会收到包含 scope、time window、source compartment 和不可逆 job identifier 的 signed manifest。Target 在正常 operation 期间无需查看该 manifest。
4. Bastion audit events 以链式方式记录，或发送至 controller storage 的 append-only 存储，使 operator 无法在 incident 发生后悄悄重写 attribution。
5. 由 24/7 provider-abuse contact 持有 verification phrase/reference，可在不公开披露 client 的情况下确认 authorization。
6. 每条 path 都实现 out-of-band stop channel，且不依赖 assessment C2、target network 或某个 operator 的账户。
7. 在 live testing 前，从每个 source 发送 benign canaries。确认 controller 能在 ROE response time 内解析并停止它们。
8. Exercise 结束后，将 SOC telemetry 与 controller ledger 进行比对，披露 source list，并解释 missed/incorrect detections。

不要加入 anti-forensics、log destruction、compromised relays 或 false subscriber identities。这些做法会破坏 accountable testing，而不是改善测试。

## Teardown checklist

- [ ] Exercise controller 确认 stop。
- [ ] C2、tunnels、redirectors、mail、VPN 和 scheduled jobs 已禁用。
- [ ] On-site devices 已物理回收并完成核对。
- [ ] Tokens、API keys、SSH keys、certificates 和 captured credentials 已撤销/轮换。
- [ ] DNS 和 cloud resources 已删除，或已转移以供防御性保留。
- [ ] Client data 已根据合同返还、保留或销毁。
- [ ] 必需的 financial、audit 和 authorization records 仍保持 encrypted 并受到 access control。
- [ ] Provider abuse cases 已关闭，且 client 已收到最终 source indicators。
- [ ] 由第二名 operator 验证没有 infrastructure 仍处于 active 状态。

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing 的客户支持政策](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — 隐私声明](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
