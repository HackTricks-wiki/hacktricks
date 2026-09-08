# Authorized Red-Team Infrastructure

对于持久化部署的现场设备，请使用 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) 设计和疑似发现处置流程。

对于专业 red team，目标是实现**可控归因**，而不是免于问责。目标方不应轻易看到 operator 的家庭 IP 或个人账户，而 engagement owner 必须能够识别来源、停止操作、处理 abuse 报告、保存证据并证明已获授权。

本页面是合法 engagement 的部署基线。对于其旨在模拟的 adversary tradecraft，包括被攻陷的 ORB、住宅 relay、fronting、dead drop 和附近的 wireless pivot，请从 [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) 和 [Government and APT Case Studies](government-and-apt-case-studies.md) 开始，然后在 [authorized labs](authorized-adversary-emulation-labs.md) 中复现所需的 telemetry。

NIST 将 rules of engagement (ROE) 定义为预先建立的约束，用于授予执行明确定义的测试活动的权限。<sup>[[1]](#references)</sup> Privacy architecture 不能扩大该权限。

## 选择 egress 模式

| 模式 | 最佳用途 | 目标方看到 | Provider/local observer 看到 | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | 大多数 assessment | Client 地址范围 | Client 身份和 operator access | 最强 |
| Red-team organization bastion | 可重复的受控 egress | Organization 地址范围 | Hosting provider 和 organization | 强 |
| Engagement-specific VPS | 隔离 clients/campaigns | VPS 地址 | Host account、billing、control-plane 和 access logs | 记录完整时较强 |
| Approved commercial VPN | Provider 和 ROE 允许的 research/scanning | Shared/dedicated VPN egress | VPN account 和 source connection | 中等 |
| Tor Browser | 需要与目标地址解除关联的 Web research | Tor exit | Local network 看到 Tor/bridge；目标看到 Tor | 不适合 allowlisted source attribution |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network 和 remote tunnel provider | 已纳入 inventory 时较强 |
| Lawful guest Wi-Fi | 低风险 administrative/research 使用 | Venue public IP 或 tunnel egress | Venue、ISP、VPN/Tor | 较弱且可被实地观察 |

对于大多数工作，client-provided 或 organization-controlled 的固定 egress 比 consumer anonymity services 更安全、更快速。它还允许 defenders 根据 exercise design 对已知 source ranges 进行 allowlist、监控，或有意**不**进行 allowlist。

## ROE infrastructure 附录

在部署前记录：

- 授予和接受授权的 legal entities；
- 确切的 targets 和明确的 exclusions；
- 开始/结束时间、时区和允许使用的 techniques；
- source IPs、autonomous-system/provider 名称、domains、redirectors、mail infrastructure 和现场设备 identifiers；
- 是否允许 phishing、C2、credential capture、wireless testing、physical access、denial-of-service、persistence 或 third-party services；
- client 和 provider approvals，包括任何 pre-notification reference；
- emergency stop phrase、全天候 client 和 provider abuse contacts，以及最大响应时间；
- 可能收集的数据类别、encryption、access、retention 和 deletion；
- evidence 和 logging 要求，包括由谁持有从 public infrastructure 到 operator 的映射；
- teardown、domain expiration、certificate revocation、credential rotation、设备回收和最终 attestation。

确认 public IPs 和 domains 确实由 authorizing party 控制，或已明确纳入 scope。NIST SP 800-115 建议在测试前确认 public target addresses 处于 organization 的管辖范围内。<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### 构建流程

1. **创建 engagement account/project**：使用准确的 billing 和 ownership details，在 red-team organization 下创建。将 roles、API keys、budgets 和 audit logs 与其他 clients 分离。
2. **检查每个 provider policy。** Cloud、VPS、CDN、domain、email 和 VPN providers 的规则各不相同。例如，AWS 允许指定的 assessments，但要求 hosted C2/covert simulations 事先获得 approval，并禁止列明的活动。<sup>[[3]](#references)</sup>
3. **分配固定的 egress addresses** 并将其写入 ROE 附录。避免快速轮换 IP/resources；这会使 incident response 复杂化，并可能违反 provider policy。
4. **强化 management：** 使用仅限 key 的 SSH 或 identity-aware management plane、抗 phishing 的 MFA、独立的 admin network、least privilege、已打补丁的 images、无 public admin ports，以及加密的 secret storage。
5. **创建 full-tunnel 路径**，从 operator endpoint 连接到 bastion。对 DNS 和 IPv6 进行明确路由，并在 tunnel 断开时强制执行 firewall deny。
6. **限制 outbound destinations 和 ports**，在可行时仅允许 authorized scope。对 scanners 进行 rate-limit，并将不可逆/破坏性 techniques 置于单独的 approval gate 之后。
7. **记录日志用于 accountability，而非 surveillance：** operator authentication、configuration changes、start/stop、source address、scoped destination 以及 tool/job identifiers。除非 exercise 有要求且受到 data plan 保护，否则避免捕获 payload/credentials。
8. **通过 organization 所有的受控 endpoint 进行验证：** observed IPv4/IPv6、DNS path、reverse DNS、clock、source-port behavior、failure/reconnect 以及 provider abuse contact。
9. **安全地共享 attribution map**：将其提供给 exercise controller 或约定的 escrow contact。如果 blind detection 属于测试内容，不要将其发布给 target team。

### 架构
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
VPS 仅相对于目标是 pseudonymous。主机可能保存联系、计费、身份、源 IP、API、设备、位置和使用记录；仅客户可见的 AWS CloudTrail 历史记录也可能暴露管理活动。<sup>[[4]](#references)</sup> 使用 cryptocurrency 支付 hosting 费用并不会删除这些记录。

## 域名和证书

- 使用由组织拥有、专用于该 engagement 的 registrar 账户。
- 启用 registrar lock、支持时启用 DNSSEC、MFA/security keys，并且仅在获批期间启用 auto-renew。
- 使用 registration privacy 来减少公开暴露，而不是歪曲 registrant 信息。ICANN policy 要求 registrar 收集 registration data，即使公开显示的信息已被隐藏或通过 proxy 提供。<sup>[[5]](#references)</sup>
- 避免使用非法冒充无关方的名称。Typosquatting/lookalike domains 必须获得客户和 provider 的明确批准。
- 清点 DNS、证书、CDN/redirector 配置，以及可能 leak 操作者或客户信息的 third-party analytics。
- Teardown 时，删除记录、撤销证书/token、保留约定的证据，并决定是否应出于防御目的保留该域名。

## Authorized on-site drop nodes

仅当物业/网络所有者和客户明确授权其确切放置位置及行为时，Raspberry Pi 或类似 appliance 才可接受。安全计划如下：

1. 记录设备序列号、MAC/private-MAC policy、照片、所有者、确切获批位置、电源来源、取回期限和篡改事件联系人。
2. 使用 minimal signed image、encrypted secrets、只读或可恢复存储、host firewall、可行时启用 automatic security updates，并且不得使用 default credentials。
3. 配置仅向指定 engagement endpoint 发起 outbound-only communication。不要暴露未经 authentication 的 listener。
4. 对目的地和 capabilities 实施 allowlist。Packet capture、credential collection、wireless impersonation 和 lateral movement 均必须分别获得明确授权。
5. 使用 mutual authentication、short-lived keys、remote kill、health reporting 和 bandwidth limits。
6. 确保设备丢失/被盗不会暴露可复用的 credentials 或客户数据。
7. 将取回和 secure wipe/decommission 安排到日历中；获取已签署的 recovery record。

未经所有者/运营者的书面许可，不要将硬件隐藏在咖啡馆、酒店、共享办公室、邻居的物业或公共场所。

## Guest networks and travel routers

如果授权场景需要 guest access：

- 与场所/客户核实 SSID 和 acceptable-use policy；
- 使用组织拥有的 travel router 或 low-trust bridge device，以隔离 privileged workstation；
- 在 privileged workstation 之外完成 captive portals；
- 在 assessment traffic 开始前建立获批的 tunnel；
- 确认 tethered devices 实际使用该 tunnel；
- 假设场所能够关联 radio association、portal、实体在场情况以及 camera/payment records；
- 绝不要绕过 access control、clone other device、攻击 Wi-Fi 或遗留设备。

## Operational separation

- 每个 client/engagement 使用独立的 endpoint compartment、cloud project、secrets set、domain group、redirector set 和 evidence store。
- 不得在获批的组织系统之外使用个人 email、browser sync、phone number、cloud drive、SSH/GPG key、code-signing identity 或 payment reimbursement。
- 除非 exercise design 接受 fingerprinting，否则不要在不同客户之间复用具有特征性的 payload configuration、callback paths、certificates 或 public repositories。
- 为 infrastructure 设定 kill date 和 budget alert。被遗弃的系统会同时给客户和 Internet 带来风险。
- 保留足够的内部 attribution 以调查事故。“No logs”通常与专业证据和安全义务不相容。

## 对 defenders 保持 blind，但可由 controller 追责

当 exercise objective 是衡量 detection，而不是测试 allowlist 时，target SOC 可以保持 blind，同时不使操作失去 accountability：

1. Exercise controller 批准每个 public source、domain、certificate 和 on-site device，但不将清单提供给 SOC。
2. Controller 将 source-to-engagement/operator map 存储在独立的 encrypted vault 中，并采用 two-person emergency access。
3. 每个 operator job 获取一份 signed manifest，其中包含 scope、time window、source compartment 和不可逆的 job identifier。正常运行期间，target 无需查看该 manifest。
4. 将 bastion audit events 链式关联或以 append-only 方式发送到 controller storage，使 operator 无法在 incident 后悄悄改写 attribution。
5. 24/7 provider-abuse contact 持有 verification phrase/reference，可在不公开披露客户的情况下确认授权。
6. 每条路径都实现 out-of-band stop channel，且不依赖 assessment C2、target network 或单个 operator 的账户。
7. 在 live testing 前，从每个 source 发送 benign canaries。确认 controller 能在 ROE response time 内解析并停止它们。
8. Exercise 结束后，将 SOC telemetry 与 controller ledger 对比，披露 source list，并说明 missed/incorrect detections。

不要添加 anti-forensics、log destruction、compromised relays 或 false subscriber identities。这些做法会破坏 accountable testing，而不是改善测试。

## Teardown checklist

- [ ] Exercise controller 确认停止。
- [ ] C2、tunnels、redirectors、mail、VPN 和 scheduled jobs 均已禁用。
- [ ] On-site devices 已物理取回并完成核对。
- [ ] Tokens、API keys、SSH keys、certificates 和 captured credentials 均已撤销/轮换。
- [ ] DNS 和 cloud resources 已删除，或已转移以供防御性保留。
- [ ] Client data 已根据合同返还、保留或销毁。
- [ ] 必需的财务、audit 和 authorization records 仍保持加密并受 access control 保护。
- [ ] Provider abuse cases 已关闭，且客户已收到最终 source indicators。
- [ ] 第二名 operator 已确认没有 infrastructure 仍处于 active 状态。

## References

- [1] [NIST CSRC — 交战规则](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — 信息安全测试与评估技术指南](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — 渗透测试客户支持政策](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — 隐私声明](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
