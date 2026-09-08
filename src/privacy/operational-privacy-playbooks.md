# Operational Privacy Playbooks

{{#include ../banners/hacktricks-training.md}}

这些 playbook 汇总了本节其他部分中的控制措施。它们是起点，而非保证：每当新的观察者、账户、设备、位置、支付方式、文件或交易对手进入工作流程时，都应更新 threat model。

## Universal preflight

1. 写明合法目标，以及必须对**谁**保持私密的信息。
2. 记录活动将涉及的身份、设备、网络、账户、支付渠道、交易对手、物理位置和数据。
3. 确定最可能的最强观察者，以及失败的后果。
4. 确认授权、适用法律、provider 条款和组织政策。
5. 确定哪些内容必须在内部保持可归因，以满足安全、incident response、会计和审计要求。
6. 选择可行的最小 compartment；在使用前建立其恢复和关闭路径。
7. 使用受控服务测试该 compartment，包括 IP/DNS/IPv6、浏览器身份、文档 metadata、支付账单和通知 leak。

使用 [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md) 中的详细模型。

## Everyday privacy baseline

目标：减少商业跟踪、account takeover 和不必要的暴露，而不是试图实现匿名。

- 使用维护良好的 OS，并启用全盘加密、自动更新、屏幕锁定，以及在可用时启用 secure boot。
- 首先配置好 password manager、恢复 email 和抗 phishing 的 MFA/security keys。
- 检查 app 权限、位置历史记录、广告标识符、cloud sync 和第三方账户连接。
- 使用主流浏览器，安装少量 extensions，启用 tracking protection 和 HTTPS，并为工作、个人和高风险浏览分别使用独立 profile。
- 按关系使用 private relay aliases 或不同的 email 地址；如果个人 phone number 只是可选项，则不要使用。
- 内容通信优先使用端到端加密，但要记住参与者、时间、群组和 endpoint 仍属于 metadata。
- 有意识地移除文件 metadata，并在发布前检查导出的副本，而不是原文件。
- 使用 virtual-card 或 wallet token 进行支付凭据 compartmentalization；不要将其称为 anonymous。
- 备份加密的恢复材料，并测试恢复。

## Pseudonymous publication

目标：防止普通读者和平台轻易将 publication 与真实身份关联起来。这无法应对有能力的定向调查。

1. 确定 platform、hosting provider、读者、联系人、本地网络、支付 provider 或法律程序是否属于 threat model。
2. 从干净基线创建专用 endpoint/account context。禁用个人浏览器 sync、cloud documents、联系人上传和通知预览。
3. 通过选定的网络 compartment 创建 pseudonymous account。不要重复使用用户名、头像、恢复渠道、写作模板或个人 identity-provider login。
4. 当 destination unlinkability 比速度更重要时，使用 Tor Browser；不要添加 extensions、过度调整或定制它，也不要在普通桌面会话在线时打开下载的文档。
5. 使用不会嵌入个人模板名称、修订作者、打印机路径、GPS/EXIF、缩略图或隐藏图层的流程进行起草。导出副本，并使用适当的 metadata tools 检查。
6. 检查内容中的自我识别事实：独特日期、工作场所细节、当地天气/时区、反射、背景音频、语言习惯以及对之前 publication 文本的重复使用。
7. 使用独立的回复渠道。将每个直接联系人、附件和 link 视为潜在的关联或 phishing 尝试。
8. 如果涉及资金，使用只暴露必要数据的合法方式。假设 platform 和受监管 intermediary 可能知道收款人，即使读者不知道。
9. 发布后，从另一个干净 context 检查公开结果。记录 platform 添加或转换的内容。
10. 只有在不会形成稳定行为 fingerprint 的情况下，才保持计划好的发布频率；应废弃该 compartment，而不是在没有说明的情况下重新利用它。

对于严肃 journalism、activism、domestic abuse 或 state-level risk，应向经验丰富的 digital-security organization 获取定制帮助；静态 checklist 无法建模当地法律或现实中的 adversary。

## Authorized red-team engagement

目标：在保留授权、控制和 incident response 的同时，使 operators 的个人身份和家庭网络不出现在目标 telemetry 中。

### Before the start window

- 完成 ROE infrastructure annex、目标/排除项、source ranges、日期、emergency stop 以及第三方/provider 权限。
- 分配专用 operator profile 或 VM、engagement secrets、evidence store、cloud project、domains 和 budget。
- 优先使用 client 提供的 egress 或组织控制的固定 bastion。测试 full-tunnel IPv4/IPv6/DNS 行为以及 fail-closed policy。
- 将 operator 到公共 infrastructure 的映射存放在 exercise controller 或约定的 escrow contact 处。
- 设置 rate limits、destination allowlists，并为 destructive、wireless、physical、phishing 或 credential-collection 操作设置单独审批。
- 使用组织控制的支付渠道，并在内部记录审批。

### During the engagement

- 从已批准的 endpoint 和 tunnel 启动；在 assessment traffic 之前验证实际观察到的 egress。
- 不要将个人账户、设备、phone numbers、repositories、SSH/GPG keys 和 cloud sync 带入该 compartment。
- 记录 operator/job、start/stop、source、scoped destination 和 configuration change，但不要收集不必要的 client content。
- 遇到 scope 不明确、意外的第三方系统、provider abuse notification、安全影响、设备丢失或与 controller 失去联系时，立即停止。
- 绝不要临时使用邻居的 Wi-Fi、盗取的 credentials、未经批准的 SIM/account，或隐藏在场所中的 hardware。

### End of engagement

- 停止 jobs 和 C2；回收已批准的 drop devices；撤销 tokens、credentials 和 certificates。
- 根据 inventory 核对 infrastructure、domains、source addresses、expenses、data 和 provider cases。
- 按合同返还、删除或保留 client data，保留最低限度的审计证据，并由第二名 operator 验证关闭完成。

完整的构建和拆除指南请参阅 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)。

## Lawful private purchase or donation

目标：在履行 issuer、会计、税务和 sanctions 义务的同时，尽量减少向 merchant 或公众披露的信息。

1. 列出谁不应获知哪些信息：公众、merchant、payment intermediary、employer/family account delegate、delivery service 或 blockchain observer。
2. 检查当地规则、recipient/counterparty、provider 条款、现金限额和记录保存需求。
3. 选择支付渠道：
- 对于接受的合法本地支付，使用不会产生 payment-network 记录的现金；
- 对于在线凭据隔离，使用受监管的 virtual/merchant-specific card；
- 只有在分析 acquisition、ledger、wallet backend、network、counterparty 和后续支出的关联之后，才使用 cryptocurrency。
4. 提供真实且必需的信息，只省略可选的 loyalty/marketing 信息。不要使用他人的身份/地址，也不要为了绕过阈值而拆分交易。
5. 分离 merchant browser/account context，并避免无关的 social login、loyalty 或个人恢复渠道。
6. 确认 statements、receipts、notifications、shipping 和公开 donor lists 中会显示哪些信息。
7. 加密存储必要的 receipt/tax/authorization 证据；在退款窗口结束后撤销一次性支付 credentials。

参阅 [Private Digital Payments](private-digital-payments.md) 和 [Cryptocurrency Privacy](cryptocurrency-privacy.md)。

## Travel and untrusted networks

目标：保护用户未管理的网络上的数据和账户，而不是隐藏未经授权的活动。

- 更新设备，并在旅行前下载所需的 credentials/maps。
- 减少存储的数据；使用全盘加密和强 unlock，制定远程恢复计划，并根据法律建议采取关机状态下的边境/物理风险措施。
- 验证场所的 SSID/captive portal。适当时优先使用个人 hotspot，但要记住 cellular subscriber 和位置记录。
- 对组织数据使用完整/强制的已批准 VPN；验证 tethered devices 是否共享该 VPN，并测试 IPv6/DNS 行为。
- 使用 travel router 实现 client isolation 和可重复的 policy，但不要将其视为匿名保证。
- 将公共 USB 充电、借用的计算机、公共打印机和共享会议室系统视为独立的威胁。
- 假设物理 উপস্থিত、radio identifiers、portal login、摄像头以及支付/位置记录都可能将此次访问关联起来。

比较和配置细节见 [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)。

## Failure and exposure response

当 compartment 发生 leak 或可能被关联时：

1. 如果继续活动会增加损害，则停止活动；适用时使用 engagement emergency stop。
2. 在不扩散敏感数据的情况下保留必要证据。记录确切时间、观察到的 indicator 和受影响的 assets。
3. 通知适当的 owner/controller/security contact。不要为了维护隐私叙事而隐瞒 incident。
4. 撤销 sessions、tokens、支付 credentials 和 infrastructure access；从已知干净的 endpoint 轮换 secrets。
5. 确定发生关联的边：endpoint、account recovery、network、payment、metadata、content、behavior、counterparty 或 physical presence。
6. 将整个受影响的 compartment 视为 burned。不要仅更换其 username 或 exit IP。
7. 履行 breach、provider、client、financial 和 legal notification 义务。
8. 只有在改变导致关联的流程后才能重建；记录该控制措施并进行测试。

## Periodic audit

- [ ] 按有日期的计划审查 threat model 以及法律/provider 假设。
- [ ] 清点 devices、accounts、aliases、domains、network paths 和 payment credentials。
- [ ] 恢复路径不会意外跨越 compartments。
- [ ] 已测试 full-tunnel、DNS、IPv6 和 fail-closed 行为。
- [ ] 已检查公开文件和 profiles 中的 metadata/content reuse。
- [ ] Wallet nodes/backends 和 crypto protocol 假设保持最新。
- [ ] Logs 和 receipts 保持最小化、加密、访问受控，并处于保留期限内。
- [ ] 旧 compartments 和 engagement infrastructure 已完全退役。
{{#include ../banners/hacktricks-training.md}}
