# Operational Privacy Playbooks

这些 playbook 汇总了本节其余部分中的控制措施。它们是起点，而非保证：每当有新的观察者、账户、设备、位置、支付方式、文件或交易对手进入工作流程时，都应更新威胁模型。

## Universal preflight

1. 写明合法目标，以及哪些信息必须对**谁**保持私密。
2. 记录活动将接触的身份、设备、网络、账户、支付渠道、交易对手、实际位置和数据。
3. 识别最可能的最强观察者，以及失败后果。
4. 确认授权、适用法律、provider 条款和组织政策。
5. 决定哪些内容必须在内部保持可归因，以满足安全、事件响应、会计和审计要求。
6. 选择可行的最小隔离环境；在使用前建立其恢复和关闭路径。
7. 使用受控服务测试该隔离环境，包括 IP/DNS/IPv6、浏览器身份、文档 metadata、支付账单和通知泄露。

参阅 [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md) 中的详细模型。

## Everyday privacy baseline

目标：减少商业追踪、账户接管和不必要的信息暴露，但不试图实现匿名。

- 使用受维护的 OS，并启用全盘加密、自动更新、屏幕锁定，以及在可用时启用 secure boot。
- 首先配置好 password manager、恢复邮箱以及抗 phishing 的 MFA/security keys。
- 检查 app 权限、位置历史、广告标识符、cloud sync 和第三方账户连接。
- 使用主流浏览器，安装少量 extensions，启用 tracking protection 和 HTTPS，并为工作、个人和高风险 browsing 使用独立 profiles。
- 按关系使用 private relay aliases 或不同的 email 地址；如果个人 phone number 只是可选项，则不要使用。
- 对消息内容优先使用端到端加密，同时记住参与者、时间、群组和 endpoints 仍会构成 metadata。
- 有意识地从文件中移除 metadata，并在发布前检查导出的副本，而不是原始文件。
- 使用 virtual-card 或 wallet tokens 进行支付凭证隔离；不要将其称为 anonymous。
- 备份加密的恢复材料并测试恢复。

## Pseudonymous publication

目标：防止普通读者和平台轻易将 publication 与公民身份关联起来。这无法抵御有能力的定向调查。

1. 明确平台、hosting provider、读者、联系人、本地网络、支付 provider 或法律程序是否属于威胁模型。
2. 从干净基线创建专用 endpoint/account context。禁用个人浏览器 sync、cloud documents、联系人上传和通知预览。
3. 通过选定的网络隔离环境创建 pseudonymous account。不要重复使用 usernames、avatars、恢复渠道、写作模板或个人 identity-provider login。
4. 当 destination unlinkability 比速度更重要时使用 Tor Browser；不要添加 extensions、过度调整或自定义它，也不要在普通 desktop session 在线时打开下载的文档。
5. 使用不会嵌入个人模板名称、修订作者、打印机路径、GPS/EXIF、thumbnails 或隐藏图层的流程进行撰写。导出副本，并使用适当的 metadata tools 检查。
6. 检查内容中可能识别自身的信息：独特日期、工作场所细节、本地天气/时区、反射、背景音频、语言习惯，以及此前 publication 文本的重复使用。
7. 使用独立的回复渠道。将每个直接联系人、附件和 link 视为潜在的关联或 phishing 尝试。
8. 如果涉及资金，使用只暴露必要数据的合法方式。即使读者不知道收款人，也应假设平台和受监管 intermediary 可能知道 payee。
9. 发布后，从另一个干净 context 检查公开结果。记录平台添加或转换的内容。
10. 只有在不会形成稳定行为 fingerprint 的情况下，才维持计划好的发布节奏；应当退役该隔离环境，而不是在不知不觉中重新挪作他用。

对于严肃 journalism、activism、家庭暴力或国家级风险，应向有经验的 digital-security organization 获取定制帮助；静态清单无法建模当地法律或现实中的对手。

## Authorized red-team engagement

目标：在保留授权、控制和事件响应能力的同时，使 operators 的个人身份和家庭网络不出现在目标 telemetry 中。

### Before the start window

- 完成 ROE infrastructure annex、targets/exclusions、source ranges、日期、emergency stop 以及第三方/provider permissions。
- 分配专用 operator profile 或 VM、engagement secrets、evidence store、cloud project、domains 和预算。
- 优先使用 client 提供的 egress 或组织控制的固定 bastion。测试 full-tunnel IPv4/IPv6/DNS 行为和 fail-closed policy。
- 将 operator 到公共 infrastructure 的映射存放在 exercise controller 或约定的 escrow contact 处。
- 设置 rate limits、destination allowlists，并为 destructive、wireless、physical、phishing 或 credential-collection actions 设置单独审批。
- 使用组织控制的 payment rail，并在内部记录审批。

### During the engagement

- 从获批的 endpoint 和 tunnel 开始；在 assessment traffic 发出前验证所观察到的 egress。
- 不要将个人账户、设备、phone numbers、repositories、SSH/GPG keys 和 cloud sync 带入隔离环境。
- 记录 operator/job、开始/停止时间、source、scoped destination 和 configuration change，但不要收集不必要的 client content。
- 如果 scope 存在歧义、出现意外的第三方系统、收到 provider abuse notification、产生安全影响、设备丢失或与 controller 的联系中断，应停止。
- 绝不要擅自使用邻居的 Wi-Fi、盗取的 credentials、未经批准的 SIM/account，或藏在场所中的 hardware。

### End of engagement

- 停止 jobs 和 C2；回收获批的 drop devices；撤销 tokens、credentials 和 certificates。
- 根据 inventory 核对 infrastructure、domains、source addresses、expenses、data 和 provider cases。
- 按照合同返还、删除或保留 client data，保留最低限度的必需 audit evidence，并由第二名 operator 验证关闭完成。

参阅 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)，了解完整的构建和 teardown 指南。

## Lawful private purchase or donation

目标：在履行 issuer、会计、税务和 sanctions 义务的同时，尽量减少向 merchant 或公众披露的信息。

1. 列出谁不应知道哪些内容：公众、merchant、payment intermediary、雇主/家庭账户 delegate、delivery service 或 blockchain observer。
2. 检查当地规则、recipient/counterparty、provider 条款、现金限额和记录保存需求。
3. 选择支付渠道：
- 对于接受且合法、不会产生 payment-network 记录的本地支付，使用现金；
- 对于在线凭证隔离，使用受监管的 virtual/merchant-specific card；
- 只有在分析 acquisition、ledger、wallet backend、network、counterparty 和后续支出关联后，才使用 cryptocurrency。
4. 提供真实且必需的详细信息，仅省略可选的 loyalty/marketing 信息。不要使用他人的身份/地址，也不要通过拆分交易来规避阈值。
5. 分离 merchant browser/account context，避免无关的 social login、loyalty 或个人 recovery channels。
6. 确认 statements、receipts、notifications、shipping 和公开 donor lists 中会显示哪些信息。
7. 加密存储必需的 receipt/tax/authorization evidence；退款窗口结束后撤销一次性 payment credentials。

参阅 [Private Digital Payments](private-digital-payments.md) 和 [Cryptocurrency Privacy](cryptocurrency-privacy.md)。

## Travel and untrusted networks

目标：保护用户不管理的网络上的数据和账户，而不是隐藏未经授权的活动。

- 在旅行前更新设备，并下载所需的 credentials/maps。
- 尽量减少存储的数据；使用全盘加密、强 unlock、远程恢复规划，以及根据法律建议采取关机状态下的边境/实体风险措施。
- 验证场所的 SSID/captive portal。在适当情况下优先使用个人 hotspot，但要记住 cellular subscriber 和位置记录。
- 对组织数据使用完整/强制的获批 VPN；验证 tethered devices 是否共享该 VPN，并测试 IPv6/DNS 行为。
- 使用 travel router 实现 client isolation 和可重复的 policy，但不要将其视为 anonymity guarantee。
- 将公共 USB charging、借用的 computers、公共 printers 和共享会议室系统视为独立威胁。
- 假设 physical presence、radio identifiers、portal login、cameras 以及 payment/location records 都可能关联这次访问。

比较和设置详情见 [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)。

## Failure and exposure response

当一个隔离环境发生 leak 或可能被关联时：

1. 如果继续活动会增加危害，则停止活动；在适用时使用 engagement emergency stop。
2. 在不扩散敏感数据的情况下保留必要证据。记录准确时间、观察到的指标和受影响资产。
3. 通知适当的 owner/controller/security contact。不要为了维持隐私叙事而隐瞒事件。
4. 撤销 sessions、tokens、payment credentials 和 infrastructure access；从已知干净的 endpoint 轮换 secrets。
5. 确定发生关联的边：endpoint、account recovery、network、payment、metadata、content、behavior、counterparty 或 physical presence。
6. 将整个受影响的隔离环境视为 burned。不要只是更改其 username 或 exit IP。
7. 履行 breach、provider、client、financial 和 legal notification 义务。
8. 只有在改变导致关联的流程后才重新构建；记录控制措施并进行测试。

## Periodic audit

- [ ] 按照有日期的计划审查威胁模型以及法律/provider 假设。
- [ ] 对设备、账户、aliases、domains、network paths 和 payment credentials 建立 inventory。
- [ ] 恢复路径不会意外跨越隔离环境。
- [ ] 已测试 full-tunnel、DNS、IPv6 和 fail-closed 行为。
- [ ] 已检查公开文件和 profiles 中的 metadata/content reuse。
- [ ] Wallet nodes/backends 和 crypto protocol 假设保持最新。
- [ ] Logs 和 receipts 数量最少、已加密、受访问控制保护，并处于保留期限内。
- [ ] 旧的隔离环境和 engagement infrastructure 已完全退役。
