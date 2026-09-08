# 私密数字支付

支付隐私是对交易数据进行受控披露。它不是使非法资金合法化、逃避税收或制裁、规避 KYC、使用虚假身份，或隐藏未经授权的委托关系的方法。支付对于商户可以是私密的，但对于发卡机构、网络、雇主、税务机关或调查人员仍可能完全可见。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) 是标准化清单，其中为每个类别提供 `Pros`、`Cons`、合法的逐步 `Procedure` 以及 `Detection`。本页面扩展介绍传统支付方式。

{% hint style="danger" %}
绝不要使用被盗账户、合成身份、钱骡、虚构的居住地或资金来源声明、交易拆分（“structuring”），或不透明的“no-KYC card”经纪商。在每个相关司法管辖区内，检查现行法律和服务提供商条款。
{% endhint %}

## 定义隐私属性

在选择支付渠道之前，先确定观察者：

| 观察者 | 典型数据 | 有效控制措施 | 仍会保留的内容 |
|---|---|---|---|
| 商户 | 姓名、电子邮件、地址、卡令牌、IP/设备、购物篮 | Guest checkout、最少的可选数据、商户专用虚拟卡 | 配送、账户和欺诈遥测数据 |
| 发卡机构/支付处理商 | 法定身份、资金来源、商户、金额、时间、设备 | 选择隐私和安全条款良好的受监管服务提供商 | 服务提供商仍会处理记录，并可能保留或披露记录 |
| 雇主/委托关系所有者 | 费用、操作人员和目的 | 分离的委托预算和访问控制账本 | 合法治理要求内部归属记录 |
| 公共区块链观察者 | 地址、资金流、金额和时间，取决于区块链 | 适当的协议和钱包管理 | 获取、终点以及之后的消费可能重新关联活动 |
| 网络/RPC/节点运营商 | IP、钱包查询、交易广播 | 本地节点或合适的隐私网络 | 时间和终点行为仍可能产生关联 |
| 现场观察者 | 面部、位置、车辆、CCTV、收据 | 普通的情境隐私措施 | 现金不会让人在现实中隐形 |

CFPB 说明，支付应用可能收集身份、设备、位置、联系人、交易和行为数据；州隐私规则不一定能阻止这些数据被商业化或所有二次使用。<sup>[[1]](#references)</sup> 应阅读实际的服务提供商隐私声明，而不要根据产品名称推断其隐私性。

## 比较支付方式

| 方式 | 隐私优势 | 主要观察者/关联点 | 适当用途 |
|---|---|---|---|
| 现金 | 没有支付网络账本 | 收款人、摄像头、目击者、现金报告规则 | 在接受现金的情况下进行合法的本地购买 |
| 开环预付卡/礼品卡 | 将卡号与主卡分离 | 销售方、激活/注册服务商、资金来源、商户 | 预算管理或有限的商户隔离 |
| 虚拟/一次性卡号 | 对商户隐藏可重复使用的 PAN；易于撤销 | 发卡机构仍知道身份和交易 | 在线商户隔离 |
| 移动钱包令牌 | 设备/商户接收令牌，而不是底层 PAN | 钱包提供商、发卡机构、支付网络和商户 | 凭证安全，而非匿名 |
| 银行转账/应用 | 方便的审计轨迹 | 银行/应用、交易对手方及关联身份 | 可追责的组织付款 |
| Cryptocurrency | 取决于协议；自托管可以减少托管方暴露 | 公共账本或隐私协议、交易所、终点、交易对手方 | 在进行针对具体协议的分析后进行合法转账 |

## 现金

现金仍被认为对隐私和金融包容性很重要，并且可以避免产生支付网络记录。<sup>[[2]](#references)</sup> 但它无法规避 CCTV、目击者、设备位置、收据、特殊情况下的序列号追踪或法定报告义务。

### 合法工作流

1. 在交易前确认接受情况和当地现金限额。限额因国家和参与方类型而异，并且会随时间变化。
2. 以一次诚实交易完成普通购买。**绝不要拆分交易**以规避门槛或报告义务。
3. 拒绝可选的忠诚度追踪或营销数据收集。对于保修、安全、配送、税务或法律要求的数据，应如实提供。
4. 将必要的购买凭证和规定的会计记录保存在加密存储中，并设置保留期限。
5. 对于组织，通过批准的流程报销，并记录操作人员、授权、目的、金额、日期和收据。

在美国，某些行业或企业收到超过 10,000 美元的现金（包括关联交易）时，必须提交 Form 8300；故意拆分交易本身可能构成非法 structuring。<sup>[[3]](#references)</sup> 其他司法管辖区有所不同，例如西班牙公布了自己的法定现金支付限制。<sup>[[4]](#references)</sup>

## 预付卡和礼品卡

“Prepaid”并不意味着匿名。商店、发卡机构、项目管理方、资金银行和商户可能关联购买、激活、设备、IP、位置和消费记录。充值、ATM 使用、国际使用、更高限额或遗失保护通常要求注册。

美国消费者指南解释称，发卡机构可能为法律验证而要求身份数据，并可能在验证失败时拒绝注册卡。<sup>[[5]](#references)</sup> FinCEN 规则规定了哪些预付项目和参与方负有 AML 义务。<sup>[[6]](#references)</sup> 在欧盟，Directive (EU) 2018/843 缩小了有限的匿名电子货币例外；Regulation (EU) 2024/1624 又改变了该框架，但通常自 **2027 年 7 月 10 日**起适用，因此不要将其描述为已在 2026 年生效。<sup>[[7]](#references)</sup>

仅在以下情况下使用预付价值：从可识别的发卡机构处合法获得，条款允许预期用途，并且其作用是预算管理或与主要支付凭证分离。避免转售市场和宣传无法验证的“no-name”卡的经纪商：其中的价值可能已被盗、已被兑换、受到地域限制或面临没收。

## 虚拟卡和钱包令牌

虚拟卡号（VCN）通常是在真实且经过验证的账户之后签发的。商户专用或一次性卡号可以减少泄露以及跨商户 PAN 关联；但**不会**向发卡机构隐藏交易。网络 tokenization 同样是用受约束的令牌替代卡凭证。<sup>[[8]](#references)</sup>

### 商户隔离工作流

1. 使用准确的身份、居住地和资金信息，在受监管的发卡机构处开立账户。
2. 使用唯一密码、可用时启用抗 phishing 的 MFA、登录提醒，并将恢复代码离线保存，以保护账户安全。
3. 生成商户锁定或一次性的 VCN。如果支持，设置合理的金额/时间限制。
4. 使用 guest checkout，仅省略**可选的**资料、忠诚度和营销字段。需要时提供准确的账单、配送和税务数据。
5. 避免登录无关的身份提供商；使用委托/账户专用浏览器隔离环境和获批准的网络路径。
6. 将收据以及 VCN 到用途的映射保存在加密的内部账本中。
7. 在退款/chargeback 期限结束后冻结或撤销该号码；监控主账户是否出现意外授权。

Capital One 和 Google 说明，虚拟号码仍与底层账户关联；EMVCo/Visa 则将 tokenization 描述为凭证替代和域限制，而不是付款人匿名化。<sup>[[8]](#references)</sup>

## 配送、账户和退款

支付只是关联图中的一条边：

- 通过重复使用个人电子邮件、电话号码、浏览器配置文件、IP 地址或忠诚度账户，可以破解唯一卡号带来的隔离效果。
- 实物配送通常需要合法收件人和地点。不要使用无关人员的地址或冒充居民。经批准的企业收货服务比捏造信息更安全。
- 数字商品可能记录账户身份、IP、设备指纹、许可证激活和下载记录。
- 退款通常会退回原支付渠道。要求收款后再转发/退款至其他地方，是欺诈和钱骡行为的警告信号。
- 商户描述、发票文本和配送通知可能将敏感购买信息暴露给账户代理人；应有意识地设置访问权限和提醒。

## 授权的红队购买

一次委托在外部应保持低调，在内部则必须可追责：

1. 获取书面范围、目的、支出上限、批准人、允许的商户/资产以及报销规则。
2. 使用组织控制的支付账户，并为每个委托或商户使用单独的 VCN 或子账户。
3. 向服务提供商提供准确的账单和注册信息。公开注册隐私可以减少暴露，但无权以虚假信息进行登记。
4. 维护加密账本，记录操作人员、批准、目的、日期、金额、交易对手方、资产标识符和收据。
5. 按要求筛查交易对手方，并遵守服务提供商、制裁、税务和报告义务。
6. 仅向财务人员提供其所需的访问权限；仅向操作人员提供其所需的有限支出能力。
7. 在拆除阶段关闭或冻结支付凭证，核对待处理费用/退款，并根据政策保留记录。

对于 crypto 特定选择，请继续阅读 [Cryptocurrency Privacy](cryptocurrency-privacy.md)。对于这些购买所支持的基础设施，请参阅 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)。

## 验证清单

- [ ] 已记录所需的隐私属性和观察者。
- [ ] 最近已检查服务提供商、商户和司法管辖区规则。
- [ ] 身份和资金来源声明真实准确。
- [ ] 在不破坏必要验证的情况下，尽量减少商户可选数据。
- [ ] 已了解资金、设备、网络、账户、配送和退款关联。
- [ ] 不涉及规避门槛、受禁止的交易对手方、钱骡、被盗凭证或第三方身份。
- [ ] 所需收据、批准、税务记录和恢复信息已加密并实施访问控制。

## References

- [1] [US CFPB — 关于收集、使用和商业化消费者支付及其他个人金融数据的信息征求意见](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — 2024 年欧元区消费者支付态度研究（SPACE）](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 填写说明](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — 现金支付报告](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [为什么我在激活或注册预付卡时被要求提供个人信息？](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) and [我可能会被拒绝使用预付卡吗？](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — 关于预付访问的最终规则](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — 使用虚拟信用卡](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
