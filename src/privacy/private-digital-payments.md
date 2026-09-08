# 私密数字支付

{{#include ../banners/hacktricks-training.md}}

支付隐私是对交易数据进行受控披露。它不是使非法资金合法化、逃避税收或制裁、规避 KYC、使用虚假身份，或隐藏未经授权的活动的方法。支付对于商户而言可以是私密的，但对发卡机构、网络、雇主、税务机关或调查人员仍可能完全可见。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) 是标准化清单，其中为每个类别提供了 `Pros`、`Cons`、合法的分步 `Procedure` 以及 `Detection`。本页面扩展介绍传统支付方式。

{% hint style="danger" %}
绝不要使用被盗账户、合成身份、钱骡、虚构的居住地或资金来源声明、交易拆分（“structuring”），或不透明的“no-KYC card”经纪商。在所有相关司法管辖区检查现行法律和服务商条款。
{% endhint %}

## 定义隐私属性

在选择支付通道前，先明确观察者：

| 观察者 | 典型数据 | 有用的控制措施 | 仍会保留的信息 |
|---|---|---|---|
| 商户 | 姓名、电子邮件、地址、卡片令牌、IP/设备、购物篮 | Guest checkout、最少的可选数据、商户专用虚拟卡 | 配送、账户和欺诈遥测数据 |
| 发卡机构/支付处理商 | 法律身份、资金来源、商户、金额、时间、设备 | 选择隐私和安全条款良好的受监管服务商 | 服务商仍会处理数据，并可能保留或披露记录 |
| 雇主/活动所有者 | 费用、操作人员和目的 | 独立的活动预算及访问控制账本 | 合法治理要求内部归属可追溯 |
| 公共区块链观察者 | 地址、资金流、金额和时间，取决于区块链 | 合适的协议和钱包操作规范 | 获取、端点及后续消费可能重新关联活动 |
| 网络/RPC/node operator | IP、钱包查询、交易广播 | 本地节点或合适的隐私网络 | 时间特征和端点行为仍可能产生关联 |
| 物理观察者 | 面部、位置、车辆、CCTV、收据 | 普通的情境隐私 | 现金不会使人员在物理层面隐身 |

CFPB 表示，支付应用可能收集身份、设备、位置、联系人、交易和行为数据；州隐私规则不一定能阻止数据变现或所有二次使用。<sup>[[1]](#references)</sup> 应阅读实际的服务商隐私声明，而不是根据产品名称推断隐私性。

## 比较支付方式

| 方式 | 隐私收益 | 主要观察者/关联点 | 适用场景 |
|---|---|---|---|
| 现金 | 没有支付网络账本 | 收款人、摄像头、目击者、现金报告规则 | 在接受现金的情况下进行合法本地购买 |
| Open-loop prepaid/gift card | 将卡号与主卡分离 | 销售方、激活/注册服务商、资金来源、商户 | 预算管理或有限的商户隔离 |
| 虚拟/一次性卡号 | 向商户隐藏可重复使用的 PAN；易于撤销 | 发卡机构仍知晓身份和交易 | 在线商户隔离 |
| 移动钱包令牌 | 设备/商户接收令牌，而非底层 PAN | 钱包服务商、发卡机构、支付网络和商户 | 凭证安全，而非匿名 |
| 银行转账/应用 | 便捷的审计轨迹 | 银行/应用、交易对手方及关联身份 | 可问责的组织支付 |
| Cryptocurrency | 取决于协议；自托管可减少托管方暴露 | 公共账本或隐私协议、交易所、端点、交易对手方 | 经过特定协议分析后的合法转账 |

## 现金

现金仍被认为对隐私和金融包容性很重要，并且不会产生支付网络记录。<sup>[[2]](#references)</sup> 但它无法规避 CCTV、目击者、设备位置、收据、特殊情况下的序列号追踪或法定报告义务。

### 合法流程

1. 在交易前确认商家是否接受现金以及当地现金限额。不同国家和交易方类型的限额不同，并且会随时间变化。
2. 以一次诚实的普通交易完成购买。**绝不要拆分交易**以规避阈值或报告义务。
3. 拒绝可选的忠诚度追踪或营销数据收集。对于保修、安全、配送、税务或法律要求的数据，应如实提供。
4. 将必要的购买凭证和规定的会计记录保存在加密存储中，并设置保留期限。
5. 对于组织，通过批准的流程进行报销，并记录操作人员、授权、目的、金额、日期和收据。

在美国，某些行业或企业收到超过 10,000 美元的现金（包括相关交易）时，必须提交 Form 8300；故意拆分交易本身可能构成违法的 structuring。<sup>[[3]](#references)</sup> 其他司法管辖区的规定不同，例如西班牙公布了自己的法定现金支付限制。<sup>[[4]](#references)</sup>

## 预付卡和礼品卡

“预付”并不意味着匿名。商店、发卡机构、项目管理方、资金银行和商户可能关联购买、激活、设备、IP、位置和消费记录。充值、ATM 访问、国际使用、更高限额或挂失保护通常需要注册。

美国消费者指南解释称，发卡机构可能要求身份数据进行法律验证，并可能在验证失败时拒绝注册卡。<sup>[[5]](#references)</sup> FinCEN 规则规定了哪些预付项目及参与者承担 AML 义务。<sup>[[6]](#references)</sup> 在欧盟，Directive (EU) 2018/843 缩减了有限的匿名电子货币例外；Regulation (EU) 2024/1624 再次改变了该框架，但通常自 **2027 年 7 月 10 日** 起适用，因此不要将其描述为 2026 年已经生效。<sup>[[7]](#references)</sup>

仅在以下条件均满足时使用预付价值：从可识别的发卡机构处合法取得；其条款允许预期用途；并且用途是预算管理或与主要支付凭证分离。避免转售市场以及宣传无法验证的“no-name”卡的经纪商：其价值可能被盗、已被兑换、存在地域限制或面临没收。

## 虚拟卡和钱包令牌

虚拟卡号（VCN）通常由真实且经过验证的账户支持。商户专用或一次性卡号可以减少数据泄露以及跨商户 PAN 关联；但它们**不会**向发卡机构隐藏交易。网络令牌化同样是用受限令牌替代卡片凭证。<sup>[[8]](#references)</sup>

### 商户隔离流程

1. 使用准确的身份、居住地和资金信息，在受监管的发卡机构处开设账户。
2. 使用唯一密码、可用时启用抗钓鱼 MFA、登录提醒，并将恢复代码离线保存，以保护账户安全。
3. 生成商户锁定或一次性 VCN。如果支持，设置合理的金额/时间限制。
4. 使用 Guest checkout，仅省略**可选的**个人资料、忠诚度和营销字段。需要时提供准确的账单、配送和税务数据。
5. 避免登录无关的身份提供商；使用活动/账户浏览器隔离环境以及获批准的网络路径。
6. 将收据和 VCN 到用途的映射关系保存在加密的内部账本中。
7. 在退款/拒付窗口结束后冻结或撤销该卡号；监控主账户是否出现意外授权。

Capital One 和 Google 说明，虚拟卡号仍与底层账户绑定；EMVCo/Visa 则将令牌化描述为凭证替换和域限制，而非付款人匿名。<sup>[[8]](#references)</sup>

## 配送、账户和退款

支付只是关联图中的一条边：

- 通过重复使用个人电子邮件、电话号码、浏览器配置文件、IP 地址或忠诚度账户，唯一卡号的隔离效果会失效。
- 实体配送通常需要合法的收件人和地点。不要使用无关人员的地址，也不要冒充居民。使用经批准的企业收货服务比伪造信息更安全。
- 数字商品可能记录账户身份、IP、设备指纹、许可证激活和下载信息。
- 退款通常会退回原支付通道。要求收款后再转发或通过其他方式退款，是欺诈和钱骡活动的警示信号。
- 商户描述、发票文本和配送通知可能将敏感购买信息暴露给账户代理人；应有意设置访问权限和提醒。

## 已授权的 red-team 购买

活动对外应保持谨慎，对内则必须可问责：

1. 获取书面范围、目的、支出上限、审批人、允许的商户/资产以及报销规则。
2. 使用组织控制的支付账户，并为每项活动或每个商户使用独立的 VCN 或子账户。
3. 向服务商提供准确的账单和注册人信息。公开注册隐私功能可以减少暴露，但不代表有权撒谎。
4. 维护加密账本，记录操作人员、审批、目的、日期、金额、交易对手方、资产标识符和收据。
5. 按要求筛查交易对手方，并遵守服务商、制裁、税务和报告义务。
6. 仅向财务人员授予其所需的访问权限；仅向操作人员授予其所需的有限支出能力。
7. 在拆除阶段关闭或冻结支付凭证，核对待处理费用/退款，并按照政策保留记录。

有关 Cryptocurrency 的具体选择，请继续阅读 [Cryptocurrency Privacy](cryptocurrency-privacy.md)。有关这些购买所支持的基础设施，请参阅 [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)。

## 验证清单

- [ ] 已记录所需的隐私属性和观察者。
- [ ] 最近已检查服务商、商户和司法管辖区规则。
- [ ] 身份和资金来源声明真实准确。
- [ ] 在不规避必要验证的情况下，已最大限度减少可选商户数据。
- [ ] 已了解资金、设备、网络、账户、配送和退款关联关系。
- [ ] 不涉及规避阈值、受禁止的交易对手方、钱骡、被盗凭证或第三方身份。
- [ ] 必需的收据、审批、税务记录和恢复信息均已加密并实施访问控制。

## References

- [1] [美国 CFPB — 关于收集、使用和变现消费者支付及其他个人财务数据的信息征询](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [欧洲中央银行 — 2024 年欧元区消费者支付态度研究（SPACE）](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [美国 IRS — Form 8300 填写说明](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [西班牙税务局 — 现金支付报告](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] 美国 CFPB — [为什么我需要提供个人信息才能激活或注册预付卡？](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) 和 [我可能被拒绝办理预付卡吗？](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — 预付访问最终规则](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — 使用虚拟信用卡](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
