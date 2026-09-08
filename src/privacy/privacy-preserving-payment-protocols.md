# 隐私保护支付协议

{{#include ../banners/hacktricks-training.md}}

高级支付系统可以对商户隐藏付款方，对公共账本隐藏收款方或金额，或阻止 mint 将提现与兑换关联起来。这些属于不同的属性。它们都无法抹除获取、设备、网络、交付、会计、制裁或 endpoint 记录。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) 为每个支付系列提供标准化的 `Pros`、`Cons`、分步 `Procedure` 和 `Detection` 条目。本页面将详细介绍高级协议。

{% hint style="danger" %}
仅使用合法资金和交易对手。不要使用隐私协议来规避必要的身份识别、制裁、税务、资金来源检查或交易报告。未充分了解许可、托管、AML 和消费者保护义务前，不要运营 exchange、mint 或 transmission service。
{% endhint %}

## 高级选项比较

| Protocol | 对公共方/商户隐藏的内容 | 受信任或可观察方 | 成熟度/可用性 |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | 外部方无法将可重复使用的 payment code 与其一次性 outputs 关联 | 公共 Bitcoin graph 仍然存在；wallet/index server 可能看到扫描活动 | 规范已完成；wallet 支持情况各异 |
| Zcash fully shielded Orchard | Sender、receiver 和 amount 在链上加密 | Wallet backend/network 以及 acquisition/off-ramp 仍然可见 | 已部署；shielded 支持情况取决于 wallet/exchange |
| GNU Taler | Merchant 无需获知 payer 身份；merchant income 仍可追责 | Taler exchange/bank 可看到资金来源；merchant 可看到订单 | 部署范围受地域限制 |
| Federated Chaumian e-cash | Federation 不应将已发行 notes 与内部 transfers/redemption 关联 | Guardian quorum 托管 reserves；gateways 可看到边界活动 | 社区部署正在兴起 |
| Lightning BOLT 12/route blinding | 减少 receiver/node 和 route disclosure | Endpoints、选定的 hops、funding chain 和 wallet services | 取决于 wallet 支持 |
| Virtual card/token | Merchant 收到受限 credential，而不是可重复使用的 PAN | Issuer/network 保留 payer 和 transaction 信息 | 成熟且广泛可用 |

## Bitcoin Silent Payments (BIP 352)

Silent Payments 允许 receiver 发布一个静态 payment code，同时每个 sender 推导出唯一的 Taproot output。外部 chain observer 无法直接将这些 outputs 与已发布的 code 关联，也不需要交互式地址请求或链上通知 output。BIP 352 已标记为 **Complete**，但会引入扫描成本，并且不兼容尚未实现该功能的 wallets。<sup>[[1]](#references)</sup>

### Receiver workflow

1. 选择明确支持 BIP 352 receiving 的受维护 wallet；根据 wallet 当前文档验证该功能，不要相信社交媒体上的说法。
2. 按照 wallet 记录的恢复方法备份 wallet seed 和 Silent Payment descriptor/key material。在发布 code 前，使用少量 testnet/mainnet 金额测试发现功能。
3. 如果 wallet 支持 BIP 352 labels，为 campaigns、invoices 或 counterparties 生成独立的 **labels**。Labels 可辅助本地记账，同时不会发布可关联的地址。
4. 通过 authenticated channel 发布静态 Silent Payment code。它可以重复使用，但冒名者可能替换成自己的 code。
5. 在可行时通过本地 full node 扫描。即使第三方 index/scanning server 无法进行花费，也可能获知请求时间或 filter data。
6. 保持已发现的 UTXOs 带有 labels，并采用与普通 Bitcoin 相同的 coin-control 规则。花费或合并这些 UTXOs 可能暴露所有权关系。
7. 确认恢复流程能够发现 payments，而不依赖未备份的外部 index。

### Sender workflow

1. 确认 wallet 支持向该 address version 发送，并验证 receiver 的长期静态 code。
2. 让 wallet 构造 output；绝不要手动转换或截断 code。
3. 仔细检查选定的 inputs。Silent Payments 改善了 recipient-address privacy，但 sender inputs 仍然位于公共 graph 上。
4. 使用 wallet 支持的 fee bumping/PSBT 行为。BIP 352 要求在 inputs 变化时重新推导 output，某些 signing modes 并不安全。
5. 保留处理争议或记账所需的加密 receipt 或 proof。

Silent Payments 解决了重复发布 recipient address 的问题。它们不会隐藏 amount、transaction timing、sender cluster、acquisition history 或后续 co-spending。

## Zcash fully shielded payments

Zcash 支持 transparent 和 shielded value pools。Orchard shielded transactions 使用 zero-knowledge proofs，使 nodes 能够验证有效性，同时对 transaction details 进行加密；Unified Addresses 可以包含多种 receiver types。<sup>[[2]](#references)</sup> 隐私取决于 wallet 实际选择的路径，而不是显示地址的第一个字符。

### Shielded workflow

1. 选择明确说明 **shielded-by-default** 行为和当前 Orchard 支持情况的受维护 wallet。验证下载来源，并备份/测试 seed。
2. 依法获得 ZEC，并记录依据/来源。Exchange 仍然知道 acquisition 和 withdrawal。
3. 接收到 wallet 支持的 Unified Address，然后检查 transaction 是否进入 shielded pool。确认 wallet 行为前，不要假定会自动 shielding。
4. 优先使用 **shielded-to-shielded** transfers。Transparent-to-shielded 和 shielded-to-transparent 边界移动会暴露 public values/timing，并可能实现 amount correlation；Orchard specification 指出，向 non-Orchard address 花费会暴露 transaction value。<sup>[[3]](#references)</sup>
5. 避免具有明显特征的 exact-amount 往返和即时边界跨越。这是隐私卫生措施，不代表可以借此隐藏所有权或规避报告义务。
6. 使用 wallet 支持的 network-privacy path。Shielded cryptography 不会向 wallet servers 或 peers 隐藏 IP/timing。
7. 保留内部合规记录，并仅在了解 viewing keys 的披露范围后，为明确的 audit/disclosure 使用它们。
8. 发送前确认 recipient wallet/exchange 支持情况；如果被迫使用 transparent receiver，隐私属性会发生变化。

## GNU Taler：匿名 payer、可追责 merchant

GNU Taler 是一种使用传统货币、blind signatures 以及受监管 exchange/bank integration 的开放电子支付协议。其设计目标是让 customers 对 merchants 保持匿名，同时使 merchants 保持可识别且可纳税。<sup>[[4]](#references)</sup> 它不是 cryptocurrency，其可用性取决于兼容的区域性 exchange、bank、wallet 和 merchant。

### 已部署地区的 user workflow

1. 在相关 currency/jurisdiction 中确认正在运营的 Taler exchange 和 merchant；阅读其当前条款、fees、KYC 和隐私声明。
2. 安装官方 wallet 并验证其来源。像保护现金一样保护 wallet backup/recovery data，因为 wallet value 可能是 bearer asset。
3. 使用真实信息，通过受支持的 bank/exchange flow 提现。即使 blind signatures 打破了 coin-to-withdrawal 的直接关联，funding institution/exchange 仍可能知道该 withdrawal。
4. 在 wallet 中查看 merchant contract：merchant identity、item/summary、amount、fees、refund 和 delivery terms。
5. 完成支付，并保留退款、保修、会计或税务所需的 receipt data。
6. 如果需要 merchant unlinkability，不要重复使用可选的 merchant session/account identifiers。
7. 将 wallet、network 和 delivery metadata 纳入 threat model；Taler 的 payment cryptography 不会隐藏 shipping address 或 compromised endpoint。

Merchant 和 exchange 仍需承担责任，运营任一组件都可能属于受监管的 payment-service activity。

## Federated Chaumian e-cash

Chaumian e-cash 使用 blind signatures，使 mint 能够签署 token，而无法看到之后被花费的 unblinded token。Fedimint 将 reserve custody 和 signing 分散到 guardian federation；其文档声明，guardians 可以看到 aggregate reserves/outstanding notes，但不应看到 federation 内的 individual balance 或谁向谁付款。<sup>[[5]](#references)</sup>

这是**托管式 bearer value**。足够数量的 guardian quorum 控制 reserves；federation failure、dishonest guardians、software bugs 或 client state 丢失都可能导致损失。Deposits、withdrawals 和 Lightning gateways 是可见的边界事件，可能通过 timing/amount 进行关联。

### Limited-risk workflow

1. 仅使用你能够承受损失的少量金额。与具有现实世界问责机制的 guardians 相比，公共/未知 federations 风险更高。
2. 通过 authenticated channel 验证 federation invite，并记录 guardian identities、quorum、jurisdiction、fees、recovery 和 shutdown policy。
3. 安装受维护且兼容的 wallet，验证其来源，并在 deposit 前了解其 backup scheme。
4. 通过记录的路径存入合法取得的 Bitcoin。记录 peg-in 用于会计，并假设其 timing/amount 在边界处公开或已被知晓。
5. 在 federation 内使用全新的 payment requests，并避免添加会重新建立 blind signature 所消除关联的 account/chat/delivery identifiers。
6. 对于 Lightning payments，将 gateway 视为 invoice 和边界 timing 的额外 observer。
7. 按照 policy 进行 redeem/withdraw，并预期 distinctive amount 和 immediate timing 可能与 deposit 或 external payment 关联。
8. 私下保留 tax/source/authorization records；不要要求 guardians 或 gateways 虚报活动。

不要将 federated e-cash 描述为 trustless、self-custodial 或 guaranteed anonymous。

## BOLT 12 offers 和 route blinding

BOLT 12 offers 可以在不发布稳定的链上地址的情况下重复使用，并且可以使用 blinded paths，使 payer 无需获知 receiver 的 clear node identity/path。这补充了 Lightning 现有的 onion routing，但不会取代它。

使用前：

1. 确认 sender 和 receiver wallets 支持相同的当前 BOLT 12 features；不要因为通用的“Lightning”品牌就推断其支持。
2. 在带外验证 offer，并检查 amount、issuer/description 和 recurrence rules。
3. 使用从 offer 生成的全新 invoice/payment context。
4. 尽量减少 node aliases、public contact information 和稳定的 network endpoints。
5. 假设 sender/receiver、first/last hop、wallet service、channel graph 以及 on-chain funding/closure 仍会披露部分关系。

## 不公开披露的可审计性

隐私与 audit 可以共存：

- 在公共 protocol 之外加密保存 labels、invoices、authorization、cost basis 和 ownership mapping。
- 当 protocol 提供 view/audit key 时，将其与 spending key 分离；先在 sample wallet 上测试其确切披露范围。
- 向 auditor 提供范围最小的 proof，而不是 seed 或不受限制的 spending credential。
- 在 transaction time 记录 software version、protocol/pool、transaction ID 或 proof、counterparty purpose 和 exchange-rate source。
- 设定 retention 和 deletion 策略，不要累积永久性的未加密 identity graph。

## Selection checklist

- [ ] 已准确标明隐藏的字段和 observer。
- [ ] 已验证 wallet/protocol 在 transaction date 的支持情况。
- [ ] 已记录 acquisition、network、node/RPC、counterparty、delivery 和后续 spend links。
- [ ] 已接受 custody、recovery、liquidity、issuer/federation solvency 和 refund 风险。
- [ ] 必需的 identity、tax、sanctions、source 和 organizational records 仍然准确。
- [ ] 小额端到端测试（包括 recovery 和 audit proof）已成功。

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
