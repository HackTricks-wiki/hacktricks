# Privacy-Preserving Payment Protocols

Advanced payment systems can hide a payer from the merchant, hide a recipient or amount from a public ledger, or prevent a mint from linking withdrawal to redemption. These are different properties. None erases acquisition, device, network, delivery, accounting, sanctions or endpoint records.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) 为每类支付提供标准化的 `Pros`、`Cons`、逐步式 `Procedure` 和 `Detection` 条目。本页面扩展介绍 advanced protocols。

{% hint style="danger" %}
仅使用合法资金并与合法交易对手进行交易。不要使用 privacy protocols 来规避强制身份识别、sanctions、税务、资金来源审查或交易报告要求。在未了解 licensing、custody、AML 和 consumer-protection 义务前，不要运营 exchange、mint 或 transmission service。
{% endhint %}

## Compare the advanced options

| Protocol | Hides from public/merchant | Trusted or observing party | Maturity/availability |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | 外部观察者无法将可重复使用的 payment code 与其一次性 outputs 关联 | Public Bitcoin graph 仍然存在；wallet/index server 可能看到扫描活动 | Specification 已完成；wallet 支持情况各不相同 |
| Zcash fully shielded Orchard | Sender、receiver 和 amount 在链上均经过加密 | Wallet backend/network 和 acquisition/off-ramp 仍然可见 | 已部署；各 wallet/exchange 对 shielded 的支持情况各不相同 |
| GNU Taler | Merchant 无需了解 payer 身份；merchant income 仍保持可追责 | Taler exchange/bank 可看到资金来源；merchant 可看到订单 | 部署范围受地域限制 |
| Federated Chaumian e-cash | Federation 不应将已发行的 notes 与内部转账或 redemption 关联 | Guardian quorum 托管 reserves；gateways 可看到边界活动 | 新兴的 community deployments |
| Lightning BOLT 12/route blinding | 减少 receiver/node 和 route disclosure | Endpoints、selected hops、funding chain 和 wallet services 仍然可见 | 支持情况取决于 wallet |
| Virtual card/token | Merchant 获得受限 credential，而不是可重复使用的 PAN | Issuer/network 保留 payer 和 transaction 信息 | 成熟且广泛可用 |

## Bitcoin Silent Payments (BIP 352)

Silent Payments 允许 receiver 发布一个静态 payment code，同时每个 sender 派生出唯一的 Taproot output。外部 chain observer 无法直接将这些 outputs 与已发布的 code 关联，也不需要交互式地址请求或链上通知 output。BIP 352 已标记为 **Complete**，但会引入扫描成本，并且与尚未实现该功能的 wallets 不兼容。<sup>[[1]](#references)</sup>

### Receiver workflow

1. 选择明确支持 BIP 352 receiving 的、仍在维护的 wallet；根据 wallet 当前文档验证该功能，不要相信 social-media claim。
2. 按照 wallet 记录的 recovery method 备份 wallet seed 以及 Silent Payment descriptor/key material。在发布 code 前，使用少量 testnet/mainnet 金额测试 discovery。
3. 在 wallet 支持 BIP 352 labels 的情况下，为 campaigns、invoices 或 counterparties 生成独立的 **labels**。Labels 可帮助本地 accounting，同时不会发布可关联的 addresses。
4. 通过 authenticated channel 发布静态 Silent Payment code。它可以重复使用，但 impostor 可能替换成自己的 code。
5. 条件允许时，通过 local full node 执行扫描。第三方 index/scanning server 可能获知请求时间或 filter data，即使它无法进行 spending。
6. 为已发现的 UTXOs 保留 labels，并使用与普通 Bitcoin 相同的 coin-control rules。Spend 或 consolidate 它们可能暴露 ownership relationships。
7. 确认 recovery 可以发现 payments，而不依赖未备份的 external index。

### Sender workflow

1. 确认 wallet 支持向该 address version 发送，并 authenticate receiver 的长期静态 code。
2. 让 wallet 构造 output；绝不要手动转换或截断 code。
3. 仔细检查 selected inputs。Silent Payments 改善了 recipient-address privacy，但 sender inputs 仍位于 public graph 上。
4. 使用 wallet 支持的 fee bumping/PSBT behavior。BIP 352 要求在 inputs 发生变化时重新派生 output，某些 signing modes 并不安全。
5. 保留争议处理或 accounting 所需的 encrypted receipt 或 proof。

Silent Payments 解决了重复发布 recipient address 的问题。它们不会隐藏 amount、transaction timing、sender cluster、acquisition history 或后续 co-spending。

## Zcash fully shielded payments

Zcash 支持 transparent 和 shielded value pools。Orchard shielded transactions 使用 zero-knowledge proofs，使 nodes 能够验证有效性，同时对 transaction details 进行加密；Unified Addresses 可以包含多种 receiver types。<sup>[[2]](#references)</sup> Privacy 取决于 wallet 实际选择的路径，而不是显示地址的第一个字符。

### Shielded workflow

1. 选择明确标示 **shielded-by-default** behavior 且支持当前 Orchard 的、仍在维护的 wallet。验证下载来源，并备份/测试 seed。
2. 合法获取 ZEC，并记录依据/来源。Exchange 仍然知道 acquisition 和 withdrawal。
3. 接收到 wallet 支持的 Unified Address，然后检查 transaction 是否进入 shielded pool。确认 wallet behavior 前，不要假设会自动 shielding。
4. 优先使用 **shielded-to-shielded** transfers。Transparent-to-shielded 和 shielded-to-transparent 的边界移动会暴露 public values/timing，并可能启用 amount correlation；Orchard specification 指出，向 non-Orchard address spending 会暴露 transaction value。<sup>[[3]](#references)</sup>
5. 避免具有明显特征的 exact-amount round trips 和立即发生的 boundary crossings。这是 privacy hygiene，不是模糊 ownership 或 reporting 的许可。
6. 使用 wallet 支持的 network-privacy path。Shielded cryptography 不会对 wallet servers 或 peers 隐藏 IP/timing。
7. 保留内部 compliance records，并仅在了解其 scope 后，为明确的 audit/disclosure 使用 viewing keys。
8. 发送前确认 recipient wallet/exchange support；如果 receiver 被迫使用 transparent，会改变 privacy property。

## GNU Taler: anonymous payer, accountable merchant

GNU Taler 是一种使用 traditional currencies、blind signatures 以及 regulated exchange/bank integration 的开放式 electronic-payment protocol。其设计目标是让 customers 对 merchants 保持 anonymous，同时让 merchants 保持可识别并承担纳税责任。<sup>[[4]](#references)</sup> 它不是 cryptocurrency，其可用性取决于兼容的 regional exchange、bank、wallet 和 merchant。

### User workflow where deployed

1. 在相关 currency/jurisdiction 中确认正在运营的 Taler exchange 和 merchant；阅读其当前 terms、fees、KYC 和 privacy notices。
2. 安装 official wallet 并验证其来源。像保护现金一样保护 wallet backup/recovery data，因为 wallet value 可能是 bearer asset。
3. 使用 truthful information，通过支持的 bank/exchange flow 提取 value。即使 blind signatures 打破了 coin-to-withdrawal 的直接关联，funding institution/exchange 仍可能知道 withdrawal。
4. 在 wallet 中查看 merchant contract：merchant identity、item/summary、amount、fees、refund 和 delivery terms。
5. 进行支付，并保留 refund、warranty、accounting 或 tax 所需的 receipt data。
6. 如果需要 merchant unlinkability，不要重复使用可选的 merchant session/account identifiers。
7. 将 wallet、network 和 delivery metadata 纳入 threat model；Taler 的 payment cryptography 不会隐藏 shipping address 或 compromised endpoint。

Merchant 和 exchange 仍需承担 accountability，运营任一组件都可能属于受监管的 payment-service activity。

## Federated Chaumian e-cash

Chaumian e-cash 使用 blind signatures，使 mint 能够签署 token，同时无法看到之后被 spend 的 unblinded token。Fedimint 将 reserve custody 和 signing 分布在 guardian federation 中；其文档称，guardians 可以看到 aggregate reserves/outstanding notes，但不应看到 federation 内部的 individual balance 或谁向谁付款。<sup>[[5]](#references)</sup>

这是 **custodial bearer value**。足够数量的 guardian quorum 可以控制 reserves；federation failure、dishonest guardians、software bugs 或 lost client state 都可能导致损失。Deposits、withdrawals 和 Lightning gateways 都是可见的 boundary events，并可能根据 timing/amount 进行关联。

### Limited-risk workflow

1. 仅使用你能够承受损失的小额资金。与具有现实世界 accountability 的 guardians 相比，将 public/unknown federations 视为更高风险。
2. 通过 authenticated channel 验证 federation invite，并记录 guardian identities、quorum、jurisdiction、fees、recovery 和 shutdown policy。
3. 安装仍在维护且兼容的 wallet，验证它，并在 deposit 前了解其 backup scheme。
4. 通过记录的路径存入合法获得的 Bitcoin。记录 peg-in 以便 accounting，并假设其 timing/amount 在边界处公开或已被知晓。
5. 在 federation 内使用 fresh payment requests，并避免添加会重新建立 blind signature 所消除的关联的 account/chat/delivery identifiers。
6. 对于 Lightning payments，将 gateway 视为能够观察 invoices 和 boundary timing 的额外 observer。
7. 按照 policy 进行 redeem/withdraw，并预期 distinctive amount 和 immediate timing 可能与 deposit 或 external payment 产生关联。
8. 私下保留 tax/source/authorization records；不要要求 guardians 或 gateways 虚报 activity。

不要将 federated e-cash 描述为 trustless、self-custodial 或 guaranteed anonymous。

## BOLT 12 offers and route blinding

BOLT 12 offers 可以在不发布稳定 on-chain address 的情况下重复使用，并且可能使用 blinded paths，使 payer 无需了解 receiver 的 clear node identity/path。这是对 Lightning 现有 onion routing 的补充，但不能取代它。

使用前：

1. 确认 sender 和 receiver wallets 支持相同的当前 BOLT 12 features；不要根据通用的“Lightning” branding 推断支持情况。
2. 在带外 authenticate offer，并检查 amount、issuer/description 和 recurrence rules。
3. 使用根据 offer 生成的 fresh invoice/payment context。
4. 尽量减少 node aliases、public contact information 和稳定的 network endpoints。
5. 假设 sender/receiver、first/last hop、wallet service、channel graph 以及 on-chain funding/closure 仍会披露部分关系。

## Auditability without public disclosure

Privacy 和 audit 可以共存：

- 在 public protocol 外部加密保存 labels、invoices、authorization、cost basis 和 ownership mapping。
- 如果 protocol 提供 **view/audit key**，将其与 spending key 分离；先在 sample wallet 上测试其确切 disclosure 范围。
- 向 auditor 提供 scope 最小化的 proof，而不是 seed 或 unrestricted spending credential。
- 在 transaction time 记录 software version、protocol/pool、transaction ID 或 proof、counterparty purpose 和 exchange-rate source。
- 定义 retention 和 deletion 规则，而不是不断积累永久性的未加密 identity graph。

## Selection checklist

- [ ] 已精确定义隐藏的 field 和 observer。
- [ ] 已验证截至 transaction date 的 wallet/protocol support。
- [ ] 已记录 acquisition、network、node/RPC、counterparty、delivery 和 later-spend links。
- [ ] 已接受 custody、recovery、liquidity、issuer/federation solvency 和 refund risks。
- [ ] Required identity、tax、sanctions、source 和 organizational records 仍然准确。
- [ ] 已成功完成小额 end-to-end test，包括 recovery 和 audit proof。

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — 工作原理](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
