# Cryptocurrency Privacy

{{#include ../banners/hacktricks-training.md}}

Cryptocurrency privacy 是一个协议与操作问题，而不是 secrecy 或 immunity 的同义词。Public ledgers、exchanges、wallet servers、network peers、merchants 以及后续 transactions 会暴露图谱的不同部分。

请从 [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) 开始，了解每种 technique 的 pros/cons/procedure/detection 格式。本页面进一步介绍 cryptocurrency 特有的机制和操作限制。

{% hint style="danger" %}
本章仅适用于合法的 self-custody 和 data minimization。不得利用本章洗钱、规避 sanctions/tax/reporting、与受禁止的 parties 交易、误导受监管 provider，或运营未获许可的 transmission service。Privacy technology 不会改变资金的法律来源或所有权。
{% endhint %}

## Threat model by layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | 身份、funding account、destination、device、IP、时间 |
| Ledger | 运行 analytics 的任何人 | transparent chains 上的 addresses/outputs、金额和时间；其他地方则是 protocol-specific metadata |
| Wallet backend | RPC provider, explorer, remote node | address queries、balances、IP、transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP、时间、流量和 protocol 使用情况 |
| Counterparty | Payer/payee | Invoice/address、delivery、conversation、account 和时间 |
| Endpoint | Malware, cloud backup, physical seizure | Seed、keys、labels、history、screenshots 和 clipboard |

Self-custody 可以将 custodian 从控制路径中移除，但不会抹除 ledger、acquisition record、network metadata 或 endpoint evidence。

## Protocol comparison

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody；fresh addresses 可避免简单的 address reuse | Public permanent transaction graph；金额/时间和 spending heuristics |
| Bitcoin PayJoin | Receiver input 可以打破 common-input-ownership heuristic | Both wallets 需要支持；transaction 仍然公开；支持程度不一 |
| Bitcoin CoinJoin | 在参与者之间创建 ambiguity | 可识别的 patterns、pre/post links、consolidation、policy/legal/provider risk |
| Lightning | Onion-routed payments 不会像普通 transfers 一样全局发布 | Channels 在链上 open/close；endpoints、peers、probes 或 custodian 可能推断数据 |
| Monero | 对 receiver、amount 和 sender set 提供更强的默认 on-chain confidentiality | Exchange、node、timing、endpoint 和 counterparty links 仍然存在 |
| Ethereum/stablecoins | 广泛可用并具备 smart-contract interoperability | Public state/actions；RPC metadata；centralized issuers 可能 block/freeze/report |

## Bitcoin: privacy-preserving baseline

Bitcoin 是 pseudonymous，而不是 anonymous。Confirmed transactions 是公开且持久的；address reuse、common-input ownership、change detection 以及公开标识的 addresses 都可以建立 clusters。<sup>[[1]](#references)</sup>

### Workflow

1. **选择维护中的 self-custody wallet。** 从官方 project 下载，在提供时验证 signatures/hashes，并应用 security updates。
2. **在可信 endpoint 上创建 wallet。** 将 recovery seed 离线记录；绝不要将其放入 email、chat、screenshots 或普通 cloud notes 中。在存入重要价值前测试 recovery。
3. **hot wallet 仅保留操作所需的价值。** 对长期价值使用适当的 offline/hardware custody，并制定 recovery plan，避免将 seed 暴露于单个脆弱位置。
4. **为每笔 transaction 生成新的 receive address/invoice。** 当可以使用 invoice server 或 authenticated private delivery 时，不要发布 static address。
5. **可行时使用自己的 full node。** Third-party explorer/electrum server 可以获知查询的 addresses 和 IP metadata。仅配置 wallet 支持的 Tor/proxy 行为；Tor 隐藏的是 network edge，而不是 blockchain graph。
6. **私下标记每个 UTXO**，注明 source、owner、purpose 和 compliance state。启用 coin control，避免不相关的 identity contexts 被共同 spend。
7. **预览 transaction：** selected inputs、change destination、amount、fee、counterparty，以及该 spend 是否会合并 compartments。避免不必要的 consolidation。
8. **单独并加密保存合法 records。** 保存 acquisition basis、invoices、authorization 和 tax/reporting information，但不要公开其 mapping。
9. **将后续 spending 视为同一 privacy decision 的一部分。** 当某个 output 与已识别 funds 共同 spend 时，一笔原本良好隔离的 receipt 仍可能被重新关联。

Bitcoin Core 的 privacy documentation 说明，full node 可以避免向 third-party servers 暴露 wallet queries，但 transaction broadcast 和 public history 仍需要分析。<sup>[[2]](#references)</sup>

## PayJoin

PayJoin 是一种 collaborative payment，receiver 会添加一个 input。这会破坏“所有 inputs 都属于 sender”的简单假设。BIP 78 描述了原始 interactive protocol；draft BIP 77 定义了使用 encrypted mailbox/OHTTP 的 asynchronous v2 design。<sup>[[3]](#references)</sup>

安全使用：

1. 确认两个维护中的 wallets 支持相同的 PayJoin version。
2. 通过 authenticated channel 获取 PayJoin-capable invoice；像保护任何 payment request 一样保护它。
3. 检查原始 amount 和 destination，然后让 wallet 验证 proposal/PSBT、fee contribution 以及 prohibited substitutions。
4. 确认最终的 wallet summary。不要手动批准意外的 output、amount 或过高的 fee。
5. 如果 negotiation 失败，了解 wallet 是否会安全 fallback 到 ordinary payment，或是否需要新的 invoice。
6. 私下保留 ownership、accounting 和 disputes 所需的 receipt/records。

PayJoin 可以改善一种 chain-analysis heuristic；但它不会向 parties、acquisition platform、endpoints 或 public ledger 隐藏 payment。

## CoinJoin: benefits and limits

CoinJoin 将多个 users 协调到一笔 transaction 中，使 input-output mapping 更不确定。针对特定历史 Wasabi 和 Samourai designs 的研究发现，这些 transactions 具有高度可识别性，并表明 pre/post-mix behavior 可以显著缩小 anonymity。<sup>[[4]](#references)</sup> 这一结果不应推广到每一种 implementation 或未来 version，但它说明“anonymity-set”数字并不是保证。

在任何合法使用前：

- 检查当前 local law、sanctions status、exchange/custodian policy 以及 tax/reporting duties；
- 使用从官方 project 获取的、维护中的 non-custodial software；
- 了解 coordinator model、fees、denial-of-service controls，以及当前 service 是否仍在运行——zkSNACKs 已于 2024 年结束其 coordinator，但其他 Wasabi coordinators 可能仍存在；
- 私下保存 source-of-funds 和 transaction records；
- 绝不要代表他人接收 unknown funds，也不要使用承诺可进行 untraceable withdrawals 的 custodial “mixer”；
- 按 source/context 分开保存 outputs，避免之后的 consolidation 破坏预期的 ambiguity。

法律结果取决于事实和司法管辖区。2025 年 Samourai 的 guilty pleas 涉及其明知地运营未获许可的 money transmitter 并转移 criminal proceeds；这并不能证明每一笔 collaborative transaction 或每个寻求 privacy 的 user 都是 criminal。<sup>[[5]](#references)</sup>

## Lightning Network

Lightning 的 Sphinx onion routing 设计为让中间 hop 获知其 predecessor 和 successor，而不是整个 route。<sup>[[6]](#references)</sup> 它不是 blanket anonymity：channel funding/closure 是公开的，nodes 会公布 topology，counterparties 知道 endpoints，routing/probing 可以推断 balances 或 parties，而 custodial wallet 可以看到其 user 的 account activity。

为了获得更好的 privacy：

1. 如果 intermediary privacy 很重要，优先使用维护中的 non-custodial wallet；先规划 channel backup/recovery。
2. 每笔 payment 使用新的 invoice 或 offer。确认 exact wallet 是否支持 BOLT 12/route blinding，不要想当然地认为它支持。
3. 避免发布不必要的 node aliases、contact details 和 stable network endpoints。
4. 在适当时通过受支持的 privacy network 连接，同时理解 uptime/timing patterns 仍可能产生 correlation。
5. 不要认为 off-chain payment 没有 records：sender、receiver、peers、watchtowers、liquidity providers 和 wallet services 可能保留 observations。

已发布的研究证明，可以通过 public data 和 active probing 推断 sender/recipient 以及 channel-balance，尽管 attacks 和 mitigations 会不断演变。<sup>[[7]](#references)</sup>

## Monero

Monero 使用 one-time stealth addresses 作为 outputs，使用 RingCT 隐藏 amounts，并使用 ring signatures 提供 probabilistic sender ambiguity；其当前 technical specifications 记录的 ring size 为 16（15 个 decoys）。<sup>[[8]](#references)</sup> 与 transparent ledgers 相比，这些是更强的 on-chain confidentiality defaults，但并不能神奇地防护 endpoint 或 operational mistakes。

### Lawful workflow

1. **合法获取。** 即使之后的 on-chain details 具有 confidentiality，regulated exchange 仍可能知道 purchase 和 withdrawal。保存 source、basis 和 reporting records。
2. **安装官方维护的 wallet**，并按照 project instructions 验证下载内容。将 seed 离线备份，并使用少量金额测试 restoration。
3. **优先使用 local node** 以获得最大的 wallet-query privacy。如果不可行，选择可通过官方支持的 onion/I2P configuration 访问的可信 remote node。Remote node 可以记录 IP、requests、timing 和 transaction IDs；某些 lightweight designs 会披露 view key。
4. **为每个 payer、campaign 或 invoice 使用新的 subaddress。** Payer 可以关联同一 subaddress 的重复使用。<sup>[[9]](#references)</sup>
5. **在本地标记 incoming contexts。** 避免在 knowledgeable payer 可能识别后续行为的情况下，进行操作上的合并 separated receipts。
6. **保护 network metadata。** 遵循官方 anonymity-network configuration；注意 timestamps、intermittent synchronization、bandwidth shape 和 stream reuse 所产生的 documented leaks。<sup>[[10]](#references)</sup>
7. **私下保存 compliance/audit data。** 仅在有意为之时，向指定的 auditor/party 披露 view key 或 transaction proof，并确切了解其会揭示什么。

历史 traceability studies 包含此后已经改变的 bugs 和 decoy-selection eras；不要将旧的 success percentages 应用于当前 transactions。同样，截至本章 2026 年 9 月的 research cutoff，FCMP++ 仍属于 roadmap work，而不是已部署的 protection。<sup>[[11]](#references)</sup>

## Ethereum and stablecoins

Ethereum 自身的 privacy material 指出，on-chain actions 是可见的，而 wallet/RPC infrastructure 会增加 IP 和 metadata exposure。<sup>[[12]](#references)</sup> Token transfers、approvals、smart-contract interactions、name services 和 gas funding 都可以连接 identities。

Centralized stablecoins 增加了 issuer control。当前 USDC 和 Tether terms 保留 block/freeze addresses 或 assets，以及遵守 legal/process obligations 的权力。<sup>[[13]](#references)</sup> 它们可能是有用的 payment instruments，但当需求是 censorship resistance 或 on-chain anonymity 时，它们并不是理想选择。

## Compliance boundaries

- FATF recommendations 通过 national law 实施，并会随时间变化；其 2026 update 强调 VASP licensing/registration 和 Travel Rule implementation。<sup>[[14]](#references)</sup>
- 在美国，FinCEN 将使用 convertible virtual currency 购买自己的 goods/services 的 person，与接受并传输或兑换该货币的 business 区分开来；具体事实和后续 rules 都很重要。<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation 要求在 crypto-asset service provider 参与时提供 originator/beneficiary information，并针对某些往返 self-hosted addresses 的 transfers 增加 verification rules。<sup>[[16]](#references)</sup>
- Sanctions 和 tax duties 仍然适用。按要求进行 screening，拒绝 prohibited parties，并保存 records；lists 和 legal status 可能快速变化。<sup>[[17]](#references)</sup>

在涉及 substantial value、cross-border activity、privacy-enhancing coordination 或类似 business 的 exchange/transmission 之前，应针对相关 jurisdictions 获取当前的 professional advice。

关于 Bitcoin Silent Payments、fully shielded Zcash、GNU Taler、federated Chaumian e-cash 和 BOLT 12，请继续阅读 [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)。

## References

- [1] [Bitcoin.org — 保护你的 privacy](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy features](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — 一个简单的 Payjoin 提案](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz 等 — Bitcoin 中去中心化 CoinJoin implementations 的采用情况和实际 privacy（AFT 2022）](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet 创始人认罪（2025）](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos 等 — Lightning Network 中 privacy 的实证分析](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html)、[RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html)、[Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) 和 [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad 和 Victor — 探索 Monero privacy 的演变（2024）](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum 上的 privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — 2026 年关于 Virtual Assets 和 VASPs 的 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — FinCEN Regulations 对管理、兑换或使用 Virtual Currencies 的 persons 的适用](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry 的 Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
