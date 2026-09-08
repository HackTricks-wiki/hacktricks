# Cryptocurrency Privacy

Cryptocurrency privacy 是协议与操作层面的问题，不是 secrecy 或 immunity 的同义词。Public ledgers、exchanges、wallet servers、network peers、merchants 以及后续交易会暴露图谱的不同部分。

请从 [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) 开始，了解每种 technique 的 pros/cons/procedure/detection 格式。本页面进一步说明 cryptocurrency 特有的机制和操作限制。

{% hint style="danger" %}
本章用于合法的 self-custody 和 data minimization。不要利用它洗钱、规避 sanctions/tax/reporting、与被禁止的 parties 交易、误导受监管 provider，或运营未获许可的 transmission service。Privacy technology 不会改变资金的合法来源或所有权。
{% endhint %}

## 按层划分的威胁模型

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Identity, funding account, destination, device, IP, time |
| Ledger | Anyone running analytics | Addresses/outputs, amounts and time on transparent chains; protocol-specific metadata elsewhere |
| Wallet backend | RPC provider, explorer, remote node | Address queries, balances, IP, transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP, timing, volume and protocol use |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account and timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, keys, labels, history, screenshots and clipboard |

Self-custody 可以将 custodian 从控制路径中移除，但不会抹去 ledger、acquisition record、network metadata 或 endpoint evidence。

## Protocol 对比

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody；fresh addresses 可避免简单的 address reuse | Public permanent transaction graph；amount/timing 和 spending heuristics |
| Bitcoin PayJoin | Receiver input 可以破坏 common-input-ownership heuristic | 两个 wallets 都需要支持；transaction 仍然公开；支持程度不一 |
| Bitcoin CoinJoin | 在协同 participants 之间制造歧义 | 可识别的 patterns、pre/post links、consolidation、policy/legal/provider risk |
| Lightning | Onion-routed payments 不会像普通 transfers 一样全局发布 | Channels 在链上 open/close；endpoints、peers、probes 或 custodian 可能推断数据 |
| Monero | 对 receiver、amount 和 sender set 提供更强的默认 on-chain confidentiality | Exchange、node、timing、endpoint 和 counterparty links 仍然存在 |
| Ethereum/stablecoins | 广泛可用并具备 smart-contract interoperability | Public state/actions；RPC metadata；centralized issuers 可能 block/freeze/report |

## Bitcoin：保护隐私的基线

Bitcoin 是 pseudonymous，而不是 anonymous。Confirmed transactions 是公开且持久的；address reuse、common-input ownership、change detection 以及公开识别的 addresses 都可能构建 clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **选择受维护的 self-custody wallet。** 从 official project 下载，在提供时验证 signatures/hashes，并应用 security updates。
2. **在可信 endpoint 上创建 wallet。** 将 recovery seed 离线记录；绝不要将其放入 email、chat、screenshots 或普通 cloud notes。存入大量资金前测试 recovery。
3. **仅将操作所需的 value 保持 hot。** 对长期 value 使用合适的 offline/hardware custody，并制定 recovery plan，避免将 seed 暴露在单一脆弱位置。
4. **为每笔 transaction 生成新的 receive address/invoice。** 当 invoice server 或 authenticated private delivery 可用时，不要发布 static address。
5. **可行时使用自己的 full node。** Third-party explorer/electrum server 可能获知查询的 addresses 和 IP metadata。只配置 wallet 支持的 Tor/proxy behavior；Tor 隐藏的是 network edge，而不是 blockchain graph。
6. **私下标记每个 UTXO**，记录 source、owner、purpose 和 compliance state。启用 coin control，避免将无关的 identity contexts 一起 spend。
7. **预览 transaction：** selected inputs、change destination、amount、fee、counterparty，以及此次 spend 是否会合并 compartments。避免不必要的 consolidation。
8. **单独并加密保存合法 records。** 保留 acquisition basis、invoices、authorization 和 tax/reporting information，但不要公开其映射关系。
9. **将后续 spending 视为同一 privacy decision 的一部分。** 一笔原本隔离良好的 receipt，可能在其 output 与已识别 funds 一起 co-spent 时被重新关联。

Bitcoin Core 的 privacy documentation 说明，full node 可以避免向 third-party servers 泄露 wallet queries，但 transaction broadcast 和 public history 仍需分析。<sup>[[2]](#references)</sup>

## PayJoin

PayJoin 是一种 collaborative payment，receiver 会加入一个 input。这会破坏“所有 inputs 都属于 sender”这一简单假设。BIP 78 描述了原始的 interactive protocol；draft BIP 77 定义了使用 encrypted mailbox/OHTTP 的 asynchronous v2 design。<sup>[[3]](#references)</sup>

安全使用：

1. 确认两个受维护的 wallets 支持相同的 PayJoin version。
2. 通过 authenticated channel 获取 PayJoin-capable invoice；像保护任何 payment request 一样保护它。
3. 检查原始 amount 和 destination，然后让 wallet 验证 proposal/PSBT、fee contribution 以及 prohibited substitutions。
4. 确认最终的 wallet summary。不要手动批准意外的 output、amount 或 excessive fee。
5. 如果 negotiation 失败，了解 wallet 是否会安全地 fallback 到 ordinary payment，或是否需要新的 invoice。
6. 私下保留 ownership、accounting 和 disputes 所需的 receipt/records。

PayJoin 可以改善一种 chain-analysis heuristic；但它不会对 parties、acquisition platform、endpoints 或 public ledger 隐藏 payment。

## CoinJoin：优点与限制

CoinJoin 将多个 users 协调到同一 transaction 中，使 input-output mapping 变得不确定。针对特定历史 Wasabi 和 Samourai designs 的研究发现了高度可识别的 transactions，并表明 pre/post-mix behavior 可以大幅缩小 anonymity。<sup>[[4]](#references)</sup> 这一结果不应推广到每一种 implementation 或 future version，但它说明“anonymity-set”数字并非保证。

在任何合法使用前：

- 检查当前 local law、sanctions status、exchange/custodian policy 和 tax/reporting duties；
- 使用从 official project 获取的、受维护的 non-custodial software；
- 了解 coordinator model、fees、denial-of-service controls，以及当前 service 是否仍在运营——zkSNACKs 已于 2024 年结束其 coordinator，但其他 Wasabi coordinators 可能仍存在；
- 私下保存 source-of-funds 和 transaction records；
- 绝不要代表他人接受 unknown funds，也不要使用承诺可进行 untraceable withdrawals 的 custodial “mixer”；
- 按 source/context 分隔 outputs，避免后续 consolidation 破坏原本想要的 ambiguity。

法律结果取决于具体事实和司法管辖区。2025 年 Samourai 的 guilty pleas 涉及明知而运营未获许可的 money transmitter，并转移 criminal proceeds；这并不意味着每一笔 collaborative transaction 或每一个寻求 privacy 的 user 都是 criminal。<sup>[[5]](#references)</sup>

## Lightning Network

Lightning 的 Sphinx onion routing 设计为让 intermediate hop 获知其 predecessor 和 successor，而不是整个 route。<sup>[[6]](#references)</sup> 它并非 blanket anonymity：channel funding/closure 是公开的，nodes 会公布 topology，counterparties 知道 endpoints，routing/probing 可以推断 balances 或 parties，而 custodial wallet 可以看到其 user 的 account activity。

为了获得更好的 privacy：

1. 如果 intermediary privacy 很重要，优先选择受维护的 non-custodial wallet；先规划 channel backup/recovery。
2. 每笔 payment 使用新的 invoice 或 offer。确认 wallet 是否确切支持 BOLT 12/route blinding，不要想当然地认为支持。
3. 避免公布不必要的 node aliases、contact details 和 stable network endpoints。
4. 在适当时通过受支持的 privacy network 连接，同时理解 uptime/timing patterns 仍可能产生关联。
5. 不要认为 off-chain payment 没有 records：sender、receiver、peers、watchtowers、liquidity providers 和 wallet services 可能保留 observations。

已发表的研究证明，可以通过 public data 和 active probing 推断 sender/recipient 及 channel-balance，但 attacks 和 mitigations 会不断演变。<sup>[[7]](#references)</sup>

## Monero

Monero 使用 one-time stealth addresses 作为 outputs，使用 RingCT 隐藏 amounts，并使用 ring signatures 提供 probabilistic sender ambiguity；其当前 technical specifications 记录的 ring size 为 16（15 个 decoys）。<sup>[[8]](#references)</sup> 与 transparent ledgers 相比，这些机制为 on-chain confidentiality 提供了更强的默认保护，但无法神奇地防止 endpoint 或 operational mistakes。

### 合法 workflow

1. **合法获取。** 即使后续 on-chain details 具有 confidentiality，regulated exchange 仍可能知道 purchase 和 withdrawal。保留 source、basis 和 reporting records。
2. **安装 official maintained wallet**，并按照 project instructions 验证下载内容。离线备份 seed，并用少量金额测试 restoration。
3. **优先使用 local node**，以最大化 wallet-query privacy。如果不切实际，选择可通过 official supported onion/I2P configuration 访问的 trusted remote node。Remote node 可以记录 IP、requests、timing 和 transaction IDs；某些 lightweight designs 会披露 view key。
4. **为每个 payer、campaign 或 invoice 使用新的 subaddress。** Payer 可能将同一 subaddress 的重复使用关联起来。<sup>[[9]](#references)</sup>
5. **在本地标记 incoming contexts。** 避免在 knowledgeable payer 可能识别后续行为的情况下，操作性地合并隔离的 receipts。
6. **保护 network metadata。** 遵循 official anonymity-network configuration；注意 timestamps、intermittent synchronization、bandwidth shape 和 stream reuse 所造成的 documented leaks。<sup>[[10]](#references)</sup>
7. **私下保存 compliance/audit data。** 仅在明确决定后，向目标 auditor/party 披露 view key 或 transaction proof，并准确理解其揭示的内容。

历史 traceability studies 包含后来已经改变的 bugs 和 decoy-selection eras；不要将旧的成功率套用到当前 transactions。同样，截至本章 2026 年 9 月的 research cutoff，FCMP++ 仍属于 roadmap work，而不是已部署的 protection。<sup>[[11]](#references)</sup>

## Ethereum 和 stablecoins

Ethereum 自身的 privacy material 指出，on-chain actions 是可见的，而 wallet/RPC infrastructure 会增加 IP 和 metadata exposure。<sup>[[12]](#references)</sup> Token transfers、approvals、smart-contract interactions、name services 和 gas funding 都可能连接 identities。

Centralized stablecoins 还增加 issuer control。当前 USDC 和 Tether terms 保留 block/freeze addresses 或 assets，以及履行 legal/process obligations 的权力。<sup>[[13]](#references)</sup> 它们可能是有用的 payment instruments，但当需求是 censorship resistance 或 on-chain anonymity 时，它们并不是理想选择。

## Compliance 边界

- FATF recommendations 通过 national law 实施，并会随时间变化；其 2026 update 强调 VASP licensing/registration 和 Travel Rule implementation。<sup>[[14]](#references)</sup>
- 在美国，FinCEN 将使用 convertible virtual currency 购买个人 goods/services 的人，与接受并 transmission 或 exchange 它的 business 区分开来；具体事实和后续 rules 都很重要。<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation 要求在 crypto-asset service provider 参与时提供 originator/beneficiary information，并为向 self-hosted addresses 或从其发起的某些 transfers 增加 verification rules。<sup>[[16]](#references)</sup>
- Sanctions 和 tax duties 仍然适用。按要求进行 screening，拒绝 prohibited parties，并保存 records；lists 和 legal status 可能迅速变化。<sup>[[17]](#references)</sup>

在涉及重大 value、跨境 activity、privacy-enhancing coordination 或类似 business 的 exchange/transmission 之前，应针对相关 jurisdictions 获取最新的 professional advice。

关于 Bitcoin Silent Payments、fully shielded Zcash、GNU Taler、federated Chaumian e-cash 和 BOLT 12，请继续阅读 [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)。

## References

- [1] [Bitcoin.org — 保护你的隐私](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy features](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — 一个简单的 PayJoin 提案](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz 等 — Bitcoin 中去中心化 CoinJoin implementations 的采用率与实际 privacy（AFT 2022）](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet 创始人认罪（2025）](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos 等 — Lightning Network 中 privacy 的实证分析](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html)、[RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html)、[Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) 和 [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad 和 Victor — 探索 Monero privacy 的演变（2024）](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum 上的 privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — 2026 Targeted Update on Virtual Assets and VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — FinCEN regulations 对管理、exchange 或使用 virtual currencies 的 persons 的适用](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry 的 Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
