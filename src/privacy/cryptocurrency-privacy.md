# Cryptocurrency Privacy

{{#include ../banners/hacktricks-training.md}}

Cryptocurrency の privacy は、秘密性や免責性の同義語ではなく、protocol と operations に関する問題です。公開 ledger、exchange、wallet server、network peer、merchant、後続の transaction は、それぞれ graph の異なる部分を露出させます。

技術ごとの pros/cons/procedure/detection 形式については、まず [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) を参照してください。このページでは、cryptocurrency 固有の仕組みと operational な制限を詳しく説明します。

{% hint style="danger" %}
この章は、合法的な self-custody と data minimization を対象としています。収益の洗浄、制裁・税務・報告の回避、禁止対象者との取引、規制対象 provider の欺罔、または無許可の transmission service の運営に使用しないでください。Privacy technology は、資金の法的な出所や所有権を変えるものではありません。
{% endhint %}

## レイヤー別の threat model

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange、bank、broker、P2P counterparty | Identity、funding account、destination、device、IP、time |
| Ledger | Analytics を実行するすべての者 | Transparent chain 上の address/output、amount、time、それ以外では protocol 固有の metadata |
| Wallet backend | RPC provider、explorer、remote node | Address query、balance、IP、transaction broadcast |
| Network | ISP、peer、anonymity-network entry | IP、timing、volume、protocol use |
| Counterparty | Payer/payee | Invoice/address、delivery、conversation、account、timing |
| Endpoint | Malware、cloud backup、physical seizure | Seed、key、label、history、screenshot、clipboard |

Self-custody によって control path から custodian を除外できますが、ledger、acquisition record、network metadata、endpoint evidence が消えるわけではありません。

## Protocol の比較

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody。fresh address により単純な address reuse を回避 | Public な永続 transaction graph、amount/timing、spending heuristic |
| Bitcoin PayJoin | Receiver の input により common-input-ownership heuristic を無効化できる | 両方の wallet が対応する必要がある。transaction は公開されたまま。対応状況にばらつきがある |
| Bitcoin CoinJoin | 協調した参加者間に ambiguity を作る | Recognizable pattern、pre/post link、consolidation、policy/legal/provider risk |
| Lightning | Onion-routed payment は通常の transfer として全体公開されない | Channel の open/close は on-chain。endpoint、peer、probe、custodian から data を推測される可能性 |
| Monero | Receiver、amount、sender set について on-chain confidentiality の default が強い | Exchange、node、timing、endpoint、counterparty の link は残る |
| Ethereum/stablecoins | 広い availability と smart-contract interoperability | Public state/action、RPC metadata。中央集権的 issuer が block/freeze/report できる |

## Bitcoin: privacy-preserving baseline

Bitcoin は pseudonymous であり、anonymous ではありません。Confirmed transaction は公開され、永続します。address reuse、common-input ownership、change detection、公開された identity 付き address によって cluster が構築されます。<sup>[[1]](#references)</sup>

### Workflow

1. **Maintained な self-custody wallet を選ぶ。** Official project から download し、提供されている場合は signature/hash を verify し、security update を適用します。
2. **Trusted endpoint 上で wallet を作成する。** Recovery seed は offline に記録し、email、chat、screenshot、通常の cloud note には絶対に保存しません。大きな金額を入れる前に recovery をテストします。
3. **Hot wallet には operational value だけを保持する。** 長期保有分には適切な offline/hardware custody を使用し、seed が単一の脆弱な場所に露出しない recovery plan を用意します。
4. **すべての transaction で fresh な receive address/invoice を生成する。** Invoice server または authenticated private delivery が利用できる場合、static address を公開しないでください。
5. **可能であれば自分の full node を使用する。** Third-party explorer/electrum server は、query された address と IP metadata を知ることができます。Wallet が対応する Tor/proxy behavior のみを設定してください。Tor は network edge を隠しますが、blockchain graph は隠しません。
6. **すべての UTXO に source、owner、purpose、compliance state を private に label 付けする。** Coin control を有効にし、無関係な identity context が同時に spend されないようにします。
7. **Transaction を preview する:** 選択した input、change destination、amount、fee、counterparty、そして spend が compartment を統合するかを確認します。不要な consolidation は避けます。
8. **合法的な record は分離して encrypted に保管する。** Acquisition basis、invoice、authorization、tax/reporting information を保存し、mapping は公開しません。
9. **後続の spending も同じ privacy decision の一部として扱う。** 十分に分離した receipt でも、identified fund と同時にその output を spend すると再 link される可能性があります。

Bitcoin Core の privacy documentation は、full node によって wallet query を third-party server に開示せずに済む一方、transaction broadcast と public history には依然として analysis が必要であると説明しています。<sup>[[2]](#references)</sup>

## PayJoin

PayJoin は、receiver が input を追加する collaborative payment です。これにより、すべての input が sender に属するという単純な仮定を無効化します。BIP 78 は元の interactive protocol を説明し、draft BIP 77 は encrypted mailbox/OHTTP を使用する asynchronous v2 design を定義しています。<sup>[[3]](#references)</sup>

安全に使用するには:

1. 両方の maintained wallet が同じ PayJoin version に対応していることを確認します。
2. PayJoin 対応 invoice を authenticated channel 経由で取得し、他の payment request と同様に保護します。
3. Original amount と destination を確認し、wallet に proposal/PSBT、fee contribution、禁止された substitution を validate させます。
4. 最終的な wallet summary を確認します。予期しない output、amount、過大な fee を手動で承認しないでください。
5. Negotiation に失敗した場合、wallet が通常の payment に安全に fallback するのか、新しい invoice が必要なのかを把握します。
6. Ownership、accounting、dispute に必要な private receipt/record を保持します。

PayJoin は chain-analysis heuristic の一つを改善しますが、payment を parties、acquisition platform、endpoint、public ledger から隠すものではありません。

## CoinJoin: 利点と制限

CoinJoin は複数の user を一つの transaction に参加させ、input と output の mapping を不確実にします。特定の過去の Wasabi および Samourai design に関する研究では、非常に recognizable な transaction が見つかり、pre/post-mix behavior によって anonymity が大幅に狭められることが示されました。<sup>[[4]](#references)</sup> この結果をすべての implementation や将来の version に一般化すべきではありませんが、“anonymity-set” number が保証ではない理由を示しています。

合法的に使用する前に:

- 現地の最新の law、sanctions status、exchange/custodian policy、tax/reporting duty を確認する。
- Official project から取得した maintained な non-custodial software を使用する。
- Coordinator model、fee、denial-of-service control、現在も service が運用されているかを理解する。zkSNACKs は 2024 年に coordinator を終了しましたが、他の Wasabi coordinator が存在する可能性があります。
- Source-of-funds と transaction record を private に保存する。
- 他人の behalf で unknown fund を受け取ったり、追跡不能な withdrawal を約束する custodial “mixer” を使用したりしない。
- Output を source/context ごとに分離し、意図した ambiguity を破壊する後続の consolidation を避ける。

法的な結果は事実関係と jurisdiction に依存します。2025 年の Samourai に関する guilty plea は、criminal proceeds を移動させる無許可の money transmitter を knowingly 運営したことに関するものであり、すべての collaborative transaction や privacy を求める user が criminal であることを示すものではありません。<sup>[[5]](#references)</sup>

## Lightning Network

Lightning の Sphinx onion routing は、中間 hop が route 全体ではなく predecessor と successor を知るよう設計されています。<sup>[[6]](#references)</sup> これは全面的な anonymity ではありません。Channel funding/closure は公開され、node は topology を advertise し、counterparty は endpoint を知り、routing/probing により balance や party を推測でき、custodial wallet は user の account activity を把握します。

より良い privacy のために:

1. Intermediary privacy が重要な場合は maintained な non-custodial wallet を優先し、まず channel backup/recovery を計画します。
2. 各 payment で fresh invoice または offer を使用します。Wallet が BOLT 12/route blinding に正確に対応しているかを確認し、対応していると仮定しないでください。
3. 不要な node alias、contact detail、stable network endpoint の公開を避けます。
4. 適切であれば supported privacy network 経由で接続します。ただし uptime/timing pattern が相関付けられる可能性は残ります。
5. Off-chain payment に record が存在しないと考えないでください。Sender、receiver、peer、watchtower、liquidity provider、wallet service が observation を保持する可能性があります。

公開研究では、public data と active probing から sender/recipient および channel-balance を推測できることが示されています。ただし、attack と mitigation は進化しています。<sup>[[7]](#references)</sup>

## Monero

Monero は output に one-time stealth address、amount の秘匿に RingCT、sender の確率的な曖昧性に ring signature を使用します。現在の technical specification では ring size は 16（decoy 15 個）とされています。<sup>[[8]](#references)</sup> これらは transparent ledger より on-chain confidentiality の default が強いという意味であり、endpoint や operational mistake からの万能な保護ではありません。

### 合法的な workflow

1. **合法的に acquire する。** Regulated exchange は、後続の on-chain detail が confidential であっても、purchase と withdrawal を把握している可能性があります。Source、basis、reporting record を保持します。
2. **Official maintained wallet を install する。** Project の指示に従って download を verify します。Seed を offline に backup し、少額で restoration をテストします。
3. **最大限の wallet-query privacy のため local node を優先する。** それが難しい場合は、officially supported onion/I2P configuration 経由で到達できる trusted remote node を選びます。Remote node は IP、request、timing、transaction ID を log できます。一部の lightweight design では view key が開示されます。
4. **Payer、campaign、invoice ごとに新しい subaddress を使用する。** Payer は同じ subaddress の繰り返し使用を相関付けられます。<sup>[[9]](#references)</sup>
5. **Incoming context を local に label 付けする。** Knowledgeable payer が後続の behavior を認識できる場合、分離した receipt を operational に merge しないようにします。
6. **Network metadata を保護する。** Official anonymity-network configuration に従い、timestamp、断続的な synchronization、bandwidth shape、stream reuse から documented leak が発生する可能性を認識します。<sup>[[10]](#references)</sup>
7. **Compliance/audit data を private に保つ。** View key または transaction proof は、意図的に、対象の auditor/party にのみ開示し、何が明らかになるのかを正確に理解します。

過去の traceability study には、bug や decoy-selection era が含まれており、その後変更されています。過去の成功率を現在の transaction に適用しないでください。同様に、FCMP++ はこの章の 2026 年 9 月の research cutoff 時点では roadmap work のままであり、deployed protection ではありません。<sup>[[11]](#references)</sup>

## Ethereum と stablecoins

Ethereum 自身の privacy material は、on-chain action が可視であり、wallet/RPC infrastructure が IP と metadata の exposure を追加すると説明しています。<sup>[[12]](#references)</sup> Token transfer、approval、smart-contract interaction、name service、gas funding はすべて identity を接続する可能性があります。

Centralized stablecoin には issuer control が加わります。現在の USDC と Tether の terms は、address や asset を block/freeze し、legal/process obligation に従う権限を留保しています。<sup>[[13]](#references)</sup> これらは有用な payment instrument かもしれませんが、censorship resistance や on-chain anonymity が要件の場合には適していません。

## Compliance の境界

- FATF recommendation は national law を通じて実装され、時間とともに変化します。2026 年の update は VASP licensing/registration と Travel Rule implementation を強調しています。<sup>[[14]](#references)</sup>
- 米国では、FinCEN は convertible virtual currency を自分の商品・service のために使用する person と、business としてそれを受け取り、transmit、exchange する person を区別しています。事実関係と後続の rule が重要です。<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation は、crypto-asset service provider が関与する場合に originator/beneficiary information を要求し、self-hosted address との間で行われる特定の transfer に verification rule を追加しています。<sup>[[16]](#references)</sup>
- Sanction と tax duty は引き続き適用されます。必要に応じて screen を行い、禁止対象者を拒否し、record を維持してください。List と legal status は急速に変化する可能性があります。<sup>[[17]](#references)</sup>

相当な value、cross-border activity、privacy-enhancing coordination、または business-like な exchange/transmission の前に、関連する jurisdiction について最新の professional advice を取得してください。

Bitcoin Silent Payments、fully shielded Zcash、GNU Taler、federated Chaumian e-cash、BOLT 12 については、引き続き [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) を参照してください。

## References

- [1] [Bitcoin.org — Privacy を保護する](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy feature](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Simple PayJoin proposal](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Bitcoin における decentralized CoinJoin implementation の adoption と実際の privacy（AFT 2022）](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet の founders が guilty plea（2025）](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Lightning Network における privacy の empirical analysis](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth address](https://www.getmonero.org/resources/moneropedia/stealthaddress.html)、[RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html)、[Ring signature](https://www.getmonero.org/resources/moneropedia/ringsignatures.html)、および [Technical specification](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Network](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Monero の privacy の evolution を探る（2024）](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum における privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Virtual Asset と VASP に関する 2026 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Virtual Currency を administer、exchange、use する person への FinCEN regulation の適用](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry 向け Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
