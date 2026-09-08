# Cryptocurrency Privacy

Cryptocurrency の privacy は、秘密性や免責性の同義語ではなく、protocol と operations に関する問題です。Public ledger、exchange、wallet server、network peer、merchant、後続の transaction は、それぞれ graph の異なる部分を露出させます。

技術ごとの pros/cons/procedure/detection 形式については、まず [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) を参照してください。このページでは、cryptocurrency 固有の mechanics と operational limits を詳しく説明します。

{% hint style="danger" %}
この chapter は、合法的な self-custody と data minimization を対象としています。収益の laundering、sanctions/tax/reporting の回避、prohibited party との取引、規制対象 provider の欺罔、無許可の transmission service の運営に使用しないでください。Privacy technology は、資金の合法性や所有権を変えるものではありません。
{% endhint %}

## Threat model by layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange、bank、broker、P2P counterparty | Identity、funding account、destination、device、IP、time |
| Ledger | Analytics を実行するすべての人 | Transparent chain 上の address/output、amount、time、およびその他の場所における protocol-specific metadata |
| Wallet backend | RPC provider、explorer、remote node | Address query、balance、IP、transaction broadcast |
| Network | ISP、peer、anonymity-network entry | IP、timing、volume、protocol use |
| Counterparty | Payer/payee | Invoice/address、delivery、conversation、account、timing |
| Endpoint | Malware、cloud backup、physical seizure | Seed、key、label、history、screenshot、clipboard |

Self-custody によって control path から custodian を排除できる場合はありますが、ledger、acquisition record、network metadata、endpoint evidence が消えるわけではありません。

## Protocol comparison

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody、fresh address による単純な address reuse の回避 | Public で永続的な transaction graph、amount/timing、spending heuristic |
| Bitcoin PayJoin | Receiver input により common-input-ownership heuristic を破れる | 両方の wallet が対応する必要がある、transaction は public のまま、対応状況にばらつきがある |
| Bitcoin CoinJoin | Coordinated participant 間に ambiguity を作る | Recognizable pattern、pre/post link、consolidation、policy/legal/provider risk |
| Lightning | Onion-routed payment は通常の transfer として global に公開されない | Channel の open/close は on-chain、endpoint、peer、probe、custodian が data を推測できる場合がある |
| Monero | Receiver、amount、sender set に対する on-chain confidentiality の default がより強い | Exchange、node、timing、endpoint、counterparty の link は残る |
| Ethereum/stablecoins | Broad availability と smart-contract interoperability | Public state/action、RPC metadata、centralized issuer による block/freeze/report |

## Bitcoin: privacy-preserving baseline

Bitcoin は pseudonymous であり、anonymous ではありません。Confirmed transaction は public かつ durable であり、address reuse、common-input ownership、change detection、publicly identified address によって cluster を構築できます。<sup>[[1]](#references)</sup>

### Workflow

1. **Maintained self-custody wallet を選ぶ。** Official project から download し、提供されている場合は signature/hash を verify して、security update を適用します。
2. **Trusted endpoint 上で wallet を作成する。** Recovery seed は offline に記録し、email、chat、screenshot、通常の cloud note には決して保存しません。Significant value を入れる前に recovery を test します。
3. **Hot には operational value だけを保持する。** Long-term value には適切な offline/hardware custody を使用し、seed が単一の脆弱な場所に露出しない recovery plan を用意します。
4. **すべての transaction で fresh receive address/invoice を生成する。** Invoice server または authenticated private delivery が可能な場合、static address を公開しないでください。
5. **可能な場合は自分の full node を使用する。** Third-party explorer/electrum server は、query された address と IP metadata を把握できます。Wallet が対応する Tor/proxy behavior のみを設定してください。Tor は network edge を隠しますが、blockchain graph は隠しません。
6. **すべての UTXO に source、owner、purpose、compliance state を private に label 付けする。** Coin control を有効にして、無関係な identity context が co-spend されないようにします。
7. **Transaction を preview する:** selected input、change destination、amount、fee、counterparty、および spend によって compartment が merge されるかを確認します。不要な consolidation は避けます。
8. **合法的な record は分離して encrypted に保持する。** Acquisition basis、invoice、authorization、tax/reporting information を、mapping を公開せずに保存します。
9. **後続の spending も同じ privacy decision の一部として扱う。** 十分に分離された receipt でも、identified fund と output を co-spend すると relink される可能性があります。

Bitcoin Core の privacy documentation は、full node によって wallet query が third-party server に露出することを避けられる一方、transaction broadcast と public history には依然として analysis が必要であると説明しています。<sup>[[2]](#references)</sup>

## PayJoin

PayJoin は、receiver が input を追加する collaborative payment です。これにより、すべての input が sender に属するという単純な仮定を無効化できます。BIP 78 は original interactive protocol を説明し、draft BIP 77 は encrypted mailbox/OHTTP を使用する asynchronous v2 design を定義しています。<sup>[[3]](#references)</sup>

安全な使用方法:

1. 両方の maintained wallet が同じ PayJoin version に対応していることを確認します。
2. PayJoin 対応 invoice を authenticated channel 経由で取得し、通常の payment request と同様に保護します。
3. Original amount と destination を確認し、wallet に proposal/PSBT、fee contribution、prohibited substitution を validate させます。
4. Final wallet summary を確認します。予期しない output、amount、過大な fee を手動で approve しないでください。
5. Negotiation が失敗した場合、wallet が通常の payment に安全に fallback するのか、新しい invoice が必要なのかを確認します。
6. Ownership、accounting、dispute に必要な private receipt/record を保持します。

PayJoin は chain-analysis heuristic の 1 つを改善しますが、payment を parties、acquisition platform、endpoint、public ledger から隠すものではありません。

## CoinJoin: benefits and limits

CoinJoin は、複数の user を 1 つの transaction に coordinate し、input と output の mapping を不確実にします。特定の過去の Wasabi および Samourai design に関する research では、非常に識別しやすい transaction が発見され、pre/post-mix behavior によって anonymity が大幅に絞り込まれる可能性が示されました。<sup>[[4]](#references)</sup> この結果をすべての implementation や future version に一般化すべきではありませんが、「anonymity-set」の数が guarantee ではない理由を示しています。

合法的に使用する前に:

- 現地の最新の law、sanctions status、exchange/custodian policy、tax/reporting duty を確認する。
- Official project から取得した、maintained で non-custodial な software を使用する。
- Coordinator model、fee、denial-of-service control、および current service が稼働しているかを理解する—zkSNACKs は 2024 年に coordinator を終了しましたが、他の Wasabi coordinator が存在する可能性があります。
- Source-of-funds と transaction record を private に保存する。
- 他人の behalf で unknown fund を受け取ったり、追跡不能な withdrawal を約束する custodial “mixer” を使用したりしない。
- Output を source/context ごとに分離し、意図した ambiguity を破壊する後続の consolidation を避ける。

Legal outcome は事実および jurisdiction に依存します。2025 年の Samourai guilty plea は、criminal proceeds を移動させる無許可の money transmitter を knowingly 運営したことに関するものであり、すべての collaborative transaction や privacy を求める user が criminal であることを示すものではありません。<sup>[[5]](#references)</sup>

## Lightning Network

Lightning の Sphinx onion routing は、中間 hop が route 全体ではなく predecessor と successor を把握するよう設計されています。<sup>[[6]](#references)</sup> これは blanket anonymity ではありません。Channel funding/closure は public であり、node は topology を advertise し、counterparty は endpoint を把握し、routing/probing によって balance や party を推測でき、custodial wallet は user の account activity を把握します。

より良い privacy のために:

1. Intermediary privacy が重要な場合は maintained non-custodial wallet を優先し、まず channel backup/recovery を計画します。
2. Payment ごとに fresh invoice または offer を使用します。正確な wallet が BOLT 12/route blinding に対応しているかを確認し、対応していると assume しないでください。
3. 不要な node alias、contact detail、stable network endpoint の公開を避けます。
4. 適切な場合は supported privacy network 経由で接続します。ただし、uptime/timing pattern が引き続き correlate される可能性を理解してください。
5. Off-chain payment に record がないと考えないでください。Sender、receiver、peer、watchtower、liquidity provider、wallet service が observation を保持する可能性があります。

公開された research では、public data と active probing による sender/recipient および channel-balance inference が実証されていますが、attack と mitigation は進化しています。<sup>[[7]](#references)</sup>

## Monero

Monero は output に one-time stealth address、amount の秘匿に RingCT、probabilistic な sender ambiguity の提供に ring signature を使用します。現在の technical specification では ring size は 16（15 decoy）と記載されています。<sup>[[8]](#references)</sup> これらは transparent ledger より on-chain confidentiality の default を強化するものですが、endpoint や operational mistake から守る magic protection ではありません。

### Lawful workflow

1. **合法的に acquire する。** Regulated exchange は、後続の on-chain detail が confidential であっても、purchase と withdrawal を把握する可能性があります。Source、basis、reporting record を保持します。
2. **Official maintained wallet を install する。** Project の instruction に従って download を verify します。Seed を offline に backup し、少額で restoration を test します。
3. **Wallet-query privacy を最大化するには local node を優先する。** それが現実的でない場合は、officially supported onion/I2P configuration 経由で到達できる trusted remote node を選びます。Remote node は IP、request、timing、transaction ID を log でき、一部の lightweight design は view key を開示します。
4. **Payer、campaign、invoice ごとに新しい subaddress を使用する。** Payer は同じ subaddress の繰り返し使用を correlate できます。<sup>[[9]](#references)</sup>
5. **Incoming context を local に label 付けする。** Knowledgeable payer が後続の behavior を認識できる場合、分離した receipt を operational に merge しないようにします。
6. **Network metadata を保護する。** Official anonymity-network configuration に従い、timestamp、intermittent synchronization、bandwidth shape、stream reuse による documented leak を認識します。<sup>[[10]](#references)</sup>
7. **Compliance/audit data を private に保持する。** View key または transaction proof は、意図的に intended auditor/party にのみ開示し、それが何を reveal するのかを正確に理解します。

Historical traceability study には、現在は変更された bug や decoy-selection era が含まれます。過去の success percentage を current transaction に適用しないでください。同様に、この chapter の 2026 年 9 月の research cutoff 時点で FCMP++ は roadmap work のままであり、deployed protection ではありません。<sup>[[11]](#references)</sup>

## Ethereum and stablecoins

Ethereum 自身の privacy material は、on-chain action が visible であり、wallet/RPC infrastructure が IP と metadata の exposure を追加すると説明しています。<sup>[[12]](#references)</sup> Token transfer、approval、smart-contract interaction、name service、gas funding は、すべて identity を connect できます。

Centralized stablecoin は issuer control を追加します。現在の USDC と Tether の terms は、address または asset を block/freeze し、legal/process obligation に従う権限を留保しています。<sup>[[13]](#references)</sup> これらは有用な payment instrument かもしれませんが、censorship resistance や on-chain anonymity が要件の場合には適していません。

## Compliance boundaries

- FATF recommendation は national law によって実施され、時間とともに変化します。2026 update では VASP licensing/registration と Travel Rule implementation が強調されています。<sup>[[14]](#references)</sup>
- US では、FinCEN は convertible virtual currency を自分自身の goods/services に使用する person と、それを受け付けて transmission または exchange を行う business を区別しています。事実関係と後続の rule が重要です。<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation は、crypto-asset service provider が関与する場合に originator/beneficiary information を要求し、self-hosted address との間の特定の transfer に verification rule を追加しています。<sup>[[16]](#references)</sup>
- Sanction と tax duty は引き続き適用されます。必要に応じて screen し、prohibited party を拒否し、record を維持してください。List と legal status は急速に変化する可能性があります。<sup>[[17]](#references)</sup>

Material value、cross-border activity、privacy-enhancing coordination、business-like exchange/transmission の前に、関連する jurisdiction について現在の professional advice を取得してください。

Bitcoin Silent Payments、fully shielded Zcash、GNU Taler、federated Chaumian e-cash、BOLT 12 については、[Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) を引き続き参照してください。

## References

- [1] [Bitcoin.org — Privacy を保護する](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy feature](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Simple Payjoin Proposal](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Bitcoin における Decentralized CoinJoin Implementation の Adoption と Actual Privacy（AFT 2022）](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet 創設者が guilty plea（2025）](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Lightning Network における Privacy の Empirical Analysis](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth address](https://www.getmonero.org/resources/moneropedia/stealthaddress.html)、[RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html)、[Ring signature](https://www.getmonero.org/resources/moneropedia/ringsignatures.html)、および [Technical specification](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Network](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Monero の Privacy の Evolution に関する調査（2024）](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum における Privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Virtual Asset と VASP に関する 2026 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Virtual Currency を Administer、Exchange、または Use する Person への FinCEN Regulation の適用](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry 向け Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
