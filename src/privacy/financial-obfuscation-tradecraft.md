# Financial Obfuscation Tradecraft

Payment privacy is an attribution problem, not a payment-brand problem. An operation leaves evidence when value is acquired, moved, converted, spent and delivered. A public-chain address can be pseudonymous while an exchange, card issuer, merchant, mobile device or shipping camera identifies the person behind it.

This page explains financial-obfuscation patterns used in cybercrime and state-linked operations so defenders can recognize them. It does **not** provide a laundering, sanctions-evasion, false-identity or KYC-bypass procedure.

## The end-to-end value graph
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
ある行為者は、観察者に両端を見られないようにしようとする。捜査側は逆のことを行う。各境界で記録を保存し、時刻・価値・手数料を正規化し、別々のペルソナが同じ仲介者、デバイス、アカウント、merchant、または送金先を再利用する **再収束点** を特定する。

## Instrument と実際の観察者

| Instrument | merchant/public から隠されるもの | 引き続き可視な相手 |
|---|---|---|
| Issuer virtual card/token | 元のカード番号 | issuer、network/token provider、wallet、merchant account、delivery systems |
| Prepaid/gift value | 通常の購入時には法的氏名が隠れる場合がある | retailer/payment rail、activation/redemption service、カメラ、デバイス、配送 |
| Cash | 公開台帳と遠隔の issuer | 取引相手、カメラ、該当する場合は出金/シリアル管理、物理的な捜索 |
| Bitcoin/new address | 直接的な法的氏名 | すべての blockchain observer、wallet/network peers、acquisition/off-ramp services |
| CoinJoin/PayJoin | 単純な common-input/payment heuristics | 公開 transaction、coordinator/peer/network metadata、後続の支出行動 |
| Privacy coin | protocol に応じて、公開 sender/receiver/amount | acquisition/off-ramp、wallet endpoint、network observer、取引相手 |
| Centralized mixer | 直接的な deposit-to-withdraw link | mixer operator/logs、blockchain の entry/exit sets、取引相手 |
| Cross-chain bridge/swap | 1つの chain 上での連続性 | 両方の chain、bridge/swap service、timing/value、liquidity constraints |
| OTC/P2P broker | 場合によっては直接の exchange account | broker、通信、銀行/現金の移動、取引相手、デバイス |

## Cards、prepaid value、nominees、mules

### Virtual and masked cards

issuer は merchant-locked または disposable なカード番号を作成できる。これにより、merchant への露出と、merchant 間でのカード番号の再利用を減らせる。issuer は依然として、その番号を顧客、funding account、デバイス、IP、transaction に対応付けている。Billing descriptors、merchant account、shipping address、browser data も引き続きリンク可能である。

「No-name」カードの marketing は、匿名の settlement を意味しない。規制対象の issuer と distributor は、identity checks を実施し、records を保持し、地域/金額制限を設け、legal process に応じる場合がある。盗まれた identity で取得したカードは identity theft を追加するだけであり、issuer/device/merchant telemetry を消すものではない。

### Prepaid and gift value

Prepaid cards と gift codes は、後続の redemption を元の payment instrument から分離するが、購入、activation、balance-query、redemption の各 event を持つ番号付きの object を生み出す。重要なパターンには、大量購入、controls の直下に設定した denomination の反復、遠隔地での迅速な redemption、1つのデバイスによる多数の balance の確認、または多数のカードが1つの merchant/account に収束することなどがある。

### Nominees、money mules、merchant fronts

Nominee または mule は、operator と service の間に位置する account と legal identity を提供する。Networks は、recruiter、account holder、payment processor、shell merchant、cash-out broker を重層化する場合がある。これにより距離は生まれるが、参加者が増えるたびに通信記録、手数料、行動上の不整合、協力する可能性のある証人が追加される。Front companies は、incorporation、tax、banking、director、invoice、hosting、shipment の records を追加する。

Defender は、共有された devices/IPs、beneficiary の再利用、geolocation の矛盾、account history と一致しない velocity、循環 transfer、複数の無関係な sender の収束、直後の onward movement を調査すべきである。指定された account holder が controlling actor だと想定してはならない。彼らを role determination が必要な node として扱う。

## Public-chain transaction-obfuscation patterns

### Address rotation and coin control

すべての receipt に新しい address を作成すると、単純な address reuse は防げるが、transaction は common inputs、change detection、exact value/time、後続の consolidation によって ownership を結び付けられる場合がある。**Coin control** により、wallet はどの output を spend するかを選択し、compartments の結合を避けられる。これは hygiene を向上させるが、すでに公開された link を消すことはできない。

### Peel chains

Peel chain では、大きな balance を繰り返し spend し、少額を外部へ送る一方で、残額を新しい address に戻す。
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
アドレスは各ステップで変わりますが、value continuity、cadence、transaction structureは、認識可能なchainを形成することがよくあります。正当なexchange hot walletも同様に振る舞う場合があるため、attributionにはservice/context evidenceが必要です。DOJは、DPRKに関連するforfeiture casesでpeel-chain analysisを使用しています。<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** 1つのsourceが多数のアドレスに分散し、investigative workloadを増やしたり、並行したconversionに備えたりします。
- **Fan-in:** 多数のsourceが1つのcollectorに集約され、common controlまたはserviceの存在を示します。
- **Structuring:** 繰り返し少額のtransferを行い、review thresholdsを回避したり、通常のvolumeに紛れ込ませたりします。
- **Commingling:** illicit fundsと無関係なfundsがwallet、pool、またはserviceを共有するため、単純な比例配分による主張は危険です。

Graph shapeは手がかりであり、証明ではありません。Analystsは、fees、UTXO/account model、service behavior、change conventionsを考慮すべきです。

### CoinJoin and PayJoin

典型的なCoinJoinでは、複数のparticipantが1つのcollaborative transactionにinputsを提供し、通常は同額面のoutputsを受け取ります。これにより、transaction内のすべてのinputとoutputが1人のownerに属するという前提が崩れます。anonymity setはparticipant countとその後のbehaviorによって制限されます。不均等なchange、toxic change、consolidation、または既知のserviceを通過することで、linksが再び形成される可能性があります。

PayJoinは、payerとpayeeの双方がinputsを提供するよう通常のpaymentを変更し、そのtransactionに対するcommon-input ownership heuristicを直接無効化します。これは主にpayment privacy protocolであり、bulk laundering serviceではありません。Detectionでは、すべてのinputsが共同所有されていると断定することを避け、誤ったclusterを強制するのではなく、uncertaintyを表現すべきです。

### Centralized mixers and tumblers

Centralized mixerはdepositを受け入れ、通常はfeesとdelaysを差し引いた後、pooled reserveから異なるcoinsを支払います。そのprivacyは、pool size、withdrawal policy、logs、operator honesty、seizureへの耐性に依存します。Entryとexitのtiming/value analysis、deposit addresses、service wallet clustering、recordsによって、対象範囲を絞り込める場合があります。Operatorsはfundsを盗んだり、完全なmappingを保持したりできます。

Legal exposureは重大であり、jurisdictionごとに異なります。ChipMixer、Samourai Wallet、Tornado Cashのdevelopers/operatorsに対するDOJ casesや、変化するsanctions litigationは、protocol、custody、control、money-transmissionに関する事実が重要であることを示しています。「decentralized」というlabelは、legal conclusionではありません。<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hoppingはassetをconversionしたり、bridgeを通して移動させたりすることで、one-ledger queryを分断しますが、economic continuityまでは分断しません:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
アナリストは、bridge contracts/service deposit addresses、transaction order、time window、exchange rate、fees、liquidity、unique amountを相関分析する。swapを繰り返すと曖昧さが増す可能性がある一方、provider/API/wallet telemetryも追加される。FATFは、疑わしい状況と組み合わさった場合、chain hopping、mixers、peer-to-peer services、anonymity-enhanced currenciesをリスク指標として明確に特定している。<sup>[[3]](#references)</sup>

### NFTs、ギャンブル、加盟店での購入

自己取引または共謀したNFT取引は、資金に見かけ上の販売ストーリーを与える可能性がある。ギャンブルでは入金を出金に交換でき、商品はデジタル価値を再販可能な在庫に変換できる。これらの経路には、marketplace accounts、creator/royalty links、wash-trading graphs、odds/play history、device logs、deliveryおよびresale evidenceが残る。損失または手数料が発生したからといって、provenanceが消失した証拠にはならない。

## Privacy-preserving cryptocurrencies

Privacy protocolsは技術的に異なる。

- **Monero**はone-time addresses、ring signatures、confidential amountsを使用し、公開上の送信者、受信者、金額の可視性を低下させる。Network observation、wallet compromise、acquisition/off-ramp、counterparty recordsは、これらのon-chain protectionsの対象外に残る。
- **Zcash shielded pools**は、shielded transactionsが使用される場合、送信者、受信者、金額を隠すことができる。transparent addressesとpool間の移動は公開されたままであり、利用パターンは実効的なanonymity setに影響する。
- **Bitcoin**はデフォルトでは透明である。New addresses、CoinJoin、PayJoin、Lightningは特定のlinkage assumptionsを変えるが、すべてのlayerをprivateにするわけではない。

Privacy technologyには、正当な安全上および商業上の用途がある。調査の観点では、ledgerが提供する情報が少ないほど、endpoint、service、network、human evidenceがより重要になる。Privacy-preserving protocolを選択したことだけから、犯罪性を推測してはならない。

## DPRK multi-layer case model

公開されたDOJの申し立ておよびforfeiture actionsは、1つのtrickではなく、複合的なprocessを説明している。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workersは、架空または盗難されたidentity materialとVPNsを使用して、remote employmentを得た。
2. employersは、stablecoinsを含むcryptocurrencyで支払った。
3. fundsはより小さな金額に分割され、chainsまたはtokensをまたぎ、NFTsを購入し、またはcommingledされた。
4. その他のstolen fundsはmixersに流入した。
5. OTC tradersとfront companiesは、valueをfiat paymentsまたはgoodsに変換した。
6. 繰り返し利用されたfacilitators、accounts、blockchain pathsにより、investigatorsは各layerを再接続できた。

Treasuryは、LazarusがAxie Infinity/Ronin theftの一部を処理するためにBlender.ioを使用したと述べている。一方、FBIはaddressesを公開し、bridges、exchanges、RPC operators、analytics firmsに対して、後続のTraderTraitor theftsに関連するfundsをblockするよう要請した。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

教訓は双方向である。state actorsは通常のcommercial/criminal servicesを利用し、public blockchainsは、当初namesが不明であっても、defendersがvalueを追跡できるようにする。

## Detection workflow

1. **raw transaction identifiersとrecordsを保全する。** Screenshotsと丸められたfiat valuesだけでは不十分である。
2. **assetsとtimeをnormalizeする。** chain、token contract、units、block time、service time zone、fees、exchange-rate sourceを記録する。
3. **evidence confidenceをlabel付けする。** service-published address、deterministic contract event、clustering heuristic、external intelligenceを区別する。
4. **両方向をtraceする。** funding origin、immediate dispersal、reconvergence、bridge exits、service deposits、spend/deliveryを見つける。
5. **off-chain evidenceをjoinする。** Account KYC、device、IP、support tickets、API keys、bank/payment、shipping、communication recordsは、曖昧さを解消することが多い。
6. **alternative explanationsをtestする。** Exchanges、custodians、payroll、privacy protocolsは、common beneficial ownershipがなくてもfan-in/outまたはco-spendsを生じさせる可能性がある。
7. **早期にcloseせずmonitorする。** dormant outputは、後にserviceへ到達した時点でattributableになる可能性がある。
8. **counselとともに、現在のsanctions/AML obligationsを適用する。** Rulesとdesignationsは変更される。過去のassociationは、現在のlegal analysisの代わりにはならない。

## Safe red-team procurement model

authorized teamは、engagement controllerがaccountabilityを保持しながら、target SOCに自身のhosting paymentを認識させない必要がある場合がある。

- engagement-specific organization cardまたはdocumented corporate walletを使用する。
- billing、tax、provider recordsを正確に保つ。
- operatorをprocurement dutiesから分離し、attribution mapへのaccessを制限する。
- mule、false identity、stolen card、sanctions workaround、unlicensed exchangerを決して使用しない。
- asset、amount、owner、service、date、refund path、teardown evidenceを記録する。
- exercise後、関連するpayment/provider indicatorsをcontrollerに開示する。

これにより、**exercise participantに対するblindness**は作り出せるが、law、provider、governanceに対するblindnessは作り出せない。

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework（peel-chain exampleとDPRK investigations）](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank代表者、crypto-laundering conspiraciesで起訴](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — DPRKのためにlaunderedされたとされる774万ドルに関するforfeiture complaint](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctionsとLazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — virtual-currency users、administrators、exchangersへのregulationsの適用](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
