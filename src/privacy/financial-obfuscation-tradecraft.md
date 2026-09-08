# Financial Obfuscation Tradecraft

{{#include ../banners/hacktricks-training.md}}

Payment privacy is an attribution problem, not a payment-brand problem. An operation leaves evidence when value is acquired, moved, converted, spent and delivered. A public-chain address can be pseudonymous while an exchange, card issuer, merchant, mobile device or shipping camera identifies the person behind it.

このページでは、防御側が認識できるよう、サイバー犯罪や国家関連の作戦で使われる financial-obfuscation パターンを説明します。これは、マネーロンダリング、sanctions-evasion、false-identity、KYC-bypass の手順を提供するものでは**ありません**。

## The end-to-end value graph
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
行為者は、観察者が両端を同時に確認できないようにしようとする。捜査側は逆に、各境界で記録を保存し、時刻・価値・手数料を正規化し、別々のペルソナが同じ仲介者、デバイス、アカウント、merchant、または送金先を再利用する**再収束点**を特定する。

## Instruments and their real observers

| Instrument | Hidden from merchant/public | Still visible to |
|---|---|---|
| Issuer virtual card/token | underlying card number | issuer, network/token provider, wallet, merchant account and delivery systems |
| Prepaid/gift value | sometimes legal name at ordinary purchase | retailer/payment rail, activation/redemption service, cameras, device and delivery |
| Cash | public ledger and remote issuer | counterparties, cameras, withdrawal/serial controls where applicable, physical search |
| Bitcoin/new address | direct legal name | every blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | simple common-input/payment heuristics | public transaction, coordinator/peer/network metadata and later spending behavior |
| Privacy coin | public sender/receiver/amount, depending on protocol | acquisition/off-ramp, wallet endpoint, network observer and counterparty |
| Centralized mixer | direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets and counterparties |
| Cross-chain bridge/swap | continuity on one chain | both chains, bridge/swap service, timing/value and liquidity constraints |
| OTC/P2P broker | direct exchange account in some cases | broker, communications, bank/cash movement, counterparties and devices |

## Cards, prepaid value, nominees and mules

### Virtual and masked cards

発行者は、merchant に固定された、または使い捨てのカード番号を作成できる。これにより、merchant 側への露出と、merchant 間でのカード番号の再利用を減らせる。発行者は依然として、それを顧客、funding account、デバイス、IP、取引に紐付けられる。請求先表示、merchant account、配送先住所、ブラウザデータもリンク可能なままである。

「No-name」カードの宣伝は、匿名で決済できることを意味しない。規制対象の発行者や販売業者は、本人確認を行い、記録を保持し、地域・金額制限を設け、法的手続きに応じる場合がある。盗用された身元情報で取得したカードは identity theft を追加するだけであり、発行者・デバイス・merchant の telemetry を消し去るものではない。

### Prepaid and gift value

Prepaid card と gift code は、後の redemption を元の決済手段から分離する一方で、購入、activation、残高照会、redemption のイベントを伴う番号付きのオブジェクトを作り出す。重要なパターンには、大量購入、controls の直下に設定された額面の反復、遠隔地での迅速な redemption、1台のデバイスによる多数の残高照会、または多数のカードが1つの merchant/account に収束することなどがある。

### Nominees, money mules and merchant fronts

Nominee または mule は、operator とサービスの間に位置するアカウントと法的身元を提供する。ネットワークでは、recruiter、account holder、payment processor、shell merchant、cash-out broker が階層化されることがある。これにより距離は生じるが、参加者が増えるたびに通信記録、手数料、行動上の不整合、協力する可能性のある証人が追加される。Front company は、設立、税務、銀行、役員、invoice、hosting、shipment の記録を生み出す。

Defender は、共有デバイス/IP、受取人の再利用、地理情報の矛盾、アカウント履歴と一致しない取引速度、循環送金、複数の無関係な送信者の収束、直後の onward movement を調査すべきである。名義上の account holder が支配的な行為者だと決めつけてはならない。役割の特定が必要な node として扱う。

## Public-chain transaction-obfuscation patterns

### Address rotation and coin control

受取のたびに新しいアドレスを作成すれば、単純なアドレス再利用は防げるが、取引は common inputs、change detection、正確な価値・時刻、後の consolidation によって所有関係を結び付けられる可能性がある。**Coin control** により、wallet はどの output を使用するか選び、compartment 同士の結合を避けられる。これは hygiene を改善するが、すでに公開されたリンクを消すことはできない。

### Peel chains

Peel chain は、大きな残高を繰り返し使用し、少額を外部へ送る一方で、残りを新しいアドレスへ戻す。
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
アドレスは各ステップで変化しますが、価値の連続性、送金間隔、トランザクション構造から、認識可能なチェーンを形成することがよくあります。正規の exchange hot wallet も同様の挙動を示すことがあるため、帰属には service/context の証拠が必要です。DOJ は、DPRK に関連する没収案件で peel-chain analysis を使用しています。<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** 1つの送金元が多数のアドレスに分散し、調査の負担を増やしたり、並行した換金に備えたりします。
- **Fan-in:** 多数の送金元が1つの collector に集約され、共通の管理主体または service が明らかになります。
- **Structuring:** 繰り返し少額送金を行い、監視 threshold を避けたり、通常の取引量に紛れ込ませたりします。
- **Commingling:** 不正資金と無関係な資金が wallet、pool、または service を共有するため、単純な比例配分による主張は危険です。

Graph の形状は手掛かりであり、証明ではありません。Analyst は、手数料、UTXO/account model、service の挙動、change の慣行を考慮すべきです。

### CoinJoin and PayJoin

一般的な CoinJoin では、複数の参加者が inputs を提供し、1つの協調的な transaction 内で outputs を受け取ります。多くの場合、output の額面は等しくなります。これにより、transaction 内の各 input と output にそれぞれ1人の所有者がいるという前提が崩れます。匿名性集合は参加者数とその後の挙動によって制限されます。不均等な change、toxic change、consolidation、または既知の service を経由することで、リンクが再び確立される可能性があります。

PayJoin は、支払者と受取人の双方が inputs を提供するよう通常の payment を変更し、その transaction に対する common-input ownership heuristic を直接無効化します。これは主に payment privacy protocol であり、大規模な laundering service ではありません。Detection では、すべての inputs が共同所有されていると断定することを避け、誤った cluster を強制的に作るのではなく、不確実性を示すべきです。

### Centralized mixers and tumblers

Centralized mixer は deposits を受け入れ、通常は手数料と遅延を差し引いた後、pooled reserve から異なる coins を支払います。その privacy は、pool の規模、withdrawal policy、logs、operator の誠実性、差し押さえへの耐性に依存します。Entry と exit のタイミングおよび価値の分析、deposit addresses、service wallet の clustering、records によって対象範囲を絞り込める可能性があります。Operator が資金を盗んだり、完全な対応表を保持したりすることもあります。

法的リスクは重大であり、jurisdiction ごとに異なります。ChipMixer、Samourai Wallet、Tornado Cash の developers/operators に対する DOJ の事案、および変化する sanctions litigation は、protocol、custody、control、money-transmission に関する事実が重要であることを示しています。「decentralized」という label は、法的な結論ではありません。<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping は asset を交換したり bridge 経由で移動させたりすることで、1つの ledger に対する query を分断しますが、economic continuity までは分断しません。
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
アナリストは、bridge contracts/service deposit addresses、transaction order、time window、exchange rate、fees、liquidity、unique amountを相関分析する。Repeated swapsは曖昧性を高める一方、provider/API/wallet telemetryを追加する可能性がある。FATFは、suspicious contextと組み合わさった場合、chain hopping、mixers、peer-to-peer services、anonymity-enhanced currenciesをrisk indicatorsとして明確に挙げている。<sup>[[3]](#references)</sup>

### NFTs、gambling、merchant purchases

Self-dealingまたはcollusive NFT tradesは、資金に見かけ上のsale narrativeを与える可能性がある。gamblingではdepositをwithdrawalと交換でき、goodsはdigital valueを再販売可能なinventoryへ変換できる。これらの経路には、marketplace accounts、creator/royalty links、wash-trading graphs、odds/play history、device logs、delivery、resale evidenceが残る。lossまたはfeeが発生したことは、provenanceが消失した証拠ではない。

## Privacy-preserving cryptocurrencies

Privacy protocolsは技術的に異なる。

- **Monero**はone-time addresses、ring signatures、confidential amountsを使用し、公開されたsender/receiver/amountの可視性を低下させる。network observation、wallet compromise、acquisition/off-ramp、counterparty recordsは、これらのon-chain protectionsの対象外として残る。
- **Zcash shielded pools**は、shielded transactionsが使用された場合、sender、receiver、amountを隠せる。transparent addressesとpool間の移行は公開されたままであり、利用パターンは実効的なanonymity setに影響する。
- **Bitcoin**はデフォルトでは透明である。New addresses、CoinJoin、PayJoin、Lightningは個別のlinkage assumptionsを変えるが、すべてのlayerをprivateにするわけではない。

Privacy technologyには、正当な安全上および商業上の用途がある。investigative perspectiveでは、ledgerが提供する情報が少ないほど、endpoint、service、network、human evidenceが重要になる。privacy-preserving protocolを選択したことだけから、犯罪性を推測してはならない。

## DPRK multi-layer case model

公開されたDOJのallegationsおよびforfeiture actionsは、1つのtrickではなく、複合的なprocessを説明している。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workersは、fictitious/stolen identity materialとVPNを使用してremote employmentを得た。
2. employersは、stablecoinsを含むcryptocurrencyで支払った。
3. fundsは小額に分散され、chainsまたはtokensを跨ぎ、NFTsを購入し、またはcommingledされた。
4. その他のstolen fundsはmixersに流入した。
5. OTC tradersとfront companiesは、valueをfiat paymentsまたはgoodsへ変換した。
6. 繰り返し利用されたfacilitators、accounts、blockchain pathsにより、investigatorsは各layerを再接続できた。

Treasuryは、LazarusがAxie Infinity/Ronin theftの一部を処理するためにBlender.ioを使用したと述べている。一方、FBIはaddressesを公開し、bridges、exchanges、RPC operators、analytics firmsに対して、後続のTraderTraitor theftsに関連するfundsをblockするよう要請した。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

教訓は双方向である。state actorsは通常のcommercial/criminal servicesを利用し、public blockchainsは、当初namesが不明であってもdefendersがvalueを追跡することを可能にする。

## Detection workflow

1. **raw transaction identifiersとrecordsを保存する。** Screenshotsと丸められたfiat valuesでは不十分である。
2. **assetsとtimeをnormalizeする。** chain、token contract、units、block time、service time zone、fees、exchange-rate sourceを記録する。
3. **evidence confidenceをlabel付けする。** service-published address、deterministic contract event、clustering heuristic、external intelligenceを区別する。
4. **両方向をtraceする。** funding origin、immediate dispersal、reconvergence、bridge exits、service deposits、spend/deliveryを見つける。
5. **off-chain evidenceを結合する。** Account KYC、device、IP、support tickets、API keys、bank/payment、shipping、communication recordsによって、曖昧性が解消されることが多い。
6. **alternative explanationsを検証する。** Exchanges、custodians、payroll、privacy protocolsは、common beneficial ownershipがなくてもfan-in/outまたはco-spendsを生じさせる可能性がある。
7. **早期に終了せずmonitorする。** dormant outputは、後にserviceへ到達した時点でattributableになる可能性がある。
8. **counselとともに現行のsanctions/AML obligationsを適用する。** Rulesとdesignationsは変更される。historical associationは、current legal analysisの代替ではない。

## Safe red-team procurement model

authorized teamは、engagement controllerがaccountabilityを維持する一方で、target SOCに自身のhosting paymentを認識させない必要がある場合がある。

- engagement-specific organization cardまたはdocumented corporate walletを使用する。
- billing、tax、provider recordsを正確に保つ。
- operatorをprocurement dutiesから分離し、attribution mapへのaccessを制限する。
- mule、false identity、stolen card、sanctions workaround、unlicensed exchangerを決して使用しない。
- asset、amount、owner、service、date、refund path、teardown evidenceを記録する。
- exercise後、関連するpayment/provider indicatorsをcontrollerに開示する。

これにより作られるのは、**exercise participantに対するblindness**であり、law、provider、governanceに対するblindnessではない。

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework（peel-chain exampleおよびDPRK investigations）](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
