# Anonymous Payment Technique Catalog

このカタログでは、通常の現金から blind-signature e-cash、public-chain obfuscation まで、支払いの**ファミリー**を扱います。「Anonymous」とは常に、特定された observer から見て anonymous という意味です。merchant、issuer、mint、exchange、blockchain analyst、network provider、employer、physical observer は、それぞれ異なる事実を確認します。

以下の手順は、合法な資金、正確なアカウント情報、承認済みの調達を前提としています。引用された事例で laundering、sanctions evasion、identity fraud を目的としていた techniques は、説明および検出方法として扱いますが、その手順は犯罪を実行するための指示ではなく、synthetic forensic exercise です。

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash and cash equivalents | リモート payment-network record がない | recipient と物理環境 | 合法な workflow |
| Prepaid/gift/voucher value | redemption と primary card を分離 | seller、issuer、redemption service | 合法な workflow、管轄により異なる |
| Virtual/tokenized card | 再利用可能な PAN を隠す、または merchant を分離 | issuer/network/wallet は payer を識別可能 | 合法な workflow |
| Payment app/intermediary | merchant には alias/intermediary だけを見せられる場合がある | app は identity/device/transaction を収集 | 比較用 baseline |
| Bitcoin hygiene/Silent Payments | pseudonym と recipient unlinkability | public graph と wallet/network boundary | deployable |
| PayJoin/CoinJoin | common ownership/linkage heuristics を弱める | participants/coordinator/network/public graph | 対応環境で deployable、legal review |
| Lightning/BOLT 12 | off-chain routing と receiver-path reduction | endpoints、hops、services、channel graph | 対応環境で deployable |
| Monero/Zcash/MWEB | protocol-level on-chain confidentiality | acquisition、endpoint、network、boundary は残る | 合法かつ対応環境で deployable |
| Ethereum ZK application | 特定の statement/action link を隠す | public inputs、RPC、relayer、app | application-specific |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody と boundaries | emerging/deployment-specific |
| Stablecoins | 便利な digital settlement | transparent chain と issuer の freeze/control | anonymous baseline ではない |
| Swaps/bridges/DEX | asset/chain をまたいで value を移動 | 両方の graph、contracts、providers | forensic mechanics、通常の合法な swap のみ |
| Mixers/peel/structuring | graph ambiguity/work を増加 | entry/exit graph と service records | synthetic detection exercise のみ |
| Nominees/mules/OTC/fronts | 人間または business intermediary を挿入 | facilitators、banks、communications | criminal-abuse analysis のみ |
| Reusable/stealth payment addresses | 支払いごとに新しい recipient address | public announcement/notification と wallet boundaries | 対応環境で deployable |
| Confidential sidechain/state channel | amount/asset または中間更新を隠す | peers、bridge/federation、lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | merchant から primary card を隠す | carrier、bank/PISP、platform が customer を識別 | 通常の識別済み支払い |
| Mutual credit/net settlement | 外部 settlement record を減らす | private ledger operator が完全な mapping を保持 | 識別済み participants のみ |

## Cash

**Mechanics:** physical bearer value が、online issuer authorization や public ledger なしに手渡されます。

**Pros:** merchant は bank/card identity を知る必要がありません。remote transaction graph がなく、広く理解され、final です。

**Cons:** 対面のみ。盗難・紛失、釣り銭・receipt・serial・reporting controls。withdrawal、camera、witness、location は payer を引き続き結び付けます。

**Procedure:** (1) cash が合法かつ受け入れ可能で、金額・報告ルールを確認する。(2) 合法に withdrawal または受領し、private accounting records を保持する。(3) 不要な loyalty/account identifiers なしで通常の merchant に支払う。(4) 必須の receipt だけを求める。(5) 購入に不要なら shipping/account data を避ける。(6) 正当な business purpose を内部記録する。

**Detection:** 適用される policy に従い、till/receipt/inventory、camera、access logs を照合する。通常の cash 使用自体を suspicious とせず、異常な cash refunding や control threshold の直下を繰り返す金額を調査する。

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer が cash/account funds を、named recipient に支払われる numbered instrument に変換します。COD では collection を delivery まで延期します。

**Pros:** recipient は payer の primary bank/card number を受け取らない場合があります。cash を遠隔に送れない場所で利用でき、明確な receipt があります。

**Cons:** issuer/retailer は必要に応じて purchase/identity data を保持します。serial tracking、recipient/delivery address、loss/fraud、地域制限があります。一般に anonymous ではありません。

**Procedure:** (1) issuer rules、limits、identification、recipient acceptance を確認する。(2) 正確な情報と合法な資金で購入する。(3) payee/amount を直ちに記入する。(4) serial/receipt を保存する。(5) 金額に適した tracked delivery を使用する。(6) redemption/refund を照合する。

**Detection:** issuer の purchase/redemption record、instrument serial、retailer/camera、shipping、recipient account を確認する。alteration、duplicate serial、地理的に矛盾する急速な redemption を検出する。

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential が、primary credit account ではなく prepaid balance に対して authorization を行います。

**Pros:** merchant exposure と loss を制限し、main PAN から merchant を分離できます。対応していれば online で利用できます。

**Cons:** purchase/activation/reload/registration、device records。KYC と limits は異なり、billing-address failure、cash-out/refund restrictions があります。「no name」は issuer record がないという意味ではありません。

**Procedure:** (1) 現在の issuer identity、fees、KYC、geography、online/recurring support を確認する。(2) 合法な資金で authorized seller から取得する。(3) 必須の data は正確に登録する。(4) 1つの compartment/purpose に使用する。(5) loads を structuring したり residency を偽造したりしない。(6) purchase/expense evidence を保持し、issuer terms に従って close/dispose する。

**Detection:** seller/activation、funding、device/IP、merchant authorization、balance checks、redemption/refund を結合する。重要なのは prepaid という label ではなく、pattern です。

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** numbered value は1つの merchant/service または ecosystem でのみ redeemable です。airtime/game/store credits はその variant です。

**Pros:** recipient merchant には code/balance だけが見える場合があります。blast radius が限定され、gift と budget separation が容易です。

**Cons:** seller と service は purchase/activation/redemption を記録します。account/device/delivery は依然として link します。scam、resale discount、expiry/region limits、弱い refund rights があります。

**Procedure:** (1) authorized channels だけで購入する。(2) secret を漏らさず code value を記録する。(3) 不要なら identifying loyalty account に結び付けない。(4) 別の legitimate merchant account/context で redeem する。(5) accepted になるまで receipt を保管する。(6) unsolicited な「tax/support/ransom」要求のために code を購入しない。

**Detection:** code issuance/redemption time、device/account convergence、bulk/threshold-pattern purchase、1台の device による多数 balance checks、遠隔地での急速な redemption を確認する。

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary が cryptocurrency を受け取り、card、voucher、merchant code を発行します。これは cross-rail conversion です。merchant には通常の card/gift value が見えますが、broker は on-chain deposit と issuance/delivery を結び付けます。

**Pros:** merchant は funding wallet を受け取りません。crypto を受け付けない合法な merchant に有用で、stored value の範囲も限定されます。

**Cons:** broker/issuer から anonymous ではありません。KYC、sanctions、exchange、card-program rules、public deposit graph、account/device/email、code redemption が両側を再接続します。scam/insolvency risk もあります。

**Procedure:** (1) legal entity、card issuer、supported jurisdiction、KYC、fees、refund policy を確認する。(2) 合法で文書化された資金だけを使用する。(3) 最小 denomination で試す。(4) 購入前に network/merchant restrictions を確認する。(5) blockchain transaction と broker receipt の両方を accounting 用に保存する。(6) identity fraud、sanctions bypass、「untraceable」cash-out を約束する broker は使用しない。

**Detection:** broker deposit addresses、unique amount/time、account/device、issued-card authorization または gift-code redemption を相関させる。issuer と broker records は public chain と merchant を橋渡しします。

## Virtual or merchant-locked card

**Mechanics:** issuer は generated PAN/token を real account に map し、merchant、amount、expiration を制限することがあります。

**Pros:** reusable PAN の開示を防ぎ、merchant compartmentation、spend limits、easy revocation、成熟した fraud control を提供します。

**Cons:** issuer は payer、funding、merchant、device/IP、time を把握します。merchant は account/delivery を確認します。一部の refund/recurring charge は失敗します。anonymous ではありません。

**Procedure:** (1) regulated issuer の official feature を使用する。(2) 1つの merchant/engagement 用に card を作成する。(3) 必要最小限の limit と expiry を設定する。(4) 必要な場合は正確な billing data を使う。(5) statement descriptor/refund behavior を確認する。(6) final settlement 後に freeze/delete し、audit evidence は保持する。

**Detection:** issuer の token-to-account mapping、merchant authorization、device、delivery を確認する。defender は merchant-specific reuse、velocity、account takeover signals を利用します。

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization は、PAN の代わりに device、merchant、payment scenario に制約された credential を使用します。<sup>[[1]](#references)</sup>

**Pros:** merchant は reusable PAN を受け取りません。device cryptography と dynamic data が cloning を減らし、card 交換なしで revoke できます。

**Cons:** issuer、token service、wallet platform、network は mappings/transactions を保持します。device/platform account と location が payer を識別する場合があります。

**Procedure:** (1) legitimate card を official wallet に enroll する。(2) platform account/device を強い authentication で保護する。(3) 購入時に device token/last digits を確認する。(4) 対応していれば不要な location/analytics を無効にする。(5) lost device/token を直ちに disable する。(6) issuer と wallet records を確認する。

**Detection:** token requestor/device cryptogram と issuer mapping、wallet/account telemetry、merchant terminal、physical evidence を確認する。

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service が accounts を管理し、内部または bank/card rails で transfer します。merchant には alias が見える場合がありますが、service は両当事者を把握します。

**Pros:** convenience、dispute/refund mechanisms、recipient が bank/card details を必ずしも見ないことです。

**Cons:** centralized identity/social/transaction/device graph、freezes、legal process。counterparty が profile を公開でき、data use が payment necessity を超える場合があります。<sup>[[2]](#references)</sup>

**Procedure:** (1) identity、privacy、retention、buyer-protection terms を読む。(2) optional profile/contact synchronization を最小化する。(3) terms が許す場合だけ、別の正確な account を使用する。(4) MFA/alerts を有効にする。(5) recipient と memo/profile の privacy を確認する。(6) records を export し、不要な links を close する。

**Detection:** provider account、device/IP、contact graph、funding/withdrawal、memo、merchant records を確認する。alias は counterparty からの pseudonymity であり、platform からの anonymity ではありません。

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions が identified accounts 間で value を移動し、必要な payment data を交換します。

**Pros:** 高速で accountable、限定的に reversible、強い records があります。virtual account number は merchant への開示を減らせます。

**Cons:** banks/processors は両側を把握します。statements、references、cross-border、Travel Rule/AML data があり、anonymous ではありません。

**Procedure:** accountability を受け入れられる場合のみ使用する。beneficiary を独立して確認し、optional memo data を最小化し、利用可能なら bank-provided virtual account/reference を使い、alerts を有効にし、invoice を保存して照合する。

**Detection:** deterministic bank/payment records、beneficiary/account ownership、device/session、fraud controls を確認する。これは baseline であり、anonymity technique ではありません。

## Account and merchant compartmentation

**Mechanics:** lawful identities/accounts、email aliases、cards、delivery contexts を分離し、無関係な merchant が activity を容易に join できないようにします。ただし issuer/controller は mapping を保持します。

**Pros:** breach と cross-merchant linkage を減らし、audit が容易で、regulated payments と両立します。

**Cons:** provider は compartments を map できます。recovery phone/device/IP、shipping が再接続します。policy が multiple accounts を禁止する場合もあります。

**Procedure:** (1) 目的を1つ定義する。(2) terms-compliant aliases/subaccounts のみ作成する。(3) merchant-specific token/card を使う。(4) cross-account contact/ad personalization を無効にする。(5) encrypted controller ledger を保持する。(6) refund/retention needs が終わったら identifiers を retire する。

**Detection:** providers は recovery、device、funding、IP を join します。merchants は delivery、browser、account behavior を join します。legitimate compartmentation と synthetic identity fraud を区別する必要があります。

## Controlled red-team procurement

**Mechanics:** SOC は purchase を blind にしますが、exercise controller は legal entity、operator、infrastructure の mapping を保持します。

**Pros:** realistic detection exercise、personal exposure なし、即時 deconfliction と audit が可能です。

**Cons:** organization/provider から anonymous ではありません。governance overhead と controller ledger mishandling による leak があります。

**Procedure:** (1) engagement-specific organization card/wallet/budget を割り当てる。(2) purchaser/operator roles を分離する。(3) asset、amount、service、purpose、kill date を記録する。(4) attribution mapping は controller の限定アクセスで保存する。(5) false identity/mule/stolen funds を使用しない。(6) closeout で indicators と refunds を reveal/reconcile する。

**Detection:** controller が provider invoice と asset を map します。SOC は cardholder data ではなく、domain、certificate、hosting、traffic から独立して discovery できるかを試験します。

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses、local labeling、selective UTXO spending により、public ledger 上の address reuse と意図しない compartment merging を減らします。

**Pros:** 広く対応し、self-custodial で、最も単純な public linkage を避けられます。

**Cons:** すべての transactions/amounts は public です。common-input/change/timing、後の consolidation が activity を link します。acquisition/RPC/network records も残ります。

**Procedure:** (1) maintained wallet を install/verify する。(2) seed recovery を backup/test する。(3) invoice ごとに新しい address を使う。(4) source/purpose を local に label する。(5) coin control で contexts の merging を避ける。(6) local node または privacy-aware connection を優先する。(7) change/fees を preview し、合法な accounting を保持する。<sup>[[3]](#references)</sup>

**Detection:** address graph、uncertainty を伴う common-input/change heuristics、exact amount/time、consolidation、service deposits、node/RPC broadcast timing、off-chain records を確認する。

## Bitcoin Silent Payments

**Mechanics:** BIP 352 は receiver が static code を公開し、sender が ECDH により unique Taproot outputs を derive できるようにします。外部 observer は outputs を code に直接 link できません。<sup>[[4]](#references)</sup>

**Pros:** address reuse なしで reusable public identifier を使えます。interactive address request や notification output が不要で、Taproot outputs に混ざります。

**Cons:** receiver scanning cost、wallet support の差。amount/sender graph と spending は public で、index server は scans を観測できます。

**Procedure:** (1) current BIP 352 wallet を選択する。(2) descriptor と scanning recovery を backup/test する。(3) 対応していれば labeled code を生成する。(4) 公開された code を authenticate する。(5) sender は inputs を確認し、小額 test を送る。(6) receiver は可能なら own node 経由で scan する。(7) received UTXOs を分離して保持する。

**Detection:** 設計上、output 単体から確実に識別できません。analysts は sender inputs、amount/time、later spending、wallet/network/index、counterparty records を使います。

## PayJoin

**Mechanics:** payer と payee が1つの payment transaction に inputs を提供し、すべての inputs が同一 owner という assumption を壊します。<sup>[[5]](#references)</sup>

**Pros:** privacy を改善した通常の payment。common heuristic を弱め、wider graph にも有益です。equal-output crowd は不要です。

**Cons:** interactive/support requirement、receiver endpoint availability。amount と final transaction は public で、implementation/fallback metadata も残ります。

**Procedure:** (1) maintained wallets が同じ PayJoin version に対応することを確認する。(2) invoice/endpoint を authenticate する。(3) wallet の PayJoin-enabled payment URI から開始する。(4) final amount/fee を確認し、想定した inputs のみ sign する。(5) manual transaction surgery を行わない。(6) broadcast と receipt を確認する。(7) negotiation failure 時の fallback を記録する。

**Detection:** blockchain analysts は common-input clustering を強制してはいけません。endpoint/provider は negotiation を log する場合があり、transaction shape だけでなく wallet/network と later-spend evidence を使用します。

## CoinJoin

**Mechanics:** 複数の participants が many inputs/outputs を持つ transaction を共同作成し、通常は equal denominations により input-output correspondence の ambiguity を増やします。

**Pros:** on-chain ambiguity set が大きくなり、self-custodial designs が存在します。round structure を測定できます。

**Cons:** coordinator/peer/network metadata、fees/liquidity、識別可能な transaction shape。toxic change と後の consolidation は gains を破壊します。legal/provider availability は異なります。

**Procedure:** (1) current wallet/coordinator availability と legality を確認する。(2) official wallet を install し backup する。(3) lawful UTXOs のみ使用する。(4) denomination、fee、coordinator model を理解する。(5) change と mixed outputs を label/separate する。(6) それらを一緒に consolidate しない。(7) official に supported な方法で network traffic を route し、accounting を保持する。

**Detection:** crime を前提にせず collaborative structure を identify する。possible mappings/anonymity set を計算し、change/consolidation、service boundaries、network/coordinator records を確認する。

## Lightning Network

**Mechanics:** HTLC payments が onion-routed channels を通過します。大部分の payment details は chain に公開されませんが、funding/closing と public channel information は公開されます。

**Pros:** 高速で低 fee。intermediaries は通常 adjacent hops だけを見ます。通常の payment details は off chain に留まります。

**Cons:** sender/receiver と first/last hop はより多くを知ります。probing、timing、channel graph、liquidity、wallet/LSP records が残ります。custodial wallets は users を識別します。

**Procedure:** (1) self-custodial と custodial の違いを理解して選ぶ。(2) wallet/seed/channel recovery を確認する。(3) exact payment の invoice を使う。(4) tradeoffs を読んだ上で private channels/LSP features を利用する。(5) 必要なら supported Tor で node IP を保護する。(6) identifying invoices の reuse を避ける。(7) channel/payment accounting を保持する。<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs、channel graph/probes、payment failure/timing、on-chain funding/closure を確認する。public transaction がないことは records がないことを意味しません。

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer が fresh invoices を生成し、blinded paths を advertise できます。payer は receiver の clear node/path を知る必要がありません。

**Pros:** receiver privacy。static invoice なしの reusable donation/payment endpoint。Lightning onion routing と統合されます。

**Cons:** wallet support の差。endpoints、selected hops、funding は残ります。public contact または network endpoint が receiver を再識別できます。

**Procedure:** (1) matching BOLT 12 support を確認する。(2) offer を authenticate する。(3) fresh invoice を request する。(4) amount/issuer/recurrence を確認する。(5) wallet から支払う。(6) receipt/refund behavior を確認する。(7) node alias/contact を最小化し accounting を保持する。<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP と first/last-hop telemetry、offer distribution account、timing/value、funding graph を確認する。route blinding は payer visibility を意図的に制限します。

## Monero

**Mechanics:** one-time stealth addresses が recipient linkage を隠し、RingCT が amounts を隠し、ring signatures が sender ambiguity を提供します。

**Pros:** on chain で privacy が default。sender/receiver/amount confidentiality。成熟した dedicated wallet/node ecosystem。

**Cons:** acquisition/off-ramp、endpoint/network/counterparty records。remote node は queries/IP を確認します。exchange support/legal treatment は異なり、small operational mistakes は contexts を link します。

**Procedure:** (1) 合法に acquire し、basis/source を保持する。(2) official maintained wallet を install/verify する。(3) seed を backup/test する。(4) local node または documented Tor/I2P remote-node path を使用する。(5) payer/invoice ごとに新しい subaddress を使う。(6) contexts を local に label する。(7) transaction proof/view access は意図的にのみ開示する。<sup>[[8]](#references)</sup>

**Detection:** exchange/merchant/device/network と seized-wallet evidence に焦点を置く。protocol use 自体は suspicious ではなく、public chain は意図的に少ない情報しか公開しません。

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs が shielded transfers を検証し、sender、receiver、amount は encrypted です。transparent pools と pool transitions は public のままです。

**Pros:** 強い shielded on-chain confidentiality。viewing keys による scoped audit。protocol-enforced validity。

**Cons:** wallet/exchange support と実際の pool choice は異なります。transparent boundary の timing/value correlation、network/RPC、endpoint は残ります。

**Procedure:** (1) shielded-by-default の maintained Orchard wallet を選ぶ。(2) verify/backup する。(3) ZEC を合法に取得する。(4) supported Unified Address に受け取り、pool を確認する。(5) shielded-to-shielded を優先する。(6) supported network privacy を使う。(7) audit 前に小額 wallet で viewing-key disclosure をテストする。<sup>[[9]](#references)</sup>

**Detection:** transparent boundary と service records、wallet/network metadata、合法的に提供された viewing keys を確認する。すべての Unified Address payments が shielded だと仮定しない。

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions が amounts を隠し、Mimblewimble-style aggregation が conventional address-rich history を除去します。Litecoin は transparent chain と並ぶ optional extension block を実装します。

**Pros:** private domain で confidential amounts と fungibility を改善し、pruning/aggregation が効率的です。

**Cons:** opt-in boundary の peg-in/out は public で correlatable。wallet/exchange support、interactive/address model differences、network/acquisition records が残ります。

**Procedure:** (1) explicit MWEB support の maintained wallet を選ぶ。(2) verify/backup し小額で test する。(3) 合法に acquire する。(4) MWEB に peg in し balance domain を確認する。(5) compatible receiver とのみ transact する。(6) distinctive な immediate peg-out を避ける。(7) private audit records を保持する。<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value、exchange/wallet/node data、later transparent spends を確認する。内部 confidential transfer details は意図的に減少しています。

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit が membership、valid note ownership、authorization などの statement を、secret を開示せずに証明します。verifier contract が検証します。deposits、withdrawals、public inputs、events、gas は link を露出させる場合があります。

**Pros:** programmable selective disclosure、anonymous-set applications、全 data を開示せずに verifiable rules を提供します。

**Cons:** contract/circuit bugs、小さな anonymity set、public boundaries、RPC/IP/session/analytics/gas funding、application と sanctions/legal risk。

**Procedure:** (1) proof が何を隠すか正確に定義する。(2) 合法な audited maintained application を使う。(3) public inputs/events と deposit/withdraw rules を確認する。(4) protocol が意図するよう action wallet と gas sponsorship を分離する。(5) privacy-aware RPC/network path を使う。(6) 小額で test する。(7) compliance records を保持する。<sup>[[11]](#references)</sup>

**Detection:** contract events、deposit/withdraw timing/value、relayer/paymaster、RPC/session、frontend storage/analytics、eventual exchange/merchant boundary を確認する。ZK proof が public と宣言された fields を隠すとは主張しない。

## Stablecoins

**Mechanics:** tokens は public chain 上で transfer されます。centralized issuers は freeze/blacklist したり、identified accounts に対して redeem したりできます。

**Pros:** price stability、liquidity、merchant support、fast settlement、easy accounting。

**Cons:** transparent address/amount/contract graph、gas funding、issuer/exchange identity/control、sanctions screening。一般に anonymity は弱いです。

**Procedure:** identified payment として扱う。compartmentation のために fresh business address を使い、token contract/network を確認し、小額で test し、wallet を保護し、trusted RPC/local node を使い、basis/source を保持し、必要な parties を screen する。

**Detection:** complete token event graph、issuer freeze list/actions、exchange/RPC/device、gas-funding relationships を確認する。

## Cashu Chaumian e-cash

**Mechanics:** mint が client-generated bearer secrets に blind-signature を付与し、mint の Bitcoin/Lightning reserves に裏付けます。double-spend を防ぎながら issuance と後の redemption を直接 link できないようにします。

**Pros:** accountless bearer tokens、instant peer transfer。mint は blinded withdrawal と spend を直接 link できません。tokens は data/QR として移動できます。

**Cons:** mint custody/solvency/censorship、bearer data の loss/theft、denomination/timing、Lightning boundaries、network metadata、初期段階の software ecosystem。<sup>[[12]](#references)</sup>

**Procedure:** (1) まず official test mint または小額の disposable value を使う。(2) maintained wallet を install し backup/restore limitations を test する。(3) mint を authenticate し custody/fees を確認する。(4) 小額を mint する。(5) authenticated private channel/QR で token を送る。(6) receiver は final と扱う前に token を swap する。(7) redeem して reconcile する。untrusted mint に meaningful value を保管しない。

**Detection:** mint は network、issue/redeem/Lightning boundaries、spent-token set を把握しますが、blinding が direct token linkage を除去します。endpoints/messages と distinctive amount/timing が link を復元する場合があります。

## Fedimint federated e-cash

**Mechanics:** guardians の threshold が reserves を保持し、e-cash に blind-signature を付与します。internal bearer transfers は guardians から private ですが、Lightning gateways が external payments を bridge します。

**Pros:** custody を分散し、private internal transfer、community governance、threshold 未満では single guardian が reserve を制御できません。

**Cons:** guardian quorum/custody/software risk、gateway が invoices/timing を観測、deposit/withdraw boundaries、client-state recovery complexity。

**Procedure:** (1) federation invite/guardians/quorum/jurisdiction を確認する。(2) maintained client を install し recovery を test する。(3) 小額の合法資金を deposit する。(4) fresh internal payment requests を使う。(5) Lightning では gateway を observer として扱う。(6) redemption を test する。(7) source/tax records を public payment data の外部に保持する。<sup>[[13]](#references)</sup>

**Detection:** federation は aggregate issuance/redemption を、gateways は external invoices を把握します。Bitcoin/Lightning は boundaries を示し、endpoint/communication evidence が internal transfers を link する場合があります。

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash により、merchants には payer を anonymous にしつつ、merchants と income は accountable にすることを目指します。

**Pros:** payer privacy by design、通常の currency、merchant accountability/refunds、speculative token 不要。

**Cons:** deployments が限定的。exchange/bank は funding を把握し、merchant は order/delivery を把握します。wallet bearer/recovery risk、regulated operators があります。

**Procedure:** (1) jurisdiction/currency に対応する current exchange/merchant を探す。(2) KYC/fees/privacy を読む。(3) official wallet を install する。(4) supported bank/exchange から合法に withdraw する。(5) merchant contract を確認する。(6) pay して receipt/refund data を保存する。(7) 不要な merchant session identifiers を避ける。<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal と merchant deposit は accountable boundaries です。merchant order/device/delivery と timing は、coins が blinded でも相関する場合があります。

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service が1つの asset を lock/burn し、別の asset を release/mint します。または counterparties が atomic exchange を行います。single-ledger view を分けますが、economic continuity は消えません。

**Pros:** asset/network interoperability、centralized custodian を避けられる場合、通常の portfolio/liquidity use。

**Cons:** 両 chain は public。time/value/fees/liquidity と contracts が correlate します。bridge/relayer/frontend/RPC records、smart-contract/counterparty、regulatory risk が残ります。

**Procedure for lawful swaps:** (1) official contract/service と legal availability を確認する。(2) custody/audit/fees/slippage を確認する。(3) 小額で test する。(4) 両 transaction IDs と rate を記録する。(5) approvals を保護する。(6) destination asset を reconcile し、不要な approval を revoke する。source of funds を disguise するために swaps を使わない。

**Detection:** bridge deposit/withdraw events、unique amount minus fees、time order、liquidity、relayer/RPC/frontend、later service deposits を確認する。

## Centralized mixer or tumbler

**Mechanics:** service が deposits を pool に受け取り、後で異なる units を返して direct input-output mapping を隠そうとします。

**Pros:** 理論上、transaction ambiguity を増やせます。

**Cons:** operator による theft/logging、entry/exit timing/value analysis、sanctions/money-transmission/criminal exposure、seizure による mapping の露出、taint/rejection risk。

**Procedure:** operational mixing guide は提供しません。[Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) を拡張して graph を安全に再現します。synthetic deposits、pooled outputs、fees、delays を作成し、analysts に incomplete mappings を与え、どの heuristics が機能するかを測定し、その後 ground truth を公開します。

**Detection:** service wallet/contract identification、entry/exit candidate sets、amount/fee/timing、deposit address reuse、seized/provider logs、downstream consolidation を確認します。probabilistic attribution と明記します。

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** change から小額 payment を繰り返し peel し、多数の addresses に value を split し、collectors に reconverge し、または review 回避のため amounts を分割します。

**Pros:** naive analyst の workload と address count を増やします。

**Cons:** recognizable value/cadence/transaction continuity、consolidation と service endpoints。structuring 自体が illegal の場合があり、fees と operational errors もあります。

**Procedure:** synthetic CSV/testnet data のみを使用する。large source、repeated payment/change edges、parallel branches、one collector を生成する。benign exchange-like examples を追加し、detection を tune して false positives を文書化する。

**Detection:** graph continuity、repeated change pattern、cadence、just-below-control amounts、common service endpoint、off-chain records を確認する。exchange hot wallets も似た pattern になるため、context が必須です。<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** 別の person/account/company が funds を receive、convert、spend し、controller と transaction の間に legal/operational layers を挿入します。

**Pros to an adversary:** named account が直ちに controller を識別しません。cash、crypto、goods、jurisdictions を bridge できます。

**Cons:** identity fraud/money-laundering exposure。participants ごとに communications、bank/company/tax/shipping records、fees、矛盾、witnesses が増えます。facilitator の reuse は hubs を作ります。

**Procedure:** real people/accounts で emulate しない。controller、recruiter、mule、OTC、shell merchant、beneficiary を含む synthetic graph を構築し、device/IP/message/bank edges を seed し、investigators に account holder と controller を区別させ、evidence confidence を記録させる。

**Detection:** shared device/IP/recovery、unusual beneficiary/velocity、many unrelated senders、immediate onward movement、company/director/invoice inconsistency、communications、cash/commodity delivery を確認する。

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** value を self-priced asset、wagering balance、resalable goods、refund に変換し、別の transaction narrative を作ります。

**Pros to an adversary:** asset form を変更し、marketplace/merchant intermediaries を導入できます。

**Cons:** marketplace/account/device と wash-trade graph、odds/play と refund records、delivery/resale evidence、fees/losses、fraud/laundering liability。

**Procedure:** concealment workflow は提供しません。related-wallet self-trades、implausible pricing、minimal play、mismatched refund instrument、common shipping を含む synthetic marketplace data を使用し、legitimate collectors/customers に対して detection を検証します。

**Detection:** circular/self-funded trades、common ownership/funding、price outliers、immediate resale/refund、minimal economic activity、shared device/delivery、proceeds reconvergence を確認します。

## Physical bearer wallet or offline token transfer

**Mechanics:** device、paper/QR、hardware bearer instrument、e-cash token が、handover 時に payment を broadcast せず secret の control を移転します。

**Pros:** exchange 中に live network event がなく、offline で利用でき、physical cash-like custody が可能です。

**Cons:** copy/theft/loss と exclusivity の不確実性。later redemption/broadcast、physical meeting/shipping、counterfeit/tamper risk が残ります。

**Procedure:** (1) reviewed instrument/protocol のみ使用する。(2) authenticity を private に initialize/verify する。(3) 小額の合法な value のみ load する。(4) documented authorized context で transfer する。(5) receiver は protocol に従い迅速に verify または sweep する。(6) sender が copy を保持していないと仮定しない。(7) ownership/tax evidence を private に記録する。

**Detection:** purchase/funding と eventual sweep/redemption、device serial/tamper evidence、delivery/meeting、endpoint records を確認する。

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant が amount、expiry、order reference を含む single-use request を作成します。payer は reusable credential を merchant に直接開示せず supported rail で settle できますが、issuer/payment processor は両 parties を識別できる場合があります。

**Pros:** credential reuse と accidental cross-merchant identifiers を制限します。exact amount/expiry が errors を減らし、通常の accounting/refunds と互換性があります。

**Cons:** invoice、delivery、browser、processor、issuer は order を link します。unique amount/time は correlation を強める場合があり、malicious payment links も一般的です。

**Procedure:** (1) merchant を独立して authenticate する。(2) exact amount、asset/network、expiry の fresh invoice を request する。(3) destination と refund rules を確認する。(4) approved engagement compartment から pay する。(5) merchant が同じ invoice を acknowledge したことを確認する。(6) receipt と transaction reference を保存する。(7) request は reuse せず expire させる。

**Detection:** merchant と processor は invoice、session、settlement を join します。unique amounts/timing と delivery が payer を識別します。**Captured wallet/device:** invoice history は counterparties と purpose を露出します。不要な memo data を最小化し、device を encrypt し、authoritative accounting は controlled finance system に保持します。

## Prepaid service credit and capability token

**Mechanics:** service が conventional payment を bounded internal credits または bearer capability に変換します。その後の API/resource use は各 request で original card を提示せずに済みますが、service は issuance と redemption を map できる場合があります。

**Pros:** spend と compromise loss を制限し、day-to-day workers を funding credential から分離し、per-project budgets と revocation を支援します。

**Cons:** 通常は pseudonymous であり anonymous ではありません。service database、redemption IP、unique usage pattern が activity を link します。bearer tokens は盗難可能で、refund に original payer が必要な場合があります。

**Procedure:** (1) organization account で credits を購入する。(2) 1つの project と budget を作る。(3) service、amount、expiry constraints を持つ narrow token を発行する。(4) approved secret manager または workload identity path だけに保管する。(5) scope 外と expiry 後の rejection を test する。(6) consumption を monitor する。(7) unused value を revoke/reconcile する。

**Detection:** provider は funding account、project、token issuance、usage を join します。geographic/process changes と anomalous consumption を alert します。**Captured node:** remaining capability が spend 可能だと仮定し、short expiry、low balance、audience binding、immediate server-side revocation を使用します。

## Privacy Pass or blinded authorization token

**Mechanics:** issuer が privacy-preserving authorization token を発行し、origin は issuance と redemption を link せずに validate できます。paid entitlement または rate-limited access を表せますが、general currency ではありません。client、attester、issuer、origin roles を分離し、IP/timing や collusion が unlinkability を壊す可能性があります。<sup>[[18]](#references)</sup>

**Pros:** supported services で unlinkable redemption、origin に reusable account cookie 不要、cached tokens による issuance/use の時間分離。

**Cons:** application-specific。issuer/attester trust と anonymity-set partitioning。IP と browser metadata は残り、token theft や distinctive issuance timing が use を correlate します。

**Procedure:** (1) relevant Privacy Pass token type に準拠した implementation を使う。(2) token が証明する entitlement を正確に定義する。(3) threat model が必要とする場合 issuer と origin administration を分離する。(4) challenge metadata を最小化する。(5) test tokens を複数発行し、owned origins で各1回 redeem する。(6) forbidden stable identifiers が logs にないか比較する。(7) replay、expiry、revocation/abuse controls を test する。

**Detection:** origins は redemption IP/time と token validity を見ます。issuers/attesters は issuance context を見ます。cryptographic break を仮定せず timing と metadata partitions を test します。**Captured client:** unspent bearer tokens が利用可能な場合があるため、value、lifetime、audience を制限し、funding credential と同じ場所に cache しません。

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team、reseller、fiscal sponsor が contract/payment を担い、operational team は bounded service を受け取ります。これは truthful records に基づく role separation であり、nominee や false identity ではありません。

**Pros:** vendor はすべての operator identity や personal payment details を受け取る必要がありません。central compliance、tax、refund handling、clear budget、offboarding が可能です。

**Cons:** sponsor は beneficiary と purpose を把握します。contracts、approvals、delivery、accounts は残り、delay/fees が発生します。同一人物が全 layers を管理すると separation は弱くなります。

**Procedure:** (1) business purpose、beneficiary、approving authority を文書化する。(2) organization-approved intermediary を選ぶ。(3) truthful details で contract する。(4) personal billing credential のない project-scoped subaccount を provision する。(5) finance administrators と operators を分ける。(6) invoices/access を reconcile する。(7) closeout で service と delegated access を terminate する。

**Detection:** procurement、identity-provider、vendor、delivery records が chain を join します。**Captured operational device:** service project は示してよいが finance credentials は示してはいけません。invoices と payer identities は field nodes ではなく finance system に保持します。

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent または smart contract が、documented conditions が満たされるまで value を保持します。payer/payee 間の direct disclosure を減らせますが、escrow と underlying payment rails は relationship を保持します。

**Pros:** dispute/delivery protection、互いに reusable credentials を少なく開示、auditable release conditions。

**Cons:** escrow custody/contract risk、fees、identity obligations。on-chain contracts は public で、order、shipping、dispute data は残ります。intermediary に対して anonymous ではありません。

**Procedure:** (1) legal entity、custody、fees、dispute forum、supported assets を確認する。(2) exact written milestone と refund path を作る。(3) approved organization account から fund する。(4) receipt と release authorization を独立して確認する。(5) evidence 後のみ release する。(6) complete audit record を保存する。(7) unused permissions/contract approvals を close する。

**Detection:** escrow account/contract events、funding/release time、beneficiary、dispute records が transaction を示します。**Captured device:** session tokens または contract approvals が release を可能にする場合があるため、separate approver/MFA を要求し、loss 時に active sessions を revoke します。

## Batched or pooled organization settlement

**Mechanics:** approved obligations を aggregate し、少数の bank/blockchain transactions で settle します。private internal ledger が各 share を割り当てます。batching は public per-purchase detail を減らせますが、coordinator は complete attribution を保持します。

**Pros:** fees を下げ、public graph edges を減らし、amounts が aggregate されると public observer から individual line items を隠せます。internal accounting も容易です。

**Cons:** coordinator は complete observer かつ high-value target。distinctive totals/timing が correlate します。custody/reconciliation risk があり、abuse すると structuring に見える場合があります。

**Procedure:** (1) accounting system で participants と lawful obligations を定義する。(2) controls 回避を目的とした thresholds ではなく、business-justified regular batch window を設定する。(3) aggregate に dual approval を要求する。(4) authenticated recipients に settle する。(5) every internal line を batch に reconcile する。(6) refunds は linked corrections として処理する。(7) ledger access を保護し policy に従い保持する。

**Detection:** coordinator ledger、approval、beneficiary records が ground truth を提供します。public analysts は input/output/value/time clustering を慎重に利用します。**Captured payer device:** requisition のみを持ち、pool signing key や participant ledger は持たないようにします。

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler が smart-account operation を submit し、paymaster が transaction fees を支払います。これにより user wallet からの direct native-gas funding edge を避けますが、operation、contract、service telemetry は public または observable です。<sup>[[19]](#references)</sup>

**Pros:** common gas-funding link を除去し、scoped sponsorship と rate limits を支援し、legitimate privacy applications の onboarding を改善します。

**Cons:** paymaster/bundler/RPC/frontend が requests を correlate できます。contract events/public inputs は残り、sponsorship policy が cohort を fingerprint します。malicious contracts/approvals は assets を盗めます。

**Procedure:** (1) correct network 上の audited maintained smart account/paymaster を使う。(2) public fields と sponsor logs を確認する。(3) contract、function、amount、nonce、expiry で sponsorship を制限する。(4) low value で test する。(5) application の intended privacy-aware path から submit する。(6) operation と fee payer を chain 上で確認する。(7) allowances/session keys を revoke し compliance records を保持する。

**Detection:** UserOperation、EntryPoint、paymaster、bundler/RPC、application logs を join します。同一 sponsorship policy の clustering は慎重に行います。**Captured wallet:** gas がなくても session keys と pending approvals が利用可能な場合があるため、scope を厳しくし account recovery policy で revoke します。

## Threshold or multisignature payment authorization

**Mechanics:** spending に independent signers の threshold が必要です。transaction は隠しませんが、payment authority を captured laptop、field node、single operator から分離します。

**Pros:** compromise/insider resistance、accountable approval、field device が complete signing authority を持たない、recovery を支援。

**Cons:** coordination/availability、signer/device/account metadata による correlation、悪い backup design による loss、識別可能な public multisig patterns。

**Procedure:** (1) funding 前に signers、threshold、limits、recovery を定義する。(2) separate supported hardware/accounts で initialize する。(3) addresses と backups を独立して verify する。(4) field workloads には unsigned requisition capability のみ与える。(5) recipient、amount、purpose を out-of-band review する。(6) small value で recovery と one-signer loss を test する。(7) compromise 後に signer を rotate する。

**Detection:** approval system、signer device、public script/contract が evidence を提供します。policy/signer-set changes を alert します。**Captured node:** 最大でも low-authority session key または unsigned request だけを露出し、quorum material を同じ場所に cache しません。

## Closed-loop community or event currency

**Mechanics:** cooperative、conference、private test environment が、enrolled participants 間のみで redeemable な credits を発行します。internal transfer は global payment networks から見えにくくできますが、operator は issuance/redemption を制御します。

**Pros:** bounded economic domain、offline/privacy-preserving payment UX の test、external card exposure の制限、明確な experimental controls。

**Cons:** small anonymity set。operator と merchants は activity を見ます。acceptance/redemption が限定され、local value にも licensing、consumer-protection、tax rules が適用される場合があります。

**Procedure:** (1) legal/compliance review を得て issuer terms を公開する。(2) consenting test participants を enroll する。(3) issuance を cap し cash-like misuse を禁止する。(4) fresh payment requests を使い public participant identifiers を最小化する。(5) aggregate reserves と private individual receipts を記録する。(6) loss/refund/redemption を test する。(7) ledger を close し residual value を約束どおり返す。

**Detection:** issuer ledger、enrollment、merchant、redemption records が flows を再構成します。unusual circular transfers や rapid cash-out を review します。**Captured wallet:** local balance と counterparties が露出するため、value を cap し state を encrypt し、auditable record 付き issuer-side freeze/reissue を支援します。

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes は reusable public identifier と ECDH-derived one-time deposit addresses を使用します。BIP 351 は新しい private-payment instruction design を定義します。public address reuse を減らし、recipient が stable payment instructions を公開できます。notification、wallet support、funding、subsequent coin selection は privacy に影響します。<sup>[[20]](#references)</sup>

**Pros:** 1つの public instruction から distinct addresses を生成でき、recipient は invoice address ごとに公開する必要がありません。対応 wallet は derived payments を monitor できます。

**Cons:** wallet interoperability の差。notification transactions や published payment code が relationship context を link します。sender、recipient、public graph は transactions を見ます。careless consolidation/change handling が benefit を壊します。

**Procedure:** (1) 両 maintained wallets が完全に同じ specification/version を support することを確認する。(2) low-value wallet で backup/recovery を test する。(3) recipient payment code を out of band で authenticate する。(4) 小額の合法な test を送る。(5) fresh derived address が使われたことを確認する。(6) relationship を local に label し coin control を適用する。(7) reliance 前に recovery と refund behavior を test する。

**Detection:** notification patterns、funding/change、later consolidation、service boundaries を確認します。public-code publication は deposit addresses が異なっても recipient context を示します。**Capture-resilient OPSEC:** spend keys を field devices から離し、最大でも watch-only relationship view のみ公開します。**Monitoring:** unexpected notification transactions、reused derived addresses、wallet gap-limit/recovery errors、unplanned consolidation を alert します。

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender が recipient の stealth meta-address から one-time stealth account を derive し、ephemeral public key と view tag を含む announcement を公開します。recipient は viewing key で announcements を scan し、対応する spend key を derive します。recipient linkage は改善しますが、sender、amount/token、gas、announcement、later spending は visible です。<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address、reusable meta-address、viewing/spending roles の分離、supported EVM assets/applications で動作。

**Cons:** announcement scanning/spam。new address の gas funding が再 link する場合があります。sender は recipient を知り、public token/amount と eventual consolidation は残ります。implementation/wallet support は異なります。

**Procedure:** (1) test network で audited maintained implementation を使う。(2) separate viewing/spending material を生成し backup する。(3) meta-address を authenticate する。(4) low-value test と announcement を送る。(5) scan して stealth account を derive する。(6) personal funding edge なしの supported gas sponsorship を test する。(7) public fields を記録し lawful accounting を保持する。

**Detection:** announcement caller、token/amount、timing、gas sponsor、spending、consolidation を追跡します。view key は spend を与えず receipt を証明できます。**Capture-resilient OPSEC:** networked scanner は可能なら viewing role のみとし、spend/recovery keys を別に保持します。**Monitoring:** malformed/spam announcements、view-key access、unexpected spend derivation、approval なしの stealth outputs movement を alert します。

## Liquid Confidential Transactions

**Mechanics:** Liquid は commitments/proofs を使い、output amounts と asset types を default で blind します。一方、transaction graph、input/output count、fee、block time は visible です。peg-in/peg-out と service boundaries は linkable で、users は blinding data を selective disclosure できます。<sup>[[22]](#references)</sup>

**Pros:** confidential amount/asset type が default、fast sidechain settlement、blinding keys/descriptors による selective audit、public observers から commercial values を隠す機能。

**Cons:** graph structure/timing は残ります。federation/bridge と exchange trust、peg boundaries、unconfidential outputs、wallet/node/network records、sender/receiver の transaction knowledge が残ります。

**Procedure:** (1) maintained Liquid wallet を選び backup model を確認する。(2) testnet または小額の合法な amount を使う。(3) confidential address に receive し、output が blinded と表示されることを確認する。(4) confidential transaction を test する。(5) explorer で public に残る fields を確認する。(6) audit に必要な scoped blinding proof のみ export する。(7) peg/exchange boundaries を文書化し funds を reconcile する。

**Detection:** visible graph/fee/time、peg/exchange records、network metadata、later unblinding evidence を分析します。hidden amount/asset を推測しません。**Capture-resilient OPSEC:** spend seed、blinding/view data、watch-only operations を分離します。**Monitoring:** accidental unconfidential addresses、unknown peg requests、descriptor changes、unapproved unblinding-key export を alert します。

## General payment or state channel

**Mechanics:** participants が funds を lock し、signed off-chain state updates を交換し、opening、closing、disputed state のみを chain に publish します。intermediate payments は global に broadcast されませんが、peers と routing/intermediary services は自分の portion を見て、endpoints は latest enforceable state を保持する必要があります。<sup>[[23]](#references)</sup>

**Pros:** fast low-fee private-to-public-ledger interactions、global transaction detail の削減、bounded channel balance、metered services と repeated counterparties に有用。

**Cons:** channel peers は互いを知り updates を保持できます。opening/closing/value/timing が correlate し、challenge windows 中に online monitoring が必要な場合があります。implementation/liquidity risk があり、単独では大きな anonymity set ではありません。

**Procedure:** (1) maintained audited implementation を選び dispute window を理解する。(2) owned parties 間で low-value test channel を open する。(3) unique nonces 付き signed state updates を交換する。(4) latest enforceable state を backup する。(5) cooperatively close する。(6) testnet で stale-state rejection を rehearse する。(7) accounting と channel-peer records を保持する。

**Detection:** public chain は lifecycle/disputes を示し、peers、watch services、application transport は off-chain timing/parties を示します。**Capture-resilient OPSEC:** hot balance を cap し、latest signed state を encrypted recoverable store に field nodes とは別に保存します。**Monitoring:** stale-state publication、missed backup、peer-key change、approaching challenge deadline を継続的に監視します。

## Mobile carrier billing

**Mechanics:** online service が mobile subscription または prepaid balance に purchase を charge します。merchant には card/bank details の代わりに carrier authorization が渡る場合がありますが、carrier は subscriber/line、device/network context、merchant、amount、time を把握します。<sup>[[24]](#references)</sup>

**Pros:** merchant に card number を渡さない。phone availability が広く、low-value digital goods に利用でき、carrier が charges を cap/reverse できます。

**Cons:** SIM/account と多くの場合 device に強く識別されます。limits は小さく fees は高く、merchant category restrictions、account takeover/SIM-swap risk、complete transaction trail があります。

**Procedure:** (1) organization carrier account で availability、limit、fee、refund terms を確認する。(2) justified な場合のみ dedicated organization line で有効化する。(3) 必要最小限の spend cap を設定する。(4) benign test item を購入する。(5) merchant/carrier receipts を確認する。(6) recurring authorization を無効にする。(7) reconcile し assessment 後に機能を停止する。

**Detection:** carrier、aggregator、merchant records が line、subscriber、IP/device、charge を join します。enterprise telecom invoices にも表れます。**Capture-resilient OPSEC:** personal number を使わず、carrier-account MFA を field device の外部に置きます。**Monitoring:** instant charge/SIM-change alerts を有効にし、unexpected premium-service enrollment、forwarding、account recovery で停止します。

## Open-banking payment initiation

**Mechanics:** explicit user consent により、regulated PISP が account-servicing bank に transfer initiation を依頼します。merchant は card credentials を受け取らない場合がありますが、PISP と banks は regulated payer、payee、consent、device、transaction records を保持します。<sup>[[25]](#references)</sup>

**Pros:** checkout で reusable card number を渡さない。strong bank authentication、exact account-to-account settlement、consent/status APIs、明確な reconciliation。

**Cons:** banks/PISP に対して anonymous ではありません。payee は legal account details/reference を見る場合があり、phishing/redirect risk、jurisdiction と refund protection の差、consent metadata があります。

**Procedure:** (1) PISP が現在 regulated で、merchant callback domain が authentic か確認する。(2) merchant request から開始する。(3) bank で payee、amount、reference、requested consent を確認する。(4) single payment のみ authorize する。(5) final status を独立して確認する。(6) residual consent があれば revoke する。(7) receipt を保持し reconcile する。

**Detection:** bank/PISP/merchant logs と transfer references が強い attribution を提供します。**Capture-resilient OPSEC:** banking authentication/recovery を operational/field devices から分離します。device には paid-service entitlement のみを保持します。**Monitoring:** bank transaction/consent alerts を使い、new PISP grants、changed payee、expected session 外の status callbacks を調査します。

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform が user に bill するか account credit を redeem し、application に signed receipt/entitlement を発行します。app developer は original funding instrument を受け取らない場合がありますが、platform は account、device、funding、product、redemption を map します。<sup>[[26]](#references)</sup>

**Pros:** merchant/developer は primary PAN を取得しません。fraud/refund と family/business controls、exposure を cap する small prepaid balance、entitlement verification を簡単にする signed receipts。

**Cons:** platform account は strong identity/behavior hub。device/storefront geography、gift-balance purchase/redemption trail、limited cash-out、freeze、cross-platform money ではない点。

**Procedure:** (1) policy が許せば organization-managed platform account を使う。(2) funding、region、refund、transferable-value rules を確認する。(3) approved budget のみ追加する。(4) official store で benign product を購入する。(5) application が expected receipt fields のみ受け取ることを確認する。(6) recurring purchase を無効にする。(7) reconcile し operational hardware から account を remove する。

**Detection:** platform receipts/server notifications、account/device login、funding records が purchase を再構成します。**Capture-resilient OPSEC:** field node を personal store account に sign in させず、可能なら scoped app entitlement のみを提供します。**Monitoring:** new-device/purchase alerts を有効にし、receipt replay、family/account changes、unexpected restore events を調査します。

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants が private ledger に obligations を記録し、periodically 各 net position のみを settle します。individual service events は separate public payments を必要としない場合がありますが、ledger operator と counterparties は詳細な attribution を保持します。

**Pros:** external transactions と fees を減らし、public observers には net settlement のみを見せ、repeated organizations に使えます。explicit credit limits が exposure を抑えます。

**Cons:** centralized ledger は complete evidence で fraud target。counterparty/default risk、legal/accounting/tax duties、small membership set、unusual net transfers による relationship exposure。

**Procedure:** (1) identified consenting organizations と legal/accounting approval のみで使用する。(2) unit、credit limit、settlement interval、dispute rules を定義する。(3) every obligation を immutable approval 付きで記録する。(4) separate finance roles に net positions を計算・承認させる。(5) ordinary lawful rail で settle する。(6) individual lines を settlement に reconcile する。(7) access を close し policy に従い records を保持する。

**Detection:** ledger、invoices、approvals、final bank/chain settlement が ground truth を提供します。net transfer のみから missing gross activity を推測しません。**Capture-resilient OPSEC:** operational devices は bounded requisitions のみ submit し、balances を edit または settlement を authorize できないようにします。**Monitoring:** credit-limit breach、backdated entries、administrator changes、reconciliation mismatch、new beneficiary への settlement を alert します。

## Capture/compromise exposure matrix

これはすべての family に seizure/loss test を適用します。目的は、合法な accounting を保持しながら spend authority と無関係な identity disclosure を制限することであり、transactions を消去したり investigation を妨害したりすることではありません。

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts、serials、notes、remaining bearer value、physical contacts | approved amount のみ携行、private accounting を分離、loss を速やかに report、false records を作らない |
| Prepaid, gift, voucher, service credits | balance、issuer、activation、redemption、account/session tokens | low balance、one purpose、truthful registration、可能なら issuer freeze/revocation |
| Virtual/tokenized card, wallet token, payment app | issuer account、device token、transactions、recovery、merchant history | device lock、transaction alerts、merchant scope、remote issuer suspension、shared recovery account を使わない |
| Bank compartment, delegated procurement, red-team procurement | organization、approvers、vendor、invoices、project | role separation、least-privilege subaccount、finance credentials を operational/field nodes に置かない |
| Invoice, escrow, batch settlement | counterparty、purpose、pending approval、coordinator/dispute trail | single-use request、separate approver、limited session、central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys、labels、addresses、transaction graph、network configuration | hardware/offline signing、encrypted wallet、passphrase limits、watch-only field view、documented recovery |
| Lightning/BOLT 12 | seed、channels、invoices、peers/LSP、payment database | minimal hot balance、encrypted backup、separate node identity、documented close/recovery |
| Monero, Zcash, MWEB, ZK applications | spend/view keys、local wallet history、RPC、boundary transactions | separate spend/view roles、可能なら hardware support、field node に exchange session を置かない |
| Stablecoins, swaps, bridges and DEX | transparent graph、approvals、RPC/frontend state、destination assets | allowances を revoke、verified contracts、low-value test、complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens、mint/federation/exchange、issuance/redemption cache | small balance、protocol が support する encrypted backup、redeem/reissue、funding credential を colocate しない |
| Paymaster, multisig/threshold | session key、one signer、pending operations、sponsor policy | narrow session key、independent quorum、signer rotation、field device が threshold に到達できないようにする |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider、communications、graph、participant records | operational use 禁止、synthetic/testnet evidence のみで emulate |
| Community/event currency | enrollment、local balance、counterparties、redemption | capped value、issuer freeze/reissue、consent、private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys、relationship metadata、announcements、derived outputs | watch/view-only network role、offline/hardware spend role、personal funding session なし |
| Liquid confidential/state channels | seed、blinding data/latest state、peers、boundaries、disputes | separate spend/view/state backup、low hot balance、independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account、consent、receipt、device、funding source | organization account、external MFA、low limit、field hardware に personal account を置かない |
| Mutual-credit clearing | members、obligations、limits、approvals、settlement ledger | operational requisition のみ、separate immutable ledger、dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial、compliance review、wallet offline は investigation の存在を証明しません。organization が observe する権限を持つ accounts、ledgers、infrastructure のみを monitor し、provider や counterparty が investigators に協力しているかを確認するための probing は行いません。

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch、duplicate serial、unexpected redemption/refund、loss report | missing instrument、approved order 外の redemption、altered receipt、custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts、new device/consent/payee、token reuse、SIM/account recovery | unknown authorization、payee change、new recovery factor、SIM swap、recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project、role/token/budget change、invoice、consumption | cross-project token、unknown admin、limit breach、invoice mismatch、unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry、approval/release、ledger integrity、reconciliation、beneficiary change | altered amount/payee、backdated ledger、unilateral release、unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions、notification/scan state、address reuse、UTXO labels、consolidation | unknown spend、reused recipient output、wallet gap/recovery failure、unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees、coordinator availability、final transaction equality | substituted output、excessive fee、unexpected input disclosure、coordinator policy change |
| Lightning/BOLT12/general channels | channel backup、invoice/offer use、liquidity、peer/LSP、chain dispute | unknown invoice payment、peer-key change、stale close、approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events、pool/domain/address type、descriptor、boundary transaction | spend without approval、transparent/unconfidential downgrade、key export、unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement、RPC/bundler、gas sponsor、allowance/session key、issuer action | wrong contract/public field、unknown approval/spend、paymaster change、issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health、token double-spend/replay、gateway、bearer balance | unknown redemption、mint key/terms change、restore failure、balance inconsistency |
| Swaps/bridges/DEX | verified contract、allowance、both-chain confirmations、rate、destination | contract/route mismatch、unlimited approval、missing destination、bridge incident |
| Multisig/threshold | signer-set/policy change、pending proposal、quorum、recovery audit | unknown proposal/signer、threshold reduction、recovery activation、policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth と detection output のみ | real account/person/value が emulation に入った場合は直ちに停止 |

## Selection and verification workflow

1. どの party に、どの field を知られてはならないかを明確にする。
2. issuer/mint/custodian、public ledger、network/RPC、merchant、physical observers を特定する。
3. current support、legality、limits、custody、recovery、refund behavior を確認する。
4. 小額の合法な end-to-end test を行う。
5. merchant receipt、provider statement、public chain、wallet/node logs を確認する。
6. backup/recovery と deliberate audit disclosure を test する。
7. 必須の source、ownership、tax、sanctions、engagement records は正確に、access-controlled に保持する。

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — 大規模 payment platforms による data collection に関する observations](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — privacy の保護](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Simple Payjoin Proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — zero-knowledge proofs を使用した privacy applications の構築](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — How it works](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
