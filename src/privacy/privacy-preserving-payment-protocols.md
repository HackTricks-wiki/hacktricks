# Privacy-Preserving Payment Protocols

{{#include ../banners/hacktricks-training.md}}

高度な決済システムは、支払者を merchant から隠したり、公開 ledger から受取人や金額を隠したり、mint が withdrawal と redemption を関連付けることを防いだりできます。これらは異なる特性です。いずれも、取得、デバイス、ネットワーク、配送、会計、制裁、エンドポイントの記録を消去するものではありません。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) では、すべての payment family について、標準化された `Pros`、`Cons`、手順ごとの `Procedure`、`Detection` の項目を提供しています。このページでは、高度な protocol を詳しく説明します。

{% hint style="danger" %}
合法な資金と取引相手のみを使用してください。必要な本人確認、制裁、税務、資金源確認、取引報告を回避するために privacy protocol を使用しないでください。ライセンス、custody、AML、consumer protection に関する義務を理解せずに、exchange、mint、transmission service を運営しないでください。
{% endhint %}

## 高度な選択肢の比較

| Protocol | public/merchant から隠すもの | 信頼または監視する party | 成熟度/利用可能性 |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | 外部者は、再利用可能な payment code を各 one-time output に関連付けられない | 公開 Bitcoin graph は残る。wallet/index server は scan を認識できる可能性がある | 仕様は完成済み。wallet の対応状況は異なる |
| Zcash fully shielded Orchard | sender、receiver、amount は on-chain で暗号化される | wallet backend/network と acquisition/off-ramp は残る | deployed。wallet/exchange により shielded support は異なる |
| GNU Taler | merchant は payer identity を知る必要がない。merchant の収入は追跡可能な状態に保たれる | Taler exchange/bank は funding を認識する。merchant は order を認識する | deployment は地域的に限定される |
| Federated Chaumian e-cash | federation は発行済み note を内部 transfer/redemption に関連付けないことが期待される | guardian quorum が reserve を custody する。gateway は境界上の activity を認識する | community deployment が拡大中 |
| Lightning BOLT 12/route blinding | receiver/node と route の disclosure を減らす | endpoint、選択された hop、funding chain、wallet service | wallet に依存 |
| Virtual card/token | merchant は再利用可能な PAN ではなく、制限付き credential を受け取る | issuer/network は payer と transaction を保持する | 成熟しており、広く利用可能 |

## Bitcoin Silent Payments (BIP 352)

Silent Payments では、receiver が 1 つの static payment code を公開し、各 sender が一意の Taproot output を導出できます。外部の chain observer は、それらの output を公開された code に直接関連付けることができず、interactive な address request や on-chain notification output も必要ありません。BIP 352 は **Complete** とされていますが、scan のコストが発生し、実装していない wallet とは互換性がありません。<sup>[[1]](#references)</sup>

### Receiver の workflow

1. BIP 352 の receiving を明示的にサポートする、保守されている wallet を選択します。social-media の主張ではなく、wallet の最新ドキュメントで機能を確認してください。
2. wallet に記載された recovery method を使用して、wallet seed と Silent Payment descriptor/key material を backup します。code を公開する前に、少額の testnet/mainnet amount で discovery をテストします。
3. wallet が BIP 352 labels をサポートしている場合、campaign、invoice、counterparty ごとに別々の **labels** を生成します。labels は、関連付け可能な address を公開せずに、ローカルの会計処理を補助します。
4. 認証済みの channel で static Silent Payment code を公開します。再利用可能ですが、攻撃者が自分の code に置き換える可能性があります。
5. 可能な場合は、local full node を通じて scan します。third-party の index/scanning server は、使用している資金を消費できなくても、request timing や filter data を把握できます。
6. 発見した UTXO に label を付け、通常の Bitcoin と同じ coin-control rule を適用します。これらを使用または統合すると、所有関係が明らかになる可能性があります。
7. backup していない外部 index に依存せず、recovery によって payment を発見できることを確認します。

### Sender の workflow

1. wallet がその address version への送信をサポートしていることを確認し、receiver の長い static code を認証します。
2. wallet に output を構築させます。code を手動で変換または切り詰めないでください。
3. 選択された input を慎重に確認します。Silent Payments は recipient-address privacy を向上させますが、sender input は依然として公開 graph 上に存在します。
4. wallet がサポートする fee bumping/PSBT の動作を使用します。BIP 352 では input が変更された場合に output の再導出が必要であり、一部の signing mode は安全ではありません。
5. dispute/accounting に必要な encrypted receipt または proof を保持します。

Silent Payments は、receiver address の繰り返し公開を解決します。amount、transaction timing、sender cluster、acquisition history、後続の co-spending は隠しません。

## Zcash fully shielded payments

Zcash は transparent と shielded の value pool をサポートします。Orchard shielded transaction は zero-knowledge proof を使用するため、transaction detail が暗号化された状態でも node は validity を検証できます。Unified Address には複数の receiver type を含めることができます。<sup>[[2]](#references)</sup> Privacy は表示された address の最初の文字ではなく、wallet が実際に選択した path に依存します。

### Shielded workflow

1. **shielded-by-default** の動作と現在の Orchard support を明確に示す、保守された wallet を選択します。download を確認し、seed を backup/test します。
2. 合法的に ZEC を取得し、根拠と source を記録します。exchange は acquisition と withdrawal を把握しています。
3. wallet がサポートする Unified Address で受け取り、transaction が shielded pool に入ったかを確認します。wallet の動作を確認せずに、自動的に shielding されたと想定しないでください。
4. **shielded-to-shielded** transfer を優先します。transparent-to-shielded と shielded-to-transparent の境界上の移動では、public value/timing が露出し、amount correlation が可能になります。Orchard specification では、non-Orchard address への spending によって transaction value が明らかになると説明されています。<sup>[[3]](#references)</sup>
5. 特徴的な正確な amount の往復や、即時の境界通過を避けます。これは privacy hygiene であり、所有権や報告を隠す許可ではありません。
6. wallet がサポートする network-privacy path を使用します。shielded cryptography は、wallet server や peer から IP/timing を隠しません。
7. 内部の compliance record を保持し、scope を理解したうえで、意図的な audit/disclosure にのみ viewing key を使用します。
8. 送信前に recipient wallet/exchange の対応を確認します。transparent receiver を強制されると、privacy property が変わります。

## GNU Taler: anonymous payer, accountable merchant

GNU Taler は、traditional currency、blind signature、regulated exchange/bank integration を使用する open electronic-payment protocol です。その設計は、merchant に対して customer を anonymous に保ちながら、merchant は identifiable かつ taxable な状態にすることを目的としています。<sup>[[4]](#references)</sup> これは cryptocurrency ではなく、利用可能性は互換性のある地域の exchange、bank、wallet、merchant に依存します。

### 展開されている場所での User workflow

1. 対象の currency/jurisdiction で運用されている Taler exchange と merchant を特定し、最新の terms、fees、KYC、privacy notice を確認します。
2. official wallet を install し、その source を確認します。wallet value は bearer asset になる可能性があるため、wallet の backup/recovery data を cash と同じように保護します。
3. 正確な情報を使用し、サポートされている bank/exchange flow で value を withdrawal します。blind signature により coin と withdrawal の直接的な link が切断されても、funding institution/exchange は withdrawal を把握する可能性があります。
4. wallet 内の merchant contract を確認します。merchant identity、item/summary、amount、fees、refund、delivery terms を確認してください。
5. 支払いを行い、refund、warranty、accounting、tax に必要な receipt data を保存します。
6. merchant unlinkability が必要な場合は、任意の merchant session/account identifier を再利用しないでください。
7. wallet、network、delivery metadata を threat model に含めます。Taler の payment cryptography は shipping address や compromised endpoint を隠しません。

merchant と exchange は引き続き説明責任を負い、いずれかの component を運用することは regulated payment-service activity になる可能性があります。

## Federated Chaumian e-cash

Chaumian e-cash は blind signature を使用するため、mint は token に署名できますが、後で使用される unblinded token を見ることはありません。Fedimint は guardian federation 全体に reserve custody と signing を分散します。その documentation では、guardian は aggregate reserve/outstanding note を認識するものの、federation 内の個々の balance や誰が誰に支払ったかは認識すべきではないと説明されています。<sup>[[5]](#references)</sup>

これは **custodial bearer value** です。十分な guardian quorum が reserve を管理します。federation failure、不正な guardian、software bug、client state の紛失によって損失が発生する可能性があります。deposit、withdrawal、Lightning gateway は可視の境界上の event であり、timing/amount を相関させることができます。

### Limited-risk workflow

1. 失っても問題のない少額のみを使用します。public/unknown federation は、現実世界で説明責任を持つ guardian よりも高リスクであると考えてください。
2. 認証済み channel で federation invite を確認し、guardian identity、quorum、jurisdiction、fees、recovery、shutdown policy を記録します。
3. 互換性のある保守された wallet を install して確認し、deposit 前に backup scheme を理解します。
4. documented path を通じて、合法的に取得した Bitcoin を deposit します。会計のために peg-in を記録し、その timing/amount が境界上で public または既知であると想定します。
5. federation 内では新しい payment request を使用し、blind signature が除去した link を再構築する account/chat/delivery identifier の追加を避けます。
6. Lightning payment では、gateway が invoice と境界上の timing を監視する追加の observer であると考えます。
7. policy に従って redeem/withdraw します。特徴的な amount と即時の timing は、deposit や外部 payment と相関する可能性があります。
8. tax/source/authorization record は private に保持し、guardian や gateway に activity を虚偽報告させないでください。

federated e-cash を trustless、self-custodial、または guaranteed anonymous と説明しないでください。

## BOLT 12 offers and route blinding

BOLT 12 offer は、stable on-chain address を公開せずに再利用でき、blinded path を使用して payer が receiver の明確な node identity/path を知る必要をなくす場合があります。これは Lightning の既存の onion routing を補完しますが、置き換えるものではありません。

使用前に、次を確認します。

1. sender と receiver の wallet が、同じ現在の BOLT 12 feature をサポートしていることを確認します。一般的な「Lightning」という branding から support を推測しないでください。
2. out-of-band で offer を認証し、amount、issuer/description、recurrence rule を確認します。
3. offer から生成された新しい invoice/payment context を使用します。
4. node alias、public contact information、stable network endpoint は最小限にします。
5. sender/receiver、first/last hop、wallet service、channel graph、on-chain funding/closure が、関係の一部を引き続き開示すると想定します。

## Public disclosure を伴わない Auditability

Privacy と audit は両立できます。

- label、invoice、authorization、cost basis、ownership mapping を、public protocol の外部で encrypted な状態にして保持します。
- protocol が提供する場合は、**view/audit key** と spending key を分離します。まず sample wallet で正確な disclosure 範囲をテストします。
- seed や unrestricted spending credential ではなく、scope を最小限にした proof を auditor に提供します。
- transaction 時点で、software version、protocol/pool、transaction ID または proof、counterparty purpose、exchange-rate source を記録します。
- 永続的な unencrypted identity graph を蓄積するのではなく、retention と deletion を定義します。

## Selection checklist

- [ ] 隠される field と observer が正確に特定されている。
- [ ] wallet/protocol support が transaction date 時点で確認されている。
- [ ] acquisition、network、node/RPC、counterparty、delivery、後続の spend link が記録されている。
- [ ] custody、recovery、liquidity、issuer/federation solvency、refund risk を受け入れている。
- [ ] 必要な identity、tax、sanctions、source、organizational record が正確に維持されている。
- [ ] recovery と audit proof を含む、end-to-end の小規模 test が成功している。

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
