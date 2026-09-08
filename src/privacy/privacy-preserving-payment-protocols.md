# Privacy-Preserving Payment Protocols

高度な決済システムは、支払者を merchant から隠したり、公開 ledger から受取人や金額を隠したり、mint が withdrawal と redemption を関連付けることを防いだりできます。これらは異なる性質です。いずれも、取得、デバイス、ネットワーク、配送、会計、制裁、endpoint の記録を消去するものではありません。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) では、すべての payment family について、標準化された `Pros`、`Cons`、手順ごとの `Procedure`、`Detection` エントリを提供しています。このページでは高度な protocol を詳しく説明します。

{% hint style="danger" %}
合法的な資金と相手方のみを使用してください。必要な本人確認、制裁、税務、資金源確認、transaction reporting を回避するために privacy protocol を使用しないでください。ライセンス、custody、AML、consumer-protection 上の義務を理解せずに、exchange、mint、transmission service を運営しないでください。
{% endhint %}

## Compare the advanced options

| Protocol | 公開情報/merchant から隠すもの | Trusted または observing party | 成熟度/利用可能性 |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | 外部者は、再利用可能な payment code と一回限りの output を関連付けられない | 公開 Bitcoin graph は残る。wallet/index server は scan を認識できる場合がある | 仕様は完成。wallet の対応状況は異なる |
| Zcash fully shielded Orchard | 送信者、受取人、金額が on-chain で暗号化される | Wallet backend/network と acquisition/off-ramp は残る | 展開済み。shielded 対応は wallet ごとに異なる |
| GNU Taler | merchant は支払者の identity を知る必要がない。merchant の収入は説明責任を維持する | Taler exchange/bank は funding を認識し、merchant は order を認識する | 展開地域は限定的 |
| Federated Chaumian e-cash | Federation は発行済み note と内部 transfer/redemption を関連付けないことが期待される | Guardian quorum が reserve を custody し、gateway は境界上の activity を認識する | コミュニティによる導入が進行中 |
| Lightning BOLT 12/route blinding | receiver/node と route の開示を低減する | Endpoint、選択された hop、funding chain、wallet service | 対応は wallet に依存 |
| Virtual card/token | merchant は再利用可能な PAN ではなく、制約付き credential を受け取る | Issuer/network は支払者と transaction を保持する | 成熟しており広く利用可能 |

## Bitcoin Silent Payments (BIP 352)

Silent Payments では、receiver は 1 つの static payment code を公開し、各 sender は一意の Taproot output を導出できます。外部の chain observer は、その output を公開された code に直接関連付けられず、interactive な address request や on-chain notification output も必要ありません。BIP 352 は **Complete** とされていますが、scan のコストが発生し、実装していない wallet とは互換性がありません。<sup>[[1]](#references)</sup>

### Receiver workflow

1. BIP 352 receiving を明示的にサポートしている、保守された wallet を選択します。social-media の主張ではなく、wallet の最新ドキュメントで機能を確認します。
2. wallet の文書化された recovery method を使用して、wallet seed と Silent Payment descriptor/key material を backup します。code を公開する前に、少額の testnet/mainnet amount で discovery をテストします。
3. wallet が BIP 352 labels をサポートしている場合、campaign、invoice、counterparty ごとに個別の **labels** を生成します。labels は、linkable address を公開せずにローカルの会計処理を補助します。
4. 認証済み channel を通じて static Silent Payment code を公開します。再利用できますが、攻撃者が自分の code に置き換える可能性があります。
5. 可能な場合は local full node を通じて scan します。第三者の index/scanning server は、支出できない場合でも request timing や filter data を知ることができます。
6. 発見した UTXO に labels を付け、通常の Bitcoin と同じ coin-control rules を適用します。これらを使用または consolidate すると、所有関係が明らかになる可能性があります。
7. backup されていない外部 index に依存せず、recovery によって payment を発見できることを確認します。

### Sender workflow

1. wallet が address version への送信をサポートしていることを確認し、receiver の長い static code を認証します。
2. wallet に output を構築させます。code を手動で変換または短縮しないでください。
3. 選択された input を慎重に確認します。Silent Payments は recipient-address privacy を向上させますが、sender input は依然として公開 graph 上にあります。
4. wallet がサポートする fee bumping/PSBT behavior を使用します。BIP 352 では input が変更された場合に output の再導出が必要であり、一部の signing mode は安全ではありません。
5. dispute/accounting に必要な暗号化済み receipt または proof を保持します。

Silent Payments は、recipient-address の繰り返し公開を解決します。金額、transaction timing、sender cluster、acquisition history、後続の co-spending を隠すものではありません。

## Zcash fully shielded payments

Zcash は transparent および shielded value pool をサポートしています。Orchard shielded transaction は zero-knowledge proof を使用するため、node は有効性を検証しながら transaction の詳細を暗号化できます。Unified Address には複数の receiver type を含められます。<sup>[[2]](#references)</sup> Privacy は表示された address の最初の文字ではなく、wallet が実際に選択した path に依存します。

### Shielded workflow

1. **shielded-by-default** behavior と現在の Orchard support を明確に示す、保守された wallet を選択します。download を確認し、seed を backup/test します。
2. ZEC を合法的に取得し、basis/source を記録します。exchange は acquisition と withdrawal を把握しています。
3. wallet がサポートする Unified Address に受け取り、その後 transaction が shielded pool に入ったか確認します。wallet の behavior を確認せずに automatic shielding を想定しないでください。
4. **shielded-to-shielded** transfer を優先します。Transparent-to-shielded および shielded-to-transparent の境界移動は、公開された value/timing を露出させ、amount correlation を可能にします。Orchard specification は、non-Orchard address への支出によって transaction value が明らかになると説明しています。<sup>[[3]](#references)</sup>
5. 特徴的な正確な金額の往復や、即時の境界越えを避けます。これは privacy hygiene であり、所有権や reporting を隠す許可ではありません。
6. wallet がサポートする network-privacy path を使用します。Shielded cryptography は wallet server や peer に対する IP/timing を隠しません。
7. 内部の compliance record を保持し、viewing key は、その範囲を理解したうえで意図的な audit/disclosure にのみ使用します。
8. 送信前に recipient wallet/exchange の対応を確認します。transparent receiver を強制されると、privacy property が変わります。

## GNU Taler: anonymous payer, accountable merchant

GNU Taler は、traditional currency、blind signature、regulated exchange/bank integration を使用する open electronic-payment protocol です。その設計は、merchant に対して customer を anonymous に保ちながら、merchant は識別可能で課税対象のままにすることを目的としています。<sup>[[4]](#references)</sup> これは cryptocurrency ではなく、利用可能性は互換性のある地域 exchange、bank、wallet、merchant に依存します。

### User workflow where deployed

1. 該当する currency/jurisdiction で運用されている Taler exchange と merchant を特定し、最新の terms、fees、KYC、privacy notice を読みます。
2. 公式 wallet を install し、その source を確認します。wallet value は bearer asset になり得るため、wallet の backup/recovery data を cash と同様に保護します。
3. 正確な情報を使用し、サポートされている bank/exchange flow を通じて value を withdrawal します。blind signature によって coin と withdrawal の直接的な link が切断されても、funding institution/exchange は withdrawal を把握できます。
4. wallet 内の merchant contract を確認します。merchant identity、item/summary、amount、fees、refund、delivery terms を確認してください。
5. 支払いを行い、refund、warranty、accounting、tax に必要な receipt data を保存します。
6. merchant unlinkability が必要な場合、任意の merchant session/account identifier を再利用しないでください。
7. wallet、network、delivery metadata を threat model に含めます。Taler の payment cryptography は shipping address や侵害された endpoint を隠しません。

merchant と exchange は引き続き説明責任を負い、どちらの component の運用も regulated payment-service activity となる可能性があります。

## Federated Chaumian e-cash

Chaumian e-cash は blind signature を使用するため、mint は token に署名できますが、後に使用される unblinded token を見ることはできません。Fedimint は guardian federation によって reserve custody と signing を分散します。その documentation では、guardian は aggregate reserve/outstanding note を認識する一方、federation 内の個別 balance や誰が誰に支払ったかは認識しないことになっています。<sup>[[5]](#references)</sup>

これは **custodial bearer value** です。十分な guardian quorum が reserve を管理します。federation failure、dishonest guardian、software bug、client state の喪失により、損失が発生する可能性があります。Deposit、withdrawal、Lightning gateway は可視性のある境界イベントであり、timing/amount を相関付けられる可能性があります。

### Limited-risk workflow

1. 失っても問題のない少額のみを使用します。public/unknown federation は、現実世界で説明責任を負う guardian よりも高リスクだと考えてください。
2. 認証済み channel を通じて federation invite を確認し、guardian identity、quorum、jurisdiction、fees、recovery、shutdown policy を記録します。
3. 保守された互換 wallet を install、確認し、deposit 前に backup scheme を理解します。
4. 文書化された path を通じて、合法的に取得した Bitcoin を deposit します。peg-in を会計目的で記録し、timing/amount は境界上で公開または把握されるものと想定します。
5. federation 内では新しい payment request を使用し、blind signature が除去した link を再構築する account/chat/delivery identifier を追加しないでください。
6. Lightning payment では、gateway が invoice と境界 timing を監視する追加の observer であると考えます。
7. policy に従って redeem/withdraw します。特徴的な金額と即時の timing により、deposit や外部 payment と相関付けられる可能性があります。
8. tax/source/authorization record を非公開で保持します。guardian や gateway に activity を虚偽報告するよう求めないでください。

Federated e-cash を trustless、self-custodial、または guaranteed anonymous と説明しないでください。

## BOLT 12 offers and route blinding

BOLT 12 offer は、stable on-chain address を公開せずに再利用でき、blinded path を使用することで payer が receiver の明確な node identity/path を知る必要をなくせます。これは Lightning の既存の onion routing を補完するものであり、置き換えるものではありません。

使用前に次を確認します。

1. sender と receiver の wallet が、同じ現在の BOLT 12 feature をサポートしていることを確認します。一般的な「Lightning」という branding から対応を推測しないでください。
2. out of band で offer を認証し、amount、issuer/description、recurrence rule を確認します。
3. offer から生成された新しい invoice/payment context を使用します。
4. node alias、公開 contact information、stable network endpoint は最小限にします。
5. sender/receiver、first/last hop、wallet service、channel graph、on-chain funding/closure によって、関係の一部が依然として開示されると想定します。

## Auditability without public disclosure

Privacy と audit は両立できます。

- label、invoice、authorization、cost basis、ownership mapping を、公開 protocol の外部で暗号化して保持します。
- protocol が提供する場合は、**view/audit key** を spending key から分離します。まず sample wallet で正確な disclosure 範囲をテストします。
- seed や unrestricted spending credential ではなく、必要最小限の範囲に限定した proof を auditor に提供します。
- transaction 時点で、software version、protocol/pool、transaction ID または proof、counterparty purpose、exchange-rate source を記録します。
- 永続的な暗号化されていない identity graph を蓄積するのではなく、retention と deletion を定義します。

## Selection checklist

- [ ] 隠される field と observer が正確に特定されている。
- [ ] transaction date 時点の wallet/protocol support が確認されている。
- [ ] Acquisition、network、node/RPC、counterparty、delivery、後続の spend link が記録されている。
- [ ] Custody、recovery、liquidity、issuer/federation solvency、refund risk を受け入れている。
- [ ] 必要な identity、tax、sanctions、source、organizational record が正確に維持されている。
- [ ] recovery と audit proof を含む小規模な end-to-end test が成功している。

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
