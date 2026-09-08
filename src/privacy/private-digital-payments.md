# Private Digital Payments

{{#include ../banners/hacktricks-training.md}}

決済プライバシーとは、取引データの開示を制御することです。これは、違法な資金を合法化したり、納税や制裁を回避したり、KYCを無効化したり、偽の身元を使用したり、許可されていない業務を隠したりする方法ではありません。決済は、加盟店からは非公開であっても、発行者、ネットワーク、雇用主、税務当局、捜査官からは完全に可視化されている場合があります。

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) は、各ファミリーについて `Pros`、`Cons`、合法的な手順の `Procedure`、`Detection` を整理した一覧です。このページでは、従来型の決済方法を詳しく説明します。

{% hint style="danger" %}
盗難アカウント、合成ID、マネーミュール、架空の居住地や資金源の申告、取引分割（「ストラクチャリング」）、または不透明な「no-KYC card」ブローカーは決して使用しないでください。関係するすべての法域で、現行法とプロバイダーの利用規約を確認してください。
{% endhint %}

## Define the privacy property

決済手段を選ぶ前に、誰が観測者なのかを明確にします。

| 観測者 | 典型的なデータ | 有効な制御 | 残るもの |
|---|---|---|---|
| 加盟店 | 氏名、メールアドレス、住所、カードトークン、IP/デバイス、購入内容 | ゲスト checkout、任意データの最小化、加盟店ごとのバーチャルカード | 配送、アカウント、fraud telemetry |
| 発行者/決済プロセッサ | 法的身元、資金源、加盟店、金額、時刻、デバイス | プライバシー/セキュリティ規約が優れた規制対象プロバイダーを選ぶ | プロバイダーは処理を行い、記録を保持・開示する場合がある |
| 雇用主/業務オーナー | 経費、担当者、目的 | 業務ごとに分離した予算とアクセス制御された台帳 | 正当なガバナンスには内部での担当者特定が必要 |
| Public blockchain observer | アドレス、資金移動、金額、時刻（チェーンによって異なる） | 適切なプロトコルと wallet discipline | 取得、エンドポイント、後続の支出によって活動が再リンクされる可能性がある |
| Network/RPC/node operator | IP、wallet queries、transaction broadcasts | Local node または適切な privacy network | タイミングやエンドポイントの挙動が相関する可能性は残る |
| 物理的な観測者 | 顔、場所、車両、CCTV、レシート | 通常の状況に応じたプライバシー対策 | 現金を使っても、人物が物理的に不可視になるわけではない |

CFPBは、決済アプリが身元、デバイス、位置情報、連絡先、取引、行動に関するデータを収集できると説明しています。また、州のプライバシー規則によって、収益化やすべての二次利用が必ずしも防止されるわけではありません。<sup>[[1]](#references)</sup> 製品名からプライバシーを推測せず、実際のプロバイダー通知を読んでください。

## Compare payment methods

| 方法 | プライバシー上の利点 | 主な観測者/リンク | 適切な用途 |
|---|---|---|---|
| 現金 | 決済ネットワークの台帳が存在しない | 受取人、カメラ、目撃者、現金報告規則 | 受け入れられる場合の合法的な地域内購入 |
| Open-loop prepaid/gift card | カード番号をメインカードから分離 | 販売者、activation/registration provider、資金源、加盟店 | 予算管理または加盟店単位の限定的な分離 |
| Virtual/one-time card number | 再利用可能なPANを加盟店から隠し、容易に無効化できる | 発行者は身元と取引を把握する | オンライン加盟店の分離 |
| Mobile-wallet token | 基礎となるPANの代わりにデバイス/加盟店がトークンを受け取る | Wallet provider、発行者、決済ネットワーク、加盟店 | credential securityであり、匿名性ではない |
| Bank transfer/app | 便利な監査証跡 | 銀行/アプリ、取引相手、リンクされた身元 | 責任の明確な組織決済 |
| Cryptocurrency | プロトコルによって異なる。self-custodyによりカストディアンへの露出を減らせる場合がある | Public ledgerまたはprivacy protocol、取引所、エンドポイント、取引相手 | プロトコル固有の分析後に行う合法的な送金 |

## Cash

現金は今もプライバシーと金融包摂に重要だと考えられており、決済ネットワーク上の記録を残しません。<sup>[[2]](#references)</sup> ただし、CCTV、目撃者、デバイスの位置情報、レシート、特別な場合のシリアル番号追跡、法的な報告義務を回避することはできません。

### Lawful workflow

1. 取引前に、利用可能かどうかと地域の現金上限を確認します。上限は国や当事者の種類によって異なり、時間とともに変わります。
2. 通常の購入を、正直な1回の取引として行います。しきい値や報告を避けるために**決して分割しないでください**。
3. 任意の loyalty tracking やマーケティング目的の収集は拒否します。保証、安全、配送、税務、法令のために必要なデータは、正確に提供します。
4. 必要な購入証明と会計記録を、保持期限を設定した暗号化ストレージに保存します。
5. 組織では、承認済みの手続きを通じて精算し、担当者、承認、目的、金額、日付、レシートを記録します。

米国では、一定の取引業者や事業者は、関連取引を含む10,000ドル超の現金受領についてForm 8300を提出します。取引を意図的に分割すること自体が、違法なストラクチャリングに該当する可能性があります。<sup>[[3]](#references)</sup> 他の法域では異なります。たとえば、スペインは独自の法定現金決済制限を公開しています。<sup>[[4]](#references)</sup>

## Prepaid and gift cards

「Prepaid」は匿名を意味しません。店舗、発行者、プログラムマネージャー、資金提供銀行、加盟店は、購入、activation、デバイス、IP、位置情報、支出を相関付ける可能性があります。チャージ、ATM利用、国際利用、高額な上限、紛失時の保護には、通常、登録が必要です。

米国の消費者向けガイダンスでは、発行者が法的確認のために身元情報を求める場合があり、確認に失敗すると登録済みカードを拒否できると説明されています。<sup>[[5]](#references)</sup> FinCENの規則は、どのprepaid programおよび参加者にAML義務があるかを定義しています。<sup>[[6]](#references)</sup> EUでは、匿名e-moneyに関する限定的な例外がDirective (EU) 2018/843によって縮小されました。Regulation (EU) 2024/1624はさらに枠組みを変更しますが、一般的には**2027年7月10日**から適用されるため、2026年時点ですでに施行されているとは説明しないでください。<sup>[[7]](#references)</sup>

Prepaid valueは、身元を特定できる発行者から合法的に取得し、その規約が意図した利用を許可しており、メリットが予算管理または主要な決済credentialからの分離である場合にのみ使用してください。転売市場や、検証不能な「no-name」カードを宣伝するブローカーは避けてください。価値が盗まれていたり、すでに利用済みだったり、地域制限の対象だったり、差し押さえの対象だったりする可能性があります。

## Virtual cards and wallet tokens

Virtual card number (VCN)は通常、実在し、確認済みのアカウントの背後で発行されます。加盟店固有または一回限りの番号により、漏洩や加盟店間でのPAN相関を減らせますが、発行者から取引を隠すことはできません。Network tokenizationも同様に、カードcredentialを制約付きトークンに置き換えます。<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. 正確な身元、居住地、資金情報を使用して、規制対象の発行者にアカウントを開設します。
2. 一意のパスワード、利用可能な場合はphishing-resistant MFA、ログインアラート、オフラインで保管したrecovery codesによって保護します。
3. 加盟店固定または一回限りのVCNを生成します。対応している場合は、妥当な金額/時間制限を設定します。
4. ゲスト checkoutを使用し、**任意の**プロフィール、loyalty、マーケティング項目だけを省略します。必要な場合は、正確な請求、配送、税務データを提供します。
5. 関係のないidentity providerへのログインは避け、業務/アカウント用のブラウザコンパートメントと承認済みのネットワーク経路を使用します。
6. レシートとVCN-to-purpose mappingを暗号化された内部台帳に保存します。
7. 返金/chargeback期間後に番号を凍結または無効化し、親アカウントで予期しない認証を監視します。

Capital OneとGoogleは、virtual numberが基礎となるアカウントに紐付いたままであると説明しています。一方、EMVCo/Visaは、tokenizationを支払人の匿名化ではなく、credential substitutionおよびdomain restrictionとして説明しています。<sup>[[8]](#references)</sup>

## Delivery, accounts and refunds

決済は、linkage graphにおける1つの辺にすぎません。

- 一意のカードでも、個人のメールアドレス、電話番号、ブラウザプロファイル、IPアドレス、loyalty accountを再利用すると識別されます。
- 物理的な配送には通常、合法的な受取人と場所が必要です。関係のない人物の住所を使用したり、居住者になりすましたりしないでください。架空の情報より、承認済みの業務用受取サービスのほうが安全です。
- Digital goodsは、アカウントの身元、IP、デバイスフィンガープリント、license activation、ダウンロードを記録する場合があります。
- 返金は通常、元の決済手段に戻されます。資金を受け取って別の場所へ転送・返金するよう求めることは、fraudおよびmoney-muleの警告です。
- Merchant descriptor、請求書の文面、配送通知によって、機微な購入情報がアカウント管理者に露出する可能性があります。アクセス権とアラートを意図的に設定してください。

## Authorized red-team purchases

業務は外部に対しては慎重に行い、内部では説明責任を果たせる状態にします。

1. 書面による範囲、目的、支出上限、承認者、許可された加盟店/資産、精算規則を取得します。
2. 組織が管理する決済アカウントと、業務または加盟店ごとに分離したVCNまたはsub-accountを使用します。
3. プロバイダーには正確な請求情報と登録者情報を保持します。Public registration privacyによって露出を最小化することはできますが、嘘をつく許可にはなりません。
4. 担当者、承認、目的、日付、金額、取引相手、資産識別子、レシートを暗号化された台帳に記録します。
5. 必要に応じて取引相手をスクリーニングし、プロバイダー、制裁、税務、報告義務に従います。
6. 財務担当者には必要なアクセスだけを与え、担当者には必要最小限の支出機能だけを与えます。
7. teardown中に決済credentialを閉鎖または凍結し、保留中の請求/返金を照合し、規程に従って記録を保持します。

暗号資産固有の選択については、[Cryptocurrency Privacy](cryptocurrency-privacy.md)を参照してください。これらの購入を支えるインフラについては、[Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)を参照してください。

## Verification checklist

- [ ] 望ましいプライバシー特性と観測者が記録されている。
- [ ] プロバイダー、加盟店、法域の規則を最近確認した。
- [ ] 身元および資金源の申告が正確である。
- [ ] 必須の確認を妨げることなく、任意の加盟店データを最小化している。
- [ ] 資金、デバイス、ネットワーク、アカウント、配送、返金のリンクを理解している。
- [ ] しきい値回避、禁止された取引相手、ミュール、盗難credential、第三者の身元が関与していない。
- [ ] 必要なレシート、承認、税務記録、recovery情報が暗号化され、アクセス制御されている。

## References

- [1] [米国CFPB — 消費者の決済その他の個人金融データの収集、利用、収益化に関する情報提供要請](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [欧州中央銀行 — ユーロ圏消費者の決済態度に関する調査（SPACE）2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [米国IRS — Form 8300の手引き](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [スペイン税務当局 — 現金決済の報告](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] 米国CFPB — [Prepaid cardの有効化または登録に個人情報を求められるのはなぜですか？](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) and [Prepaid cardを拒否されることはありますか？](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Accessに関する最終規則](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [指令 (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — virtual credit cardの利用](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
