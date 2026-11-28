# Reconnaissance and Threat-Intelligence APIs

{{#include ../../banners/hacktricks-training.md}}

これらのサービスは、reconnaissance、reputation、breach、enrichment の各種ワークフローを支援します。API、利用枠、料金、許可される利用方法は頻繁に変更されるため、顧客識別情報や機密データを送信する前に、最新のベンダー文書とエンゲージメントの許可内容を確認してください。asset-discovery の手順については、[External Recon Methodology](README.md) を参照してください。

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

IPアドレスが不審または悪意のある活動に関連付けられているかを照会します。利用にはアカウントまたはAPIキーが必要な場合があります。

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

IPアドレス、ユーザー名、またはメールアドレスが、自動アカウント登録やその他の報告されたbot活動に関連付けられているかを確認します。

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

業務用メールアドレスや、ドメインに関連する連絡先のパターンを検索・検証します。リクエスト上限と許可される利用方法は、現在のプランで確認してください。

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IPアドレスやドメインに関連する脅威インテリジェンスのindicatorと活動を検索します。

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

メールアドレス、ドメイン、または企業の情報を、利用可能なビジネス／プロフィールデータで補完します。データの範囲、アクセス、プライバシーに関する制約は、現在の製品とプランによって異なります。

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Webサイト上で確認されたテクノロジーを特定し、選択したプランで許可される範囲で履歴データや関連データを取得します。

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

IPアドレスが不審または悪意のある活動に関連付けられているかを確認します。現在のAPIプランと利用上限を確認してください。

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

ドメイン、URL、またはIPアドレスについて、FortiGuardのカテゴリ分類と脅威インテリジェンスを調べます。利用可否はサービスによって異なります。

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

IPアドレスが、報告されたスパム活動のリストに掲載されているかを確認します。

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

サービスのコミュニティやその他のシグナルに基づくドメインのreputationを取得します。

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IPアドレスのgeolocation、ASN、組織情報などのメタデータを取得します。利用枠は現在のプランで確認してください。

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

このプラットフォームは、過去の名前解決情報、IPアドレスやネームサーバーに関連するドメイン、関連レコードなど、DNSおよびインフラストラクチャの情報を提供します。過去のDNS情報から以前のoriginアドレスが判明することがありますが、CDNを確実に迂回できるわけではないため、必ず検証してください。

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

メールアドレス、ドメイン、または企業名を、利用可能なID情報やビジネス属性で補完します。個人データは、許可とプライバシー要件に従って取り扱ってください。

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQのPassiveTotal機能はMicrosoft Defender Threat Intelligenceに移行しました。製品へのアクセス、API、維持されている機能は変更されているため、旧PassiveTotalの仕様を前提にせず、Microsoftの最新の文書を参照してください。

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

サービスのアクセス制御に従い、ドメイン、IPアドレス、メールアドレス、およびインデックス化された過去のデータやleakされたデータを検索します。

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

IPアドレスやその他のindicatorについて、脅威インテリジェンスとreputationのデータを検索します。

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

IPアドレスまたは範囲について、インターネットスキャンや一般的なサービス活動の観測情報を検索します。現在のトライアルおよびコミュニティアクセスの条件を確認してください。

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IPアドレス、ホスト、または検索クエリに関するインターネットスキャン情報やサービス情報を取得します。APIの利用可否はアカウントのプランによって異なります。

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

ホスト、証明書、ドメイン、インターネットサービスのデータセットを検索します。データモデルと対象範囲はShodanとは異なります。

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

プロバイダーが公開情報から確認したクラウドストレージのオブジェクトやバケットのインデックスを、キーワードで検索します。

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

インデックス化されたbreachデータを、メールアドレス、ユーザー名、ドメイン、関連レコードから検索します。許可を得た場合にのみ利用し、breachデータを不必要に公開しないでください。

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

インデックス化されたpasteの内容から、メールアドレスやその他の語句の出現を検索します。組み込む前に、サービスが現在も利用可能か確認してください。

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

メールアドレスのreputationとリスクシグナルを取得します。

## GhostProject (historical) <sup>[[24]](#references)</sup>

過去に、leakされたメールアドレス／パスワードのデータを検索できるとうたっていました。第三者による取り扱いのリスクが高いサービスとして扱い、利用前に、現在の提供状況、合法性、許可を確認してください。

## BinaryEdge (discontinued) <sup>[[25]](#references)</sup>

IPアドレスや関連資産について、インターネットスキャン、露出状況、脅威インテリジェンスのデータを提供していました。現在、サイトはCoalitionへの移行に関する告知にリダイレクトされ、APIはリクエストを拒否するため、利用不可として扱ってください。

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

メールアドレスまたは検証済みドメインが、既知のbreachに含まれているかを確認します。別サービスのPwned Passwordsでは、prefixを使ってパスワードハッシュを確認できますが、平文パスワードは明らかになりません。

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IPのgeolocation、データセンター、ASN、proxy/VPNなどの関連情報を取得します。利用枠は現在のプランによって異なります。

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IPのgeolocationと、OSINTを目的とした特定の情報を取得します。商用利用に関する現在の規約を確認してください。

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
ドメイン（レジストラ、登録日と有効期限、ネームサーバー、ホスティングIPと国）またはIPアドレス（そのIPでホストされている他のドメイン）を調べ、ドメインまたはIPが無料の侵害済みリストに掲載されているか確認できます。このリストには、フィッシングやsinkhole化されたマルウェアのドメインと、過去48時間にhoneypotセンサーを攻撃したアドレスが含まれます。Web検索と侵害チェックAPIはアカウント不要ですが、検索結果へのAPIアクセスには有料プランが必要です。


[DNSDumpster](https://dnsdumpster.com/) はDNS reconnaissanceの結果を提供します。<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) は、サイト、ホスティング、インターネットインフラストラクチャに関する情報を提供します。<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) は、オンラインのサブドメイン検出インターフェースを提供します。<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [コーネル大学の研究 — 侵害された認証情報を確認するプロトコル（GhostProjectを含む）](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [NetAPI API documentation](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
