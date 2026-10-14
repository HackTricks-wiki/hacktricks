# Reconnaissance と Threat-Intelligence API

{{#include ../../banners/hacktricks-training.md}}

これらのサービスは、Reconnaissance、レピュテーション、breach、enrichment のワークフローを支援します。API、利用上限、価格、許可される用途は頻繁に変更されるため、顧客の識別情報や機密データを送信する前に、ベンダーの最新ドキュメントとエンゲージメントの許可を確認してください。asset-discovery の手順については、[External Recon Methodology](README.md) を参照してください。

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

IP アドレスが不審または悪意のある活動に関連付けられているかどうかを照会します。利用にはアカウントまたは API key が必要な場合があります。

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

IP アドレス、ユーザー名、またはメールアドレスが、自動化されたアカウント登録やその他の報告済み bot 活動に関連付けられているかどうかを確認します。

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

ビジネス用メールアドレスと、ドメインに関連する連絡先のパターンを検索・検証します。リクエスト上限と許可される用途については、現在のプランを確認してください。

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP アドレスやドメインに関連する threat-intelligence indicators と活動を検索します。

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

メールアドレス、ドメイン、または企業に、利用可能なビジネス／プロフィールデータを付加します。データの範囲、アクセス、プライバシー上の制約は、現在の製品とプランによって異なります。

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Web サイトで確認されたテクノロジーを特定し、選択したプランで許可されている場合は、履歴データや関連データを取得します。

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

IP アドレスが不審または悪意のある活動に関連付けられているかどうかを確認します。現在の API プランと上限を確認してください。

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

ドメイン、URL、または IP アドレスについて、FortiGuard のカテゴリ分類と threat intelligence を検索します。利用可能な機能はサービスによって異なります。

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

IP アドレスが、報告された spam 活動を理由にリストへ登録されているかどうかを確認します。

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

サービスのコミュニティやその他のシグナルに基づく、ドメインのレピュテーションを取得します。

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IP アドレスの geolocation、ASN、組織、および関連メタデータを取得します。利用上限については、現在のプランを確認してください。

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

このプラットフォームは、過去の名前解決結果、IP や name server に関連付けられたドメイン、関連レコードなどの DNS・インフラ情報を提供します。過去の DNS 情報から以前の origin アドレスが判明する場合がありますが、CDN を確実に回避できるわけではないため、検証が必要です。

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

メールアドレス、ドメイン、または企業名に、利用可能なアイデンティティ情報やビジネス属性を付加します。個人データは、許可およびプライバシー要件に従って取り扱ってください。

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ の PassiveTotal 機能は、Microsoft Defender Threat Intelligence に移行しました。製品へのアクセス、API、引き継がれた機能は変更されているため、従来の PassiveTotal に関する前提ではなく、Microsoft の最新ドキュメントを参照してください。

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

サービスのアクセス制御に従い、ドメイン、IP アドレス、メールアドレス、およびインデックス化された過去のデータや leak されたデータを検索します。

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

IP アドレスやその他の indicators について、threat-intelligence およびレピュテーションデータを検索します。

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

IP アドレスまたは範囲を検索し、インターネット上のスキャンや一般的なサービス活動の観測情報を確認します。現在のトライアルおよびコミュニティアクセスの条件を確認してください。

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IP アドレス、ホスト、または検索クエリについて、インターネットスキャンやサービスの情報を取得します。API の利用可否はアカウントのプランによって異なります。

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

ホスト、証明書、ドメイン、インターネットサービスのデータセットを検索します。データモデルと対象範囲は Shodan とは異なります。

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

キーワードで検索し、プロバイダーが公開状態を確認したクラウドストレージのオブジェクトや bucket のインデックスを調べます。

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

インデックス化された breach データから、メールアドレス、ユーザー名、ドメイン、および関連レコードを検索します。許可を得た場合にのみ使用し、breach データを不必要に公開しないでください。

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

メールアドレスやその他の語句が、インデックス化された paste の内容に含まれているか検索します。統合する前に、サービスが引き続き利用可能か確認してください。

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

メールアドレスのレピュテーションとリスクに関するシグナルを取得します。

## GhostProject (historical) <sup>[[24]](#references)</sup>

過去には、leak されたメールアドレス／パスワードデータの検索を提供していました。第三者によるデータ取り扱いのリスクが高いサービスとみなし、使用前に利用可能性、合法性、許可を確認してください。

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP アドレスや関連資産について、インターネットスキャン、露出状況、threat-intelligence のデータを取得します。

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

メールアドレスまたは検証済みドメインが、既知の breach に含まれているか確認します。別サービスの Pwned Passwords は、prefix を使用してパスワードハッシュを確認します。平文のパスワードが明らかになることは**ありません**。

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation、データセンター、ASN、proxy/VPN、および関連する enrichment フィールドを取得します。利用上限は現在のプランによって異なります。

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
選択したデータポイントを含む、IP geolocation および OSINT 向けの enrichment を提供します。商用利用については、現在の利用規約を確認してください。


[DNSDumpster](https://dnsdumpster.com/) は DNS-reconnaissance の結果を提供します。<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) はサイト、ホスティング、インターネットインフラに関する情報を提供します。<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) はオンラインの subdomain-discovery インターフェースを提供します。<sup>[[31]](#references)</sup>

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
- [24] [コーネル大学の研究 — 侵害された認証情報を確認するためのプロトコル (GhostProject を含む)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
