# API対応オンラインプラットフォーム

{{#include ../banners/hacktricks-training.md}}

これらのサービスは、reconnaissance、reputation、breach、または enrichment のワークフローをサポートします。各サービスのAPI、quota、pricing、permitted usesは頻繁に変更されるため、顧客識別子や機密データを送信する前に、vendorの最新ドキュメントとengagement authorizationを確認してください。

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

IP addressが不審または悪意のある活動に関連付けられているかを照会します。アクセスにはaccountまたはAPI keyが必要な場合があります。

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

IP address、username、またはemail addressが、自動化されたaccount registrationやその他の報告済みbot activityに関連付けられているかを確認します。

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

professional email addressと、domainに関連するcontact patternを検索・検証します。request limitsとpermitted usesについては、現在のplanを確認してください。

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP addressやdomainに関連するthreat-intelligence indicatorとactivityを検索します。

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

利用可能なbusiness/profile dataを使って、email address、domain、またはcompanyの情報をenrichします。coverage、access、privacy constraintsは、現在のproductとplanによって異なります。

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

website上で確認されたtechnologyを特定し、選択したplanで許可されている場合は、historical dataまたはrelationship dataを取得します。

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

IP addressが不審または悪意のある活動に関連付けられているかを確認します。現在のAPI planとlimitsを確認してください。

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

domain、URL、またはIP addressについて、FortiGuardのcategorizationとthreat intelligenceを検索します。利用可能性はserviceによって異なります。

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

IP addressが報告済みのspam activityとしてlistingされているかを確認します。

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

serviceのcommunityやその他のsignalに基づくdomainのreputationを取得します。

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IP addressのgeolocation、ASN、organization、および関連metadataを取得します。quotaについては現在のplanを確認してください。

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

このplatformは、historical resolution、IPまたはname serverに関連するdomain、関連recordなど、DNSとinfrastructure intelligenceを提供します。Historical DNSから以前のorigin addressが判明する場合がありますが、CDNを確実にbypassできるわけではなく、検証が必要です。

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

利用可能なidentityおよびbusiness attributeを使って、email address、domain、またはcompany nameの情報をenrichします。personal dataはauthorizationとprivacy requirementsに従って取り扱ってください。

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQのPassiveTotal capabilitiesはMicrosoft Defender Threat Intelligenceへ移行されました。product access、API、および保持されたfunctionalityは変更されているため、legacy PassiveTotalの前提ではなく、Microsoftの最新documentationを使用してください。

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

domain、IP address、email address、およびindex化されたhistorical dataまたはleaked dataを、serviceのaccess controlに従って検索します。

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

IP addressやその他のindicatorについて、threat-intelligenceおよびreputation dataを検索します。

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

IP addressまたはrangeについて、internet scanningや一般的なservice activityの観測結果を検索します。現在のtrialおよびcommunity accessのtermsを確認してください。

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IP address、host、またはsearch queryについて、internet scanとservice informationを取得します。API accessはaccount planによって異なります。

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

host、certificate、domain、およびinternet serviceのdatasetを検索します。data modelとcoverageはShodanとは異なります。

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

keywordによって、providerが公開観測したcloud-storage objectとbucketのindexを検索します。

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

email address、username、domain、および関連recordについて、index化されたbreach dataを検索します。authorizationがある場合にのみ使用し、breach dataの不要な露出は避けてください。

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

email addressやその他のtermの出現箇所について、index化されたpaste contentを検索します。integrateする前に、serviceが現在も利用可能かを確認してください。

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

email addressのreputationとrisk signalを取得します。

## GhostProject (historical) <sup>[[24]](#references)</sup>

過去には、leaked email/password dataの検索を謳っていました。serviceはhigh-riskなthird-party handlingとして扱い、使用前にavailability、legality、およびauthorizationを確認してください。

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP addressと関連assetについて、internet scan、exposure、およびthreat-intelligence dataを取得します。

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

email addressまたはverified domainが既知のbreachに含まれているかを確認します。別個のPwned Passwords serviceはprefixによってpassword hashを確認するものであり、plaintext passwordを明らかにするものではありません。

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation、data-center、ASN、proxy/VPN、および関連するenrichment fieldを取得します。quotaは現在のplanによって異なります。

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
選択したdata pointを用いて、IP geolocationとOSINT指向のenrichmentを行います。commercial useについては現在のtermsを確認してください。


[DNSDumpster](https://dnsdumpster.com/)はDNS-reconnaissanceの結果を提供します。<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/)はsite、hosting、およびinternet infrastructure intelligenceを提供します。<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)はonline subdomain discovery interfaceを提供します。<sup>[[31]](#references)</sup>

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
- [24] [Cornell research — Compromised Credentialsを確認するためのprotocol（GhostProjectを含む）](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
