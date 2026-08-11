# 带 API 的在线平台

{{#include ../banners/hacktricks-training.md}}

这些服务支持侦察、信誉评估、breach 或 enrichment 工作流。其 API、配额、定价和允许的用途经常变化；在发送客户标识符或敏感数据之前，请确认当前的供应商文档和 engagement 授权。

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

查询某个 IP 地址是否曾与可疑或恶意活动相关联。访问可能需要账户或 API key。

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

检查某个 IP 地址、用户名或电子邮件地址是否曾与自动化账户注册或其他已报告的 bot 活动相关联。

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

查找并验证专业电子邮件地址和与域名相关的联系人模式。请检查当前方案的请求限制和允许用途。

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

搜索与 IP 地址和域名相关的威胁情报指标及活动。

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

使用可用的业务/profile 数据丰富电子邮件地址、域名或公司信息。覆盖范围、访问权限和隐私限制取决于当前产品和方案。

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

识别网站上观察到的技术，并在所选方案允许的情况下获取历史数据或关联数据。

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

检查某个 IP 地址是否与可疑或恶意活动相关联。请确认当前的 API 方案和限制。

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

查询 FortiGuard 对域名、URL 或 IP 地址的分类和威胁情报。可用性因服务而异。

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

检查某个 IP 地址是否因已报告的 spam 活动而被列入名单。

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

根据该服务的社区信号和其他信号获取域名信誉。

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

获取 IP 地址的地理位置、ASN、组织及相关元数据。请检查当前方案的配额。

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

该平台提供 DNS 和基础设施情报，例如历史解析结果、与 IP 或 name server 相关联的域名以及相关记录。历史 DNS 可能会暴露较早的源地址，但不能可靠地绕过 CDN，必须进行验证。

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

使用可用的身份和业务属性丰富电子邮件地址、域名或公司名称。请根据授权和隐私要求处理个人数据。

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ 的 PassiveTotal 功能已转入 Microsoft Defender Threat Intelligence。产品访问权限、API 和保留的功能均已发生变化，因此应使用 Microsoft 的当前文档，而不是基于旧版 PassiveTotal 的假设。

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

搜索域名、IP 地址、电子邮件地址以及已索引的历史数据或 leaked data，但须遵守该服务的访问控制。

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

搜索 IP 地址和其他指标，以获取威胁情报和信誉数据。

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

搜索 IP 地址或地址范围，以获取互联网扫描和常见服务活动的观测结果。请检查当前的试用和社区访问条款。

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

获取某个 IP 地址、主机或搜索查询的互联网扫描和服务信息。API 访问取决于账户方案。

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

搜索主机、证书、域名和互联网服务数据集；其数据模型和覆盖范围与 Shodan 不同。

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

按关键词搜索该提供商索引的、公开观察到的 cloud-storage 对象和 buckets。

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

搜索已索引的 breach 数据中的电子邮件地址、用户名、域名和相关记录。仅在获得授权的情况下使用，并避免不必要地暴露 breach 数据。

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

搜索已索引的 paste 内容，以查找某个电子邮件地址或其他术语的出现位置。在集成之前，请确认该服务仍然可用。

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

获取某个电子邮件地址的信誉和风险信号。

## GhostProject (historical) <sup>[[24]](#references)</sup>

历史上曾宣传可搜索 leaked 的电子邮件/密码数据。应将该服务视为高风险的第三方数据处理服务，并在使用前验证其可用性、合法性和授权情况。

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

获取 IP 地址及相关资产的互联网扫描、暴露面和威胁情报数据。

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

检查某个电子邮件地址或已验证域名是否出现在已知 breach 中。独立的 Pwned Passwords 服务通过前缀检查密码哈希；它不会泄露明文密码。

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

获取 IP 地理位置、数据中心、ASN、proxy/VPN 及相关 enrichment 字段。配额取决于当前方案。

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
提供包含选定数据点的 IP 地理位置和面向 OSINT 的 enrichment。请检查当前条款中关于商业用途的规定。


[DNSDumpster](https://dnsdumpster.com/) 提供 DNS-reconnaissance 结果。<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) 提供网站、托管和互联网基础设施情报。<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) 提供在线子域名发现界面。<sup>[[31]](#references)</sup>

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
- [24] [Cornell research — 用于检查泄露凭据的协议（包括 GhostProject）](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
