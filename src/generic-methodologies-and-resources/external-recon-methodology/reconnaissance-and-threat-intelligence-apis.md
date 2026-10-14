# 侦察与威胁情报 API

{{#include ../../banners/hacktricks-training.md}}

这些服务支持侦察、信誉查询、泄露数据查询或信息补全工作流。这些服务的 API、配额、定价和允许用途经常变化；在发送客户标识符或敏感数据前，请确认供应商的最新文档和参与授权。资产发现流程请参阅 [External Recon Methodology](README.md)。

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

查询某个 IP 地址是否曾与可疑或恶意活动相关联。访问可能需要账户或 API key。

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

检查某个 IP 地址、用户名或电子邮件地址是否曾与自动化账户注册或其他已报告的机器人活动相关联。

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

查找并验证专业电子邮件地址及与域名相关的联系人模式。请查看当前套餐的请求限制和允许用途。

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

搜索与 IP 地址和域名相关的威胁情报指标及活动。

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

使用可用的业务/个人资料数据补充电子邮件地址、域名或公司信息。数据覆盖范围、访问权限和隐私限制取决于当前产品和套餐。

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

识别网站上发现的技术，并在所选套餐允许的情况下获取历史数据或关联数据。

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

检查某个 IP 地址是否与可疑或恶意活动相关联。请确认当前 API 套餐和限制。

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

查询 FortiGuard 对域名、URL 或 IP 地址的分类和威胁情报。不同服务的可用性有所不同。

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

检查某个 IP 地址是否因已报告的垃圾邮件活动而被列入名单。

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

获取基于该服务社区及其他信号的域名信誉信息。

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

获取 IP 地址的地理位置、ASN、所属组织及相关元数据。请查看当前套餐的配额。

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

该平台提供 DNS 和基础设施情报，例如历史解析记录、与 IP 或名称服务器相关联的域名，以及相关记录。历史 DNS 可能会揭示先前的源站地址，但无法可靠地绕过 CDN，且必须进行验证。

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

使用可用的身份和业务属性补充电子邮件地址、域名或公司名称信息。请根据授权和隐私要求处理个人数据。

## RiskIQ / Microsoft Defender Threat Intelligence（旧版迁移） <sup>[[14]](#references)</sup>

RiskIQ 的 PassiveTotal 功能已迁移至 Microsoft Defender Threat Intelligence。产品访问权限、API 和保留的功能均已发生变化，因此请以 Microsoft 的当前文档为准，不要依赖旧版 PassiveTotal 的假设。

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

搜索域名、IP 地址、电子邮件地址以及已索引的历史数据或泄露数据，具体取决于该服务的访问控制。

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

搜索 IP 地址及其他指标，获取威胁情报和信誉数据。

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

搜索 IP 地址或地址范围，查看互联网扫描和常见服务活动的观测记录。请查看当前试用和社区访问条款。

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

根据 IP 地址、主机或搜索查询获取互联网扫描和服务信息。API 访问权限取决于账户套餐。

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

搜索主机、证书、域名和互联网服务数据集；其数据模型和覆盖范围与 Shodan 不同。

## [GrayHatWarfare bucket 搜索](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

按关键词搜索该提供商索引的公开云存储对象和 bucket。

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

搜索已索引的泄露数据，查找电子邮件地址、用户名、域名及相关记录。仅在获得授权的情况下使用，并避免不必要地暴露泄露数据。

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

搜索已索引的 paste 内容，查找某个电子邮件地址或其他词条。将其集成前，请确认该服务仍可使用。

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

获取某个电子邮件地址的信誉和风险信号。

## GhostProject（历史服务） <sup>[[24]](#references)</sup>

该服务过去曾宣称可搜索泄露的电子邮件/密码数据。请将其视为高风险的第三方数据处理服务，并在使用前确认其可用性、合法性和授权情况。

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

获取 IP 地址及相关资产的互联网扫描、暴露面和威胁情报数据。

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

检查某个电子邮件地址或已验证域名是否出现在已知泄露事件中。独立的 Pwned Passwords 服务通过前缀检查密码哈希；它**不会**泄露明文密码。

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

获取 IP 地理位置、数据中心、ASN、代理/VPN 及相关信息补全字段。配额取决于当前套餐。

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
提供 IP 地理位置和面向 OSINT 的信息补全，包括部分数据点。请查看当前条款，确认是否允许商业用途。


[DNSDumpster](https://dnsdumpster.com/) 提供 DNS 侦察结果。<sup>[[29]](#references)</sup>

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
- [24] [Cornell research — Protocols for Checking Compromised Credentials (includes GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)

{{#include ../../banners/hacktricks-training.md}}
