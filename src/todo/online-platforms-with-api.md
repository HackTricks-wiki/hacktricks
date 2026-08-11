# API가 있는 Online Platforms

{{#include ../banners/hacktricks-training.md}}

이러한 service는 reconnaissance, reputation, breach 또는 enrichment workflow를 지원합니다. 해당 service의 API, quota, pricing 및 허용된 사용 방식은 자주 변경되므로, customer identifier 또는 민감한 데이터를 전송하기 전에 현재 vendor documentation과 engagement authorization을 확인하세요.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

IP address가 의심스럽거나 악의적인 activity와 연관된 적이 있는지 query합니다. Access에는 account 또는 API key가 필요할 수 있습니다.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

IP address, username 또는 email address가 자동화된 account registration이나 기타 보고된 bot activity와 연관된 적이 있는지 확인합니다.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Professional email address와 domain 관련 contact pattern을 찾고 verify합니다. Request limit과 허용된 사용 방식은 현재 plan에서 확인하세요.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP address 및 domain과 연관된 threat-intelligence indicator와 activity를 검색합니다.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

사용 가능한 business/profile data를 이용해 email address, domain 또는 company를 enrich합니다. Coverage, access 및 privacy 제약은 현재 product와 plan에 따라 달라집니다.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Website에서 관찰된 technology를 식별하고, 선택한 plan에서 허용하는 경우 historical 또는 relationship data를 가져옵니다.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

IP address가 의심스럽거나 악의적인 activity와 연관되어 있는지 확인합니다. 현재 API plan과 limit을 확인하세요.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Domain, URL 또는 IP address에 대한 FortiGuard categorization과 threat intelligence를 조회합니다. Availability는 service에 따라 다릅니다.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

IP address가 보고된 spam activity로 등재되어 있는지 확인합니다.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

해당 service의 community 및 기타 signal을 기반으로 domain의 reputation을 가져옵니다.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IP address에 대한 geolocation, ASN, organization 및 관련 metadata를 가져옵니다. Quota는 현재 plan에서 확인하세요.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

이 platform은 historical resolution, IP 또는 name server와 연관된 domain 및 관련 record와 같은 DNS 및 infrastructure intelligence를 제공합니다. Historical DNS는 이전 origin address를 노출할 수 있지만 CDN을 안정적으로 우회하지는 않으며 검증이 필요합니다.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

사용 가능한 identity 및 business attribute를 이용해 email address, domain 또는 company name을 enrich합니다. Authorization 및 privacy requirement에 따라 personal data를 처리하세요.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ의 PassiveTotal capability는 Microsoft Defender Threat Intelligence로 transition되었습니다. Product access, API 및 유지되는 functionality가 변경되었으므로 legacy PassiveTotal 가정 대신 Microsoft의 현재 documentation을 사용하세요.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Service의 access control에 따라 domain, IP address, email address 및 index된 historical 또는 leaked data를 검색합니다.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Threat-intelligence 및 reputation data를 위해 IP address와 기타 indicator를 검색합니다.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Internet scanning 및 일반적인 service activity에 대한 observation을 위해 IP address 또는 range를 검색합니다. 현재 trial 및 community-access 약관을 확인하세요.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IP address, host 또는 search query에 대한 internet-scan 및 service information을 가져옵니다. API access는 account plan에 따라 달라집니다.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, certificate, domain 및 internet-service dataset을 검색합니다. 해당 data model과 coverage는 Shodan과 다릅니다.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Keyword를 사용해 provider가 공개적으로 관찰한 cloud-storage object 및 bucket의 index를 검색합니다.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Email address, username, domain 및 관련 record에 대한 index된 breach data를 검색합니다. Authorization이 있는 경우에만 사용하고 breach data가 불필요하게 노출되지 않도록 하세요.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Email address 또는 기타 term이 포함된 index된 paste content를 검색합니다. 통합하기 전에 service가 여전히 available한지 확인하세요.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Email address에 대한 reputation 및 risk signal을 가져옵니다.

## GhostProject (historical) <sup>[[24]](#references)</sup>

과거에 leaked email/password data 검색 기능을 광고했습니다. 해당 service를 high-risk third-party handling으로 간주하고 사용하기 전에 availability, legality 및 authorization을 확인하세요.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP address 및 관련 asset에 대한 internet-scan, exposure 및 threat-intelligence data를 가져옵니다.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Email address 또는 verified domain이 알려진 breach에 포함되어 있는지 확인합니다. 별도의 Pwned Passwords service는 prefix를 사용해 password hash를 확인하며, plaintext password를 노출하지 **않습니다**.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation, data-center, ASN, proxy/VPN 및 관련 enrichment field를 가져옵니다. Quota는 현재 plan에 따라 달라집니다.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
선택된 data point를 사용한 IP geolocation 및 OSINT 지향 enrichment를 제공합니다. Commercial use에 대한 현재 약관을 확인하세요.


[DNSDumpster](https://dnsdumpster.com/)는 DNS-reconnaissance result를 제공합니다.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/)는 site, hosting 및 internet-infrastructure intelligence를 제공합니다.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)는 online subdomain-discovery interface를 제공합니다.<sup>[[31]](#references)</sup>

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
- [24] [Cornell research — 침해된 자격 증명 확인을 위한 Protocol (GhostProject 포함)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
