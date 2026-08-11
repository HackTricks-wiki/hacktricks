# API वाली ऑनलाइन प्लेटफ़ॉर्म

{{#include ../banners/hacktricks-training.md}}

ये services reconnaissance, reputation, breach या enrichment workflows को support करती हैं। इनके APIs, quotas, pricing और permitted uses अक्सर बदलते रहते हैं; customer identifiers या sensitive data भेजने से पहले वर्तमान vendor documentation और engagement authorization की पुष्टि करें।

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

जांचें कि कोई IP address suspicious या malicious activity से जुड़ा रहा है या नहीं। Access के लिए account या API key आवश्यक हो सकती है।

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

जांचें कि कोई IP address, username या email address automated account registration या अन्य reported bot activity से जुड़ा रहा है या नहीं।

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Professional email addresses और domain-related contact patterns खोजें और verify करें। Request limits और permitted uses के लिए वर्तमान plan की जांच करें।

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP addresses और domains से जुड़े threat-intelligence indicators और activity खोजें।

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

उपलब्ध business/profile data से किसी email address, domain या company को enrich करें। Coverage, access और privacy constraints वर्तमान product और plan पर निर्भर करते हैं।

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Websites पर देखी गई technologies की पहचान करें और जहां selected plan अनुमति देता हो, वहां historical या relationship data प्राप्त करें।

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

जांचें कि कोई IP address suspicious या malicious activity से जुड़ा है या नहीं। वर्तमान API plans और limits की पुष्टि करें।

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Domains, URLs या IP addresses के लिए FortiGuard categorization और threat intelligence देखें। Availability service के अनुसार अलग-अलग होती है।

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

जांचें कि कोई IP address reported spam activity के लिए listed है या नहीं।

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Service के community और अन्य signals के आधार पर किसी domain की reputation प्राप्त करें।

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

किसी IP address के लिए geolocation, ASN, organization और संबंधित metadata प्राप्त करें। Quotas के लिए वर्तमान plan की जांच करें।

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

यह platform DNS और infrastructure intelligence प्रदान करता है, जैसे historical resolutions, IPs या name servers से जुड़े domains और संबंधित records। Historical DNS किसी पुराने origin address का पता लगा सकता है, लेकिन यह CDN को reliably bypass नहीं करता और इसका validation आवश्यक है।

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

उपलब्ध identity और business attributes से किसी email address, domain या company name को enrich करें। Personal data को authorization और privacy requirements के अनुसार handle करें।

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ की PassiveTotal capabilities Microsoft Defender Threat Intelligence में transition हो गई हैं। Product access, APIs और retained functionality बदल चुके हैं, इसलिए legacy PassiveTotal assumptions के बजाय Microsoft का current documentation उपयोग करें।

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Service के access controls के अधीन domains, IP addresses, email addresses और indexed historical या leaked data खोजें।

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Threat-intelligence और reputation data के लिए IP addresses तथा अन्य indicators खोजें।

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Internet scanning और common service activity के observations के लिए IP addresses या ranges खोजें। Current trial और community-access terms की जांच करें।

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

किसी IP address, host या search query के लिए internet-scan और service information प्राप्त करें। API access account plan पर निर्भर करता है।

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, certificate, domain और internet-service datasets खोजें; इसका data model और coverage Shodan से अलग है।

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Keyword के आधार पर provider के publicly observed cloud-storage objects और buckets के index में खोजें।

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Email addresses, usernames, domains और संबंधित records के लिए indexed breach data खोजें। इसका उपयोग केवल authorization के साथ करें और breach data के अनावश्यक exposure से बचें।

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

किसी email address या अन्य term के occurrences के लिए indexed paste content खोजें। इसे integrate करने से पहले verify करें कि service अभी भी उपलब्ध है।

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

किसी email address के लिए reputation और risk signals प्राप्त करें।

## GhostProject (historical) <sup>[[24]](#references)</sup>

Historically leaked email/password data की searches का advertising करता था। Service को high-risk third-party handling मानें और उपयोग से पहले इसकी availability, legality और authorization की पुष्टि करें।

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP addresses और संबंधित assets के लिए internet-scan, exposure और threat-intelligence data प्राप्त करें।

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

जांचें कि कोई email address या verified domain ज्ञात breaches में दिखाई देता है या नहीं। अलग Pwned Passwords service prefix के आधार पर password hashes की जांच करती है; यह plaintext passwords reveal **नहीं** करती।

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation, data-center, ASN, proxy/VPN और संबंधित enrichment fields प्राप्त करें। Quotas वर्तमान plan पर निर्भर करते हैं।

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
चयनित data points के साथ IP geolocation और OSINT-oriented enrichment। Commercial use के लिए वर्तमान terms की जांच करें।


[DNSDumpster](https://dnsdumpster.com/) DNS-reconnaissance results प्रदान करता है।<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) site, hosting और internet-infrastructure intelligence प्रदान करता है।<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) एक online subdomain-discovery interface प्रदान करता है।<sup>[[31]](#references)</sup>

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
{{#include ../banners/hacktricks-training.md}}
