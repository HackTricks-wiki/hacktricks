# Reconnaissance और Threat-Intelligence APIs

{{#include ../../banners/hacktricks-training.md}}

ये services reconnaissance, reputation, breach या enrichment workflows में सहायता करती हैं। इनके APIs, quotas, pricing और अनुमत उपयोग में अक्सर बदलाव होते हैं; customer identifiers या sensitive data भेजने से पहले vendor के मौजूदा documentation और engagement authorization की पुष्टि करें। Asset-discovery sequence के लिए [External Recon Methodology](README.md) देखें।

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

जाँचें कि कोई IP address संदिग्ध या malicious activity से जुड़ा रहा है या नहीं। Access के लिए account या API key की आवश्यकता हो सकती है।

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

जाँचें कि कोई IP address, username या email address automated account registration या bot activity की अन्य रिपोर्टों से जुड़ा रहा है या नहीं।

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Professional email addresses और domain से जुड़े contact patterns खोजें और verify करें। Request limits और अनुमत उपयोग के लिए मौजूदा plan देखें।

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP addresses और domains से जुड़े threat-intelligence indicators और activity खोजें।

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

उपलब्ध business/profile data से email address, domain या company की जानकारी बढ़ाएँ। Coverage, access और privacy की सीमाएँ मौजूदा product और plan पर निर्भर करती हैं।

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Websites पर देखी गई technologies की पहचान करें और चुने हुए plan में अनुमति होने पर historical या relationship data प्राप्त करें।

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

जाँचें कि कोई IP address संदिग्ध या malicious activity से जुड़ा है या नहीं। मौजूदा API plans और limits की पुष्टि करें।

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Domains, URLs या IP addresses के लिए FortiGuard categorization और threat intelligence देखें। उपलब्धता service के अनुसार अलग-अलग होती है।

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

जाँचें कि कोई IP address reported spam activity के लिए सूचीबद्ध है या नहीं।

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Service के community और अन्य signals के आधार पर किसी domain की reputation प्राप्त करें।

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

किसी IP address के लिए geolocation, ASN, organization और संबंधित metadata प्राप्त करें। Quotas के लिए मौजूदा plan देखें।

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

यह platform DNS और infrastructure intelligence देता है, जैसे historical resolutions, IPs या name servers से जुड़े domains और संबंधित records। Historical DNS से पहले का origin address पता चल सकता है, लेकिन इससे CDN को भरोसेमंद तरीके से bypass नहीं किया जा सकता और इसकी पुष्टि करना ज़रूरी है।

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

उपलब्ध identity और business attributes से email address, domain या company name की जानकारी बढ़ाएँ। Personal data को authorization और privacy requirements के अनुसार संभालें।

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ की PassiveTotal capabilities को Microsoft Defender Threat Intelligence में शामिल किया गया। Product access, APIs और उपलब्ध functionality में बदलाव हुए हैं, इसलिए legacy PassiveTotal से जुड़ी धारणाओं के बजाय Microsoft का मौजूदा documentation देखें।

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Service के access controls के अधीन, domains, IP addresses, email addresses और indexed historical या leaked data खोजें।

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Threat-intelligence और reputation data के लिए IP addresses और अन्य indicators खोजें।

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Internet scanning और सामान्य service activity के observations के लिए IP addresses या ranges खोजें। मौजूदा trial और community-access की शर्तें देखें।

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

किसी IP address, host या search query के लिए internet-scan और service की जानकारी प्राप्त करें। API access account plan पर निर्भर करता है।

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, certificate, domain और internet-service datasets खोजें; इसका data model और coverage, Shodan से अलग है।

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Keyword के आधार पर provider के publicly observed cloud-storage objects और buckets के index में खोजें।

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Email addresses, usernames, domains और संबंधित records के लिए indexed breach data खोजें। केवल authorization के साथ इसका उपयोग करें और breach data को अनावश्यक रूप से उजागर करने से बचें।

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

किसी email address या अन्य शब्द के occurrences के लिए indexed paste content खोजें। इसे integrate करने से पहले पुष्टि करें कि service अब भी उपलब्ध है।

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

किसी email address के लिए reputation और risk signals प्राप्त करें।

## GhostProject (ऐतिहासिक) <sup>[[24]](#references)</sup>

ऐतिहासिक रूप से इसने leaked email/password data में searches की सुविधा दी थी। इसे third-party data handling का high-risk मामला मानें और उपयोग से पहले इसकी उपलब्धता, वैधता और authorization की पुष्टि करें।

## BinaryEdge (बंद) <sup>[[25]](#references)</sup>

यह IP addresses और संबंधित assets के लिए internet-scan, exposure और threat-intelligence data देता था। इसकी site अब Coalition transition notice पर redirect होती है और API requests अस्वीकार करती है, इसलिए इसे अनुपलब्ध मानें।

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

जाँचें कि कोई email address या verified domain ज्ञात breaches में शामिल है या नहीं। अलग Pwned Passwords service, prefix के आधार पर password hashes जाँचती है; यह **plaintext passwords** नहीं दिखाती।

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation, data-center, ASN, proxy/VPN और संबंधित enrichment fields प्राप्त करें। Quotas मौजूदा plan पर निर्भर करते हैं।

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
चुने हुए data points के साथ IP geolocation और OSINT-oriented enrichment प्राप्त करें। Commercial use के लिए मौजूदा शर्तें देखें।

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
किसी domain की जानकारी (registrar, registration और expiry dates, name servers, hosting IP और country) या IP address की जानकारी (उस पर hosted अन्य domains) देखें। यह भी जाँचें कि domain या IP इसकी free compromised lists में है या नहीं: phishing और sinkholed malware domains, और वे addresses जिन्होंने पिछले 48 घंटों में इसके honeypot sensors पर attack किया है। Web lookups और compromised-check API के लिए account की आवश्यकता नहीं है; lookups के API access के लिए paid plan चाहिए।


[DNSDumpster](https://dnsdumpster.com/) DNS-reconnaissance के परिणाम देता है।<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) site, hosting और internet-infrastructure intelligence देता है।<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) subdomain-discovery के लिए online interface देता है।<sup>[[31]](#references)</sup>

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
- [24] [Cornell research — Compromised Credentials की जाँच के लिए Protocols (GhostProject सहित)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [NetAPI API documentation](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
