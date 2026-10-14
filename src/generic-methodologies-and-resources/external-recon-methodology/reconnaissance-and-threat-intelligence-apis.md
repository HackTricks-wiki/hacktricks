# Reconnaissance और Threat-Intelligence APIs

{{#include ../../banners/hacktricks-training.md}}

ये सेवाएँ reconnaissance, reputation, breach या enrichment workflows में सहायता करती हैं। इनके APIs, quotas, pricing और अनुमत उपयोग में अक्सर बदलाव होते रहते हैं; ग्राहक पहचानकर्ता या संवेदनशील डेटा भेजने से पहले विक्रेता के मौजूदा दस्तावेज़ और engagement की अनुमति की पुष्टि करें। Asset-discovery sequence के लिए [External Recon Methodology](README.md) देखें।

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

जाँचें कि क्या कोई IP address संदिग्ध या दुर्भावनापूर्ण गतिविधि से जुड़ा रहा है। पहुँच के लिए account या API key की आवश्यकता हो सकती है।

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

जाँचें कि क्या कोई IP address, username या email address automated account registration या bot से जुड़ी अन्य रिपोर्ट की गई गतिविधि से संबंधित रहा है।

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

व्यावसायिक email addresses और domain से संबंधित contact patterns खोजें और सत्यापित करें। Request limits और अनुमत उपयोग के लिए मौजूदा plan देखें।

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP addresses और domains से जुड़े threat-intelligence indicators और गतिविधि खोजें।

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

उपलब्ध business/profile data से email address, domain या company की जानकारी बढ़ाएँ। Coverage, access और privacy संबंधी सीमाएँ मौजूदा product और plan पर निर्भर करती हैं।

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

वेबसाइटों पर देखी गई technologies की पहचान करें और चुने गए plan की अनुमति के अनुसार historical या relationship data प्राप्त करें।

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

जाँचें कि क्या कोई IP address संदिग्ध या दुर्भावनापूर्ण गतिविधि से जुड़ा है। मौजूदा API plans और limits की पुष्टि करें।

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Domains, URLs या IP addresses के लिए FortiGuard categorization और threat intelligence देखें। उपलब्धता सेवा के अनुसार अलग-अलग होती है।

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

जाँचें कि क्या कोई IP address रिपोर्ट की गई spam गतिविधि के लिए सूचीबद्ध है।

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

सेवा के community और अन्य संकेतों के आधार पर किसी domain की reputation प्राप्त करें।

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IP address के लिए geolocation, ASN, organization और संबंधित metadata प्राप्त करें। Quotas के लिए मौजूदा plan देखें।

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

यह platform DNS और infrastructure intelligence प्रदान करता है, जैसे historical resolutions, IPs या name servers से जुड़े domains और संबंधित records। Historical DNS से पहले का origin address मिल सकता है, लेकिन यह CDN को भरोसेमंद तरीके से bypass नहीं करता और इसकी पुष्टि करना आवश्यक है।

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

उपलब्ध identity और business attributes से email address, domain या company name की जानकारी बढ़ाएँ। Personal data को अनुमति और privacy आवश्यकताओं के अनुसार संभालें।

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ की PassiveTotal क्षमताएँ Microsoft Defender Threat Intelligence में स्थानांतरित हो गईं। Product access, APIs और उपलब्ध सुविधाएँ बदल चुकी हैं, इसलिए पुराने PassiveTotal अनुमानों के बजाय Microsoft के मौजूदा दस्तावेज़ देखें।

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

सेवा के access controls के अधीन रहते हुए domains, IP addresses, email addresses और indexed historical या leaked data खोजें।

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Threat-intelligence और reputation data के लिए IP addresses और अन्य indicators खोजें।

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Internet scanning और सामान्य service गतिविधि के अवलोकन खोजने के लिए IP addresses या ranges खोजें। मौजूदा trial और community-access की शर्तें देखें।

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IP address, host या search query के लिए internet-scan और service संबंधी जानकारी प्राप्त करें। API access account plan पर निर्भर करता है।

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, certificate, domain और internet-service datasets खोजें; इसका data model और coverage, Shodan से अलग है।

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Keyword के आधार पर सार्वजनिक रूप से देखे गए cloud-storage objects और buckets के provider index में खोजें।

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Email addresses, usernames, domains और संबंधित records के लिए indexed breach data खोजें। इसका उपयोग केवल अनुमति के साथ करें और breach data को अनावश्यक रूप से उजागर करने से बचें।

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Email address या अन्य शब्द की मौजूदगी के लिए indexed paste content खोजें। इसे integrate करने से पहले पुष्टि करें कि सेवा अभी भी उपलब्ध है।

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

किसी email address के लिए reputation और risk signals प्राप्त करें।

## GhostProject (ऐतिहासिक) <sup>[[24]](#references)</sup>

ऐतिहासिक रूप से leaked email/password data में खोज करने का प्रचार किया गया था। इस सेवा को उच्च-जोखिम वाली third-party data handling मानें और उपयोग से पहले इसकी उपलब्धता, वैधता और अनुमति की पुष्टि करें।

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP addresses और संबंधित assets के लिए internet-scan, exposure और threat-intelligence data प्राप्त करें।

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

जाँचें कि क्या कोई email address या verified domain ज्ञात breaches में मौजूद है। अलग Pwned Passwords सेवा prefix के आधार पर password hashes जाँचती है; यह plaintext passwords **नहीं** दिखाती।

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation, data-center, ASN, proxy/VPN और संबंधित enrichment fields प्राप्त करें। Quotas मौजूदा plan पर निर्भर करती हैं।

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
चुने गए data points के साथ IP geolocation और OSINT-केंद्रित enrichment। व्यावसायिक उपयोग की मौजूदा शर्तें देखें।


[DNSDumpster](https://dnsdumpster.com/) DNS-reconnaissance के परिणाम प्रदान करता है।<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) site, hosting और internet-infrastructure intelligence प्रदान करता है।<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) subdomain खोजने के लिए online interface प्रदान करता है।<sup>[[31]](#references)</sup>

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
- [24] [कॉर्नेल शोध — समझौता किए गए credentials की जाँच के लिए protocols (GhostProject शामिल)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
