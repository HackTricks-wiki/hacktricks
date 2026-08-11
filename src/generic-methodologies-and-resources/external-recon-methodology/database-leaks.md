# Database leaks

{{#include ../../banners/hacktricks-training.md}}

## Data Breach Search Engines

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IPs और CIDRs देखें, और tags, CVEs तथा metadata के आधार पर scanner activity को query करें।<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - usernames, email addresses, IP addresses और अन्य selectors के आधार पर exposed data खोजें; monitoring और API भी उपलब्ध हैं।<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - जांचें कि कोई email address ज्ञात data breaches या paste records में दिखाई देता है या नहीं; notifications और API भी उपलब्ध हैं।<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - profile picture, email, username, phone number, crypto address या website के आधार पर reported scammer records खोजें।<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - indexed sources में email addresses, domains, URLs, IPs और CIDRs जैसे selectors खोजें।<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - exposed credentials, infostealer-infected identities और stolen session cookies के लिए business email या domain जांचें।<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - domains, names, emails, IDs, phones, IPs, URLs या hashes का उपयोग करके leaked databases खोजें।<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - जांचें कि आपका email या username compromise हुआ है या नहीं।
- [LeakCheck](https://leakcheck.io/) - exposed email, username, phone, hash या domain data खोजें और नई entries के लिए monitor करें।<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - किसी दी गई company के email addresses खोजें।
- [Library of Leaks](https://search.libraryofleaks.org/) - leak datasets सहित public documents, companies और people खोजें।<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - email, domain या raw string के आधार पर leaked credentials खोजें और नए exposures के लिए monitor करें।<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - infected devices से infostealer logs खोजें और नए data को monitor करें।<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - data breaches में खोजें और credential exposure को monitor करें।<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - community-driven database breach search engine।
- [Leaked.domains](https://leaked.domains/) - domain, email, username, password, IP और अन्य selectors के आधार पर leaked credentials और संबंधित records खोजें।<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - dark-web activity, credential leaks, infostealer data और brand mentions को monitor करें।<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dump search और monitoring platform।

## Tools to enumerate data leaks

- [Leaker](https://github.com/vflame6/leaker) - passive leak discovery CLI, जो email, username, domain, keyword या phone के आधार पर कई online sources खोजता है।<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizer का उपयोग](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Global Scammer Database - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [अपना Exposure जांचें - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Data Breach Search Engine - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Data Breach Search Engine](https://leak-lookup.com/)
- [13] [Leaked.Domains - Universal Search](https://leaked.domains/)
- [14] [WhiteIntel - Dark Web Intelligence & Monitoring Platform](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
