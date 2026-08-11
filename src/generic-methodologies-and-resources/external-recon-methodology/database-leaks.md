# Database leak

{{#include ../../banners/hacktricks-training.md}}

## Data Breach Search Engines

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IP와 CIDR을 조회하고, tag, CVE 및 metadata로 scanner activity를 검색합니다.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - username, email address, IP address 및 기타 selector로 노출된 데이터를 검색하며, monitoring과 API도 제공합니다.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - email address가 알려진 data breach 또는 paste record에 포함되어 있는지 확인하며, notification과 API도 제공합니다.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - profile picture, email, username, phone number, crypto address 또는 website로 신고된 scammer record를 검색합니다.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - 색인된 source에서 email address, domain, URL, IP 및 CIDR과 같은 selector를 검색합니다.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - business email 또는 domain에서 노출된 credential, infostealer에 감염된 identity 및 탈취된 session cookie를 확인합니다.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - domain, name, email, ID, phone, IP, URL 또는 hash를 사용하여 유출된 database를 검색합니다.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - email 또는 username이 침해되었는지 확인합니다.
- [LeakCheck](https://leakcheck.io/) - 노출된 email, username, phone, hash 또는 domain 데이터를 검색하고 새로운 entry를 monitoring합니다.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - 특정 company의 email address를 찾습니다.
- [Library of Leaks](https://search.libraryofleaks.org/) - leak dataset을 포함한 public document, company 및 people을 검색합니다.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - email, domain 또는 raw string으로 유출된 credential을 검색하고 새로운 노출을 monitoring합니다.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - 감염된 device에서 수집된 infostealer log를 검색하고 새로운 데이터를 monitoring합니다.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - data breach를 검색하고 credential 노출을 monitoring합니다.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - community가 운영하는 database breach search engine입니다.
- [Leaked.domains](https://leaked.domains/) - domain, email, username, password, IP 및 기타 selector로 유출된 credential과 관련 record를 검색합니다.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - dark web activity, credential leak, infostealer data 및 brand mention을 monitoring합니다.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dump 검색 및 monitoring platform입니다.

## Tools to enumerate data leaks

- [Leaker](https://github.com/vflame6/leaker) - email, username, domain, keyword 또는 phone으로 여러 online source를 검색하는 passive leak discovery CLI입니다.<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizer 사용 방법](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Global Scammer Database - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [노출 여부 확인 - SpyCloud](https://spycloud.com/check-your-exposure/)
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
