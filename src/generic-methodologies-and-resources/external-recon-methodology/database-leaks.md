# Database leak 검색 엔진

{{#include ../../banners/hacktricks-training.md}}

## Data Breach 검색 엔진

유출 데이터 또는 평판 데이터를 검색할 때 API 액세스 및 서비스별 유의 사항은 [Reconnaissance and Threat-Intelligence APIs 카탈로그](reconnaissance-and-threat-intelligence-apis.md)를 참조하세요.

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IP 및 CIDR을 조회하고 태그, CVE, 메타데이터로 scanner 활동을 검색합니다.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - 사용자 이름, 이메일 주소, IP 주소 및 기타 검색 조건으로 노출된 데이터를 검색합니다. 모니터링 및 API도 이용할 수 있습니다.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - 이메일 주소가 알려진 data breach 또는 paste 기록에 포함되어 있는지 확인합니다. 알림 및 API도 이용할 수 있습니다.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - 프로필 사진, 이메일, 사용자 이름, 전화번호, crypto 주소 또는 웹사이트로 신고된 사기꾼 기록을 검색합니다.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - 색인된 소스에서 이메일 주소, 도메인, URL, IP, CIDR 등의 검색 조건으로 검색합니다.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - 회사 이메일 또는 도메인에서 노출된 자격 증명, infostealer에 감염된 ID, 탈취된 세션 쿠키를 확인합니다.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - 도메인, 이름, 이메일, ID, 전화번호, IP, URL 또는 해시를 사용해 유출된 데이터베이스를 검색합니다.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - 이메일 또는 사용자 이름이 유출되었는지 확인합니다.
- [LeakCheck](https://leakcheck.io/) - 노출된 이메일, 사용자 이름, 전화번호, 해시 또는 도메인 데이터를 검색하고 새 항목을 모니터링합니다.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - 특정 회사의 이메일 주소를 찾습니다.
- [Library of Leaks](https://search.libraryofleaks.org/) - leak 데이터셋을 포함한 공개 문서, 회사, 사람을 검색합니다.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - 이메일, 도메인 또는 원시 문자열로 유출된 자격 증명을 검색하고 새로운 노출을 모니터링합니다.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - 감염된 기기에서 수집한 infostealer 로그를 검색하고 새 데이터를 모니터링합니다.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - data breach를 검색하고 자격 증명 노출을 모니터링합니다.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - 커뮤니티 기반 database breach 검색 엔진입니다.
- [Leaked.domains](https://leaked.domains/) - 도메인, 이메일, 사용자 이름, 비밀번호, IP 및 기타 검색 조건으로 유출된 자격 증명과 관련 기록을 검색합니다.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - 다크웹 활동, 자격 증명 leak, infostealer 데이터, 브랜드 언급을 모니터링합니다.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dump 검색 및 모니터링 플랫폼입니다.

## data leak 열거 도구

- [Leaker](https://github.com/vflame6/leaker) - 이메일, 사용자 이름, 도메인, 키워드 또는 전화번호로 여러 온라인 소스를 검색하는 passive leak 탐색 CLI입니다.<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizer 사용하기](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [글로벌 사기꾼 데이터베이스 - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [노출 여부 확인 - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Data Breach 검색 엔진 - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Data Breach 검색 엔진](https://leak-lookup.com/)
- [13] [Leaked.Domains - 통합 검색](https://leaked.domains/)
- [14] [WhiteIntel - 다크웹 인텔리전스 및 모니터링 플랫폼](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
