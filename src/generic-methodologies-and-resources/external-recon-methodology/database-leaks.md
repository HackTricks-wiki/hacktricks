# Database leaks

## Data Breach Search Engines

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IP と CIDR を検索し、タグ、CVE、metadata で scanner activity を query できます。<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - username、email address、IP address、その他の selector で exposed data を検索できます。monitoring と API も利用できます。<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - email address が既知の data breach または paste record に含まれているか確認できます。notification と API も利用できます。<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - profile picture、email、username、phone number、crypto address、または website で報告済みの scammer record を検索できます。<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - email address、domain、URL、IP、CIDR などの selector を indexed source 全体から検索できます。<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - business email または domain について、exposed credential、infostealer に感染した identity、stolen session cookie を確認できます。<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - domain、name、email、ID、phone、IP、URL、hash を使用して leaked database を検索できます。<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - email または username が compromised か確認できます。
- [LeakCheck](https://leakcheck.io/) - exposed email、username、phone、hash、または domain data を検索し、新しい entry を monitoring できます。<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - 指定した company の email address を検索できます。
- [Library of Leaks](https://search.libraryofleaks.org/) - leak dataset を含む public document、company、person を検索できます。<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - email、domain、または raw string で leaked credential を検索し、新しい exposure を monitoring できます。<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - infected device から取得された infostealer log を検索し、新しい data を monitoring できます。<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - data breach 全体を検索し、credential exposure を monitoring できます。<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - community-driven の database breach search engine です。
- [Leaked.domains](https://leaked.domains/) - domain、email、username、password、IP、その他の selector で leaked credential と関連 record を検索できます。<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - dark web activity、credential leak、infostealer data、brand mention を monitoring できます。<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dump の検索および monitoring platform です。

## Tools to enumerate data leaks

- [Leaker](https://github.com/vflame6/leaker) - email、username、domain、keyword、または phone で複数の online source を検索する、passive leak discovery CLI です。<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizer の使用方法](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Global Scammer Database - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Exposure の確認 - SpyCloud](https://spycloud.com/check-your-exposure/)
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
