# Database leak

{{#include ../../banners/hacktricks-training.md}}

## Data Breach Search Engines

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IPやCIDRを検索し、tags、CVE、metadataによってscanner activityを照会できます。<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - username、email address、IP address、その他のselectorでexposed dataを検索できます。monitoringとAPIも利用できます。<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - email addressが既知のdata breachやpaste recordに含まれているか確認できます。notificationsとAPIも利用できます。<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - profile picture、email、username、phone number、crypto address、websiteで報告済みのscammer recordを検索できます。<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - email address、domain、URL、IP、CIDRなどのselectorをindexed source全体から検索できます。<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - business emailまたはdomainについて、exposed credential、infostealerに感染したidentity、stolen session cookieを確認できます。<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - domain、name、email、ID、phone、IP、URL、hashを使用してleaked databaseを検索できます。<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - emailまたはusernameがcompromiseされたか確認できます。
- [LeakCheck](https://leakcheck.io/) - exposed email、username、phone、hash、domain dataを検索し、新しいentryをmonitoringできます。<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - 指定したcompanyのemail addressを検索できます。
- [Library of Leaks](https://search.libraryofleaks.org/) - leak datasetを含むpublic document、company、personを検索できます。<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - email、domain、raw stringでleaked credentialを検索し、新しいexposureをmonitoringできます。<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - infected deviceから取得されたinfostealer logを検索し、新しいdataをmonitoringできます。<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - data breach全体を検索し、credential exposureをmonitoringできます。<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - community-drivenなdatabase breach search engineです。
- [Leaked.domains](https://leaked.domains/) - domain、email、username、password、IP、その他のselectorでleaked credentialと関連recordを検索できます。<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - dark-web activity、credential leak、infostealer data、brand mentionをmonitoringできます。<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dumpの検索およびmonitoring platformです。

## Tools to enumerate data leaks

- [Leaker](https://github.com/vflame6/leaker) - email、username、domain、keyword、phoneで複数のonline sourceを検索するpassive leak discovery CLIです。<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizerの使用方法](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Global Scammer Database - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Exposureの確認 - SpyCloud](https://spycloud.com/check-your-exposure/)
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
