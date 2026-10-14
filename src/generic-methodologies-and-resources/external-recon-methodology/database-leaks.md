# Database leaks

{{#include ../../banners/hacktricks-training.md}}

## 数据泄露搜索引擎

有关搜索 breach 或 reputation 数据时的 API 访问和服务特定注意事项，请参阅 [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)。

- [GreyNoise Visualizer](https://viz.greynoise.io/) - 查询 IP 和 CIDR，并通过 tags、CVE 和 metadata 查询扫描器活动。<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - 通过用户名、电子邮件地址、IP 地址和其他查询条件搜索暴露的数据；还提供监控服务和 API。<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - 检查电子邮件地址是否出现在已知数据泄露或 paste 记录中；还提供通知服务和 API。<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - 通过头像、电子邮件、用户名、电话号码、加密货币地址或网站搜索举报的诈骗者记录。<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - 在已索引的数据源中搜索电子邮件地址、域名、URL、IP 和 CIDR 等查询条件。<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - 检查企业电子邮件或域名是否涉及暴露的凭据、被 infostealer 感染的身份信息以及被盗的 session cookies。<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - 使用域名、姓名、电子邮件、ID、电话、IP、URL 或哈希搜索泄露的数据库。<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - 检查你的电子邮件或用户名是否遭到泄露。
- [LeakCheck](https://leakcheck.io/) - 搜索暴露的电子邮件、用户名、电话、哈希或域名数据，并监控新增条目。<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - 查找指定公司的电子邮件地址。
- [Library of Leaks](https://search.libraryofleaks.org/) - 搜索公开文档、公司和个人，包括 leak 数据集。<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - 通过电子邮件、域名或原始字符串搜索泄露的凭据，并监控新的暴露数据。<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - 搜索来自受感染设备的 infostealer 日志，并监控新增数据。<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - 搜索各种数据泄露，并监控凭据暴露情况。<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - 由社区驱动的数据库泄露搜索引擎。
- [Leaked.domains](https://leaked.domains/) - 通过域名、电子邮件、用户名、密码、IP 和其他查询条件搜索泄露的凭据及相关记录。<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - 监控 dark web 活动、凭据泄露、infostealer 数据和品牌提及。<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dump 搜索与监控平台。

## 枚举 data leaks 的工具

- [Leaker](https://github.com/vflame6/leaker) - 被动 leak 发现 CLI，可按电子邮件、用户名、域名、关键词或电话搜索多个在线数据源。<sup>[[15]](#references)</sup>

## References

- [1] [使用 GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [全球诈骗者数据库 - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [检查你的暴露情况 - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [数据泄露搜索引擎 - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - 数据泄露搜索引擎](https://leak-lookup.com/)
- [13] [Leaked.Domains - 通用搜索](https://leaked.domains/)
- [14] [WhiteIntel - Dark Web 情报与监控平台](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
