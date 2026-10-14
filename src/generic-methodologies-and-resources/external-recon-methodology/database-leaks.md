# Бази даних leaks

{{#include ../../banners/hacktricks-training.md}}

## Пошукові системи витоків даних

Щоб дізнатися про доступ до API та особливості окремих сервісів під час пошуку даних про витоки або репутацію, див. [каталог API для розвідки та аналізу загроз](reconnaissance-and-threat-intelligence-apis.md).

- [GreyNoise Visualizer](https://viz.greynoise.io/) — шукайте IP-адреси й CIDR-блоки, а також запити активності сканерів за тегами, CVE та метаданими.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) — шукайте exposed data за іменами користувачів, адресами електронної пошти, IP-адресами та іншими селекторами; також доступні моніторинг і API.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) — перевірте, чи фігурує адреса електронної пошти у відомих data breaches або записах paste; також доступні сповіщення й API.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) — шукайте записи про шахраїв за зображенням профілю, адресою електронної пошти, іменем користувача, номером телефону, криптоадресою або вебсайтом.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) — шукайте за такими селекторами, як адреси електронної пошти, домени, URL-адреси, IP-адреси й CIDR-блоки, у проіндексованих джерелах.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) — перевірте робочу адресу електронної пошти або домен на предмет exposed credentials, облікових записів, заражених infostealer, і викрадених session cookies.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) — шукайте в leaked databases за доменами, іменами, адресами електронної пошти, ідентифікаторами, телефонами, IP-адресами, URL-адресами або хешами.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) — перевірте, чи було скомпрометовано вашу адресу електронної пошти або ім’я користувача.
- [LeakCheck](https://leakcheck.io/) — шукайте exposed data за адресою електронної пошти, іменем користувача, телефоном, хешем або доменом і відстежуйте нові записи.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) — знаходьте адреси електронної пошти для певної компанії.
- [Library of Leaks](https://search.libraryofleaks.org/) — шукайте в публічних документах, компаніях і даних про людей, зокрема в наборах даних leak.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) — шукайте leaked credentials за адресою електронної пошти, доменом або довільним рядком і відстежуйте нові випадки витоку.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) — шукайте журнали infostealer із заражених пристроїв і відстежуйте нові дані.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) — шукайте в data breaches і відстежуйте витік облікових даних.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) — пошукова система витоків баз даних, створена спільнотою.
- [Leaked.domains](https://leaked.domains/) — шукайте leaked credentials і пов’язані записи за доменом, адресою електронної пошти, іменем користувача, паролем, IP-адресою та іншими селекторами.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) — відстежуйте активність у dark web, витоки облікових даних, дані infostealer і згадки брендів.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) — платформа для пошуку й моніторингу дампів Pastebin.

## Інструменти для пошуку data leaks

- [Leaker](https://github.com/vflame6/leaker) — CLI для пасивного пошуку leaks, який перевіряє кілька онлайн-джерел за адресою електронної пошти, іменем користувача, доменом, ключовим словом або номером телефону.<sup>[[15]](#references)</sup>

## References

- [1] [Використання GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Глобальна база даних шахраїв — ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Перевірте, чи ваші дані exposed — SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Пошукова система витоків даних — LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup — пошукова система витоків даних](https://leak-lookup.com/)
- [13] [Leaked.Domains — універсальний пошук](https://leaked.domains/)
- [14] [WhiteIntel — платформа розвідки та моніторингу dark web](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
