# Database leaks

{{#include ../../banners/hacktricks-training.md}}

## Пошукові системи витоків даних

- [GreyNoise Visualizer](https://viz.greynoise.io/) - Пошук IP-адрес і CIDR, а також запитів щодо активності сканерів за тегами, CVE та метаданими.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - Пошук exposed даних за іменами користувачів, email-адресами, IP-адресами та іншими селекторами; також доступні моніторинг і API.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Перевірка, чи з’являється email-адреса у відомих витоках даних або paste-записах; також доступні сповіщення та API.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - Пошук записів про шахраїв за зображенням профілю, email, іменем користувача, номером телефону, crypto-адресою або вебсайтом.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - Пошук селекторів, таких як email-адреси, домени, URL, IP-адреси та CIDR, в indexed джерелах.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - Перевірка business email або домену на наявність exposed облікових даних, identities, інфікованих infostealer, і викрадених session cookies.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - Пошук у leaked базах даних за доменами, іменами, email, ID, телефонами, IP-адресами, URL або хешами.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - Перевірка, чи були скомпрометовані ваша email-адреса або ім’я користувача.
- [LeakCheck](https://leakcheck.io/) - Пошук exposed даних email, імен користувачів, телефонів, хешів або доменів і моніторинг нових записів.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - Пошук email-адрес для певної компанії.
- [Library of Leaks](https://search.libraryofleaks.org/) - Пошук публічних документів, компаній і людей, зокрема leak-наборів даних.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - Пошук leaked облікових даних за email, доменом або raw-рядком і моніторинг нових exposures.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - Пошук infostealer-логів з інфікованих пристроїв і моніторинг нових даних.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - Пошук у витоках даних і моніторинг exposure облікових даних.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - Community-driven пошукова система витоків баз даних.
- [Leaked.domains](https://leaked.domains/) - Пошук leaked облікових даних і пов’язаних записів за доменом, email, іменем користувача, паролем, IP-адресою та іншими селекторами.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - Моніторинг активності в dark web, витоків облікових даних, даних infostealer і згадок про бренд.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Платформа для пошуку та моніторингу dump-даних Pastebin.

## Інструменти для перерахування витоків даних

- [Leaker](https://github.com/vflame6/leaker) - Пасивний CLI для виявлення leak, який шукає в кількох online-джерелах за email, іменем користувача, доменом, ключовим словом або номером телефону.<sup>[[15]](#references)</sup>

## References

- [1] [Використання GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Глобальна база даних шахраїв - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Перевірка exposure - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Пошукова система витоків даних - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Пошукова система витоків даних](https://leak-lookup.com/)
- [13] [Leaked.Domains - Універсальний пошук](https://leaked.domains/)
- [14] [WhiteIntel - Платформа dark-web розвідки та моніторингу](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
