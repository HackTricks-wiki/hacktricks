# Online Platforms with API

{{#include ../banners/hacktricks-training.md}}

Ці сервіси підтримують робочі процеси розвідки, перевірки репутації, аналізу breach або enrichment. Їхні API, квоти, ціни та дозволені способи використання часто змінюються; перед надсиланням ідентифікаторів клієнтів або чутливих даних перевіряйте актуальну документацію постачальника та дозвіл на проведення робіт.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Перевіряє, чи була IP-адреса пов'язана з підозрілою або шкідливою активністю. Для доступу може знадобитися обліковий запис або API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Перевіряє, чи була IP-адреса, ім'я користувача або адреса електронної пошти пов'язана з автоматизованою реєстрацією облікових записів або іншою повідомленою bot-активністю.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Знаходить і перевіряє професійні адреси електронної пошти та пов'язані з доменом контактні шаблони. Перевіряйте поточний план щодо лімітів запитів і дозволених способів використання.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Здійснює пошук індикаторів threat intelligence та активності, пов'язаної з IP-адресами й доменами.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Доповнює адресу електронної пошти, домен або компанію доступними бізнес-/профільними даними. Обсяг охоплення, доступ і обмеження щодо приватності залежать від поточного продукту та плану.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Визначає технології, виявлені на вебсайтах, і надає історичні дані або дані про зв'язки, якщо це дозволено вибраним планом.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Перевіряє, чи пов'язана IP-адреса з підозрілою або шкідливою активністю. Перевіряйте актуальні API-плани та ліміти.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Виконує пошук категоризації FortiGuard і threat intelligence для доменів, URL або IP-адрес. Доступність залежить від сервісу.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Перевіряє, чи внесена IP-адреса до списку через повідомлену spam-активність.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Отримує репутацію домену на основі даних спільноти сервісу та інших сигналів.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Надає геолокацію, ASN, організацію та пов'язані метадані для IP-адреси. Перевіряйте квоти поточного плану.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ця платформа надає DNS та інфраструктурну інформацію, зокрема історичні резолюції, домени, пов'язані з IP-адресами або name servers, і пов'язані записи. Історичний DNS може розкрити попередню origin-адресу, але не забезпечує надійного обходу CDN і має бути перевірений.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Доповнює адресу електронної пошти, домен або назву компанії доступними ідентифікаційними та бізнес-атрибутами. Обробляйте персональні дані відповідно до вимог авторизації та приватності.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Можливості PassiveTotal від RiskIQ були перенесені до Microsoft Defender Threat Intelligence. Доступ до продукту, API та збережена функціональність змінилися, тому використовуйте актуальну документацію Microsoft, а не припущення щодо legacy PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Здійснює пошук доменів, IP-адрес, адрес електронної пошти та індексованих історичних або leaked даних відповідно до засобів контролю доступу сервісу.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Здійснює пошук IP-адрес та інших індикаторів для отримання даних threat intelligence і репутації.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Здійснює пошук IP-адрес або діапазонів для виявлення спостережень за інтернет-скануванням і активністю поширених сервісів. Перевіряйте актуальні умови trial і community-доступу.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Отримує інформацію про інтернет-сканування та сервіси для IP-адреси, хоста або пошукового запиту. Доступ до API залежить від плану облікового запису.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Здійснює пошук у наборах даних про хости, сертифікати, домени та інтернет-сервіси; його модель даних і охоплення відрізняються від Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Здійснює пошук у індексі постачальника публічно виявлених об'єктів і bucket у cloud storage за ключовим словом.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Здійснює пошук в індексованих breach-даних за адресами електронної пошти, іменами користувачів, доменами та пов'язаними записами. Використовуйте лише з дозволом і уникайте непотрібного розкриття breach-даних.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Здійснює пошук в індексованому вмісті paste наявності адреси електронної пошти або іншого терміна. Перед інтеграцією перевірте, чи сервіс досі доступний.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Отримує репутаційні сигнали та сигнали ризику для адреси електронної пошти.

## GhostProject (historical) <sup>[[24]](#references)</sup>

Раніше рекламував пошук leaked даних електронної пошти та паролів. Розглядайте сервіс як високоризикову обробку даних стороннім постачальником і перед використанням перевірте його доступність, законність та наявність дозволу.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Надає дані про інтернет-сканування, експозицію та threat intelligence для IP-адрес і пов'язаних активів.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Перевіряє, чи присутня адреса електронної пошти або верифікований домен у відомих breach. Окремий сервіс Pwned Passwords перевіряє хеші паролів за префіксом; він **не** розкриває паролі у відкритому вигляді.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Отримує геолокацію IP, дані про дата-центр, ASN, proxy/VPN та пов'язані поля enrichment. Квоти залежать від поточного плану.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Геолокація IP та enrichment, орієнтований на OSINT, із вибраними точками даних. Перевіряйте актуальні умови комерційного використання.


[DNSDumpster](https://dnsdumpster.com/) надає результати DNS-розвідки.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) надає інформацію про сайти, хостинг та інтернет-інфраструктуру.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) надає онлайн-інтерфейс для виявлення субдоменів.<sup>[[31]](#references)</sup>

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
- [24] [Дослідження Cornell — Protocols for Checking Compromised Credentials (includes GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
