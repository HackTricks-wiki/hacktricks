# Розвідка та API розвідданих про загрози

{{#include ../../banners/hacktricks-training.md}}

Ці сервіси підтримують робочі процеси розвідки, перевірки репутації, витоків або збагачення даних. Їхні API, квоти, ціни та дозволені способи використання часто змінюються; перш ніж надсилати ідентифікатори клієнтів або конфіденційні дані, перевірте актуальну документацію постачальника та наявність дозволу на проведення робіт. Послідовність пошуку активів наведена в [Методології зовнішньої розвідки](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Перевірте, чи пов’язана IP-адреса з підозрілою або зловмисною активністю. Для доступу може знадобитися обліковий запис або API-ключ.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Перевірте, чи пов’язана IP-адреса, ім’я користувача або адреса електронної пошти з автоматизованою реєстрацією облікових записів або іншою зареєстрованою бот-активністю.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Знаходьте та перевіряйте професійні адреси електронної пошти й пов’язані з доменами контактні шаблони. Перевірте в поточному тарифному плані обмеження кількості запитів і дозволені способи використання.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Шукайте індикатори розвідданих про загрози та активність, пов’язані з IP-адресами й доменами.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Збагачуйте адресу електронної пошти, домен або компанію доступними бізнес-даними чи даними профілю. Охоплення, доступ і обмеження конфіденційності залежать від поточного продукту й тарифного плану.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Визначайте технології, виявлені на вебсайтах, і отримуйте історичні дані або дані про зв’язки, якщо це дозволяє обраний тарифний план.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Перевірте, чи пов’язана IP-адреса з підозрілою або зловмисною активністю. Перевірте актуальні тарифні плани й обмеження API.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Перевірте категоризацію FortiGuard і розвіддані про загрози для доменів, URL-адрес або IP-адрес. Доступність залежить від сервісу.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Перевірте, чи внесена IP-адреса до списку через зареєстровану спам-активність.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Отримайте оцінку репутації домену на основі даних спільноти сервісу та інших сигналів.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Отримайте геолокацію, ASN, організацію та пов’язані метадані для IP-адреси. Перевірте квоти в поточному тарифному плані.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ця платформа надає розвіддані про DNS та інфраструктуру, зокрема історію резолюцій, домени, пов’язані з IP-адресами або серверами імен, і пов’язані записи. Історичні DNS-дані можуть показати попередню адресу origin-сервера, але вони не дають надійного способу обійти CDN і потребують перевірки.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Збагачуйте адресу електронної пошти, домен або назву компанії доступними атрибутами особи та бізнесу. Обробляйте персональні дані відповідно до вимог щодо дозволів і конфіденційності.

## RiskIQ / Microsoft Defender Threat Intelligence (перехід зі старої версії) <sup>[[14]](#references)</sup>

Можливості RiskIQ PassiveTotal перейшли до Microsoft Defender Threat Intelligence. Доступ до продукту, API та збережена функціональність змінилися, тому орієнтуйтеся на актуальну документацію Microsoft, а не на застарілі припущення щодо PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Шукайте домени, IP-адреси, адреси електронної пошти та проіндексовані історичні або leaked дані з урахуванням правил доступу сервісу.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Шукайте розвіддані про загрози та репутацію IP-адрес й інших індикаторів.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Шукайте дані про спостереження сканування інтернету та типову активність сервісів для IP-адрес або діапазонів. Перевірте актуальні умови пробного доступу та доступу для спільноти.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Отримуйте дані інтернет-сканування та інформацію про сервіси для IP-адреси, хоста або пошукового запиту. Доступ до API залежить від тарифного плану облікового запису.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Шукайте в наборах даних про хости, сертифікати, домени й інтернет-сервіси; модель даних та охоплення відрізняються від Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Шукайте за ключовими словами в індексі постачальника, що містить публічно виявлені об’єкти й бакети хмарних сховищ.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Шукайте в проіндексованих даних витоків адреси електронної пошти, імена користувачів, домени та пов’язані записи. Використовуйте сервіс лише за наявності дозволу й уникайте непотрібного розголошення даних витоків.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Шукайте в проіндексованому вмісті paste-сервісів згадки адреси електронної пошти або іншого терміна. Перш ніж інтегрувати сервіс, перевірте, чи він досі доступний.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Отримайте сигнали репутації та ризику для адреси електронної пошти.

## GhostProject (історичний) <sup>[[24]](#references)</sup>

Раніше сервіс пропонував пошук у leaked даних електронної пошти й паролів. Ставтеся до нього як до високоризикового стороннього сервісу обробки даних і перш ніж користуватися ним перевірте його доступність, законність і наявність дозволу.

## BinaryEdge (припинено) <sup>[[25]](#references)</sup>

Сервіс надавав дані інтернет-сканування, експозиції та розвіддані про загрози для IP-адрес і пов’язаних активів. Тепер сайт переспрямовує на повідомлення про перехід до Coalition, а API відхиляє запити, тому вважайте сервіс недоступним.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Перевірте, чи фігурує адреса електронної пошти або верифікований домен у відомих витоках. Окремий сервіс Pwned Passwords перевіряє хеші паролів за префіксом; він **не** розкриває паролі у відкритому вигляді.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Отримуйте геолокацію IP, дані про дата-центри, ASN, проксі/VPN та інші поля для збагачення. Квоти залежать від поточного тарифного плану.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Збагачення даних про геолокацію IP та OSINT із вибраними точками даних. Перевірте актуальні умови комерційного використання.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Перевіряйте домен (реєстратора, дати реєстрації та закінчення терміну дії, сервери імен, IP-адресу хостингу та країну) або IP-адресу (інші розміщені на ній домени), а також наявність домену чи IP-адреси у безкоштовних списках скомпрометованих об’єктів: фішингові домени й домени з malware, спрямовані в sinkhole, а також адреси, що атакували honeypot-сенсори сервісу протягом останніх 48 годин. Для вебперевірок і API перевірки скомпрометованих об’єктів обліковий запис не потрібен; доступ до API перевірок вимагає платного тарифного плану.


[DNSDumpster](https://dnsdumpster.com/) надає результати DNS-розвідки.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) надає розвіддані про сайти, хостинг та інтернет-інфраструктуру.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) надає онлайн-інтерфейс для пошуку піддоменів.<sup>[[31]](#references)</sup>

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
- [24] [Дослідження Cornell — протоколи перевірки скомпрометованих облікових даних (включно з GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [Документація API NetAPI](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
