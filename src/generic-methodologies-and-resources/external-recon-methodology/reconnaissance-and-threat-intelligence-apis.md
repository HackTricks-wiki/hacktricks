# API для розвідки та аналізу загроз

{{#include ../../banners/hacktricks-training.md}}

Ці сервіси підтримують процеси розвідки, перевірки репутації, витоків даних або збагачення інформації. Їхні API, квоти, ціни та дозволені способи використання часто змінюються; перш ніж надсилати ідентифікатори клієнтів або конфіденційні дані, перевірте актуальну документацію постачальника та наявність дозволу на проведення робіт. Послідовність пошуку активів описана в [Методології зовнішньої розвідки](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Перевірте, чи пов’язана IP-адреса з підозрілою або зловмисною активністю. Для доступу може знадобитися обліковий запис або API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Перевірте, чи пов’язані IP-адреса, ім’я користувача або адреса електронної пошти з автоматизованою реєстрацією облікових записів чи іншою зафіксованою активністю ботів.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Знаходьте та перевіряйте професійні адреси електронної пошти й контактні шаблони, пов’язані з доменами. Перевірте актуальний тарифний план щодо обмежень запитів і дозволених способів використання.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Шукайте індикатори розвідданих про загрози та активність, пов’язану з IP-адресами й доменами.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Збагачуйте адресу електронної пошти, домен або дані про компанію доступними бізнес-даними та даними профілю. Обсяг даних, доступ і обмеження конфіденційності залежать від актуального продукту й тарифного плану.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Визначайте технології, виявлені на вебсайтах, і отримуйте історичні дані або дані про взаємозв’язки, якщо це дозволяє вибраний тарифний план.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Перевірте, чи пов’язана IP-адреса з підозрілою або зловмисною активністю. Перевірте актуальні тарифні плани та обмеження API.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Переглядайте категоризацію FortiGuard і розвіддані про загрози для доменів, URL-адрес або IP-адрес. Доступність залежить від сервісу.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Перевірте, чи внесено IP-адресу до списку через повідомлення про спам.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Отримуйте дані про репутацію домену на основі спільноти сервісу та інших сигналів.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Отримуйте геолокацію, ASN, організацію та інші пов’язані метадані для IP-адреси. Перевірте квоти актуального тарифного плану.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Ця платформа надає розвіддані про DNS та інфраструктуру, зокрема історію розв’язання імен, домени, пов’язані з IP-адресами або серверами імен, і пов’язані записи. Історичні дані DNS можуть розкрити попередню IP-адресу origin-сервера, але не дають надійно обійти CDN і потребують перевірки.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Збагачуйте адресу електронної пошти, домен або назву компанії доступними атрибутами особи та бізнесу. Обробляйте персональні дані відповідно до вимог щодо дозволу та конфіденційності.

## RiskIQ / Microsoft Defender Threat Intelligence (перехід зі старої версії) <sup>[[14]](#references)</sup>

Можливості RiskIQ PassiveTotal перейшли до Microsoft Defender Threat Intelligence. Доступ до продукту, API та наявна функціональність змінилися, тому користуйтеся актуальною документацією Microsoft, а не покладайтеся на застарілі припущення щодо PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Шукайте домени, IP-адреси, адреси електронної пошти та індексовані історичні або leaked-дані відповідно до обмежень доступу сервісу.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Шукайте IP-адреси та інші індикатори, щоб отримати розвіддані про загрози й репутацію.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Шукайте IP-адреси або діапазони, щоб переглянути дані про спостереження за скануванням інтернету та типову активність сервісів. Перевірте актуальні умови пробного доступу й доступу для спільноти.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Отримуйте дані інтернет-сканування та відомості про сервіси для IP-адреси, хоста або пошукового запиту. Доступ до API залежить від тарифного плану облікового запису.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Шукайте в наборах даних про хости, сертифікати, домени та інтернет-сервіси; модель даних і покриття відрізняються від Shodan.

## [Пошук bucket-ів у GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Шукайте за ключовими словами в індексі постачальника, що містить публічно виявлені об’єкти та bucket-и хмарного сховища.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Шукайте в індексованих даних витоків адреси електронної пошти, імена користувачів, домени та пов’язані записи. Користуйтеся сервісом лише з дозволу та не розголошуйте зайві дані витоків.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Шукайте в індексованому вмісті paste-сервісів згадки адреси електронної пошти або іншого терміна. Перш ніж інтегрувати сервіс, переконайтеся, що він досі доступний.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Отримуйте сигнали репутації та ризику для адреси електронної пошти.

## GhostProject (історичний) <sup>[[24]](#references)</sup>

Раніше сервіс пропонував пошук у leaked-даних адрес електронної пошти та паролів. Ставтеся до нього як до високоризикового стороннього сервісу обробки даних і перед використанням перевірте його доступність, законність та наявність дозволу.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Отримуйте дані інтернет-сканування, відомості про відкриті ресурси та розвіддані про загрози для IP-адрес і пов’язаних активів.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Перевірте, чи фігурує адреса електронної пошти або підтверджений домен у відомих витоках. Окремий сервіс Pwned Passwords перевіряє хеші паролів за префіксом; він **не** розкриває паролі у відкритому вигляді.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Отримуйте геолокацію IP-адреси, дані про дата-центр, ASN, proxy/VPN та інші пов’язані поля збагачення. Квоти залежать від актуального тарифного плану.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Геолокація IP-адрес і збагачення даних для OSINT з вибраними точками даних. Перевірте актуальні умови комерційного використання.


[DNSDumpster](https://dnsdumpster.com/) надає результати DNS-розвідки.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) надає розвіддані про сайти, хостинг та інтернет-інфраструктуру.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) надає онлайн-інтерфейс для пошуку піддоменів.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [API BotScout](https://botscout.com/api.htm)
- [3] [API Hunter](https://hunter.io/api-documentation)
- [4] [API AlienVault OTX](https://otx.alienvault.com/api)
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
- [24] [Дослідження Cornell — протоколи перевірки скомпрометованих облікових даних (містить GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Пошук піддоменів NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
