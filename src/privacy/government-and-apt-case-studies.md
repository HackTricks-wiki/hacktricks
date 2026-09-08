# Дослідження випадків діяльності урядів і APT

{{#include ../banners/hacktricks-training.md}}

Ці публічні випадки показують, як окремі privacy techniques поєднуються в реальних операціях. Позначення атрибуції наведено так, як їх використовували згадані дослідники або уряди; сама лише IP-адреса, збіг інструментів чи геополітична відповідність не є достатнім доказом атрибуції.

## APT28: віддалений доступ до Wi-Fi за принципом найближчого сусіда

**Публічний висновок.** Volexity пов'язала вторгнення 2022 року з GruesomeLarch/APT28. Після того як доступ до Internet із використанням перевірених облікових даних було заблоковано MFA, actor скомпрометував організації поблизу цілі та отримав доступ до корпоративної Wi-Fi-мережі цілі через розташований неподалік dual-homed host. Шлях через Wi-Fi прийняв облікові дані без MFA, яке вимагалося для зовнішнього доступу.<sup>[[1]](#references)</sup>

**Вплив на privacy.** Фінальний доступ здійснювався з фізичної зони радіодії, а проміжні організації були victims. Операція не потребувала поїздок і змусила звичайну IP-геолокацію вказувати на сусідню організацію.

**Що це викрило.** Сповіщення цілі, розслідування host/network, активність облікових даних, топологію інтерфейсів і фізичну близькість потрібно було аналізувати як єдиний ланцюг. Аномальним фактом була не просто нова IP-адреса, а легітимна ідентичність, що з'явилася через нетиповий контекст Wi-Fi/device, одночасно зі скомпрометованими системами поблизу.

**Захисний висновок.** Застосовуйте доступ до Wi-Fi на основі сертифікатів і пристроїв, зіставляйте RADIUS із NAC/MDM та фізичним контекстом і досліджуйте сусідню інфраструктуру, а не припускайте, що останній hop належить оператору.

## APT28: переорієнтація кримінальної інфраструктури Moobot підрозділом GRU

**Публічний висновок.** У лютому 2024 року US Department of Justice описав botnet із сотень маршрутизаторів Ubiquiti EdgeOS. Criminal actors встановили Moobot на маршрутизаторах, на яких залишалися відомі стандартні облікові дані адміністратора; після цього підрозділ GRU 26165 додав scripts і files, перетворивши наявний кримінальний botnet на espionage platform, яку використовували для spearphishing і крадіжки облікових даних.<sup>[[2]](#references)</sup>

**Вплив на privacy.** GRU не створювала всю інфраструктуру самостійно. Використання вже скомпрометованого fleet розмістило адреси сторонніх домашніх користувачів і малих офісів між actor і цілями, змішало державну активність із кримінальною та зменшило кількість специфічних для actor артефактів реєстрації.

**Що це викрило.** Файли маршрутизаторів, поведінка malware control і routing information без вмісту підтримали розслідування. Під час disruption тимчасово змінилися firewall rules і було видалено malicious files, водночас DOJ попередив, що незмінені стандартні облікові дані можуть спричинити повторне зараження.

**Захисний висновок.** Замінюйте routers, які більше не підтримуються, прибирайте адміністративний доступ, exposed to the Internet, змінюйте стандартні облікові дані, встановлюйте patches, збирайте configuration/flow data edge-пристроїв і шукайте fleet behavior. «Residential US IP» не є доказом того, що оператор перебуває у США.

## Volt Typhoon: KV Botnet і living off the land

**Публічний висновок.** DOJ і спільний advisory CISA описали використання PRC-sponsored actor Volt Typhoon KV Botnet, що складався переважно зі скомпрометованих Cisco і NETGEAR SOHO routers із завершеним життєвим циклом, для приховування PRC origin активності, спрямованої проти critical infrastructure. Усередині victims actor надавав перевагу valid accounts і вбудованим administration tools; agencies повідомили, що в деяких середовищах доступ тривав щонайменше п'ять років.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Вплив на приватність.** Схожий на ORB шлях приховував походження, а living-off-the-land зменшував кількість нових бінарних файлів і можливостей для сигнатурного виявлення після отримання доступу. Приховування на мережевому рівні та на кінцевих точках посилювали одне одного.

**Що викрило атаку.** Структура маршрутизаторів/контролерів, технічний збір даних за рішенням суду, повторювана активність і аналіз між жертвами мали більше значення, ніж один IOC. Перезапуск маршрутизатора видаляв волатильне KV malware в описаних випадках, але не усував базову вразливість пристрою, пов'язану із завершенням терміну підтримки.

**Захисний висновок.** Замінюйте edge-пристрої з завершеним терміном підтримки, централізуйте логи автентифікації та мережевих пристроїв, створюйте базову модель поведінки адміністраторів, обмежуйте вихідні з'єднання та шукайте поведінкові послідовності на рівнях ідентичності, endpoint і мережі.

## ORB-мережі, пов'язані з Китаєм: infrastructure as a service

**Публічні висновки.** Mandiant описала екосистему ORB-мереж, які використовували кілька шпигунських угруповань, пов'язаних із Китаєм. Provisioned networks використовували орендовані VPS-вузли; non-provisioned networks — скомпрометовані IoT-пристрої та маршрутизатори; hybrid networks поєднували їх. ORB3/SPACEHOP підтримувала активність, пов'язану з APT5/APT15. ORB2/FLORAHOX поєднувала administration server, орендовані сервери, налаштований Tor layer і скомпрометовані пристрої Cisco, ASUS та DrayTek. Mandiant оцінила, що деякі мережі адмініструвалися незалежно та здавалися в оренду кільком APT-акторам.<sup>[[5]](#references)</sup>

**Вплив на приватність.** Інфраструктура стала сервісною межею. Один оператор міг отримувати географічні/резидентські exit-вузли, не підтримуючи парк жертв, а багато клієнтів, які спільно використовували цю інфраструктуру, ускладнювали просте зіставлення актора з IP-адресою. Швидка заміна вузлів прискорювала «вимирання IOC».

**Що викрило атаку.** Мережева топологія, клоновані образи серверів, порти/сервіси, зв'язки з контролерами, імпланти маршрутизаторів і життєві цикли залишалися придатними для кластеризації. Mandiant повідомила, що деякі IP-адреси вузлів залишалися в ORB лише 31 день.

**Захисний висновок.** Відстежуйте ORB як мінливу сутність: ролі вузлів, service fingerprints, upstream-зв'язки, поведінку сканування та ритм ротації. Завершення дії IP-індикатора має оновлювати кластер, а не стирати справу.

## Глобальна шпигунська система КНР: маршрутизатори, довірені зв'язки та дзеркалювання трафіку

**Публічні висновки.** У багатонаціональному advisory 2025 року описано активність, що перетиналася з комерційними назвами, зокрема Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 та GhostEmperor. Агентства повідомили про орендовані VPS і скомпрометовані проміжні маршрутизатори, використані для доступу до телекомунікаційних і мережевих провайдерів. Актори переміщувалися через довірені зв'язки provider/customer, змінювали маршрути, створювали GRE/IPsec-тунелі, використовували device containers і вмикали SPAN/RSPAN/ERSPAN або native packet capture для збору автентифікаційних даних і клієнтського трафіку.<sup>[[13]](#references)</sup>

**Вплив на приватність.** Скомпрометований маршрутизатор одночасно є relay, точкою спостереження та довіреним учасником мережі. Приватні interconnections можуть обходити засоби контролю, розраховані на публічний Internet, а traffic mirroring дає змогу збирати облікові дані без розгортання endpoint agent.

**Що викриває атаку.** Configuration diffs, неочікуване адміністрування через SNMP/SSH/web, нові static routes/tunnels, mirror sessions, Guest Shell containers, PCAP-файли, зміни адресатів TACACS+/RADIUS і вимкнене логування. Advisory наголошує, що деякі проміжні маршрутизатори не входили до раніше названого публічного botnet, тому відсутність відомих ORB-індикаторів не виправдовувала їх.

**Захисний висновок.** Використовуйте out-of-band administration, централізовані логи конфігурації/автентифікації, перевірки цілісності signed image і runtime, обмеження egress для management interface та alerts для змін route/mirror/tunnel/AAA. Перед eviction перевіряйте можливий компроміс серед усіх довірених peer.

## UNC3886 RedPenguin: пасивні backdoor на маршрутизаторах ISP

**Публічні висновки.** Mandiant пов'язала кастомні backdoor, похідні від TINYSHELL, на маршрутизаторах Juniper MX із завершеним терміном підтримки з UNC3886. Набір включав active і passive implants, імена, що імітували легітимні daemon, поведінку для вимкнення логів, process injection у trusted process, можливість SOCKS proxy та інфраструктуру, оцінену як ORB staging nodes. Пасивні варіанти перевіряли пакети через `libpcap` і активувалися лише після magic pattern; один із них міг перемикатися на active callback, переданий у trigger.<sup>[[14]](#references)</sup>

**Вплив на приватність.** Пасивний implant не має періодичного beacon, за яким його можна виявити. Він використовує ті самі порти/трафік, що й справжній мережевий appliance, активується ненадовго та може передавати трафік через ORB замість прямого підключення до ultimate controller.

**Що викриває атаку.** Аналіз пам'яті, відмінності між кодом на диску та запущеним кодом, неочікувані packet-capture filters/socket behavior, імена процесів/файлів, що лише наближено імітують легітимні daemon, адміністрування через terminal servers, відсутні логи та двоетапний зв'язок між staging nodes і backend controller.

**Захисний висновок.** Збирайте пам'ять, а також докази з файлової системи/конфігурації, порівнюйте процеси/модулі з відомим чистим образом, відстежуйте використання packet-capture/socket-filter, захищайте management terminal servers і замінюйте мережеве обладнання з завершеним терміном підтримки. Відсутність outbound beacon не означає відсутність компрометації.

## APT29: Tor domain fronting

**Публічні висновки.** MITRE зазначає, що APT29 використовувала pluggable transport `meek` у Tor для domain-front C2-трафіку. Зовнішнє TLS-ім'я виглядало як дозволений домен, розміщений у CDN, тоді як внутрішній HTTP host визначав фактичний маршрут.<sup>[[6]](#references)</sup>

**Вплив на приватність.** Спостерігач, який фільтрує трафік, міг бачити звичайний front/CDN, а не внутрішній destination, і блокування могло спричинити collateral damage.

**Що викриває атаку.** CDN може спостерігати невідповідність маршрутизації, а захисник із endpoint visibility або lawful TLS visibility може зіставити процес, authority, тривалість з'єднання, byte pattern і подальшу активність. Зміни політики провайдера можуть вимкнути техніку.

**Захисний висновок.** Не покладайтеся лише на SNI allowlisting. Застосовуйте application-aware egress, порівнюйте TLS- та HTTP-ідентичності там, де це можливо, і пов'язуйте мережеву подію з процесом-ініціатором.

## APT41 та інші dead-drop resolvers

**Публічні висновки.** MITRE документує використання APT41 легітимних сайтів, зокрема GitHub, Pastebin, Microsoft TechNet, Cloudflare і community forums, для публікації або отримання C2-інформації. Інші state-linked tooling аналогічно використовували публікації, документи та соціальні мережі.<sup>[[7]](#references)</sup>

**Вплив на приватність.** Бінарний файл містить легітимний service/object, а не стабільну C2-адресу. Об'єкт можна редагувати для ротації інфраструктури, а початковий запит зливається зі звичайним TLS-трафіком.

**Що викриває атаку.** Ідентифікатор об'єкта або облікового запису залишається стабільним; рідкісні процеси регулярно отримують його; вміст декодується; після цього відбувається друге outbound-з'єднання. Дані облікового запису провайдера та API можуть пов'язати публікацію з оператором.

**Захисний висновок.** Зберігайте повні proxy paths/object IDs і process lineage на endpoint. Подія на рівні домену, наприклад «підключення до GitHub», є надто загальною.

## Turla: C2 через satellite address

**Публічні висновки.** Kaspersky повідомила, що Turla зловживала незашифрованими downstream broadcasts старих односторонніх DVB-S Internet services. Оператор у зоні покриття супутника міг вибрати адресу легітимного абонента й отримати відповіді, broadcast на неї, через що C2 виглядала розміщеною за супутниковим провайдером в іншому регіоні.<sup>[[8]](#references)</sup>

**Вплив на приватність.** Видима server address не ідентифікувала отримувача, а звичайні процедури вилучення hosting та WHOIS були менш корисними.

**Що викриває атаку.** Актору все одно був потрібен outbound request path, маршрутизація була асиметричною, легітимний абонент не ініціював C2-обмін, а RF/provider investigation могла звузити зону пошуку отримувача.

**Захисний висновок.** Розглядайте геолокацію лише як одну з гіпотез. Перевіряйте симетричність шляху, RTT, власника маршрутизації та те, чи міг заявлений endpoint фактично надавати спостережуваний service.

## Cyclops Blink і VPNFilter: edge-пристрої як довготривале прикриття

**Публічні висновки.** У advisory NCSC/CISA/FBI/NSA 2022 року описано модульне malware Sandworm Cyclops Blink на пристроях WatchGuard, розгорнуте постійно як firmware update і здатне додавати модулі. Окремо DOJ описала ранній APT28 botnet VPNFilter із маршрутизаторів і NAS-пристроїв, здатний до збору розвідувальних даних, destructive activity та misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Вплив на приватність.** Edge appliances постійно перебувають онлайн, вважаються довіреною інфраструктурою та погано покриваються EDR. Firmware persistence може пережити звичайний restart і перетворити пристрій жертви на relay або control point.

**Що викриває атаку.** Цілісність firmware, vendor-specific implant protocol, неочікувана доступність керування, зміни конфігурації та outbound beaconing. Edge-пристрої мають бути forensic subjects, а не прозорою інфраструктурою.

## КНДР: нашарування ідентичності, мережі та фінансів

**Публічні висновки.** У справах DOJ описано, як працівники КНДР отримували віддалені роботи, використовуючи фальшиві або викрадені identity material і VPN, отримували cryptocurrency, розділяли перекази, обмінювали активи/мережі, використовували NFT та commingling proceeds. В інших справах описано OTC traders і front companies, які конвертували викрадену crypto у покупки. Treasury та FBI публічно пов'язали доходи Lazarus/TraderTraitor із mixers і визначили адреси, пов'язані з масштабними крадіжками.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Вплив на приватність.** Це не «private coin». Це multi-domain chain: persona та remote access приховують місцезнаходження працівника; crypto переміщує вартість; layering руйнує прості наративи транзакцій; OTC traders/front companies забезпечують міст до товарів і fiat.

**Що викриває атаку.** Аномалії роботодавця/пристрою, повторно використані facilitators, безперервність часу/вартості в blockchain, записи exchange/bridge, sanctioned addresses, ідентичність облікового запису та записи про відправлення/компанію повторно з'єднують ланцюг.

**Захисний висновок.** Командам hiring, IAM, endpoint, payroll, blockchain і sanctions потрібна спільна модель справи. Докладніше див. у [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Міжінцидентні закономірності

| Закономірність | Приклади APT | Адаптація захисника |
|---|---|---|
| Exit є іншою жертвою | APT28/Moobot, Volt Typhoon/KV, ORBs | досліджуйте та усувайте проблему exit; не ототожнюйте його з місцезнаходженням актора |
| Засоби контролю відрізняються залежно від межі | APT28 nearest neighbor | надайте внутрішньому/бездротовому доступу такий самий рівень identity assurance, як і доступу з Internet |
| Легітимний service є routing layer | APT29, APT41 | зберігайте контекст object/path/process, а не лише destination domain |
| Edge-пристроям бракує telemetry | KV, Moobot, Cyclops Blink, ORBs | централізуйте логи config/auth/flow і перевіряйте firmware/inventory |
| Інфраструктура спільна та короткоживуча | China-nexus ORBs | кластеризуйте поведінку/топологію та відстежуйте зміни ролей у часі |
| Кілька слабких розділень утворюють ланцюг | DPRK personas + VPN + crypto + OTC | об'єднуйте докази ідентичності, пристрою, мережі, платежів і фізичного середовища |

## References

- [1] [Volexity — Атака Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Припинення роботи router botnet Moobot, контрольованого GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Припинення роботи PRC KV Botnet](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Актори КНР скомпрометували та підтримували постійний доступ до критичної інфраструктури США](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Шпигунські актори, пов'язані з Китаєм, використовують ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Advisory Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Припинення роботи APT28 VPNFilter](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Представнику Foreign Trade Bank КНДР висунуто обвинувачення у змовах із відмивання crypto](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Санкції проти Blender.io та кошти Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Протидія компрометації мереж у всьому світі акторами, спонсорованими Китаєм](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 атакує маршрутизатори Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
