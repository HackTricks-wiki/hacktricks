# Конфіденційність мережі та Anonymous Connectivity

Конфіденційність мережі — це рішення щодо маршрутизації, а не повна ідентичність. Обирайте шлях, визначаючи, хто не повинен мати змоги поєднати **джерело**, **призначення**, **вміст** і **часові характеристики**.

Для нормалізованого опису — `Pros`, `Cons`, покрокової `Procedure` та `Detection` для кожного сімейства шляхів доступу — почніть із [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). На цій сторінці розглянуто поширені варіанти, придатні для розгортання.

## Що зазвичай може бачити кожен спостерігач

| Шлях | Локальна мережа / ISP | Посередник | Призначення | Основне обмеження | Відносна швидкість |
|---|---|---|---|---|---|
| Direct HTTPS | Джерело, метадані призначення, час і обсяг | Hosting/CDN бачить з'єднання | Source IP, дані browser/app | Немає конфіденційності source IP | Найвища |
| Commercial VPN | Джерело, підключене до VPN; метадані звичайного призначення не видно | VPN бачить метадані джерела та призначення | VPN egress IP | Один провайдер стає точкою кореляції | Зазвичай висока |
| Self-hosted VPN/VPS | Джерело, підключене до VPS | Логи хоста/облікового запису/платіжної та керівної площини | VPS egress IP | Легко пов'язати з орендованим сервером/обліковим записом | Зазвичай висока |
| Tor Browser | Джерело, підключене до Tor/bridge; час і обсяг | Кожен relay бачить обмежену частину | Tor exit, дані browser | Повільніше; ризики облікового запису/кінцевої точки/кореляції | Середня/низька |
| Tails/Whonix | Подібний шлях Tor із сильнішими межами маршрутизації | Ті самі обмеження Tor | Tor exit/дані application | Операційні помилки, host і hardware все ще залишаються | Середня/низька |
| Public guest Wi-Fi + HTTPS | Місце проведення бачить локальний пристрій/час і призначення | ISP місця проведення бачить метадані | Guest public IP | Кореляція фізичного місця/порталу/device | Висока/змінна |
| Cellular hotspot | Carrier бачить абонента/device/location і призначення | VPN/Tor, якщо використовується | Carrier, VPN або Tor egress IP | Мобільна підписка та location є стійкими ідентифікаторами | Висока/змінна |
| Mixnet | Access бачить використання mixnet, час і обсяг | Кілька mixing nodes | Gateway/egress | Екосистема розвивається; витрати на latency і bandwidth | Найнижча |

HTTPS захищає вміст під час передавання, але не всі метадані. EFF зазначає, що домен, час і розмір трафіку можуть залишатися видимими для посередників, навіть коли шляхи сторінок, облікові дані та повідомлення зашифровані.<sup>[[1]](#references)</sup>

## VPN: швидка конфіденційність із концентрованою довірою

VPN корисний для приховування метаданих призначення від access ISP, захисту першого переходу в ненадійній мережі, представлення стабільної engagement egress address або доступу до приватної мережі. Він **не** робить користувача anonymous. VPN бачить source connection і може спостерігати метадані призначення; облікові записи, cookies, GPS, fingerprints і платіжна інформація залишаються.<sup>[[1]](#references)</sup>

### Контрольний список оцінювання провайдера

1. **Власність і юрисдикція:** визначте юридичну особу, материнську компанію, країни роботи, субпідрядників інфраструктури та застосовний юридичний процес.
2. **Зібрані дані:** розрізняйте account/billing, source IP, timestamps з'єднань, bandwidth, crash telemetry, DNS queries і destination logs. «No browsing logs» не означає «no data».
3. **Зберігання та видалення:** знайдіть точні строки й перевірте, чи дотримуються такого самого графіка backups, fraud systems і processors.
4. **Докази:** надавайте перевагу публічним аудитам із зазначеними scope, date, findings і remediation; відтворюваним/open clients; transparency reports і задокументованим інцидентам.
5. **Protocol і client:** підтримувані WireGuard, OpenVPN або інший перевірений protocol; automatic updates; DNS та IPv6 handling; kill switch і per-platform leak tests.
6. **Бізнес-модель:** зрозумійте, як фінансується безкоштовний або субсидований service. Наявність в app store сама по собі не є доказом надійної роботи.
7. **Відповідність платежів:** альтернативний платіж може зменшити розкриття billing даних VPN, але не стирає source IP, який спостерігається під час кожного з'єднання.

### Налаштування та перевірка VPN

1. Встановіть підписаний client провайдера/організації з його офіційного джерела.
2. Оберіть **full tunnel**, якщо немає задокументованого маршруту, який має обходити його. Split tunneling створює шляхи кореляції та leak.
3. Увімкніть fail-closed/always-on поведінку та блокування трафіку під час повторного підключення.
4. Передавайте DNS через tunnel і перевірте IPv4 та IPv6. Вимикайте protocol лише тоді, коли його неможливо безпечно тунелювати й прийнято втрату функціональності.
5. Перевірте sleep/wake, перемикання мереж, captive-portal login, tunnel crash і hotspot tethering. NCSC попереджає, що tethered clients на деяких платформах можуть обходити VPN телефона.<sup>[[2]](#references)</sup>
6. Використовуйте контрольовану організацією test endpoint для фіксації спостережуваних IPv4, IPv6, DNS resolver і часу з'єднання. Не піддавайте чутливу engagement впливу випадкових сайтів «leak test».
7. Повторюйте тестування після змін client, OS, network або policy.

## Tor Browser: сильніша web unlinkability

Tor будує circuit через кілька relays, тому жоден окремий relay зазвичай не знає одночасно source і destination. Destination бачить Tor exit, а не IP користувача; локальна мережа зазвичай бачить Tor connection.<sup>[[3]](#references)</sup> Tor розроблений для TCP applications із низькою latency, тому він повільніший і не може гарантувати захист від adversary, здатного корелювати обидва кінці.<sup>[[4]](#references)</sup>

### Безпечний workflow Tor Browser

1. Завантажуйте Tor Browser лише з Tor Project або official mirror і, коли можливо, перевіряйте signature.
2. Використовуйте **Tor Browser**, а не звичайний browser, спрямований на Tor SOCKS port. Звичайні browsers можуть спричинити DNS/WebRTC leak і витік ідентифікаційного state.<sup>[[5]](#references)</sup>
3. Зберігайте default size, fonts, extensions і privacy settings. Додаткові add-ons можуть зробити browser більш унікальним.<sup>[[6]](#references)</sup>
4. Обирайте рівень безпеки **Safer** або **Safest**, коли прийнятні пов'язані з цим обмеження.
5. Використовуйте bridge, коли прямий Tor заблокований або звичайні relay IP створюють неприйнятну локальну видимість. Bridges ускладнюють просте розпізнавання, але не усувають traffic analysis.<sup>[[7]](#references)</sup>
6. Не входьте до identifying account, не надавайте identifying information і не відкривайте завантажені активні документи у зовнішньому networked application.
7. Використовуйте окремі session/context для кожної identity. «New circuit» — не те саме, що стирання browser/application identity; за потреби використовуйте **New Identity** або перезапускайте ізольоване середовище.
8. Надавайте перевагу authenticated HTTPS або authenticated onion service. Tor exit може спостерігати незашифрований HTTP traffic.

### Tor разом із VPN

Їх поєднання не є автоматично безпечнішим. VPN перед Tor може приховати прямі підключення до Tor relays від ISP, але VPN бачитиме source; Tor перед VPN надає VPN стабільний view post-Tor activity і може зменшити anonymity set. Неправильна конфігурація може спричинити leak. Tor Project рекомендує такі комбінації лише для advanced, explicit threat models.<sup>[[8]](#references)</sup>

## Public і guest Wi-Fi

Сучасний HTTPS означає, що пасивні сусіди зазвичай не можуть прочитати належно зашифрований web content, але guest Wi-Fi не забезпечує anonymity. Місце проведення може записувати час association, device identifiers, дані captive portal, destinations і DHCP details; камери, покупки, транспорт і фізичне спостереження можуть ідентифікувати користувача. Фальшива hotspot із подібною назвою також може перехоплювати portal credentials або змінювати незашифрований traffic.<sup>[[9]](#references)</sup>

### Законний workflow guest network

1. Використовуйте лише мережу, запропоновану для гостей, або мережу, на використання якої власник надав явний дозвіл. Запитайте персонал про точний SSID і процедуру portal.
2. Оновіть endpoint і travel router до прибуття. Вимкніть file/printer sharing, inbound discovery, auto-join і probing збережених мереж.
3. Увімкніть private/randomized Wi-Fi address ОС. Сучасні системи Apple можуть використовувати rotating addresses у відкритих/слабко захищених мережах; сучасна рандомізація Android зазвичай є постійною для кожного SSID. Це зменшує лише один локальний ідентифікатор.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Надавайте перевагу travel router, контрольованому організацією, або low-trust bridge device між privileged workstation і guest network. Це централізує firewall/VPN policy, але не приховує router від місця проведення.<sup>[[12]](#references)</sup>
5. Завершуйте captive portal лише через визначений low-trust device/browser. Ніколи не вводьте personal або reused credentials для нібито anonymous context. Після встановлення connectivity закрийте portal browser.
6. Запустіть full-tunnel VPN або Tor до чутливої активності та підтвердьте fail-closed behavior.
7. Після використання забудьте мережу й перегляньте policy облікового запису portal та зберігання даних.

{% hint style="danger" %}
Злам Wi-Fi сусіда, обхід portal, використання leaked guest credentials, клонування доступу іншого гостя або приховування Raspberry Pi в кафе — це несанкціонована активність, а не privacy technique. Безпечними еквівалентами є законна guest network, site із дозволом client або задокументований drop node, розміщений і вилучений за письмовою згодою власника property.
{% endhint %}

## Travel routers

Travel router може ізолювати workstation від hostile local broadcasts, застосовувати firewall, надавати узгоджений internal SSID і автоматично повторно підключати VPN. Він **не** є anonymous: upstream бачить його radio identity і час traffic, а VPN provider бачить source tunnel.

- Використовуйте підтримувані OpenWrt/vendor firmware і видаліть невикористовувані services.
- Адмініструйте через Ethernet або окремий management SSID з унікальним password.
- Вимкніть WAN-side administration, UPnP, WPS, file sharing і unsolicited inbound traffic.
- Використовуйте randomized/private WAN MAC лише за підтримки та дозволу.
- Застосовуйте VPN policy на router, включно з DNS та IPv6, і блокуйте egress у разі відмови tunnel.
- Не припускайте, що phone hotspot проводить tethered devices через VPN телефона; перевіряйте це.

## Cellular, SIM і eSIM

Cellular зручний, але не anonymous. Operators зберігають subscriber/device identifiers і location, отриману з network attachment; eSIM усе одно є mobile subscription. Prepaid не обов'язково означає незареєстрований — вимоги залежать від країни й змінюються.<sup>[[13]](#references)</sup>

Операційно:

- Використовуйте окремий підтримуваний device для зменшення розкриття personal data, а не для створення вигаданого subscriber.
- Не носіть «окремий» device постійно разом із personal phone, якщо co-location входить до threat model.
- Вимкніть невикористовувані cellular, Wi-Fi, Bluetooth і location access; вимкнення живлення створює сильнішу radio boundary, ніж перемикачі UI.
- Передавайте sensitive traffic через approved VPN/Tor path, визнаючи, що carrier все одно знає subscription/device location і tunnel endpoint.
- Перевіряйте актуальні правила registration і retention у national regulator або local counsel; не покладайтеся на онлайн-списки «anonymous SIM countries».

## DNS і TLS metadata

- **DoH/DoT/DoQ** шифрують DNS між client і resolver, запобігаючи простому локальному читанню або зміні, але resolver усе одно бачить queries і transport identifiers. Вони переміщують trust, але не забезпечують anonymity.<sup>[[14]](#references)</sup>
- **ODoH** додає proxy, щоб resolver не мав потреби дізнаватися client IP, за умови що proxy і target не collude. Traffic analysis прямо не входить до scope.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** може захищати внутрішнє server name у TLS handshake, коли client, DNS і server це підтримують. Destination IP, timing, volume і endpoint залишаються видимими.<sup>[[16]](#references)</sup>
- У правильно налаштованому VPN або Tor environment DNS має йти через підтримуваний route цього environment. Додавання окремого resolver може створити нового observer або fingerprint.

### Workflow перевірки Encrypted-DNS/ECH

1. Визначте, що контролює DNS: VPN/Tor environment, OS або application. Налаштуйте його на **одному** призначеному layer замість поєднання непов'язаних resolvers.
2. Оберіть resolver за його опублікованою privacy/retention policy та ввімкніть strict encrypted mode, якщо platform це підтримує. Opportunistic fallback може непомітно повернутися до plaintext.
3. Виконайте query до унікального subdomain у authoritative test zone, якою ви керуєте; підтвердьте, що authoritative log бачить призначений recursive resolver.
4. Авторизовано capture лише traffic тестового device. Підтвердьте, що access network не може прочитати plaintext DNS, визнаючи, що вона бачить encrypted resolver/tunnel endpoint.
5. Перевірте заблокований/недоступний encrypted resolver. Умова успіху — обрана fail-closed або задокументована fallback behavior, а не випадковий clear query.
6. Для ECH використовуйте контрольований ECH-enabled host і перегляньте client/server diagnostics, щоб підтвердити прийняття **inner** ClientHello. Просте надання HTTPS record не доводить, що ECH спрацював.
7. Повторюйте після змін network, captive portal, browser updates і VPN reconnects. Зафіксуйте, який component відповідає за DNS/ECH, щоб наступні administrators не створили bypass.

## Mixnets

Mixnets, такі як Nym або Katzenpost, додають fixed-size packets, delay, reordering і cover traffic для протидії timing correlation. Ці властивості коштують latency і bandwidth, а незалежні докази масштабного deployment обмежені. Розглядайте поточні consumer mixnets як **emerging/high-latency options**, а не як швидші або гарантовані заміни Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow оцінювання

1. Визначте maintained client і точну supported application; не спрямовуйте довільний browser/system traffic через undocumented proxy.
2. Прочитайте актуальну threat model щодо entry, mix nodes, gateway, destination і припущень про collusion.
3. Встановіть software з official signed source в окремому test compartment і використовуйте лише benign owned endpoint.
4. Виміряйте delivery latency, message-size limits, reliability, retransmission і поведінку за недоступності gateway.
5. Перевірте local traffic і owned endpoint, щоб підтвердити intended path і source. Переконайтеся, чи використовують replies той самий privacy design.
6. Перевірте shutdown/failure: application не повинна непомітно переходити до direct Internet access.
7. Не вимикайте cover traffic, не зменшуйте delays і не обирайте незвичайні fixed routes лише заради speed; ці зміни можуть скасувати заявлену anonymity model.
8. Залишайте рішення експериментальним, доки конкретний deployment, independent analysis і operational reliability не відповідатимуть рівню наслідків.

## Network preflight checklist

- [ ] Authorization охоплює access network, target, dates і source infrastructure.
- [ ] Endpoint не містить сторонніх identities або активних sync sessions.
- [ ] IPv4, IPv6, DNS і reconnect behavior відповідають plan.
- [ ] Destination бачить лише очікуваний egress.
- [ ] Captive portal і hotspot behavior протестовані без sensitive traffic.
- [ ] Local sharing/discovery та automatic network joining вимкнені.
- [ ] Observer table і залишковий ризик traffic-correlation прийняті.
- [ ] Provider policy, retention і emergency contact актуальні.

Для split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P і disposable remote browsers перейдіть до [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Вибір VPN, який підходить саме вам](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Рекомендації з безпеки пристроїв: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Захист конфіденційності та anonymity, який забезпечує Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Короткий вступ до Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Використання Tor з іншими browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins і add-ons у Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Розблокування Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Використання Tor Browser із VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Чи безпечні Public Wi-Fi Networks?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Конфіденційність Wi-Fi на пристроях Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Реалізація MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Принципи безпечних Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Обов'язкова SIM registration: policy і regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Рекомендації для DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
