# Конфіденційність мережі та Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Конфіденційність мережі — це рішення щодо маршрутизації, а не повна ідентичність. Обирайте шлях, відповідаючи на питання, хто не повинен мати змоги пов’язати **джерело**, **призначення**, **вміст** і **часові характеристики**.

Для нормалізованого переліку — `Pros`, `Cons`, покрокової `Procedure` і `Detection` для кожного сімейства шляхів доступу — почніть з [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). На цій сторінці розглянуто поширені варіанти, придатні для розгортання.

## Що зазвичай може бачити кожен спостерігач

| Шлях | Локальна мережа / ISP | Посередник | Призначення | Основне обмеження | Відносна швидкість |
|---|---|---|---|---|---|
| Direct HTTPS | Метадані джерела, призначення, часові характеристики та обсяг | Hosting/CDN бачить з’єднання | Source IP, дані браузера/застосунку | Немає приватності Source IP | Найшвидший |
| Commercial VPN | Джерело, підключене до VPN; звичайні метадані призначення не видно | VPN бачить метадані джерела та призначення | VPN egress IP | Один провайдер стає точкою кореляції | Зазвичай швидкий |
| Self-hosted VPN/VPS | Джерело, підключене до VPS | Логи хоста/акаунта/платіжної системи/control plane | VPS egress IP | Легко пов’язати з орендованим сервером/акаунтом | Зазвичай швидкий |
| Tor Browser | Джерело, підключене до Tor/bridge; часові характеристики/обсяг | Кожен relay бачить лише обмежену частину | Tor exit, дані браузера | Повільніший; ризики акаунта/endpoint/кореляції | Середня/низька |
| Tails/Whonix | Подібний Tor-шлях із сильнішими межами маршрутизації | Ті самі обмеження Tor | Tor exit/дані застосунку | Операційні помилки, host і hardware залишаються | Середня/низька |
| Public guest Wi-Fi + HTTPS | Заклад бачить локальний пристрій/часові характеристики та призначення | ISP закладу бачить метадані | Guest public IP | Фізична кореляція, captive portal і пристрій | Висока/змінна |
| Cellular hotspot | Carrier бачить subscriber/device/location і призначення | VPN/Tor, якщо використовується | Carrier, VPN або Tor egress IP | Мобільна підписка та location є довготривалими ідентифікаторами | Висока/змінна |
| Mixnet | Access бачить використання mixnet; часові характеристики/обсяг | Кілька mixing nodes | Gateway/egress | Екосистема розвивається; витрати latency і bandwidth | Найнижча |

HTTPS захищає вміст під час передавання, але не всі метадані. EFF зазначає, що domain, час і розмір traffic можуть залишатися видимими для посередників, навіть коли шляхи сторінок, облікові дані та повідомлення зашифровані.<sup>[[1]](#references)</sup>

## VPN: швидка приватність із концентрованою довірою

VPN корисний для приховування метаданих призначення від access ISP, захисту першого переходу в ненадійній мережі, використання стабільної engagement egress-адреси або доступу до приватної мережі. Він **не** робить користувача anonymous. VPN бачить source connection і може спостерігати метадані destination; акаунти, cookies, GPS, fingerprints і платіжна інформація залишаються.<sup>[[1]](#references)</sup>

### Чекліст оцінювання провайдера

1. **Ownership and jurisdiction:** визначте юридичну особу, материнську компанію, країни роботи, субпідрядників інфраструктури та застосовні юридичні процедури.
2. **Collected data:** розрізняйте account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries і destination logs. “No browsing logs” не означає “no data”.
3. **Retention and deletion:** знайдіть точні строки та з’ясуйте, чи дотримуються такого самого графіка резервні копії, fraud systems і processors.
4. **Evidence:** надавайте перевагу публічним аудитам із зазначеними scope, date, findings і remediation; відтворюваним/open clients; transparency reports і задокументованим інцидентам.
5. **Protocol and client:** підтримуваний WireGuard, OpenVPN або інший перевірений протокол; automatic updates; DNS та IPv6 handling; kill switch і per-platform leak tests.
6. **Business model:** зрозумійте, як фінансується безкоштовний або субсидований сервіс. Сама наявність у app store не є доказом надійної роботи.
7. **Payment fit:** альтернативний спосіб оплати може зменшити розкриття billing-даних VPN-провайдеру, але не стирає source IP, який спостерігається під час кожного з’єднання.

### Налаштування та перевірка VPN

1. Встановіть підписаний клієнт провайдера/організації з офіційного джерела.
2. Оберіть **full tunnel**, якщо немає документованого маршруту, який має обходити його. Split tunneling створює шляхи кореляції та leak.
3. Увімкніть fail-closed/always-on і блокування traffic під час повторного підключення.
4. Передавайте DNS через tunnel і перевірте IPv4 та IPv6. Вимикайте протокол лише тоді, коли його неможливо безпечно тунелювати та прийнято втрату функціональності.
5. Перевірте sleep/wake, перемикання мереж, captive-portal login, tunnel crash і hotspot tethering. NCSC попереджає, що tethered clients на деяких платформах можуть обходити VPN телефона.<sup>[[2]](#references)</sup>
6. Використовуйте контрольований організацією test endpoint для запису observed IPv4, IPv6, DNS resolver і connection timing. Не піддавайте чутливе engagement випадковим сайтам для “leak test”.
7. Повторюйте тестування після змін клієнта, OS, мережі або policy.

## Tor Browser: сильніша unlinkability у web

Tor створює circuit через кілька relay, тому жоден окремий relay зазвичай не знає одночасно source і destination. Destination бачить Tor exit, а не IP користувача; локальна мережа зазвичай бачить Tor connection.<sup>[[3]](#references)</sup> Tor призначений для TCP-застосунків із низькою latency, тому він повільніший і не може гарантувати захист від adversary, здатного корелювати обидва кінці.<sup>[[4]](#references)</sup>

### Безпечний workflow Tor Browser

1. Завантажуйте Tor Browser лише з Tor Project або офіційного mirror і, коли можливо, перевіряйте signature.
2. Використовуйте **Tor Browser**, а не звичайний браузер, спрямований на Tor SOCKS port. Звичайні браузери можуть створювати DNS/WebRTC leak і розкривати identifying state.<sup>[[5]](#references)</sup>
3. Зберігайте стандартні розмір, шрифти, extensions і privacy settings. Додаткові add-ons можуть зробити браузер більш унікальним.<sup>[[6]](#references)</sup>
4. Обирайте рівень безпеки **Safer** або **Safest**, якщо прийнятніші обмеження функціональності.
5. Використовуйте bridge, коли direct Tor заблокований або звичайні relay IP створюють неприйнятну локальну видимість. Bridges зменшують легкість розпізнавання, але не усувають traffic analysis.<sup>[[7]](#references)</sup>
6. Не входьте в identifying account, не надавайте identifying information і не відкривайте завантажені active documents у зовнішньому networked application.
7. Використовуйте окремі session/context для кожної identity. “New circuit” — це не те саме, що стирання browser/application identity; використовуйте **New Identity** або перезапускайте isolated environment відповідно до ситуації.
8. Надавайте перевагу authenticated HTTPS або authenticated onion service. Tor exit може спостерігати незашифрований HTTP traffic.

### Tor разом із VPN

Їхнє поєднання не є автоматично безпечнішим. VPN перед Tor може приховати direct Tor relay connections від ISP, тоді як VPN бачить source; Tor перед VPN надає VPN стабільне уявлення про post-Tor activity і може зменшити anonymity set. Неправильна конфігурація може створити leak. Tor Project рекомендує такі комбінації лише для advanced, explicit threat models.<sup>[[8]](#references)</sup>

## Публічний і гостьовий Wi-Fi

Сучасний HTTPS означає, що пасивні сусіди зазвичай не можуть читати належно зашифрований web content, але guest Wi-Fi не забезпечує anonymity. Заклад може записувати час підключення, device identifiers, captive-portal data, destinations і DHCP details; камери, покупки, транспорт і фізичне спостереження можуть ідентифікувати користувача. Фальшива точка доступу зі схожою назвою також може викрасти portal credentials або змінити незашифрований traffic.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Використовуйте лише мережу, запропоновану для гостей, або мережу, на використання якої власник надав явний дозвіл. Попросіть персонал назвати точний SSID і процедуру portal.
2. Оновіть endpoint і travel router до прибуття. Вимкніть file/printer sharing, inbound discovery, auto-join і probing збережених мереж.
3. Увімкніть private/randomized Wi-Fi address в OS. Сучасні системи Apple можуть використовувати rotating addresses у відкритих/слабко захищених мережах; сучасна рандомізація Android зазвичай є постійною для кожного SSID. Це зменшує лише один локальний ідентифікатор.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Надавайте перевагу organization-controlled travel router або low-trust bridge device між privileged workstation і guest network. Це централізує firewall/VPN policy, але не приховує router від закладу.<sup>[[12]](#references)</sup>
5. Проходьте captive portal лише через визначений low-trust device/browser. Ніколи не вводьте особисті або повторно використовувані credentials для начебто anonymous context. Закрийте portal browser після встановлення з’єднання.
6. Запустіть full-tunnel VPN або Tor до sensitive activity і підтвердьте fail-closed behavior.
7. Видаліть мережу після використання та перегляньте policy щодо portal account/data retention.

{% hint style="danger" %}
Злам Wi-Fi сусіда, обхід portal, використання leaked guest credentials, клонування доступу іншого гостя або приховування Raspberry Pi в кафе — це unauthorized activity, а не privacy technique. Безпечні еквіваленти — lawful guest network, схвалений клієнтом site або documented drop node, розміщений і вилучений за письмовою згодою власника майна.
{% endhint %}

## Travel routers

Travel router може ізолювати workstation від hostile local broadcasts, застосовувати firewall, надавати стабільний internal SSID і автоматично відновлювати VPN connection. Він **не** є anonymous: upstream бачить його radio identity та traffic timing, а VPN provider бачить tunnel source.

- Використовуйте підтримувану OpenWrt/vendor firmware і видаліть невикористовувані services.
- Адмініструйте через Ethernet або окремий management SSID з унікальним password.
- Вимкніть WAN-side administration, UPnP, WPS, file sharing і unsolicited inbound traffic.
- Використовуйте randomized/private WAN MAC лише там, де це підтримується і дозволено.
- Застосовуйте VPN policy на router, включно з DNS та IPv6, і блокуйте egress у разі відмови tunnel.
- Не припускайте, що phone hotspot тунелює tethered devices через VPN телефона; перевірте це.

## Cellular, SIM та eSIM

Cellular зручний, але не anonymous. Оператори зберігають subscriber/device identifiers і location, визначене за network attachment; eSIM усе одно є mobile subscription. Prepaid не означає надійно unregistered — вимоги різняться за країнами та змінюються.<sup>[[13]](#references)</sup>

Операційно:

- Використовуйте окремий підтримуваний device, щоб зменшити exposure особистих даних, а не для створення вигаданого subscriber.
- Не носіть “окремий” device постійно разом з особистим телефоном, якщо co-location входить до threat model.
- Вимкніть невикористовувані cellular, Wi-Fi, Bluetooth і location access; вимкнення живлення створює сильнішу radio boundary, ніж UI toggles.
- Передавайте sensitive traffic через approved VPN/Tor path, усвідомлюючи, що carrier усе одно знає subscription/device location і tunnel endpoint.
- Перевіряйте актуальні правила registration і retention у national regulator або local counsel; не покладайтеся на online lists “anonymous SIM countries”.

## DNS і TLS metadata

- **DoH/DoT/DoQ** шифрують DNS між client і resolver, запобігаючи простому локальному читанню або зміні, але resolver усе одно бачить queries і transport identifiers. Вони переміщують trust, але не забезпечують anonymity.<sup>[[14]](#references)</sup>
- **ODoH** додає proxy, щоб resolver не мусив знати client IP, за умови, що proxy і target не collude. Traffic analysis прямо не входить до scope.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** може захистити inner server name у TLS handshake, коли client, DNS і server це підтримують. Destination IP, timing, volume та endpoint залишаються видимими.<sup>[[16]](#references)</sup>
- У правильно налаштованому VPN або Tor environment DNS має проходити через підтримуваний route цього environment. Додавання окремого resolver може створити нового observer або fingerprint.

### Workflow перевірки Encrypted-DNS/ECH

1. Визначте, який компонент контролює DNS: VPN/Tor environment, OS або application. Налаштуйте його на **одному** призначеному layer замість комбінування непов’язаних resolver.
2. Оберіть resolver відповідно до його опублікованої privacy/retention policy і ввімкніть strict encrypted mode, якщо платформа це підтримує. Opportunistic fallback може непомітно повернутися до plaintext.
3. Виконайте запит до унікального subdomain у authoritative test zone, якою ви керуєте; підтвердьте, що authoritative log бачить призначений recursive resolver.
4. З дозволу capture лише traffic тестового device. Підтвердьте, що access network не може читати plaintext DNS, усвідомлюючи, що вона бачить encrypted resolver/tunnel endpoint.
5. Перевірте заблокований/недоступний encrypted resolver. Умовою успіху є обрана fail-closed або documented fallback behavior, а не випадковий clear query.
6. Для ECH використовуйте контрольований ECH-enabled host і перевірте client/server diagnostics, щоб підтвердити прийняття **inner** ClientHello. Саме лише надання HTTPS record не доводить успішність ECH.
7. Повторюйте після змін мережі, captive portal, browser updates і VPN reconnects. Записуйте, який компонент володіє DNS/ECH, щоб наступні адміністратори не створили bypass.

## Mixnets

Mixnets, такі як Nym або Katzenpost, додають fixed-size packets, delay, reordering і cover traffic для протидії timing correlation. Ці властивості коштують latency та bandwidth, а незалежні докази масштабного deployment обмежені. Розглядайте поточні consumer mixnets як **emerging/high-latency options**, а не як швидші або гарантовані заміни Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow оцінювання

1. Визначте maintained client і точний supported application; не спрямовуйте довільний browser/system traffic через undocumented proxy.
2. Ознайомтеся з актуальним threat model для entry, mix nodes, gateway, destination та collusion assumptions.
3. Встановіть software з official signed source в окремому test compartment і використовуйте лише benign owned endpoint.
4. Виміряйте delivery latency, message-size limits, reliability, retransmission і поведінку за недоступності gateway.
5. Перевірте local traffic і owned endpoint, щоб підтвердити intended path та source. Перевірте, чи використовують replies такий самий privacy design.
6. Перевірте shutdown/failure: application не має непомітно переходити до direct Internet access.
7. Не вимикайте cover traffic, не зменшуйте delays і не обирайте unusual fixed routes лише заради швидкості; такі зміни можуть зробити заявлену anonymity model недійсною.
8. Залишайте це experimental, доки конкретний deployment, незалежний analysis та operational reliability не відповідатимуть рівню наслідків.

## Network preflight checklist

- [ ] Authorization охоплює access network, target, dates і source infrastructure.
- [ ] Endpoint не містить unrelated identities або активних sync sessions.
- [ ] IPv4, IPv6, DNS і reconnect behavior відповідають плану.
- [ ] Destination бачить лише очікуваний egress.
- [ ] Captive portal і hotspot behavior протестовано без sensitive traffic.
- [ ] Local sharing/discovery та automatic network joining вимкнено.
- [ ] Observer table і residual traffic-correlation risk прийнято.
- [ ] Provider policy, retention та emergency contact актуальні.

Для split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P і disposable remote browsers перейдіть до [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Вибір VPN, який вам підходить](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Рекомендації щодо безпеки пристроїв: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Захист конфіденційності та anonymity, який забезпечує Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Короткий вступ до Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Використання Tor з іншими браузерами](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins і add-ons у Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Розблокування Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Використання Tor Browser із VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Чи безпечні публічні Wi-Fi Networks?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy із пристроями Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Реалізація MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Принципи безпечних Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Обов’язкова SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Рекомендації для операторів DNS Privacy Service](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
