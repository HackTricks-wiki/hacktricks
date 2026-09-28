# Мережева конфіденційність і Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Мережева конфіденційність — це рішення щодо маршрутизації, а не повна ідентичність. Обирайте шлях, визначаючи, хто не повинен мати змоги пов’язати **джерело**, **призначення**, **вміст** і **часові характеристики**.

Для стандартизованого переліку — `Pros`, `Cons`, покрокової `Procedure` і `Detection` для кожного сімейства шляхів доступу — почніть з [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). На цій сторінці розглянуто поширені варіанти, доступні для розгортання.

## Що зазвичай може бачити кожен спостерігач

| Шлях | Локальна мережа / ISP | Посередник | Призначення | Основне обмеження | Відносна швидкість |
|---|---|---|---|---|---|
| Direct HTTPS | Метадані джерела, призначення, час і обсяг | Hosting/CDN бачить з’єднання | Source IP, дані браузера/застосунку | Відсутність конфіденційності source IP | Найвища |
| Commercial VPN | Джерело, підключене до VPN; звичайні метадані призначення не видно | VPN бачить метадані джерела та призначення | VPN egress IP | Один провайдер стає точкою кореляції | Зазвичай висока |
| Self-hosted VPN/VPS | Джерело, підключене до VPS | Логи хоста, облікового запису, платежів і control plane | VPS egress IP | Легко пов’язати з орендованим сервером/обліковим записом | Зазвичай висока |
| Tor Browser | Джерело, підключене до Tor/bridge; час і обсяг | Кожен relay бачить лише обмежену частину | Tor exit, дані браузера | Нижча швидкість; ризики облікових записів, кінцевих точок і кореляції | Середня/низька |
| Tails/Whonix | Подібний Tor-шлях із сильнішими межами маршрутизації | Ті самі обмеження Tor | Tor exit/дані застосунку | Операційні помилки, а також хост і обладнання залишаються чинниками | Середня/низька |
| Public guest Wi-Fi + HTTPS | Заклад бачить локальний пристрій, час і призначення | ISP закладу бачить метадані | Публічний IP гостя | Кореляція за фізичним місцем, captive portal і пристроєм | Висока/змінна |
| Cellular hotspot | Оператор бачить абонента, пристрій, місцезнаходження та призначення | VPN/Tor, якщо використовується | Carrier, VPN або Tor egress IP | Мобільна підписка та місцезнаходження є сталими ідентифікаторами | Висока/змінна |
| Mixnet | Точка доступу бачить використання mixnet, час і обсяг | Кілька mixing nodes | Gateway/egress | Екосистема розвивається; витрати на затримку та пропускну здатність | Найнижча |

HTTPS захищає вміст під час передавання, але не всі метадані. EFF зазначає, що домен, час і розмір трафіку можуть залишатися видимими для посередників, навіть коли шляхи сторінок, облікові дані та повідомлення зашифровані.<sup>[[1]](#references)</sup>

## VPN: швидка конфіденційність із концентрованою довірою

VPN корисний для приховування метаданих призначення від ISP доступу, захисту першого переходу в ненадійній мережі, надання стабільної egress-адреси для engagement або доступу до приватної мережі. Він **не** робить користувача anonymous. VPN бачить вихідне з’єднання та може спостерігати метадані призначення; облікові записи, cookies, GPS, fingerprint і платіжна інформація залишаються.<sup>[[1]](#references)</sup>

### Контрольний список оцінювання провайдера

1. **Власність і юрисдикція:** визначте юридичну особу, материнську компанію, країни роботи, субпідрядників інфраструктури та застосовні юридичні процедури.
2. **Зібрані дані:** розрізняйте дані облікового запису/платежів, source IP, часові позначки з’єднань, пропускну здатність, crash telemetry, DNS-запити та логи призначень. «No browsing logs» не означає «no data».
3. **Зберігання та видалення:** знайдіть точні строки й перевірте, чи дотримуються такого самого розкладу резервні копії, системи захисту від шахрайства та processors.
4. **Докази:** надавайте перевагу публічним аудитам із зазначеними сферою охоплення, датою, результатами та виправленнями; відтворюваним/open-клієнтам; звітам про прозорість і задокументованим інцидентам.
5. **Протокол і клієнт:** підтримуваний WireGuard, OpenVPN або інший перевірений протокол; automatic updates; обробка DNS та IPv6; kill switch; а також per-platform leak tests.
6. **Бізнес-модель:** зрозумійте, як фінансується безкоштовний або субсидований сервіс. Сама наявність у app store не є доказом надійної роботи.
7. **Відповідність способу оплати:** альтернативний спосіб оплати може зменшити розкриття платіжних даних VPN-провайдеру, але не стирає source IP, який спостерігається під час кожного з’єднання.

### Налаштування та перевірка VPN

1. Встановіть підписаний клієнт провайдера/організації з її офіційного джерела.
2. Оберіть **full tunnel**, якщо немає задокументованого маршруту, який повинен обходити VPN. Split tunneling створює шляхи для кореляції та leak.
3. Увімкніть режим fail-closed/always-on і блокування трафіку під час повторного підключення.
4. Передавайте DNS через tunnel і перевірте IPv4 та IPv6. Вимикайте протокол лише тоді, коли його неможливо безпечно передати через tunnel і прийнято втрату функціональності.
5. Перевірте sleep/wake, перемикання мереж, вхід через captive portal, падіння tunnel і tethering через hotspot. NCSC попереджає, що tethered-клієнти на деяких платформах можуть обходити VPN телефона.<sup>[[2]](#references)</sup>
6. Використовуйте test endpoint під контролем організації для запису спостережуваних IPv4, IPv6, DNS resolver і часу з’єднання. Не піддавайте чутливий engagement впливу випадкових сайтів для «leak test».
7. Повторюйте тестування після змін клієнта, OS, мережі або політик.

### Обходи маршрутизації у ворожій LAN

VPN може залишатися видимо «підключеним», хоча окремі пакети обходять його, оскільки операційна система обирає маршрут **до** того, як VPN зашифрує пакет. TunnelCrack продемонстрував два способи зловживання поширеними винятками маршрутизації: **LocalNet** змушує Internet destination виглядати як такий, що знаходиться у безпосередньо підключеній підмережі, тоді як **ServerIP** підміняє розв’язання VPN-gateway, щоб цільова адреса успадкувала виняток clear-network, необхідний VPN transport. Це помилки клієнта/маршрутизації, а не злами WireGuard, OpenVPN, IPsec або TLS; payload HTTPS залишається end-to-end зашифрованим, але локальний спостерігач може отримати метадані призначення/часу та будь-які дані cleartext-протоколів.<sup>[[18]](#references)</sup>

TunnelVision застосовує той самий pre-encryption primitive через DHCP option 121. Шкідливий або скомпрометований DHCP-сервер може встановити classless route, специфічніший за catch-all route VPN, обравши фізичний інтерфейс для довільного хоста або діапазону. Control channel VPN може залишатися активним, тому kill switch, який спрацьовує лише через від’єднання tunnel, може не активуватися, а одна публічна перевірка «IP leak» може не виявити вибіркові обходи.<sup>[[19]](#references)</sup>

Packet-filter kill switch, який дозволяє на фізичному інтерфейсі лише DHCP і автентифікований VPN transport, має перетворити це на поведінку fail-closed, але цілеспрямоване впровадження маршрутів усе ще може створити side channel вибіркової відмови в обслуговуванні. Для Linux workload із високими наслідками віддавайте перевагу надійнішому [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), у якому application namespace не має фізичного інтерфейсу або default route до clear-network.<sup>[[19]](#references)</sup>

#### Перевірка у власній лабораторії

Тестуйте точні client/OS/version на власних AP, DHCP server, VPN endpoint і destination; твердження щодо продукту загалом швидко застарівають, оскільки реалізації маршрутизації та packet-filter є специфічними для платформи. Виконуйте capture також на самому endpoint, а не лише на test server — один вебсайт для перевірки egress-IP не доводить, що кожне призначення використовує tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Підключіть VPN, запишіть адресу VPN-сервера та збережіть усі таблиці маршрутизації IPv4/IPv6 і правила policy-routing. У Windows використовуйте `route print`; у macOS — `netstat -rn`; у Linux — наведені нижче команди.
2. Запитайте обраний маршрут для кількох IP-адрес призначень, якими ви володієте. Next hop/interface має бути tunnel, за винятком задокументованої кінцевої точки VPN transport.
3. Для TunnelVision поновіть lease у контрольованій DHCP-мережі та встановіть route option 121 **лише для власної тестової destination**. Успішний результат означає, що трафік усе ще проходить через tunnel або блокується, — він ніколи не має передаватися як traffic destination через фізичний інтерфейс.
4. Для LocalNet призначте клієнту лабораторну public documentation subnet, наприклад `203.0.113.0/24`, і розмістіть у ній власну тестову destination. Переконайтеся, що ввімкнення LAN access не змушує destinations Internet-класу обходити tunnel.
5. Для ServerIP до підключення VPN налаштуйте контрольований DNS так, щоб він розв’язував власне ім’я VPN-хоста у власну тестову destination, тоді як lab gateway переспрямовував VPN transport до справжнього власного VPN endpoint. Клієнт не повинен звільняти від tunnel непов’язаний application traffic до spoofed address.
6. Повторіть тест із увімкненим і вимкненим параметром «local network access», після reconnect, sleep/wake, перемикання мережі та crash VPN-процесу. Окремо протестуйте IPv4, IPv6 і DNS.
7. Перевірте capture фізичного інтерфейсу. Він має містити DHCP і зашифровані пакети до VPN-сервера, але не пакети, адресовані безпосередньо власній тестовій destination. Також переконайтеся, що відхилений bypass не може непомітно активуватися після запитів користувача або відновлення підключення.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: посилена unlinkability у вебі

Tor будує circuit через кілька relay, тому зазвичай жоден окремий relay не знає одночасно і джерело, і призначення. Призначення бачить exit Tor, а не IP-адресу користувача; локальна мережа зазвичай бачить з'єднання з Tor.<sup>[[3]](#references)</sup> Tor розроблений для TCP-застосунків із низькою затримкою, тому він повільніший і не може гарантувати захист від adversary, здатного корелювати обидва кінці.<sup>[[4]](#references)</sup>

### Безпечний workflow Tor Browser

1. Завантажуйте Tor Browser лише з Tor Project або офіційного mirror і, коли можливо, перевіряйте signature.
2. Використовуйте **Tor Browser**, а не звичайний браузер, спрямований на Tor SOCKS port. Звичайні браузери можуть допускати leak DNS/WebRTC та ідентифікаційного стану.<sup>[[5]](#references)</sup>
3. Зберігайте стандартний розмір, шрифти, extensions і privacy settings. Додаткові add-ons можуть зробити браузер більш унікальним.<sup>[[6]](#references)</sup>
4. Обирайте рівень безпеки **Safer** або **Safest**, якщо прийнятне збільшення кількості непрацюючих функцій.
5. Використовуйте bridge, коли прямий Tor заблокований або коли звичайні relay IP-адреси створювали б неприйнятну локальну видимість. Bridges зменшують простоту розпізнавання, але не усувають traffic analysis.<sup>[[7]](#references)</sup>
6. Не входьте до ідентифікованого account, не надавайте ідентифікаційну інформацію та не відкривайте завантажені активні документи у зовнішньому застосунку з доступом до мережі.
7. Використовуйте окрему session/context для кожної identity. «New circuit» — це не те саме, що стирання browser/application identity; за потреби використовуйте **New Identity** або перезапускайте ізольоване середовище.
8. Надавайте перевагу authenticated HTTPS або authenticated onion service. Tor exit може спостерігати незашифрований HTTP-трафік.

### Tor разом із VPN

Їхнє поєднання не є автоматично безпечнішим. VPN перед Tor може приховати прямі з'єднання з Tor relay від ISP, тоді як VPN бачить джерело; Tor перед VPN дає VPN стабільне уявлення про активність після Tor і може зменшити anonymity set. Неправильна конфігурація може створити leaks. Tor Project рекомендує такі комбінації лише для advanced, explicit threat models.<sup>[[8]](#references)</sup>

## Публічний і гостьовий Wi-Fi

Сучасний HTTPS означає, що пасивні сусіди зазвичай не можуть прочитати належним чином зашифрований вебконтент, але гостьовий Wi-Fi не забезпечує anonymity. Заклад може записувати час підключення, ідентифікатори пристрою, дані captive portal, призначення та DHCP details; камери, покупки, транспорт і фізичне спостереження можуть ідентифікувати користувача. Фальшива hotspot з подібною назвою також може перехоплювати облікові дані portal або змінювати незашифрований трафік.<sup>[[9]](#references)</sup>

### Lawful workflow для гостьової мережі

1. Використовуйте лише мережу, запропоновану для гостей, або мережу, на використання якої власник надав явний дозвіл. Запитайте персонал точний SSID і процедуру portal.
2. Оновіть endpoint і travel router до прибуття. Вимкніть file/printer sharing, inbound discovery, auto-join і перевірку збережених мереж.
3. Увімкніть приватну/randomized Wi-Fi address в ОС. Сучасні системи Apple можуть використовувати rotating addresses у відкритих/слабко захищених мережах; сучасна рандомізація Android зазвичай є постійною для кожного SSID. Це зменшує лише один локальний ідентифікатор.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Надавайте перевагу travel router, контрольованому організацією, або bridge device з низьким рівнем довіри між privileged workstation і гостьовою мережею. Це централізує firewall/VPN policy, але не приховує router від закладу.<sup>[[12]](#references)</sup>
5. Проходьте captive portal лише через призначений low-trust device/browser. Ніколи не вводьте особисті або повторно використовувані credentials у контексті, який нібито є anonymous. Закрийте browser portal після встановлення з'єднання.
6. Запустіть full-tunnel VPN або Tor до початку sensitive activity і підтвердьте fail-closed behavior.
7. Після використання забудьте мережу та перевірте policy облікового запису portal і зберігання даних.

{% hint style="danger" %}
Злам Wi-Fi сусіда, обхід portal, використання leaked guest credentials, клонування доступу іншого гостя або приховування Raspberry Pi в кафе є несанкціонованою активністю, а не privacy technique. Безпечними альтернативами є lawful guest network, client-approved site або documented drop node, розміщений і вилучений за письмовою згодою власника майна.
{% endhint %}

## Travel routers

Travel router може ізолювати workstation від hostile local broadcasts, застосовувати firewall, надавати узгоджений internal SSID і автоматично відновлювати VPN. Він **не є anonymous**: upstream бачить його radio identity і timing трафіку, а VPN provider бачить source tunnel.

- Використовуйте підтримувані OpenWrt/vendor firmware і видаліть невикористовувані services.
- Адмініструйте через Ethernet або окремий management SSID з унікальним password.
- Вимкніть WAN-side administration, UPnP, WPS, file sharing і unsolicited inbound traffic.
- Використовуйте randomized/private WAN MAC лише там, де це підтримується і дозволено.
- Застосовуйте VPN policy на router, включно з DNS та IPv6, і блокуйте egress у разі відмови tunnel.
- Не припускайте, що phone hotspot спрямовує tethered devices через VPN телефона; перевірте це.

## Cellular, SIM та eSIM

Cellular зручний, але не anonymous. Оператори зберігають subscriber/device identifiers і location, отримане з підключення до мережі; eSIM усе одно є mobile subscription. Prepaid не означає надійно unregistered — вимоги залежать від країни та змінюються.<sup>[[13]](#references)</sup>

Операційно:

- Використовуйте окремий підтримуваний device, щоб зменшити exposure персональних даних, а не для створення вигаданого subscriber.
- Не носіть «окремий» device постійно разом з особистим телефоном, якщо co-location входить до threat model.
- Вимкніть невикористовувані cellular, Wi-Fi, Bluetooth і location access; вимкнення живлення є сильнішою radio boundary, ніж перемикачі UI.
- Передавайте sensitive traffic через approved VPN/Tor path, пам'ятаючи, що carrier усе одно знає subscription/device location і tunnel endpoint.
- Перевіряйте актуальні правила registration і retention у національного регулятора або місцевого counsel; не покладайтеся на онлайн-списки «anonymous SIM countries».

## DNS і TLS metadata

- **DoH/DoT/DoQ** шифрують DNS між client і resolver, запобігаючи простому локальному читанню або зміні, але resolver усе одно бачить queries і transport identifiers. Вони змінюють trust, але не забезпечують anonymity.<sup>[[14]](#references)</sup>
- **ODoH** додає proxy, щоб resolver не мусив дізнаватися IP client, за умови, що proxy і target не collude. Traffic analysis прямо виключено з області захисту.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** може захищати внутрішнє ім'я server у TLS handshake, коли client, DNS і server його підтримують. Destination IP, timing, volume та endpoint залишаються видимими.<sup>[[16]](#references)</sup>
- У правильно налаштованому VPN або Tor environment DNS має використовувати підтримуваний route цього environment. Додавання окремого resolver може створити нового observer або fingerprint.

### Workflow перевірки Encrypted-DNS/ECH

1. Визначте, що контролює DNS: VPN/Tor environment, ОС чи application. Налаштуйте його в **одному** передбаченому layer, а не поєднуйте непов'язані resolvers.
2. Оберіть resolver за його опублікованою privacy/retention policy та увімкніть strict encrypted mode, якщо платформа його підтримує. Opportunistic fallback може непомітно повернутися до plaintext.
3. Виконайте запит до унікального subdomain у authoritative test zone, якою ви керуєте; підтвердьте, що authoritative log бачить intended recursive resolver.
4. За наявності authorization захопіть лише трафік test device. Підтвердьте, що access network не може читати plaintext DNS, пам'ятаючи, що вона може бачити encrypted resolver/tunnel endpoint.
5. Перевірте заблокований/недоступний encrypted resolver. Умовою успіху є обрана fail-closed або documented fallback behavior, а не випадковий clear query.
6. Для ECH використовуйте контрольований ECH-enabled host та перевірте client/server diagnostics, щоб підтвердити прийняття **inner** ClientHello. Сам факт наявності HTTPS record не доводить успішність ECH.
7. Повторюйте перевірку після змін мережі, captive portals, browser updates і VPN reconnects. Записуйте, який component відповідає за DNS/ECH, щоб подальші administrators не створили bypass.

## Mixnets

Mixnets, такі як Nym або Katzenpost, додають packets фіксованого розміру, затримку, reorder і cover traffic для протидії timing correlation. Ці властивості коштують latency та bandwidth, а незалежні докази масштабної deployment обмежені. Розглядайте сучасні consumer mixnets як **emerging/high-latency options**, а не як швидші або гарантовані заміни Tor/VPNs.<sup>[[17]](#references)</sup>

### Workflow оцінювання

1. Визначте maintained client і точний supported application; не спрямовуйте довільний browser/system traffic через undocumented proxy.
2. Прочитайте актуальну threat model для entry, mix nodes, gateway, destination і припущень щодо collusion.
3. Встановіть client з official signed source в окремому test compartment і використовуйте лише benign owned endpoint.
4. Виміряйте delivery latency, message-size limits, reliability, retransmission і поведінку у разі недоступності gateway.
5. Перевірте local traffic і owned endpoint, щоб підтвердити intended path і source. Перевірте, чи replies використовують той самий privacy design.
6. Перевірте shutdown/failure: application не має непомітно повертатися до direct Internet access.
7. Не вимикайте cover traffic, не зменшуйте delays і не обирайте unusual fixed routes лише заради швидкості; ці зміни можуть зробити заявлену anonymity model недійсною.
8. Вважайте це experimental, доки конкретні deployment, independent analysis і operational reliability не відповідатимуть рівню наслідків.

## Network preflight checklist

- [ ] Authorization охоплює access network, target, dates і source infrastructure.
- [ ] Endpoint не містить unrelated identities або active sync sessions.
- [ ] IPv4, IPv6, DNS і reconnect behavior відповідають плану.
- [ ] Controlled DHCP/local-subnet route injection не може перемістити test traffic на physical interface.
- [ ] Destination бачить лише очікуваний egress.
- [ ] Captive portal і hotspot behavior перевірені без sensitive traffic.
- [ ] Local sharing/discovery та automatic network joining вимкнені.
- [ ] Observer table і residual traffic-correlation risk прийняті.
- [ ] Provider policy, retention і emergency contact актуальні.

Для split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P і disposable remote browsers продовжуйте до [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Вибір VPN, який підходить саме вам](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Рекомендації щодо безпеки пристроїв: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Захист приватності та anonymity, який забезпечує Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Короткий вступ до Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Використання Tor з іншими браузерами](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins і add-ons у Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Розблокування Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Використання Tor Browser з VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Чи безпечні публічні Wi-Fi Networks?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy на пристроях Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Реалізація MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Принципи безпечних privileged access workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Обов'язкова SIM registration: policy та regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Рекомендації для операторів DNS Privacy Service](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Обхід тунелів: витік трафіку VPN Client через зловживання routing tables](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: як attackers можуть зняти маску з routing-based VPNs, спричинивши повний VPN leak](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
