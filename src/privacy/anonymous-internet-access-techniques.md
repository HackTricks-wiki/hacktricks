# Каталог технік анонімного доступу до Інтернету

Це канонічний інвентар шляхів доступу. Він охоплює **сімейства** протоколів і операційних підходів, а не назви всіх постачальників. Жоден шлях до Інтернету не гарантує анонімності: обліковий запис, браузер, кінцева точка, час, оплата, cloud-control-plane і фізичні докази можуть зруйнувати навіть маршрут, що виглядає ідеальним.

Кожен запис використовує однакові поля. «Процедура» означає законне розгортання або емуляцію у власній лабораторії. Якщо реальна техніка залежить від компрометації маршрутизатора, викрадення доступу чи зловживання неготовим посередником, відтворення замінює це системами, якими володіє учасник вправи.

## Матриця охоплення

| Сімейство | Що бачить призначення | Найсильніша властивість | Швидкість | Застосування |
|---|---|---|---|---|
| Shared NAT/CGNAT | спільну публічну адресу | неоднозначність між абонентами | висока | придатне до розгортання |
| VPN, VPS, SOCKS/HTTP/SSH proxy | адресу relay | швидке розділення адреси джерела | висока | придатне до розгортання |
| Multi-hop/split relay, MASQUE | кінцевий proxy | розділення знань або повний IP-тунель | висока/помірна | з trusted relay |
| Tor, bridge, onion service | exit або onion identity | багатосторонній маршрут і спільний браузер | помірна | придатне до розгортання |
| I2P, GNUnet, mixnet | peer/gateway overlay | overlay або стійкість до аналізу часу | низька/змінна | для окремих застосунків |
| OHTTP/ODoH, Private Relay | gateway/egress | розділення джерела й запиту | висока | лише підтримувані застосунки |
| Public Wi-Fi, travel router | адресу закладу/тунелю | зміна місця/шляху доступу | висока | потрібен дозвіл |
| Cellular/eSIM, satellite | адресу оператора/провайдера | незалежний фізичний uplink | висока/змінна | оператор бачить підписку |
| Remote browser/jump host | віддалене workspace | розділення endpoint і egress | висока | придатне до розгортання |
| Residential/mobile proxy | споживчу/операторську адресу | вигляд споживчої мережі | висока | критичні згода/походження |
| ORB/compromised relay | адресу іншої жертви | приховування походження та запозичена репутація | висока | лише відтворення у власній лабораторії |
| CDN/fronting/redirector | передню адресу CDN | захист back-end інфраструктури | висока | потрібен дозвіл провайдера/власника |
| Fast flux/DGA/dead drop | змінний node/service | стійкість до виявлення інфраструктури | змінна | лише власна лабораторія |
| Drop/nearest-neighbor | локальну адресу поруч із ціллю | перетин географічної/мережевої межі | висока | лише лабораторія на власних майданчиках |
| Store-and-forward/offline | gateway або фізичний receiver | зменшення інтерактивного часового зв’язку | низька | для окремих застосунків |
| Pluggable/refraction transport | Tor entry або cooperating diversion proxy | стійке до цензури досяжне з’єднання | змінна | підтримуваний client або research lab |
| IPFS gateway/PIR/remote fetcher | gateway або application service | розділення publisher/query/request | змінна | лише обмежені застосунки |
| Anycast/QUIC/MPTCP | стабільний broker або кілька subflow | rendezvous і безперервність сесії | висока | доступність, не анонімність |
| CI/CD automation runner | адресу hosted runner | одноразовий підзвітний egress | висока | лише власний workflow |
| Non-IP local first hop | gateway організації | вилучення Internet stack із sensor | низька | deployment із дозволу власника |

## Direct shared NAT і carrier-grade NAT

**Механіка:** кілька користувачів спільно використовують одну публічну адресу; access provider зіставляє адреси й порти на боці абонентів із публічним tuple.

**Переваги:** висока швидкість; спеціальний client не потрібен; IP на боці призначення може ідентифікувати лише домогосподарство, заклад або пул carrier.

**Недоліки:** provider може зберігати відповідності subscriber/port/time; облікові записи й fingerprint залишаються; інші користувачі можуть зіпсувати репутацію адреси.

**Процедура:** (1) підтвердити, що авторизований доступ використовує NAT/CGNAT; (2) записати точні public IP і source port на власному endpoint; (3) розділяти application identities; (4) не вважати shared addressing засобом приватності; (5) використати сильніший шлях, якщо ISP не повинен знати призначення.

**Виявлення:** destinations мають зберігати source port і точний час, а не лише IP. Providers зіставляють журнали NAT allocation; investigators об’єднують дані account/device/browser.

## Commercial VPN

**Механіка:** зашифроване full-tunnel з’єднання завершується на VPN; destinations бачать його egress. VPN зазвичай може пов’язати source, timing і destinations.

**Переваги:** висока швидкість; простота; захист від локального пасивного спостереження; стабільні або спільні exits; добре підходить для контрольованого red-team egress.

**Недоліки:** концентрована довіра; telemetry billing/login; помилки kill-switch/DNS/IPv6; shared exits часто блокуються через репутацію.

**Процедура:** (1) визначити provider, owner, jurisdiction, retention і assessment policy; (2) встановити підписаний official client; (3) увімкнути full tunnel, always-on і fail-closed behavior; (4) свідомо налаштувати DNS та IPv6; (5) перевірити observed IPv4/IPv6/DNS на власному endpoint; (6) зупинити й повторно під’єднати tunnel та підтвердити відсутність clear fallback.<sup>[[1]](#references)</sup>

**Виявлення:** локальні мережі бачать тривалий encrypted flow до VPN infrastructure; providers мають authentication/connection records; destinations використовують ASN/reputation разом із account, TLS/browser і behavior correlation.

## Self-hosted VPN або rented VPS egress

**Механіка:** оператор контролює WireGuard/OpenVPN gateway або пересилає traffic через rented server.

**Переваги:** передбачувана висока швидкість; фіксована адреса, яку можна додати до allowlist; власні logging/firewall; хороший incident control.

**Недоліки:** мала anonymity set; cloud tenant, payment, source login, API та image history пов’язують оператора; новий характерний server легко кластеризувати.

**Процедура:** (1) створити project організації для конкретного engagement; (2) розгорнути підтримуваний image і fixed address; (3) обмежити management MFA/key-based administration; (4) налаштувати full-tunnel egress і DNS; (5) за можливості дозволити лише scoped destinations; (6) перевірити leak/failure behavior; (7) зберегти controller audit records; (8) знищити credentials і resources під час teardown.

**Виявлення:** зіставляти hosting ASN, first-seen address, certificate/service fingerprint і scanning behavior; cloud owners використовують control-plane, console, billing і flow logs.

## HTTP CONNECT, SOCKS і SSH forwarding

**Механіка:** application просить proxy відкрити TCP stream; SOCKS також може передавати name resolution і UDP залежно від версії; SSH пересилає streams усередині одного encrypted session.

**Переваги:** легкість; per-application; висока швидкість; корисно для chaining і доступу до segmented networks.

**Недоліки:** applications можуть обходити proxy; DNS може витікати; proxy бачить суміжні endpoints; browser state зберігається; open proxies можуть бути пастками або скомпрометованими системами.

**Процедура:** (1) розгорнути proxy на власному host; (2) вимагати authentication і обмежити source/destination; (3) налаштувати один disposable application profile; (4) за потреби забезпечити remote DNS resolution; (5) перевірити через власний DNS/HTTP endpoint; (6) заблокувати direct egress для workload; (7) перевірити й змінити proxy credentials.

**Виявлення:** виявляти процеси, здатні створювати tunnels, CONNECT/SOCKS negotiation, довгі SSH sessions і destinations, невідповідні application; proxy logs відновлюють streams.

## URL-rewriting web proxy і browser proxy extension

**Механіка:** website отримує destination і переписує links/forms через власний origin, або extension спрямовує browser requests до proxy. Destination бачить service, тоді як service може бачити plaintext після TLS termination, а також вставляти чи зберігати content.

**Переваги:** system-wide client не потрібен; швидко для простого browsing; працює там, де VPN встановити неможливо.

**Недоліки:** proxy може читати credentials/content, змінювати downloads і fingerprint користувачів; scripts/WebSockets/downloads можуть обходити proxy; browser extension має широкі привілеї; мала anonymity set і часті блокування.

**Процедура:** (1) використовувати лише proxy, яким керує організація, для authorized testing; (2) ізолювати його в disposable browser без personal accounts; (3) заборонити введення passwords і sensitive downloads; (4) перевірити, що кожен subresource на власній сторінці проходить через proxy; (5) протестувати WebSocket, download і form behavior; (6) після використання видалити extension/profile.

**Виявлення:** destination logs реєструють proxy; enterprise proxy/DNS і extension inventory ідентифікують service; content-security/reporting або власні canary subresources виявляють direct bypass; proxy logs зіставляють user session із targets.

## Multi-hop proxy або provider multi-hop VPN

**Механіка:** entry бачить source, а один чи кілька traversal relays відокремлюють його від exit, який бачить destination.

**Переваги:** звичайний relay не повинен бачити обидва кінці; збій або захоплення одного node розкриває менше; гнучка географія.

**Недоліки:** спільне адміністрування/logs руйнує розділення; latency; timing correlation; більше відмов і DNS routes; той самий account/payment може об’єднати всі hops.

**Процедура:** (1) визначити, якого observer усуває кожен hop; (2) коли розділення важливе, використовувати незалежно адміністровані власні/схвалені relays; (3) забезпечити лише entry access із workload; (4) гарантувати, що кожен relay може досягати тільки наступного hop; (5) перевірити logs на кожному layer; (6) зупинити кожен hop і підтвердити fail-closed behavior. Відтворювати за допомогою [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Виявлення:** зіставляти adjacent NetFlow timing/volume, повторювані proxy handshakes і спільну controller infrastructure; не визначати географію оператора за exit.

## Split-knowledge application relay і OHTTP

**Механіка:** client шифрує stateless HTTP message для gateway і надсилає його через relay. Relay бачить client IP, але не request; gateway бачить request, але зазвичай лише relay IP.

**Переваги:** сильний, auditable privacy partition для підтримуваних requests; менші накладні витрати, ніж у загальних anonymity networks.

**Недоліки:** не довільний browsing; cookies/authentication можуть повторно пов’язати запити; collusion relay/gateway і traffic analysis залишаються; application має це реалізувати.

**Процедура:** (1) обрати application із явною підтримкою RFC 9458; (2) перевірити gateway keys через official configuration path; (3) уникати стабільних per-user fields; (4) надсилати лише підтримуваний stateless request; (5) порівняти relay, gateway і target logs; (6) перевірити key rotation/failure без direct fallback.<sup>[[2]](#references)</sup>

**Виявлення:** enterprise endpoints показують initiating process і OHTTP relay; gateways виявляють malformed/replayed traffic; timing і стабільні payload/account fields можуть пов’язувати requests.

## MASQUE CONNECT-UDP/CONNECT-IP і HTTP privacy proxies

**Механіка:** HTTP Extended CONNECT через TLS/QUIC переносить UDP або IP packets через proxy. Це може реалізувати сучасний VPN-like tunnel і змішати transport із HTTP/3, але proxy залишається observer.<sup>[[3]](#references)</sup>

**Переваги:** ефективні multiplexing/roaming; підтримка UDP або full IP; розгортання через сучасну HTTP infrastructure.

**Недоліки:** це не anonymity network; proxy/account бачить source і destinations; QUIC/HTTP fingerprints і well-known paths видимі endpoints/providers.

**Процедура:** (1) використати client/service, що документує підтримку RFC 9298/9484; (2) автентифікувати proxy certificate/configuration; (3) визначити дозволені target routes; (4) увімкнути encrypted DNS усередині path; (5) перевірити UDP, TCP, IPv6 і failover на власних endpoints; (6) перевірити proxy request і flow logs.

**Виявлення:** endpoints бачать client process і virtual interface; networks можуть класифікувати тривалий QUIC/TLS до proxy; proxy logs розкривають CONNECT target/path і призначені routes.

## Tor Browser

**Механіка:** Tor обирає guard, middle і exit relays; layered encryption обмежує видимість кожного relay. Tor Browser додає стандартизований browser, призначений протидіяти fingerprinting.

**Переваги:** велика публічна anonymity set; жоден звичайний relay не знає обидва кінці; destination unlinkability без роботи власних servers.

**Недоліки:** повільніше; орієнтовано на TCP; exit reputation/blocks; logins і disclosures ідентифікують користувача; end-to-end timing correlation залишається.

**Процедура:** (1) завантажити й перевірити Tor Browser із project; (2) зберігати defaults і не використовувати extensions; (3) обрати відповідний security level; (4) створити окремі identity/session; (5) уникати identifying accounts і зовнішніх active documents; (6) використовувати HTTPS або authenticated onion services; (7) перевіряти exit лише на власному endpoint.<sup>[[4]](#references)</sup>

**Виявлення:** локальні мережі можуть визначити відомий guard traffic, якщо не використовується bridge/transport; destinations бачать exits і Tor Browser behavior; end-to-end observers зіставляють timing/volume.

## Tor bridges і pluggable transports

**Механіка:** непублічний bridge замінює public guard; obfs4, Snowflake або WebTunnel змінюють transport першого hop для протидії простому блокуванню/probing.

**Переваги:** обходить censorship і приховує очевидні public-relay destinations; після entry зберігає Tor circuit.

**Недоліки:** transport patterns/bridge discovery все ще можливі; змінна продуктивність; не додає захисту від accounts або global timing.

**Процедура:** (1) спочатку спробувати direct Tor; (2) у Tor Browser Connection settings обрати вбудований підтримуваний transport або запросити official bridge; (3) не використовувати випадкові binaries/lists; (4) під’єднатися й виконати benign test; (5) перевірити reconnect і clock; (6) залишити всі інші browser settings стандартними.<sup>[[5]](#references)</sup>

**Виявлення:** censors використовують destination discovery, protocol/flow classification і active probing; defenders мають відрізняти circumvention use від compromise та спиратися на endpoint process/context.

## VPN before Tor і Tor before VPN

**Механіка:** VPN-before-Tor приховує direct Tor use від access ISP, але відкриває source VPN. Tor-before-VPN передає VPN post-Tor traffic і часто стабільну customer/tunnel identity.

**Переваги:** усуває конкретного observer, якщо правильно спроєктовано; може досягати мереж, що блокують один layer.

**Недоліки:** складність, незвичний fingerprint, leaks, менша anonymity set і false confidence; Tor Project вважає такі комбінації advanced.<sup>[[6]](#references)</sup>

**Процедура:** (1) записати, якого observer усувають і якого нового додають; (2) використовувати disposable environment; (3) встановити лише задуманий outer path; (4) застосувати firewall routes; (5) перевірити DNS/IPv4/IPv6 і порядок кожної відмови; (6) порівняти visibility обох providers; (7) відмовитися від stack, якщо він не дає вимірюваної переваги.

**Виявлення:** local/VPN/Tor observers бачать різні adjacent layers; timing залишається end-to-end; незвичні nested tunnel fingerprints і provider accounts можуть пов’язувати sessions.

## Onion service

**Механіка:** client і service будують Tor circuits до rendezvous, приховуючи service IP і не використовуючи exit.

**Переваги:** захист розташування source і service; end-to-end onion authentication; відсутність public inbound port; optional client authorization.

**Недоліки:** origin leaks через updates/analytics/errors; onion key критично важливий; application identity/timing і host compromise залишаються.

**Процедура:** (1) ізолювати application і прив’язати його лише до loopback/socket; (2) встановити підтримуваний Tor; (3) налаштувати v3 onion service за official instructions; (4) захистити/зробити backup key лише якщо потрібна стабільна identity; (5) додати client authorization для закритого використання; (6) прибрати third-party fetches; (7) зовні перевірити недосяжність origin.<sup>[[7]](#references)</sup>

**Виявлення:** host/network defenders знаходять Tor process/configuration і outbound circuits; application errors, DNS, certificates або third-party resources можуть розкрити origin.

## I2P internal services

**Механіка:** I2P використовує окремі односпрямовані inbound/outbound tunnels для destinations усередині overlay; public-Internet outproxies додають trust point.

**Переваги:** децентралізована внутрішня публікація; відсутність залежності від official exit; розділені inbound/outbound paths.

**Недоліки:** не є заміною загальному web; менша ecosystem; тривала peer behavior; outproxy може бачити public browsing.

**Процедура:** (1) встановити з official source; (2) використовувати dedicated context; (3) дозволити integration/bandwidth stabilization; (4) звернутися до I2P-native власного service; (5) уникати outproxies, якщо вони прямо не потрібні; (6) перевірити, що shutdown не дає direct fallback; (7) перевірити local peer і service logs.<sup>[[8]](#references)</sup>

**Виявлення:** локальні мережі бачать довготривалий peer traffic і bootstrap behavior; endpoints розкривають router/application processes; outproxies logs фіксують exits.

## Mixnets

**Механіка:** fixed-size packets, batching, delay, reordering і cover traffic зменшують timing correlation; gateways з’єднують applications.

**Переваги:** краща стійкість до timing analysis, ніж у low-latency proxies; корисно для асинхронних messages/transactions.

**Недоліки:** latency, bandwidth overhead, менше розгортань і application limits; gateway/account metadata може зберігатися.

**Процедура:** (1) обрати підтримуваний client і supported application; (2) прочитати actual threat model; (3) встановити в окремому compartment; (4) надіслати benign data до власного endpoint; (5) виміряти latency/reliability і reply path; (6) протестувати gateway failure; (7) ніколи не вимикати delays/cover traffic лише заради швидкості.<sup>[[9]](#references)</sup>

**Виявлення:** endpoints ідентифікують client; access networks можуть класифікувати gateways/packet cadence; gateways і exits бачать суміжні ролі, а ширше correlation потребує довших статистичних вікон.

## GNUnet anonymous file sharing

**Механіка:** GNUnet може маршрутизувати publish/search/download requests через peers і додавати cover traffic відповідно до anonymity level. Власна документація попереджає, що default level 1 не вимагає cover traffic, а потужний traffic analysis може визначити origin.<sup>[[10]](#references)</sup>

**Переваги:** децентралізований, application-native anonymous sharing; керована вимога cover traffic.

**Недоліки:** не звичайний anonymous web access; витрати performance/storage; обмеження peers і traffic analysis; документація GNUnet VPN зазначає, що його IP overlay не забезпечує належної анонімності.

**Процедура:** (1) встановити підтримувану official build; (2) ізолювати test peer; (3) обмежити bandwidth/storage; (4) опублікувати harmless unique test file із вибраним anonymity level; (5) отримати його з іншого власного peer; (6) записати cover-traffic і latency; (7) не стверджувати, що IP VPN component забезпечує еквівалентну анонімність.

**Виявлення:** peer bootstrap, overlay traffic, local datastore/process і file identifiers; широкий observer може аналізувати обсяг traffic щодо cover traffic.

## Encrypted DNS, ODoH і ECH

**Механіка:** DoH/DoT/DoQ шифрують до resolver; ODoH розділяє client address і query між proxy та resolver; ECH шифрує inner TLS ClientHello/server name.

**Переваги:** прибирає plaintext DNS/SNI від деяких локальних observers; ODoH розділяє знання source/query.

**Недоліки:** це не IP-anonymity path; resolver/proxy/server зберігають свої ролі; destination IP/timing/volume і endpoint залишаються; fallback може спричинити leak.

**Процедура:** (1) визначити, кому належить DNS — OS, application чи tunnel; (2) увімкнути strict encrypted mode або supported ODoH; (3) протестувати унікальний власний domain; (4) захопити локальний traffic і підтвердити відсутність clear query; (5) відмовити resolver і перевірити очікувану поведінку; (6) для ECH підтвердити в server diagnostics прийняття inner ClientHello.<sup>[[11]](#references)</sup>

**Виявлення:** endpoint/resolver logs розкривають queries; networks ідентифікують encrypted-resolver endpoints і destination flows; ECH state видимий endpoints/CDN навіть якщо прихований на path.

## Split-provider privacy relay

**Механіка:** products на кшталт iCloud Private Relay використовують ingress, що знає client, і незалежно керований egress, що знає destination, із coarse region handling.

**Переваги:** просте розділення знань; висока швидкість; інтегрований DNS/web protection для підтримуваного traffic.

**Недоліки:** product/application scope обмежений; account/platform provider усе одно ідентифікує customer; не довільна system anonymity; collusion/legal і timing risks.

**Процедура:** (1) підтвердити, які саме applications і traffic types підтримуються; (2) увімкнути feature у dedicated platform context за потреби; (3) обрати region behavior; (4) окремо протестувати Safari/DNS і unsupported applications; (5) перевірити destination address; (6) перевірити network switching/failure.<sup>[[12]](#references)</sup>

**Виявлення:** access бачить ingress; destination бачить egress; platform/relay logs і account records охоплюють відповідний layer; unsupported applications розкривають звичайні paths.

## Remote browser, VDI, RDP або organization jump host

**Механіка:** browsing/tool execution відбувається на remote system; destination бачить його egress, а workspace provider бачить operator connection і control plane.

**Переваги:** висока швидкість; ізоляція risky content; стабільний controlled egress; disposable state і strong organizational audit.

**Недоліки:** provider/admin може бачити session/account; screen/clipboard/file channels витікають; remote browser fingerprint може бути унікальним; для workspace owner це не anonymous.

**Процедура:** (1) створювати одне organization-owned workspace на engagement; (2) вимагати MFA і обмежити administration; (3) вимкнути або обмежити clipboard/upload/download; (4) спрямувати traffic через approved fixed egress; (5) не використовувати personal IdP/sync; (6) експортувати лише перевірені evidence; (7) знищити workspace і credentials за графіком.

**Виявлення:** provider та IdP logs пов’язують user із session; destinations кластеризують workspace egress/browser; enterprise defenders ідентифікують remote-control protocols і anomalous cloud sessions.

## Public або guest Wi-Fi

**Механіка:** traffic виходить через venue NAT або tunnel, запущений там.

**Переваги:** висока швидкість і спільна non-home address; dedicated infrastructure не потрібна.

**Недоліки:** venue association/DHCP/portal, camera, purchase і location evidence; hostile peers/APs; terms; physical risk.

**Процедура:** (1) отримати доступ, запропонований гостям, і перевірити SSID у персоналу; (2) використати patched low-trust device; (3) вимкнути sharing/auto-join і ввімкнути private MAC; (4) пройти portal без reused identity; (5) запустити fail-closed VPN/Tor path; (6) перевірити tethered traffic; (7) забути network.

**Виявлення:** venue пов’язує AP, MAC, DHCP, portal і час; destination бачить venue/tunnel; investigators поєднують physical і device evidence. Ніколи не обходьте access control.

## Travel router

**Механіка:** operator-owned router під’єднується до venue Wi-Fi/Ethernet і надає ізольовану internal network із enforced tunnel policy.

**Переваги:** ізолює workstations; central kill switch/DNS; узгоджена client network; захищає privileged endpoints від local broadcasts.

**Недоліки:** router стає стабільним radio/DHCP fingerprint; додає attack surface; captive portals і tethering можуть обходити tunnel.

**Процедура:** (1) оновити supported firmware; (2) встановити унікальні management credentials і вимкнути WAN admin/WPS/UPnP; (3) налаштувати private upstream MAC, де дозволено; (4) створити окремий internal SSID; (5) застосувати full-tunnel DNS/IPv6 firewall policy; (6) протестувати portal, reconnect і tunnel failure.

**Виявлення:** venue бачить router association і traffic shape; local RF/DHCP fingerprinting ідентифікує його; VPN provider бачить venue source.

## Cellular, prepaid SIM і eSIM

**Механіка:** modem використовує carrier radio access і зазвичай carrier NAT; VPN/Tor layer може змінити exit, видимий destination.

**Переваги:** незалежність від локальної wired/Wi-Fi network; мобільність; висока швидкість; корисний backhaul для authorized drops.

**Недоліки:** carrier знає subscriber/eSIM, IMSI, IMEI, cells, time і assigned ports; registration laws відрізняються; co-location із personal phone пов’язує devices.

**Процедура:** (1) законно отримати service із точними обов’язковими даними; (2) використовувати окремий organization-owned modem/device; (3) зареєструвати його в exercise controller; (4) вимкнути unrelated radios/accounts; (5) встановити approved tunnel; (6) перевірити, чи tethered clients справді використовують його; (7) перед поїздкою перевірити припущення щодо provider і retention.<sup>[[13]](#references)</sup>

**Виявлення:** carrier records і RF location; enterprise USB/PCI/MDM inventory і rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet і satellite downlink abuse

**Механіка:** звичайний service використовує registered terminal/provider. Старий one-way DVB-S abuse дозволяв receiver усередині beam спостерігати незашифрований downlink traffic, адресований legitimate subscriber, використовуючи інший path для outbound requests.

**Переваги:** широка зона покриття; незалежний last mile; історичний one-way abuse міг помилково приписувати C2 географії subscriber.

**Недоліки:** equipment/RF/provider records; latency і coverage; сучасні bidirectional systems відрізняються; outbound path і asymmetric routing залишаються evidence.

**Процедура:** для законного доступу зареєструвати власний terminal і за потреби тунелювати traffic. Для емуляції історичної поведінки Turla відтворити synthetic one-way packet captures у RF-free lab і перевірити, чи analysts виявлять reply до host, який не робив request; не перехоплювати live satellite traffic.<sup>[[14]](#references)</sup>

**Виявлення:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency і malware configuration.

## Residential/mobile proxy або consented proxyware

**Механіка:** backconnect gateway призначає consumer broadband/mobile exits — sticky або rotating. Supply може бути consensual, deceptively bundled або malicious.

**Переваги:** висока швидкість; географічний вибір; consumer ASN обходить частину hosting blocks; великі pools.

**Недоліки:** provenance/consent і legal risk; broker бачить customer; infected exits шкодять victims; rotation створює anomalies; дорого й ненадійно.

**Процедура:** використовувати лише documented, informed-consent organization-owned agents для емуляції: (1) зареєструвати test endpoints; (2) інвентаризувати owners/IPs; (3) налаштувати gateway; (4) перемикати sticky/per-request modes; (5) надсилати traffic лише до власного target; (6) порівняти gateway/exit/target logs; (7) видалити кожен agent.

**Виявлення:** impossible travel, стабільний browser/account під час швидких змін IP/ASN, backconnect protocols, proxyware process/network artifacts і broker/controller relations.

## ORB, botnet і compromised edge-device relays

**Механіка:** leased або compromised routers/IoT/servers формують access, traversal і exit roles, керовані як fleet. Кілька APT customers можуть спільно використовувати її.

**Переваги:** запозичена reputation/geography; короткоживучі exits; стійка multi-hop mesh; слабкий прямий actor-to-IP link.

**Недоліки:** criminal victimization; implant/controller і fleet patterns; захоплення intermediary; непередбачувана продуктивність; operator/customer service records.

**Процедура:** ніколи не компрометувати реальні devices. Використовувати [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) створити ізольовані entry/transit/target networks; (2) під’єднати власні dual-homed relay containers; (3) пересилати лише один test port; (4) надіслати benign request; (5) перевірити, що target бачить лише exit; (6) змінити exit; (7) видалити всі названі assets.<sup>[[15]](#references)</sup>

**Виявлення:** відстежувати topology, ports/services, controller relations, implant fingerprints і node lifecycle; централізувати edge configuration/flow/integrity telemetry; не ототожнювати exit IP з actor.

## CDN redirector, domain fronting і domainless fronting

**Механіка:** public edge пересилає лише traffic, що відповідає grammar; fronting використовує benign outer SNI і відмінний inner HTTP authority або blank SNI, якщо intermediary це дозволяє.

**Переваги:** приховує/захищає back-end; швидкий global edge; змішує destination зі shared service; швидкий cutover.

**Недоліки:** CDN бачить усі routing і tenant; багато providers забороняють cross-tenant fronting; SNI/Host/process/flow і account artifacts; повторне використання configuration кластеризує campaigns.

**Процедура:** відтворювати лише на власному reverse proxy за допомогою [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): створити local certificate/edge, спрямувати один mismatched Host до власного target, записати SNI і Host, надіслати normal/mismatched requests, потім видалити containers.<sup>[[16]](#references)</sup>

**Виявлення:** порівнювати SNI/ECH/Host/`:authority` на endpoint або terminating edge; пов’язувати initiating process, tenant/origin, request grammar і flow cadence.

## Dynamic DNS, DGA, fast flux і double flux

**Механіка:** DDNS оновлює стабільне ім’я; DGA створює змінні candidate names; fast flux обертає service addresses із низьким TTL; double flux також обертає name servers.

**Переваги:** стійке discovery; швидка заміна infrastructure; controller приховується за багатьма nodes.

**Недоліки:** DNS створює централізовану telemetry; entropy/NXDOMAIN/churn; low TTL і широкі ASN patterns; registration і authoritative infrastructure залишаються.

**Процедура:** використовувати [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): обслуговувати власну zone, що повертає RFC 5737 addresses із п’ятисекундним TTL, повторювати queries, змінити synthetic epoch і перевірити analytics. Ніколи не спрямовувати test records до third parties.<sup>[[17]](#references)</sup>

**Виявлення:** sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters і follow-on процесу; legitimate CDNs виключати з урахуванням context.

## Legitimate web service, dead-drop resolver і one-way tasking

**Механіка:** public post, repository, document, object або feed містить encoded current endpoint або task. Client може повертати results іншим channel.

**Переваги:** дозволений service із високою репутацією; TLS; rotation endpoint без зміни binary; asymmetric tasking ускладнює просте flow correlation.

**Недоліки:** стабільні object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content може бути seized або changed.

**Процедура:** використовувати [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): розмістити encoded pointer на одному власному container, fetch/decode із short-lived client, звернутися до другого власного service, зберегти обидва logs, потім виконати teardown.

**Виявлення:** пов’язувати незвичний process → stable object read → decode → new destination; hash/preserve content і зберігати повні object paths, а не лише domain.

## Serverless, ephemeral container і cloud-NAT egress

**Механіка:** functions/short-lived jobs працюють за provider NAT або front; logical service залишається стабільним, поки instances і addresses обертаються.

**Переваги:** швидке розгортання/знищення; shared egress масштабу provider; мало local disk; еластична regional routing.

**Недоліки:** tenant, role, API, image, secret, invocation, billing і front-to-origin logs довговічні; cold-start і platform fingerprints; provider policy.

**Процедура:** (1) використати власний exercise tenant організації; (2) розгорнути benign function, що звертається лише до власного endpoint; (3) записати project/role/image/config; (4) викликати через кілька instances; (5) порівняти target IPs з audit/request IDs; (6) перевірити log retention; (7) видалити function, roles і secrets.

**Виявлення:** cloud audit/invocation logs, незвичне role creation, shared egress зі стабільною request grammar, image/layer і secret reuse, а також front-origin correlation.

## Authorized on-site drop

**Механіка:** інвентаризований small computer використовує local wired/Wi-Fi та outbound VPN/cellular rendezvous, представляючи local source.

**Переваги:** реалістичне тестування internal-origin; висока швидкість; можна тестувати NAC, physical inventory і egress controls.

**Недоліки:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF і camera evidence; втрата може розкрити credentials.

**Процедура:** дотримуватися [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) отримати точний письмовий дозвіл на розміщення; (2) записати serial, MAC, photo, location і retrieval time; (3) використовувати signed minimal image і short-lived mutual credentials; (4) обмежити outbound-only destinations/capabilities; (5) додати server-side quarantine і bandwidth limits; (6) перевірити SOC visibility і loss response; (7) отримати node, зберегти необхідні evidence, потім очистити згідно з погодженою lifecycle policy. Ніколи не ховати його в несанкціонованому місці.

**Виявлення:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera і physical inspection.

## Nearest-neighbor wireless pivot

**Механіка:** actor контролює host у радіусі target, а потім використовує target Wi-Fi credentials для віддаленого перетину boundary. APT28 застосовувала nearby compromised organizations таким чином.<sup>[[18]](#references)</sup>

**Переваги:** оператору не потрібно їхати; target бачить local radio source; обходить controls, що застосовуються лише до Internet entry.

**Недоліки:** потрібні nearby compromised/owned dual-radio host і valid access; RADIUS/NAC/AP та neighbor endpoint evidence; signal/device anomalies.

**Процедура:** відтворювати лише за допомогою [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): під’єднати власний pivot до neighbor і target lab SSIDs, пересилати лише один service, зібрати обидва AP/pivot logs, потім увімкнути EAP-TLS/device posture і підтвердити відмову другої спроби.

**Виявлення:** зіставляти RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login і physical presence; шукати nearby endpoints із simultaneous radios, forwarding і tunnels.

## Community mesh, delay-tolerant і offline store-and-forward

**Механіка:** traffic проходить через local peers, asynchronous gateways, removable media або scheduled queues замість однієї інтерактивної Internet session.

**Переваги:** працює під час disruption/censorship; delayed/batched delivery послаблює просте timing; для local communication немає central last mile.

**Недоліки:** висока latency; мала anonymity set; custody/physical metadata; malicious peers; data зрештою досягає gateway, який його бачить.

**Процедура:** (1) побудувати ізольовану власну three-node mesh або file queue; (2) шифрувати/authenticate content end to end; (3) прибрати direct Internet routes з origin; (4) переслати benign file після controlled delay; (5) перевірити, що лише gateway контактує з власним destination; (6) порівняти custody/timestamps; (7) зберегти необхідні evidence, потім очистити temporary media/queues під час approved closeout.

**Виявлення:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity і content identifiers. Довші correlation windows замінюють аналіз interactive flows.

## TURN relay і forced-relay WebRTC

**Механіка:** Traversal Using Relays around NAT (TURN) призначає public relay address і переносить UDP, TCP або TLS traffic між client і peers. ICE policy може примусово використовувати relay замість direct candidate. TURN вирішує reachability, а не загальну anonymity: server автентифікує client і бачить allocations, peers, time та volume.<sup>[[19]](#references)</sup>

**Переваги:** широко реалізований; працює з restrictive NAT; підтримує mobile WebRTC; peer не отримує direct transport address client, якщо relay-only policy застосовано правильно.

**Недоліки:** TURN operator бачить обидві суміжні сторони; application identity, media fingerprint і signaling залишаються; relay-only потребує bandwidth і latency; неправильна конфігурація все ще може збирати host або server-reflexive candidates.

**Процедура:** (1) розгорнути власний organization-owned TURN service із TLS і short-lived credentials; (2) обмежити realms, peers, ports, quotas і expiration; (3) налаштувати test application на relay-only ICE; (4) зателефонувати власному peer; (5) перевірити `getStats()` і packet capture, щоб підтвердити, що media передавалася лише через relay candidates; (6) відмовити relay і підтвердити відсутність direct fallback; (7) зберегти allocation logs для engagement.

**Виявлення:** signaling, browser process і TURN allocations пов’язують session із relay; networks бачать sustained flows до TURN ports або TLS endpoints; peer бачить allocated relay. **Captured node:** application state і ephemeral TURN credentials можуть розкрити realm і rendezvous service. Мінімізувати exposure за допомогою per-device short-lived credentials і залишати operator authentication лише на controller.

## Outbound-only rendezvous або reverse overlay

**Механіка:** node за NAT ініціює authenticated connection до organization-controlled broker. Operator окремо автентифікується на broker, який дозволяє вузький management channel; inbound port forwarding і direct operator-to-node route не потрібні.

**Переваги:** стабільність за NAT і captive last miles; central revocation і audit; зміна адреси field node не потребує operator discovery; чітко розділяє operator identity і node credential.

**Недоліки:** broker стає цінною correlation point; periodic keepalives впізнавані; broad tunnel може стати небезпечним pivot; втрата broker припиняє management.

**Процедура:** дотримуватися [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): видати одну scoped device identity, дозволити лише власний broker і approved management service, використовувати authenticated keepalive, застосувати fail-closed routing, перевірити address changes і reboot recovery та відкликати identity під час loss drill. WireGuard документує 25-second persistent keepalive як загалом корисний NAT interval, коли він справді потрібен.<sup>[[20]](#references)</sup>

**Виявлення:** broker та identity-provider logs пов’язують обидві сторони; access network бачить повторюваний encrypted destination/cadence; endpoint inventory показує overlay agent. **Captured node:** припускати розкриття device key, broker name, tunnel addresses і cached task data. Він не повинен містити operator private key, personal account або reusable controller token.

## Pull mailbox, message queue або object-store rendezvous

**Механіка:** field workload опитує authenticated mailbox для signed, pre-approved jobs і публікує обмежені results. Operator записує в queue через окремий control plane; interactive socket між ними відсутній.

**Переваги:** переносить intermittent links; розділяє timing і addressing; quotas та schemas обмежують capability; простий central audit і revocation.

**Недоліки:** polling cadence і стабільні object/queue names fingerprint system; provider logs пов’язують producer і consumer; delayed control; captured queued data може розкрити exercise.

**Процедура:** (1) створити одну engagement queue і одну device identity; (2) визначити signed schema benign, explicitly scoped jobs; (3) задати message TTL, maximum result size і rate; (4) дозволити node читати лише свою queue і писати лише у свій result prefix; (5) перевірити offline accumulation, duplicate delivery і revocation; (6) централізувати immutable access logs; (7) видалити queue після виконання retention requirements.

**Виявлення:** шукати periodic API calls незвичного process, стабільні bucket/object/queue paths, однакові user-agent або TLS behavior і послідовність fetch-then-new-connection. **Captured node:** local cache може розкрити pending jobs і object names; зберігати cache encrypted, bounded і disposable, зберігаючи authoritative controller logs.

## Dual-uplink failover і connection migration

**Механіка:** approved field node має два незалежні uplinks — наприклад venue Ethernet/Wi-Fi і organization cellular — та зберігає control session через overlay або message broker під час зміни routes. Це availability engineering, а не anonymity.

**Переваги:** переживає відмову одного provider, AP або captive portal; підтримує planned maintenance; дозволяє швидко ізолювати підозрілий path.

**Недоліки:** два providers створюють дві location/account records; одночасне використання полегшує correlation; route і DNS leaks під час failover; cellular co-location evidence залишається.

**Процедура:** (1) зареєструвати обидва organization-owned interfaces і providers; (2) призначити deterministic route priorities і health checks до власних endpoints; (3) прив’язати DNS і management до overlay; (4) не дозволяти secondary path приймати inbound traffic; (5) від’єднати кожен path і перевірити session recovery, source policy і відсутність direct destination access; (6) створити alert на незаплановану зміну path; (7) задокументувати data use і roaming limits.

**Виявлення:** зіставляти той самий device certificate, request grammar і timing між ASNs; local inventory бачить обидва radios; carriers/venues зберігають власні records. **Captured node:** обидва SIM/device identifiers і відомі SSIDs можуть бути видимими; використовувати organization assets і ніколи не поєднувати node з personal devices.

## Organization private APN або managed cellular tunnel

**Механіка:** carrier private APN розміщує enrolled SIMs у private routed domain або тунелює traffic до enterprise gateway. Це відокремлює device від public mobile Internet, але не приховує його від carrier або contracting organization.

**Переваги:** стабільна private addressing; carrier-level enrollment і traffic policy; відсутність public inbound exposure; корисно для authorized remote appliances.

**Недоліки:** subscriber, IMSI/IMEI, cell і billing attribution сильні; procurement lead time і cost; carrier/gateway outage; не anonymous для operator.

**Процедура:** (1) укласти APN contract на ім’я assessment organization; (2) додати до allowlist лише registered SIMs і gateway prefixes; (3) додати application-layer mutual authentication; (4) обмежити APN route rendezvous і update services; (5) протестувати SIM removal, roaming, public-Internet breakout і revocation; (6) контролювати carrier і gateway records; (7) під час closeout скасувати або quarantine кожну SIM.

**Виявлення:** carrier inventory і cell telemetry, APN gateway flows, SIM/IMEI mismatch і enterprise asset records. **Captured node:** SIM і modem ідентифікують contract навіть при encrypted storage; capture resilience означає швидке suspension і вузьку authorization, а не deniability.

## Long-range point-to-point wireless bridge

**Механіка:** directional Wi-Fi або інше licensed/unlicensed point-to-point radio з’єднує два owner-approved sites, із Internet egress на remote site. Це може змінити apparent IP location без commercial proxy.

**Переваги:** висока throughput; незалежність від intermediate wired carriers; контрольовані RF і routing; корисно для тестування segmentation і remote-site monitoring.

**Недоліки:** line-of-sight, spectrum, landlord і regulatory constraints; характерні RF emissions і hardware; обидва endpoints є physical evidence; weather/power/alignment впливають на stability.

**Процедура:** (1) отримати письмовий дозвіл для обох sites і перевірити spectrum/power rules; (2) обстежити path без transmission за межами approved parameters; (3) використовувати authenticated encryption і management VLAN; (4) обмежити bridge власним rendezvous або test subnet; (5) протестувати failover, alignment, power recovery і RF containment; (6) маркувати/інвентаризувати обидва radios; (7) видалити їх і перевірити reset configuration після exercise.

**Виявлення:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic і remote-site egress logs. **Captured node:** configuration розкриває peer і management domain; використовувати унікальні exercise credentials, без personal management accounts, і швидко відкликати peer key.

## Consented cooperative або community exit

**Механіка:** volunteers або partner organizations свідомо запускають relays за опублікованою policy. Traffic виходить зі shared community pool, а coordination layer веде облік abuse і revocation.

**Переваги:** різноманітні non-cloud networks; explicit consent безпечніша за proxyware; shared governance може розподіляти trust; корисно для research і censorship-resilience studies.

**Недоліки:** малі pools і membership records зменшують anonymity; exit operators отримують complaints і бачать traffic metadata; malicious participants, variable uptime і jurisdiction differences.

**Процедура:** (1) опублікувати acceptable-use і logging policy; (2) отримати informed opt-in від кожного operator; (3) видати unique relay identity і обмежити destinations/rates; (4) надати abuse handling і one-action revocation; (5) під час testing надсилати лише authorized traffic до власних endpoints; (6) виміряти churn і correlation exposure; (7) чисто видалити relay після завершення consent.

**Виявлення:** membership/control-plane records, relay certificates, common software fingerprint і exit behavior ідентифікують pool. **Captured node:** relay configuration може ідентифікувати cooperative, але не повинна містити client identities; client-to-session accountability зберігати на authorized controller із access control.

## IPv6 temporary addresses і prefix rotation

**Механіка:** IPv6 privacy extensions створюють temporary interface identifiers, щоб стабільна address не використовувалась для кожного outbound connection. Зміна provider prefix може додати rotation, але delegated prefix, subscriber record і upper-layer fingerprint залишаються.<sup>[[21]](#references)</sup>

**Переваги:** зменшує passive long-term tracking за стабільним interface identifier; вбудовано у common operating systems; відсутні relay overhead.

**Недоліки:** не забезпечує source anonymity; ISP і local network усе ще знають prefix/device; DNS, accounts і browser state пов’язують sessions; address churn ускладнює allowlists і logging.

**Процедура:** (1) перевірити current stable і temporary addresses на власному client; (2) увімкнути OS-supported privacy-address default, а не third-party spoofing; (3) багаторазово звернутися до власного IPv6 endpoint протягом address lifetimes; (4) підтвердити, що inbound services прив’язані лише до intended stable addresses; (5) зберігати DHCPv6/RA/neighbor і точні endpoint logs; (6) протестувати VPN/firewall behavior для кожної IPv6 address.

**Виявлення:** корелювати delegated prefix, layer-2 identity, neighbor discovery, account і endpoint telemetry, а не вважати одну address одним device. **Captured node:** network profiles та interface identifiers залишаються; temporary addressing запобігає одному passive identifier, але не forensic attribution.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 і meek

**Механіка:** pluggable transport змінює вигляд першого Tor connection або спосіб досягнення bridge. Snowflake використовує short-lived volunteer WebRTC proxies, WebTunnel нагадує ordinary HTTPS, obfs4 протидіє простій protocol identification і active probing, а meek пересилає через supported web infrastructure. Це censorship-circumvention transports у Tor, а не додаткові end-to-end anonymity layers.<sup>[[22]](#references)</sup>

**Переваги:** корисно, коли direct Tor або відомі relays blocked; Snowflake уникає стабільної public bridge address; інтегровано в maintained Tor clients; destination усе ще отримує звичайні Tor properties.

**Недоліки:** низька або змінна performance; broker/front/bridge і local network бачать різні metadata; transport fingerprints і blocking залишаються можливими; volunteer proxy не замінює Tor і не повинен вважатися trusted для application plaintext.

**Процедура:** (1) встановити й перевірити official Tor Browser або supported Tor client; (2) обрати вбудований transport у Connection/Bridges; (3) під’єднатися лише до власної diagnostic page; (4) підтвердити, що page бачить Tor exit, а не Snowflake/WebTunnel peer; (5) порівняти bootstrap і performance; (6) відмовити transport і підтвердити, що client не під’єднується silently direct; (7) після test повернутися до standard supported configuration.

**Виявлення:** censor може поєднати destination allowlists, TLS/WebRTC behavior, broker discovery і flow analysis; endpoints розкривають Tor і transport configuration. **Capture-resilient OPSEC:** використовувати standard client, ніколи не копіювати personal browser state і припускати, що bridge/broker history можна відновити. **Monitoring:** стежити за Tor bootstrap logs, unexpected direct DNS/connection attempts і controller-side owned-page observations; transport failure не є доказом discovery.

## Refraction networking або decoy routing

**Механіка:** cooperating network operator виявляє covert signal у traffic, що виглядає адресованим allowed decoy, і перенаправляє flow до circumvention proxy. Deployment потребує infrastructure у network path; client не може створити це лише вибором innocent website.<sup>[[23]](#references)</sup>

**Переваги:** apparent destination може бути складно заблокувати без collateral damage; не потрібно розповсюджувати public bridge address; корисна research model для on-path-assisted circumvention.

**Недоліки:** спеціалізована ISP/transit participation; deployability і performance залежать від routing; client-to-decoy flow і proxy-side activity залишаються; global або cooperating observer може корелювати timing.

**Процедура:** не надсилати signals через uninvolved networks. Відтворити architecture в isolated lab: (1) створити owned client, router, decoy і proxy namespaces; (2) використати benign tagged test request; (3) дозволити owned router перенаправляти лише цей tag до proxy; (4) записати pre/post-routing tuples і request IDs; (5) порівняти ordinary і signaled flows; (6) протестувати false positives і removal; (7) знищити lab routes.

**Виявлення:** authorized network operators можуть перевіряти routing divergence, unusual client hello/tag behavior і decoy-versus-back-end flow discrepancies. **Capture-resilient OPSEC:** research client має містити лише test keys і documentation addresses. **Monitoring:** порівнювати signed lab-router decisions із proxy arrivals; не зондувати production transit providers, щоб визначити, чи виявили вони signaling.

## Content-addressed gateway або cached peer retrieval

**Механіка:** HTTP gateway отримує IPFS content identifier (CID), можливо з cache або peers, і повертає verifiable content client. Original publisher може бачити gateway або інших peers, а не final reader; gateway бачить reader IP і requested CID. Native peer-to-peer retrieval відкриває client peers і DHT/routing participants.<sup>[[24]](#references)</sup>

**Переваги:** publisher і reader можуть бути розділені caches; immutable content можна перевірити hash; replicated data переживає втрату одного host; HTTP clients не потребують native peer stack.

**Недоліки:** public CIDs і gateway logs розкривають interests; timing першого retrieval може пов’язати publisher і reader; malicious web content і path-style same-origin hazards; public gateways працюють best-effort і забороняють abuse.

**Процедура:** (1) опублікувати harmless test file у власній private IPFS swarm або власному gateway; (2) записати CID; (3) отримати його через окремий власний HTTP gateway із subdomain isolation; (4) перевірити bytes за CID; (5) повторити після caching; (6) порівняти publisher, peer і gateway logs; (7) unpin і видалити test content після завершення retention.

**Виявлення:** gateways logs записують source/CID; DHT і peer connections розкривають retrieval; endpoint history і file hashes ідентифікують content. **Capture-resilient OPSEC:** не зберігати private publishing key на read-only field client і шифрувати sensitive content до content addressing. **Monitoring:** створювати alerts на unexpected pinning, peer-set change, CID requests поза allowlist або gateway account notices.

## Private information retrieval service

**Механіка:** Private Information Retrieval (PIR) дозволяє client отримати один record із database, криптографічно приховуючи вибраний index від server за заявленою single- або multi-server threat model. Це захищає query selection для bounded dataset, але не є general web access чи IP anonymity.<sup>[[25]](#references)</sup>

**Переваги:** сильна application-specific query privacy; вимірювана leakage model; корисно для key directories, blocklists або малих public databases; може зменшити потребу розкривати точні lookup terms.

**Недоліки:** computation/bandwidth overhead; server дізнається connection time/IP, якщо не використовується relay; dataset version, response size і application state можуть розділяти users; maturity implementation різниться.

**Процедура:** (1) розгорнути audited PIR implementation на synthetic owned database; (2) опублікувати dataset version і parameters; (3) отримати кілька indices із однаковими request sizes; (4) локально перевірити correctness; (5) порівняти server logs і підтвердити відсутність index; (6) протестувати malicious/truncated responses і version mismatch; (7) документувати точне privacy assumption, а не називати це anonymous browsing.

**Виявлення:** networks бачать service use і volume; endpoint telemetry розкриває client і final record use; compromised server може змінювати datasets або timing. **Capture-resilient OPSEC:** зберігати на client лише public database parameters і bounded cache. **Monitoring:** перевіряти signed dataset roots, fixed request shapes, зміни error-rate і server-key rotations.

## Constrained server-side fetcher, preview або rendering service

**Механіка:** remote service отримує або рендерить URL і повертає screenshot, metadata або sanitized content. Destination бачить адресу fetcher; service бачить requester, URL і result. Зловживання link-preview bots, security scanners або third-party URL fetchers не є authorized proxy use.

**Переваги:** ізолює active content від workstation; destination отримує controlled fetcher fingerprint; можна застосувати обмеження file type, size, destination і rendering; disposable execution environment.

**Недоліки:** service має повне знання request; account/API/billing records; SSRF і data-exfiltration risk; scripts, authentication та interactive sites можуть не працювати; унікальні URLs пов’язують requester і fetch.

**Процедура:** (1) розгорнути organization-owned fetcher із strict allowlist власних test domains; (2) блокувати private, link-local, metadata і redirect-to-unapproved addresses; (3) обмежити methods, redirects, bytes і render time; (4) вилучити credentials/cookies; (5) подати власний URL; (6) порівняти requester, fetcher і target logs; (7) знищити render instance і зберегти central audit згідно з policy.

**Виявлення:** target бачить service ASN/fingerprint; provider і controller logs пов’язують requester із URL; endpoint process/API calls показують submission. **Capture-resilient OPSEC:** використовувати один short-lived project token без довільної destination authority. **Monitoring:** alerts на allowlist denials, redirect violations, fetches без controller job ID і provider abuse notices.

## Anycast rendezvous pool

**Механіка:** кілька organization-controlled nodes рекламують або front-ять один stable service address, а routing обирає найближчий instance. Anycast покращує availability і приховує окремий back-end від client, але operator усе одно контролює всі instances, а service address стабільна.<sup>[[26]](#references)</sup>

**Переваги:** resilient regional ingress; field reconfiguration не потрібна при відмові instance; DDoS/load distribution; central policy може переміщати sessions між відомими nodes.

**Недоліки:** BGP/CDN і provider records ідентифікують organization; path changes можуть ламати stateful sessions; monitoring відрізняється за client location; одну stable address легко заблокувати або кластеризувати за reputation.

**Процедура:** використовувати provider-supported organization project або isolated routing lab: (1) розгорнути два identical authenticated health endpoints; (2) відкрити одну documented service address; (3) зберігати session state на broker, а не на edge; (4) withdraw один node і перевірити reconnection; (5) перевірити certificate, policy і log consistency; (6) створити alert на unauthorized origin/region; (7) видалити advertisements і credentials під час closeout.

**Виявлення:** BGP/RPKI/history, provider tenancy, certificates і identical service behavior ідентифікують pool. **Capture-resilient OPSEC:** edge зберігає лише regional service identity і не має operator або fleet-enrollment key. **Monitoring:** зондувати кожен region з authorized monitors, порівнювати route origin і configuration digest, а unexpected origin вважати incident.

## QUIC migration і Multipath TCP continuity

**Механіка:** QUIC connection IDs можуть утримувати client session під час NAT rebinding або address changes; Multipath TCP може переносити один reliable byte stream через кілька subflows. Вони покращують continuity під час переходів Wi-Fi/cellular, але відкривають old і new paths common peer та можуть спрощувати cross-path correlation.<sup>[[27]](#references)</sup>

**Переваги:** швидше recovery під час uplink changes; application session не мусить перезапускатися; MPTCP поєднує resilience і throughput; корисно для approved field nodes.

**Недоліки:** не anonymity; peer бачить migration/subflows; connection identifiers і simultaneous traffic пов’язують paths; middlebox/carrier support різниться; duplicated provider records збільшують exposure.

**Процедура:** (1) увімкнути supported transport лише між owned field client і rendezvous; (2) автентифікувати application незалежно від IP; (3) почати bounded transfer через approved Wi-Fi; (4) перейти на organization cellular; (5) підтвердити path validation, data integrity і відсутність clear/direct fallback; (6) протестувати idle timeout і return; (7) зберігати broker records кожного path transition.

**Виявлення:** peer безпосередньо бачить address migration або MPTCP subflows; access providers бачать свою частину; connection IDs, TLS identity і timing пов’язують обидва. **Capture-resilient OPSEC:** зберігати лише device-scoped session material і швидко завершувати resumable state. **Monitoring:** alert на impossible path changes, simultaneous unapproved networks, migration storms і resumption після quarantine.

## Managed CI/CD або ephemeral automation runner egress

**Механіка:** organization-owned workflow виконує bounded network check на hosted runner. Destination бачить cloud runner address, тоді як platform зберігає repository, actor, workflow, token, log і billing attribution. Це remote execution із підзвітним egress, а не anonymity від provider.<sup>[[28]](#references)</sup>

**Переваги:** disposable clean environment; reproducible job definition; inbound connection не потрібне; корисно для geographically distributed availability checks; strong controller audit.

**Недоліки:** platform і organization ідентифікують initiator; broad workflow tokens і untrusted pull requests небезпечні; shared IP reputation; logs/artifacts можуть зберігати secrets або target data.

**Процедура:** (1) створити private organization repository і environment для assessment; (2) дозволити лише manually approved, fixed benign jobs до власних endpoints; (3) використовувати minimal read-only workflow permissions без production secrets; (4) виконати check; (5) порівняти workflow, provider і target records; (6) перевірити, що artifacts не містять credentials; (7) видалити environment token і зберегти необхідний audit.

**Виявлення:** provider audit і workflow logs дають пряме attribution; targets ідентифікують runner ASNs/ranges і stable request grammar. **Capture-resilient OPSEC:** ніколи не розміщувати field-device, signing, wallet або cloud-administrator secrets у runner variables. **Monitoring:** вимагати branch/environment approval і створювати alerts на workflow edits, fork execution, secret reads і unexpected destinations.

## Non-IP local first hop до власного gateway

**Механіка:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio або serial/optical link передає bounded messages від nearby sensor до owner-approved Internet gateway. Field device сам не має Internet route; gateway є єдиним egress. Radio range і protocol limits роблять це telemetry/store-and-forward design, а не interactive anonymous Internet.

**Переваги:** прибирає Internet stack і credentials із найменшого field device; низьке енергоспоживання; gateway централізує policy; може долати тимчасові dead zones.

**Недоліки:** RF/physical discovery, pairing і device identifiers; мала bandwidth і range; gateway усе одно пов’язує messages; spectrum і encryption restrictions різняться; capture може розкрити queued data.

**Процедура:** (1) отримати site і spectrum approval; (2) pair один власний sensor з одним власним gateway за допомогою unique keys; (3) визначити signed fixed-size message types, TTL і rate; (4) не надавати sensor default IP route; (5) дозволити gateway пересилати лише до власного collector; (6) протестувати replay, range loss і gateway outage; (7) інвентаризувати й отримати обидва devices.

**Виявлення:** RF survey, pairing database, physical inspection і gateway process/flow logs розкривають path. **Capture-resilient OPSEC:** sensor містить лише pairwise key і bounded encrypted queue, ніколи operator, Wi-Fi, cellular або controller credentials. **Monitoring:** alert на new peers, sequence rollback, key failure, unusual RF rate і messages через unregistered gateway.

## Матриця exposure під час capture/compromise

Ця таблиця застосовує перевірку capture-resilience до кожного наведеного family. «Мінімізувати» означає зменшити кількість secrets і blast radius на authorized assets; це ніколи не означає стирати evidence або приховуватися від investigation.

| Technique family | Що може розкрити captured endpoint/relay | Мінімальний authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | відомі networks, DHCP/portal history, MACs, tunnel peer | окремий organization device; private MAC за підтримки; без personal accounts; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs і adjacent hop | одна identity на engagement; короткий TTL; вузькі routes; broker-side revocation; без master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers і cached requests | мінімізувати payload identifiers; pin approved config; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state і peer history | standard client; окремі service keys; encrypted minimal state; rotate compromised service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files і remote tenant | phishing-resistant MFA на gateway; disabled transfer channels; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider і approximate location | organization contract; без personal co-location; вузька APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | лише consented/owned nodes; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment і billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit centrally retained |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results і custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement; unique device identity; no operator secret; tamper/state telemetry; revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route і uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history і endpoint/application state | розглядати лише як anti-tracking; зберігати network logs; поєднувати з endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state і research keys | standard client або isolated lab; без personal browser state; без production signaling |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway або service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state і всі відомі paths | лише regional identity; короткий resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs і artifacts | least-privilege workflow; без production/field/wallet secrets; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages і gateway identity | unique pairwise key; fixed message schema; без Wi-Fi/cellular/operator credential |

## Monitoring possible discovery for every access family

Жоден client-side test не доводить, що investigator або defender спостерігає. Контролюйте зміни в системах, якими володіє engagement, підтверджуйте їх controller/client і зупиняйтеся замість probing observers. Наведені рядки охоплюють усі перелічені techniques; поєднуйте їх із [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Covered techniques | Безпечні controller-side signals | Умова quarantine/stop |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation або provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback або out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer або provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health і owned canary page | personal-account crossover, unexpected non-Tor connection або compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association і content hash | unknown peer/gateway, sequence rollback, unauthorized content або missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export і cloud audit | unknown login/workflow edit, secret read, unexpected destination або project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature і TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use або site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation і broker session | impossible migration, simultaneous unapproved paths або session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root або provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Вибір і тестування path

1. Назвати observer, якого потрібно усунути, і data, яку потрібно приховати.
2. Обрати найменш складне family, що це забезпечує.
3. Намалювати source, entry, traversal, exit, DNS, account і payment observers.
4. Використовувати окрему endpoint/application identity.
5. Перевірити IPv4, IPv6, DNS, WebRTC/application bypass і destination view.
6. Зламати кожен hop і підтвердити, що failure є closed.
7. Порівняти logs кожного контрольованого component.
8. Записати residual timing, provider, endpoint і physical links.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
