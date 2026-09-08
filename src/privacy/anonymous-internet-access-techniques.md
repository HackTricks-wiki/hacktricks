# Каталог методів анонімного доступу до Internet

{{#include ../banners/hacktricks-training.md}}

Це канонічний перелік шляхів доступу. Він охоплює протокольні та операційні **сімейства**, а не назви всіх постачальників. Жоден Internet-шлях не гарантує анонімності: обліковий запис, браузер, кінцева точка, час, оплата, cloud-control-plane та фізичні докази можуть викрити навіть маршрут, що здається ідеальним.

Кожен запис використовує однакові поля. «Procedure» означає законне розгортання або емуляцію у власній лабораторії. Якщо реальна техніка залежить від компрометації маршрутизатора, викрадення доступу чи зловживання небажаним посередником, відтворення замінює ці системи власними системами, що належать учасникам вправи.

## Матриця охоплення

| Сімейство | Що бачить призначення | Найсильніша властивість | Швидкість | Обробка |
|---|---|---|---|---|
| Shared NAT/CGNAT | спільну публічну адресу | неоднозначність між абонентами | висока | придатне до розгортання |
| VPN, VPS, SOCKS/HTTP/SSH proxy | адресу relay | швидке розділення адреси джерела | висока | придатне до розгортання |
| Multi-hop/split relay, MASQUE | кінцевий proxy | розподіл знань або повний IP-тунель | висока/середня | з trusted relay |
| Tor, bridge, onion service | exit або onion identity | багатосторонній маршрут і типовий браузер | середня | придатне до розгортання |
| I2P, GNUnet, mixnet | peer/gateway overlay | overlay або стійкість до аналізу часу | низька/змінна | залежить від застосунку |
| OHTTP/ODoH, Private Relay | gateway/egress | розподіл джерела та запиту | висока | лише підтримувані застосунки |
| Public Wi-Fi, travel router | адреса майданчика/тунелю | зміна місця та шляху доступу | висока | потрібен дозвіл |
| Cellular/eSIM, satellite | адреса оператора/провайдера | незалежний фізичний uplink | висока/змінна | оператор бачить доступ |
| Remote browser/jump host | віддалене workspace | розділення endpoint та egress | висока | придатне до розгортання |
| Residential/mobile proxy | адреса споживчої мережі/оператора | вигляд споживчої мережі | висока | критичні згода й походження |
| ORB/compromised relay | адреса іншої жертви | приховування джерела та запозичена репутація | висока | лише відтворення у власній лабораторії |
| CDN/fronting/redirector | front-адреса CDN | захист back-end-інфраструктури | висока | потрібен дозвіл провайдера/власника |
| Fast flux/DGA/dead drop | змінний вузол/сервіс | стійкість до виявлення інфраструктури | змінна | лише власна лабораторія |
| Drop/nearest-neighbor | адреса поруч із ціллю | перетин географічної/мережевої межі | висока | лише лабораторія власника |
| Store-and-forward/offline | gateway або фізичний receiver | зменшення інтерактивного часового зв’язку | низька | залежить від застосунку |
| Pluggable/refraction transport | Tor entry або proxy diversion | стійкий до цензури доступ | змінна | підтримуваний client або lab |
| IPFS gateway/PIR/remote fetcher | gateway або application service | розділення publisher/query/request | змінна | лише обмежений застосунок |
| Anycast/QUIC/MPTCP | стабільний broker або кілька subflow | rendezvous і безперервність сесії | висока | доступність, не анонімність |
| CI/CD automation runner | адреса hosted runner | одноразовий контрольований egress | висока | лише власний workflow |
| Non-IP local first hop | gateway організації | вилучення Internet stack із sensor | низька | схвалене власником розгортання |

## Прямий shared NAT і carrier-grade NAT

**Mechanics:** кілька користувачів спільно використовують публічну адресу; access provider зіставляє subscriber-адреси й порти з публічним tuple.

**Pros:** швидко; спеціальний client не потрібен; сама IP-адреса на боці призначення може ідентифікувати лише домогосподарство, майданчик або пул оператора.

**Cons:** provider може зберігати відповідності subscriber/port/time; облікові записи та fingerprints залишаються; інші користувачі можуть зіпсувати репутацію адреси.

**Procedure:** (1) перевірити, чи авторизований доступ використовує NAT/CGNAT; (2) записати точні public IP і source port на власному endpoint; (3) розділити application identities; (4) не вважати shared addressing засобом privacy; (5) застосувати сильніший шлях, якщо ISP не повинен знати призначення.

**Detection:** destinations мають зберігати source port і точний час, а не лише IP. Providers зіставляють NAT allocation logs; investigators об’єднують account/device/browser evidence.

## Commercial VPN

**Mechanics:** зашифроване full-tunnel connection завершується на VPN; destinations бачать його egress. VPN зазвичай може пов’язати source, timing і destinations.

**Pros:** швидко; просто; захищає від локального пасивного спостереження; стабільні або спільні exits; придатне для контрольованого red-team egress.

**Cons:** концентрована довіра; billing/login telemetry; помилки kill-switch/DNS/IPv6; shared exits часто блокуються через репутацію.

**Procedure:** (1) визначити provider, owner, jurisdiction, retention і assessment policy; (2) встановити підписаний офіційний client; (3) увімкнути full tunnel, always-on і fail-closed; (4) свідомо маршрутизувати DNS та IPv6; (5) перевірити observed IPv4/IPv6/DNS на власному endpoint; (6) зупинити/перепідключити tunnel і підтвердити відсутність clear fallback.<sup>[[1]](#references)</sup>

**Detection:** local networks бачать довгий зашифрований flow до VPN infrastructure; providers мають authentication/connection records; destinations використовують ASN/reputation, account, TLS/browser і behavioral correlation.

## Self-hosted VPN або rented VPS egress

**Mechanics:** operator контролює WireGuard/OpenVPN gateway або пересилає traffic через rented server.

**Pros:** передбачувана швидкість; фіксована адреса для allowlist; власні logging/firewall; добрий incident control.

**Cons:** мала anonymity set; cloud tenant, payment, source login, API та image history пов’язують operator; новий distinctive server легко кластеризувати.

**Procedure:** (1) створити engagement-specific organization project; (2) розгорнути supported image і fixed address; (3) обмежити management MFA/key-based administration; (4) налаштувати full-tunnel egress і DNS; (5) за можливості дозволити лише scoped destinations; (6) перевірити leak/failure behavior; (7) зберігати controller audit records; (8) знищити credentials і resources під час teardown.

**Detection:** зіставляти hosting ASN, first-seen address, certificate/service fingerprint і scanning behavior; cloud owners використовують control-plane, console, billing і flow logs.

## HTTP CONNECT, SOCKS і SSH forwarding

**Mechanics:** application просить proxy відкрити TCP stream; SOCKS також може передавати name resolution і UDP залежно від версії; SSH пересилає streams усередині одного зашифрованого session.

**Pros:** легкі; per-application; швидкі; корисні для chaining і segmented networks.

**Cons:** applications можуть обходити proxy; DNS може leak; proxy бачить сусідні endpoints; browser state зберігається; open proxies можуть бути пастками або compromised systems.

**Procedure:** (1) розгорнути proxy на власному host; (2) вимагати authentication і обмежити source/destination; (3) налаштувати один одноразовий application profile; (4) забезпечити remote DNS resolution за потреби; (5) перевірити власним DNS/HTTP endpoint; (6) заблокувати direct egress для workload; (7) перевірити та змінити proxy credentials.

**Detection:** виявляти tunnel-capable processes, CONNECT/SOCKS negotiation, довгі SSH sessions і destinations, несумісні з application; proxy logs відновлюють streams.

## URL-rewriting web proxy і browser proxy extension

**Mechanics:** website отримує destination і переписує links/forms через власний origin, або extension спрямовує browser requests до proxy. Destination бачить service, а service може бачити plaintext після TLS termination, а також inject або зберігати content.

**Pros:** system-wide client не потрібен; швидко для простого browsing; працює там, де VPN встановити неможливо.

**Cons:** proxy може читати credentials/content, змінювати downloads і fingerprint users; scripts/WebSockets/downloads можуть обходити proxy; browser extension має широкі privileges; мала anonymity set і часте blocking.

**Procedure:** (1) використовувати лише organization-operated proxy для authorized testing; (2) ізолювати його в disposable browser без personal accounts; (3) заборонити введення passwords і sensitive downloads; (4) перевірити на власній сторінці всі subresources; (5) протестувати WebSocket, download і form behavior; (6) видалити extension/profile після використання.

**Detection:** destination logs фіксують proxy; enterprise proxy/DNS і extension inventory визначають service; content-security/reporting або власні canary subresources виявляють direct bypass; proxy logs пов’язують user session із targets.

## Multi-hop proxy або provider multi-hop VPN

**Mechanics:** entry бачить source, а один чи кілька traversal relays відокремлюють його від exit, який бачить destination.

**Pros:** звичайний relay не потребує бачити обидва кінці; compromise/seizure одного вузла розкриває менше; гнучка географія.

**Cons:** спільне адміністрування/logs руйнує розподіл; latency; timing correlation; більше помилок і DNS routes; той самий account/payment може об’єднати всі hops.

**Procedure:** (1) визначити, якого observer усуває кожен hop; (2) для важливого separation використовувати незалежно адміністровані власні/схвалені relays; (3) примусити workload мати лише entry access; (4) кожному relay дозволити доступ тільки до next hop; (5) перевірити logs на кожному рівні; (6) зупинити кожен hop і підтвердити fail-closed. Відтворювати через [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection:** зіставляти adjacent NetFlow timing/volume, повторні proxy handshakes і спільну controller infrastructure; не визначати географію operator за exit.

## Split-knowledge application relay і OHTTP

**Mechanics:** client шифрує stateless HTTP message для gateway і надсилає його через relay. Relay бачить client IP, але не request; gateway бачить request, але зазвичай лише relay IP.

**Pros:** сильний, auditable privacy partition для підтримуваних requests; менші overhead, ніж у загальних anonymity networks.

**Cons:** не довільний browsing; cookies/authentication можуть знову зв’язати користувача; collusion relay/gateway і traffic analysis залишаються; application має це реалізувати.

**Procedure:** (1) вибрати application із явною підтримкою RFC 9458; (2) перевірити gateway keys через офіційний configuration path; (3) уникати стабільних per-user fields; (4) надсилати лише supported stateless request; (5) порівняти relay, gateway і target logs; (6) протестувати key rotation/failure без direct fallback.<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoints показують initiating process і OHTTP relay; gateways виявляють malformed/replayed traffic; timing і stable payload/account fields можуть корелювати requests.

## MASQUE CONNECT-UDP/CONNECT-IP і HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT через TLS/QUIC передає UDP або IP packets через proxy. Він може реалізувати сучасний VPN-like tunnel і змішувати transport з HTTP/3, але proxy залишається observer.<sup>[[3]](#references)</sup>

**Pros:** ефективне multiplexing/roaming; підтримка UDP або full IP; розгортання через сучасну HTTP infrastructure.

**Cons:** не anonymity network; proxy/account бачить source і destinations; QUIC/HTTP fingerprints і well-known paths видимі endpoints/providers.

**Procedure:** (1) використовувати client/service із documented support RFC 9298/9484; (2) authenticate proxy certificate/configuration; (3) визначити allowed target routes; (4) увімкнути encrypted DNS усередині path; (5) перевірити UDP, TCP, IPv6 і failover на власних endpoints; (6) перевірити proxy request і flow logs.

**Detection:** endpoints бачать client process і virtual interface; networks можуть класифікувати sustained QUIC/TLS до proxy; proxy logs розкривають CONNECT target/path і assigned routes.

## Tor Browser

**Mechanics:** Tor вибирає guard, middle і exit relays; layered encryption обмежує видимість кожного relay. Tor Browser додає standardized browser, призначений для протидії fingerprinting.

**Pros:** велика public anonymity set; жоден звичайний relay не знає обидва кінці; destination unlinkability без власних servers.

**Cons:** повільніше; переважно TCP; exit reputation/blocks; logins і disclosures ідентифікують user; залишається low-latency timing correlation.

**Procedure:** (1) завантажити й перевірити Tor Browser із project; (2) залишити defaults і не додавати extensions; (3) вибрати відповідний security level; (4) створити окремі identity/session; (5) уникати identifying accounts і зовнішніх active documents; (6) використовувати HTTPS або authenticated onion services; (7) перевіряти exit лише власним endpoint.<sup>[[4]](#references)</sup>

**Detection:** local networks можуть ідентифікувати відомий guard traffic без bridge/transport; destinations бачать exits і Tor Browser behavior; end-to-end observers корелюють timing/volume.

## Tor bridges і pluggable transports

**Mechanics:** непублічний bridge замінює public guard; obfs4, Snowflake або WebTunnel змінюють first-hop transport для протидії простому blocking/probing.

**Pros:** обходять censorship і приховують очевидні public-relay destinations; після entry зберігають Tor circuit.

**Cons:** transport patterns/bridge discovery все ще можливі; змінна performance; не захищають від accounts або global timing.

**Procedure:** (1) спочатку спробувати direct Tor; (2) у Tor Browser Connection settings вибрати вбудований supported transport або запросити official bridge; (3) не використовувати random binaries/lists; (4) підключитися і виконати benign test; (5) перевірити reconnect і clock; (6) зберегти стандартні browser settings.<sup>[[5]](#references)</sup>

**Detection:** censors використовують destination discovery, protocol/flow classification і active probing; defenders мають відрізняти circumvention від compromise та враховувати endpoint process/context.

## VPN before Tor і Tor before VPN

**Mechanics:** VPN-before-Tor приховує direct Tor use від access ISP, але відкриває source VPN. Tor-before-VPN передає VPN post-Tor traffic і часто стабільну customer/tunnel identity.

**Pros:** усуває конкретного observer за правильного проєктування; може досягати networks, що блокують один layer.

**Cons:** складність, uncommon fingerprint, leaks, менша anonymity set і false confidence; Tor Project вважає комбінації advanced.<sup>[[6]](#references)</sup>

**Procedure:** (1) записати, якого observer усунуто і якого додано; (2) використати disposable environment; (3) встановити лише intended outer path; (4) застосувати firewall routes; (5) перевірити DNS/IPv4/IPv6 і порядок кожної failure; (6) порівняти visibility обох providers; (7) відмовитися від stack без вимірюваної переваги.

**Detection:** local/VPN/Tor observers бачать різні adjacent layers; timing залишається end-to-end; unusual nested tunnel fingerprints і provider accounts можуть пов’язати sessions.

## Onion service

**Mechanics:** client і service будують Tor circuits до rendezvous, приховуючи service IP та уникаючи exit.

**Pros:** захист розташування source і service; end-to-end onion authentication; відсутній public inbound port; optional client authorization.

**Cons:** origin leaks через updates/analytics/errors; onion key критичний; application identity/timing і host compromise залишаються.

**Procedure:** (1) ізолювати application і bind лише до loopback/socket; (2) встановити supported Tor; (3) налаштувати v3 onion service за official instructions; (4) захищати/backup key лише за потреби стабільної identity; (5) додати client authorization для closed use; (6) вилучити third-party fetches; (7) зовні перевірити недоступність origin.<sup>[[7]](#references)</sup>

**Detection:** host/network defenders знаходять Tor process/configuration і outbound circuits; application errors, DNS, certificates або third-party resources можуть викрити origin.

## I2P internal services

**Mechanics:** I2P використовує окремі односпрямовані inbound/outbound tunnels для destinations усередині overlay; public-Internet outproxies додають trust point.

**Pros:** decentralized internal publishing; відсутня залежність від official exit; окремі inbound/outbound paths.

**Cons:** не general web replacement; менша ecosystem; тривала peer behavior; outproxy може спостерігати public browsing.

**Procedure:** (1) встановити з official source; (2) використати dedicated context; (3) дозволити integration/bandwidth stabilization; (4) звернутися до власного I2P-native service; (5) не використовувати outproxies без явної потреби; (6) перевірити shutdown без direct fallback; (7) перевірити local peer/service logs.<sup>[[8]](#references)</sup>

**Detection:** local networks бачать long-lived peer traffic і bootstrap behavior; endpoints розкривають router/application processes; outproxies logs фіксують exits.

## Mixnets

**Mechanics:** fixed-size packets, batching, delay, reordering і cover traffic зменшують timing correlation; gateways з’єднують applications.

**Pros:** краща стійкість до timing analysis, ніж у low-latency proxies; придатні для asynchronous messages/transactions.

**Cons:** latency, bandwidth overhead, менше deployment і application limits; gateway/account metadata може зберігатися.

**Procedure:** (1) вибрати maintained client і supported application; (2) прочитати actual threat model; (3) встановити в окремій compartment; (4) надіслати benign data власному endpoint; (5) виміряти latency/reliability і reply path; (6) перевірити gateway failure; (7) не вимикати delays/cover traffic заради швидкості.<sup>[[9]](#references)</sup>

**Detection:** endpoints ідентифікують client; access networks класифікують gateways/packet cadence; gateways/exits бачать adjacent roles, а ширша correlation потребує довших статистичних вікон.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet може маршрутизувати publish/search/download requests через peers і додавати cover traffic відповідно до anonymity level. Документація попереджає, що default level 1 не вимагає cover traffic, а потужний traffic analysis може визначити origin.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing; налаштовувана вимога cover traffic.

**Cons:** не звичайний anonymous web access; performance/storage cost; обмеження peers і traffic analysis; GNUnet VPN documentation зазначає, що його IP overlay не забезпечує good anonymity.

**Procedure:** (1) встановити maintained official build; (2) ізолювати test peer; (3) обмежити bandwidth/storage; (4) опублікувати harmless unique test file з обраним anonymity level; (5) отримати його з іншого власного peer; (6) записати cover-traffic і latency; (7) не стверджувати, що IP VPN component забезпечує еквівалентну anonymity.

**Detection:** peer bootstrap, overlay traffic, local datastore/process і file identifiers; broad observer може зіставити traffic volume з cover traffic.

## Encrypted DNS, ODoH і ECH

**Mechanics:** DoH/DoT/DoQ шифрують до resolver; ODoH розділяє client address і query між proxy та resolver; ECH шифрує inner TLS ClientHello/server name.

**Pros:** усуває plaintext DNS/SNI від деяких local observers; ODoH розподіляє knowledge про source/query.

**Cons:** не IP-anonymity path; resolver/proxy/server зберігають свої roles; destination IP/timing/volume і endpoint залишаються; fallback може leak.

**Procedure:** (1) визначити, хто володіє DNS: OS, application чи tunnel; (2) увімкнути strict encrypted mode або supported ODoH; (3) протестувати unique owned domain; (4) виконати local capture для перевірки відсутності clear query; (5) відмовити resolver і перевірити intended behavior; (6) для ECH підтвердити server diagnostics про прийняття inner ClientHello.<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logs розкривають queries; networks визначають encrypted-resolver endpoints і destination flows; ECH state видимий endpoints/CDN, навіть якщо прихований на шляху.

## Split-provider privacy relay

**Mechanics:** products на кшталт iCloud Private Relay використовують ingress, який знає client, та незалежно керований egress, який знає destination, із coarse region handling.

**Pros:** low-friction split knowledge; швидко; інтегрований DNS/web protection для supported traffic.

**Cons:** обмежений product/application scope; account/platform provider все одно ідентифікує customer; не довільна system anonymity; collusion/legal і timing risks.

**Procedure:** (1) підтвердити exact supported applications і traffic types; (2) увімкнути feature у dedicated platform context за потреби; (3) вибрати region behavior; (4) окремо протестувати Safari/DNS і unsupported applications; (5) перевірити destination address; (6) протестувати network switching/failure.<sup>[[12]](#references)</sup>

**Detection:** access бачить ingress; destination бачить egress; platform/relay logs і account records охоплюють свої layers; unsupported applications розкривають normal paths.

## Remote browser, VDI, RDP або organization jump host

**Mechanics:** browsing/tool execution відбувається на remote system; destination бачить його egress, а workspace provider — operator connection і control plane.

**Pros:** швидко; ізолює risky content; стабільний controlled egress; disposable state і сильний organizational audit.

**Cons:** provider/admin може спостерігати session/account; screen/clipboard/file channels leak; remote browser fingerprint може бути унікальним; для workspace owner це не anonymous.

**Procedure:** (1) створювати organization-owned workspace для кожного engagement; (2) вимагати MFA і обмежити administration; (3) вимкнути або обмежити clipboard/upload/download; (4) маршрутизувати через approved fixed egress; (5) не використовувати personal IdP/sync; (6) експортувати лише reviewed evidence; (7) знищувати workspace і credentials за графіком.

**Detection:** provider і IdP logs пов’язують user із session; destinations кластеризують workspace egress/browser; enterprise defenders ідентифікують remote-control protocols і anomalous cloud sessions.

## Public або guest Wi-Fi

**Mechanics:** traffic виходить через venue NAT або tunnel, створений там.

**Pros:** висока швидкість і shared non-home address; dedicated infrastructure не потрібна.

**Cons:** venue association/DHCP/portal, camera, purchase та location evidence; hostile peers/APs; terms; physical risk.

**Procedure:** (1) отримати guest access і перевірити SSID у staff; (2) використати patched low-trust device; (3) вимкнути sharing/auto-join і ввімкнути private MAC; (4) пройти portal без reused identity; (5) запустити fail-closed VPN/Tor path; (6) перевірити tethered traffic; (7) забути network.

**Detection:** venue зіставляє AP, MAC, DHCP, portal і time; destination бачить venue/tunnel; investigators поєднують physical і device evidence. Ніколи не обходити access control.

## Travel router

**Mechanics:** operator-owned router підключається до venue Wi-Fi/Ethernet і надає ізольовану internal network з enforced tunnel policy.

**Pros:** ізолює workstations; central kill switch/DNS; consistent client network; захищає privileged endpoints від local broadcasts.

**Cons:** router стає стабільним radio/DHCP fingerprint; додає attack surface; captive portals і tethering можуть обходити tunnel.

**Procedure:** (1) оновити supported firmware; (2) встановити unique management credentials і вимкнути WAN admin/WPS/UPnP; (3) налаштувати private upstream MAC за дозволом; (4) створити окремий internal SSID; (5) застосувати full-tunnel DNS/IPv6 firewall policy; (6) протестувати portal, reconnect і tunnel failure.

**Detection:** venue бачить router association і traffic shape; local RF/DHCP fingerprinting ідентифікує його; VPN provider бачить venue source.

## Cellular, prepaid SIM і eSIM

**Mechanics:** modem використовує carrier radio access і зазвичай carrier NAT; VPN/Tor layer може змінити destination-visible exit.

**Pros:** незалежність від local wired/Wi-Fi network; мобільність; висока швидкість; корисний backhaul для authorized drops.

**Cons:** carrier знає subscriber/eSIM, IMSI, IMEI, cells, time і assigned ports; registration laws різняться; co-location з personal phone пов’язує devices.

**Procedure:** (1) законно отримати service з точними необхідними даними; (2) використати окремий organization-owned modem/device; (3) зареєструвати його у exercise controller; (4) вимкнути unrelated radios/accounts; (5) встановити approved tunnel; (6) перевірити, чи tethered clients справді проходять через нього; (7) до подорожі перевірити provider і retention assumptions.<sup>[[13]](#references)</sup>

**Detection:** carrier records і RF location; enterprise USB/PCI/MDM inventory та rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet і satellite downlink abuse

**Mechanics:** normal service використовує registered terminal/provider. Старі one-way DVB-S abuse дозволяли receiver усередині beam спостерігати незашифрований downlink traffic, адресований legitimate subscriber, використовуючи інший шлях для outbound requests.

**Pros:** широкий footprint; незалежний last mile; історичний one-way abuse міг хибно приписувати C2 географії subscriber.

**Cons:** equipment/RF/provider records; latency і coverage; сучасні bidirectional systems відрізняються; outbound path і asymmetric routing залишають evidence.

**Procedure:** для законного доступу зареєструвати власний terminal і за потреби тунелювати traffic. Для емуляції історичної поведінки Turla відтворити synthetic one-way packet captures у RF-free lab і перевірити, чи analysts виявляють reply host, який не робив request; не перехоплювати live satellite traffic.<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency і malware configuration.

## Residential/mobile proxy або consented proxyware

**Mechanics:** backconnect gateway призначає consumer broadband/mobile exits, sticky або rotating. Supply може бути consensual, deceptively bundled або malicious.

**Pros:** висока швидкість; geographic choice; consumer ASN обходить частину hosting blocks; великі pools.

**Cons:** provenance/consent і legal risk; broker бачить customer; infected exits шкодять victims; rotation створює anomalies; дорого й ненадійно.

**Procedure:** використовувати лише documented, informed-consent organization-owned agents для emulation: (1) enroll test endpoints; (2) inventory owners/IPs; (3) налаштувати gateway; (4) rotate sticky/per-request modes; (5) надсилати лише на owned target; (6) порівняти gateway/exit/target logs; (7) видалити кожен agent.

**Detection:** impossible travel, стабільний browser/account при швидкій зміні IP/ASN, backconnect protocols, proxyware process/network artifacts і broker/controller relations.

## ORB, botnet і compromised edge-device relays

**Mechanics:** leased або compromised routers/IoT/servers формують access, traversal і exit roles, що адмініструються fleet. Кілька APT customers можуть ділити її.

**Pros:** borrowed reputation/geography; short-lived exits; resilient multi-hop mesh; слабкий direct actor-to-IP link.

**Cons:** criminal victimization; implant/controller і fleet patterns; intermediary seizure; inconsistent performance; operator/customer service records.

**Procedure:** ніколи не компрометувати реальні devices. Використовувати [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) створити isolated entry/transit/target networks; (2) під’єднати owned dual-homed relay containers; (3) forward лише one test port; (4) надіслати benign request; (5) перевірити, що target бачить лише exit; (6) rotate exit; (7) tear down усі named assets.<sup>[[15]](#references)</sup>

**Detection:** відстежувати topology, ports/services, controller relations, implant fingerprints і node lifecycle; централізувати edge configuration/flow/integrity telemetry; не ототожнювати exit IP з actor.

## CDN redirector, domain fronting і domainless fronting

**Mechanics:** public edge пересилає лише traffic, що відповідає grammar; fronting використовує benign outer SNI і інший inner HTTP authority або blank SNI, якщо intermediary це дозволяє.

**Pros:** приховує/захищає back-end; швидкий global edge; маскує destination під shared service; швидкий cutover.

**Cons:** CDN бачить routing і tenant; багато providers забороняють cross-tenant fronting; SNI/Host/process/flow і account artifacts; повторне використання configuration кластеризує campaigns.

**Procedure:** відтворювати лише на власному reverse proxy через [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): створити local certificate/edge, спрямувати один mismatched Host до owned target, записати SNI і Host, надіслати normal/mismatched requests, потім видалити containers.<sup>[[16]](#references)</sup>

**Detection:** порівнювати SNI/ECH/Host/`:authority` на endpoint або terminating edge; пов’язувати initiating process, tenant/origin, request grammar і flow cadence.

## Dynamic DNS, DGA, fast flux і double flux

**Mechanics:** DDNS оновлює stable name; DGA створює changing candidate names; fast flux обертає service addresses із low TTL; double flux також обертає name servers.

**Pros:** стійке discovery; швидка заміна infrastructure; controller прихований за багатьма nodes.

**Cons:** DNS створює central telemetry; entropy/NXDOMAIN/churn; low TTL і broad ASN patterns; registration та authoritative infrastructure залишаються.

**Procedure:** використовувати [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): обслуговувати owned zone, що повертає RFC 5737 addresses із five-second TTL, повторно запитувати її, змінити synthetic epoch і перевірити analytics. Ніколи не спрямовувати test records на third parties.<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters і process follow-on; legitimate CDNs виключати з урахуванням context.

## Legitimate web service, dead-drop resolver і one-way tasking

**Mechanics:** public post, repository, document, object або feed містить encoded current endpoint або task. Client може повертати results іншим channel.

**Pros:** high-reputation service; TLS; endpoint rotation без зміни binary; asymmetric tasking ускладнює просту flow correlation.

**Cons:** stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content може бути seized або changed.

**Procedure:** використовувати [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): розмістити encoded pointer на одному owned container, fetch/decode з short-lived client, звернутися до другого owned service, зберегти обидва logs, потім tear down.

**Detection:** корелювати unusual process → stable object read → decode → new destination; hash/preserve content і зберігати повні object paths, а не лише domain.

## Serverless, ephemeral container і cloud-NAT egress

**Mechanics:** functions/short-lived jobs працюють за provider NAT або front; logical service стабільний, а instances і addresses змінюються.

**Pros:** швидке deployment/destruction; provider-scale shared egress; мало local disk; elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing і front-to-origin logs довговічні; cold-start/platform fingerprints; provider policy.

**Procedure:** (1) використовувати organization-owned exercise tenant; (2) розгорнути benign function, що звертається лише до owned endpoint; (3) записати project/role/image/config; (4) викликати через кілька instances; (5) порівняти target IPs з audit/request IDs; (6) перевірити log retention; (7) видалити function, roles і secrets.

**Detection:** cloud audit/invocation logs, unusual role creation, shared egress зі stable request grammar, image/layer і secret reuse та front-origin correlation.

## Authorized on-site drop

**Mechanics:** inventoried small computer використовує local wired/Wi-Fi та outbound VPN/cellular rendezvous і представляє local source.

**Pros:** реалістичне testing internal origin; висока швидкість; перевірка NAC, physical inventory і egress controls.

**Cons:** physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF і camera evidence; loss може розкрити credentials.

**Procedure:** дотримуватися [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) отримати точний письмовий дозвіл; (2) записати serial, MAC, photo, location і retrieval time; (3) використовувати signed minimal image і short-lived mutual credentials; (4) обмежити outbound destinations/capabilities; (5) додати server-side quarantine і bandwidth limits; (6) перевірити SOC visibility і loss response; (7) повернути, зберегти необхідні докази та sanitize відповідно до policy. Ніколи не ховати у venue без згоди.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera і physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** actor контролює host у radio range target, а потім використовує target Wi-Fi credentials для віддаленого перетину межі. APT28 використовувала nearby compromised organizations таким способом.<sup>[[18]](#references)</sup>

**Pros:** operator не подорожує; target бачить local radio source; обходить controls, застосовані лише до Internet entry.

**Cons:** потрібні nearby compromised/owned dual-radio host і valid access; RADIUS/NAC/AP та neighbor endpoint evidence; signal/device anomalies.

**Procedure:** відтворювати лише через [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): під’єднати owned pivot до neighbor і target lab SSIDs, forward лише one service, зібрати обидва AP/pivot logs, потім увімкнути EAP-TLS/device posture і підтвердити failure другої спроби.

**Detection:** корелювати RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login і physical presence; шукати nearby endpoints із simultaneous radios, forwarding і tunnels.

## Community mesh, delay-tolerant і offline store-and-forward

**Mechanics:** traffic проходить через local peers, asynchronous gateways, removable media або scheduled queues, а не через одну interactive Internet session.

**Pros:** працює під час disruption/censorship; delayed/batched delivery послаблює просту timing analysis; для local communication не потрібен central last mile.

**Cons:** висока latency; мала anonymity set; custody/physical metadata; malicious peers; data зрештою доходить до gateway, який його бачить.

**Procedure:** (1) побудувати isolated owned three-node mesh або file queue; (2) end-to-end encrypt/authenticate content; (3) вилучити direct Internet routes з origin; (4) relay benign file після controlled delay; (5) перевірити, що лише gateway контактує з owned destination; (6) порівняти custody/timestamps; (7) зберегти необхідні докази, потім sanitize temporary media/queues під час approved closeout.

**Detection:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity і content identifiers. Довші correlation windows замінюють interactive-flow analysis.

## TURN relay і forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN) виділяє public relay address і переносить UDP, TCP або TLS traffic між client і peers. ICE policy може примусово використовувати relay замість exposing direct candidate. TURN вирішує reachability, а не general anonymity: server authenticates client і бачить allocations, peers, time та volume.<sup>[[19]](#references)</sup>

**Pros:** широко реалізований; працює з restrictive NAT; підтримує mobile WebRTC; peer не отримує direct transport address client, якщо relay-only policy налаштована правильно.

**Cons:** TURN operator бачить обидві adjacent sides; application identity, media fingerprint і signaling залишаються; relay-only коштує bandwidth і latency; misconfiguration усе ще може збирати host або server-reflexive candidates.

**Procedure:** (1) розгорнути organization-owned TURN service з TLS і short-lived credentials; (2) обмежити realms, peers, ports, quotas і expiration; (3) встановити relay-only ICE; (4) зателефонувати owned peer; (5) перевірити `getStats()` і packet capture, щоб підтвердити передачу media лише relay candidates; (6) відмовити relay і підтвердити відсутність direct fallback; (7) зберегти allocation logs для engagement.

**Detection:** signaling, browser process і TURN allocations пов’язують session з relay; networks бачать sustained flows до TURN ports або TLS endpoints; peer бачить allocated relay. **Captured node:** application state і ephemeral TURN credentials можуть розкрити realm та rendezvous service. Мінімізувати exposure через per-device short-lived credentials і зберігати operator authentication лише на controller.

## Outbound-only rendezvous або reverse overlay

**Mechanics:** node за NAT ініціює authenticated connection до organization-controlled broker. Operator окремо authenticates до broker, який дозволяє вузький management channel; inbound port forwarding і direct operator-to-node route не потрібні.

**Pros:** стабільність за NAT і captive last miles; central revocation/audit; зміна адреси field node не потребує discovery; operator identity чітко відокремлена від node credential.

**Cons:** broker стає high-value correlation point; periodic keepalives помітні; broad tunnel може стати небезпечним pivot; втрата broker припиняє management.

**Procedure:** дотримуватися [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): видати одну scoped device identity, дозволити лише owned broker і approved management service, використовувати authenticated keepalive, застосувати fail-closed routing, протестувати address changes і reboot recovery, відкликати identity під час loss drill. WireGuard описує 25-second persistent keepalive як загалом корисний NAT interval, коли він справді потрібен.<sup>[[20]](#references)</sup>

**Detection:** broker та identity-provider logs пов’язують обидві сторони; access network бачить повторюваний encrypted destination/cadence; endpoint inventory показує overlay agent. **Captured node:** вважати розкритими device key, broker name, tunnel addresses і cached task data. На ньому не повинно бути operator private key, personal account або reusable controller token.

## Pull mailbox, message queue або object-store rendezvous

**Mechanics:** field workload опитує authenticated mailbox щодо signed, pre-approved jobs і надсилає bounded results. Operator пише в queue через окремий control plane; interactive socket між ними відсутній.

**Pros:** tolerates intermittent links; розділяє timing/addressing; quotas і schemas обмежують capability; простий central audit/revocation.

**Cons:** polling cadence і stable object/queue names fingerprint system; provider logs пов’язують producer/consumer; delayed control; captured queued data може розкрити exercise.

**Procedure:** (1) створити одну engagement queue і device identity; (2) визначити signed schema benign, explicitly scoped jobs; (3) встановити message TTL, maximum result size і rate; (4) дозволити node pull лише власної queue і write лише власного result prefix; (5) протестувати offline accumulation, duplicate delivery і revocation; (6) централізувати immutable access logs; (7) видалити queue після retention requirements.

**Detection:** шукати periodic API calls unusual process, stable bucket/object/queue paths, identical user-agent/TLS behavior і fetch-then-new-connection sequence. **Captured node:** local cache може розкрити pending jobs і object names; cache має бути encrypted, bounded і disposable, а authoritative controller logs слід зберегти.

## Dual-uplink failover і connection migration

**Mechanics:** approved field node має два незалежні uplinks — наприклад venue Ethernet/Wi-Fi і organization cellular — та зберігає control session через overlay або message broker при зміні routes. Це availability engineering, не anonymity.

**Pros:** переживає збій provider, AP або captive portal; підтримує maintenance; дозволяє швидко ізолювати suspect path.

**Cons:** два providers створюють дві location/account records; simultaneous use полегшує correlation; route/DNS leaks під час failover; cellular co-location evidence залишається.

**Procedure:** (1) зареєструвати обидва organization-owned interfaces/providers; (2) призначити deterministic route priorities і health checks до owned endpoints; (3) прив’язати DNS і management до overlay; (4) не дозволяти secondary path приймати inbound traffic; (5) від’єднати кожен path і перевірити session recovery, source policy та відсутність direct destination access; (6) alert на unplanned path change; (7) документувати data use і roaming limits.

**Detection:** корелювати той самий device certificate, request grammar і timing між ASNs; local inventory бачить обидва radios; carriers/venues зберігають власні records. **Captured node:** можуть бути видимі обидва SIM/device identifiers і known SSIDs; використовувати organization assets, не поєднувати node з personal devices.

## Organization private APN або managed cellular tunnel

**Mechanics:** carrier private APN поміщає enrolled SIMs у private routed domain або тунелює traffic до enterprise gateway. Відокремлює device від public mobile Internet, але не приховує його від carrier або contracting organization.

**Pros:** stable private addressing; carrier-level enrollment і traffic policy; відсутній public inbound exposure; придатний для authorized remote appliances.

**Cons:** subscriber, IMSI/IMEI, cell і billing attribution сильні; procurement lead time/cost; carrier/gateway outage; не anonymous для operator.

**Procedure:** (1) contract APN на ім’я assessment organization; (2) whitelist registered SIMs і gateway prefixes; (3) додати application-layer mutual authentication; (4) обмежити APN route до rendezvous і update services; (5) протестувати SIM removal, roaming, public-Internet breakout і revocation; (6) monitor carrier/gateway records; (7) cancel або quarantine кожну SIM під час closeout.

**Detection:** carrier inventory/cell telemetry, APN gateway flows, SIM/IMEI mismatch і enterprise asset records. **Captured node:** SIM і modem ідентифікують contract навіть при encrypted storage; capture resilience означає швидке suspension і narrow authorization, а не deniability.

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fi або інший licensed/unlicensed point-to-point radio з’єднує два approved sites owner, із Internet egress на remote site. Може перемістити apparent IP location без commercial proxy.

**Pros:** висока throughput; незалежність від intermediate wired carriers; контрольовані RF/routing; корисний для testing segmentation і remote-site monitoring.

**Cons:** line-of-sight, spectrum, landlord і regulatory constraints; distinctive RF emissions/hardware; обидва endpoints — physical evidence; weather/power/alignment впливають на stability.

**Procedure:** (1) отримати письмовий дозвіл обох sites і перевірити spectrum/power rules; (2) survey path без transmission поза approved parameters; (3) використати authenticated encryption і management VLAN; (4) обмежити bridge власним rendezvous/test subnet; (5) протестувати failover, alignment, power recovery і RF containment; (6) label/inventory обидва radios; (7) remove і перевірити configuration reset після exercise.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic і remote-site egress logs. **Captured node:** configuration розкриває peer і management domain; використовувати unique exercise credentials, без personal management accounts, із швидким peer-key revocation.

## Consented cooperative або community exit

**Mechanics:** volunteers/partner organizations knowingly run relays за published policy. Traffic виходить зі shared community pool, а coordination layer обліковує abuse і revocation.

**Pros:** різноманітні non-cloud networks; explicit consent безпечніша за proxyware; shared governance розподіляє trust; корисно для research/censorship-resilience.

**Cons:** small pools і membership records зменшують anonymity; exit operators отримують complaints і бачать traffic metadata; malicious participants, variable uptime і jurisdiction differences.

**Procedure:** (1) опублікувати acceptable-use/logging policy; (2) отримати informed opt-in кожного operator; (3) видати unique relay identity і обмежити destinations/rates; (4) забезпечити abuse handling і one-action revocation; (5) під час testing надсилати лише authorized traffic до owned endpoints; (6) вимірювати churn і correlation exposure; (7) cleanly remove relay після завершення consent.

**Detection:** membership/control-plane records, relay certificates, common software fingerprint і exit behavior ідентифікують pool. **Captured node:** relay configuration може ідентифікувати cooperative, але не має містити client identities; client-to-session accountability зберігати на authorized controller під access control.

## IPv6 temporary addresses і prefix rotation

**Mechanics:** IPv6 privacy extensions створюють temporary interface identifiers, щоб stable address не використовувалася для кожного outbound connection. Provider prefix changes можуть додати rotation, але delegated prefix, subscriber record і upper-layer fingerprint залишаються.<sup>[[21]](#references)</sup>

**Pros:** зменшує passive long-term tracking за stable interface identifier; вбудовано в common operating systems; немає relay overhead.

**Cons:** не source anonymity; ISP/local network усе ще знають prefix/device; DNS, accounts і browser state пов’язують sessions; address churn ускладнює allowlists/logging.

**Procedure:** (1) перевірити stable і temporary addresses на owned client; (2) увімкнути OS-supported privacy-address default, а не third-party spoofing; (3) повторно звернутися до owned IPv6 endpoint упродовж address lifetimes; (4) підтвердити, що inbound services bind лише intended stable addresses; (5) зберігати DHCPv6/RA/neighbor та точні endpoint logs; (6) перевірити VPN/firewall behavior для кожної IPv6 address.

**Detection:** корелювати delegated prefix, layer-2 identity, neighbor discovery, account і endpoint telemetry, а не вважати одну address одним device. **Captured node:** network profiles і interface identifiers залишаються; temporary addressing запобігає одному passive identifier, але не forensic attribution.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 і meek

**Mechanics:** pluggable transport змінює вигляд першого Tor connection або спосіб досягнення bridge. Snowflake використовує short-lived volunteer WebRTC proxies, WebTunnel нагадує ordinary HTTPS, obfs4 протидіє простій protocol identification та active probing, а meek пересилає через supported web infrastructure. Це censorship-circumvention transports у Tor, а не додаткові end-to-end anonymity layers.<sup>[[22]](#references)</sup>

**Pros:** корисні, коли direct Tor або known relays blocked; Snowflake уникає stable public bridge address; інтегровані в maintained Tor clients; destination усе ще отримує звичайні Tor properties.

**Cons:** lower/variable performance; broker/front/bridge і local network бачать різні metadata; transport fingerprints і blocking можливі; volunteer proxy не замінює Tor і не має отримувати application plaintext.

**Procedure:** (1) встановити й перевірити official Tor Browser або supported Tor client; (2) вибрати built-in transport у Connection/Bridges; (3) підключатися лише до owned diagnostic page; (4) підтвердити, що page бачить Tor exit, а не Snowflake/WebTunnel peer; (5) порівняти bootstrap/performance; (6) відмовити transport і перевірити відсутність silent direct connection; (7) після тесту повернути standard supported configuration.

**Detection:** censor може поєднати destination allowlists, TLS/WebRTC behavior, broker discovery і flow analysis; endpoints розкривають Tor і transport configuration. **Capture-resilient OPSEC:** використовувати standard client, не копіювати personal browser state і вважати bridge/broker history recoverable. **Monitoring:** відстежувати Tor bootstrap logs, unexpected direct DNS/connection attempts і controller-side owned-page observations; transport failure не доводить discovery.

## Refraction networking або decoy routing

**Mechanics:** cooperating network operator виявляє covert signal у traffic, нібито адресованому allowed decoy, і перенаправляє flow до circumvention proxy. Потрібна infrastructure у network path; client не може створити це лише вибором innocent website.<sup>[[23]](#references)</sup>

**Pros:** apparent destination може бути важко блокувати без collateral damage; public bridge address не потрібно розповсюджувати; корисна research model on-path-assisted circumvention.

**Cons:** specialized ISP/transit participation; deployability/performance залежать від routing; client-to-decoy flow і proxy-side activity залишаються; global/cooperating observer може корелювати timing.

**Procedure:** не signal через uninvolved networks. Відтворювати architecture в isolated lab: (1) створити owned client, router, decoy і proxy namespaces; (2) використати benign tagged test request; (3) дозволити owned router redirect лише цей tag до proxy; (4) log pre/post-routing tuples і request IDs; (5) порівняти ordinary/signaled flows; (6) протестувати false positives/removal; (7) destroy lab routes.

**Detection:** authorized network operators можуть перевіряти routing divergence, unusual client hello/tag behavior та decoy-versus-back-end flow discrepancies. **Capture-resilient OPSEC:** research client має містити лише test keys і documentation addresses. **Monitoring:** порівнювати signed lab-router decisions із proxy arrivals; не probe production transit providers, щоб визначити, чи вони виявили signaling.

## Content-addressed gateway або cached peer retrieval

**Mechanics:** HTTP gateway отримує IPFS content identifier (CID), можливо з cache або peers, і повертає verifiable content client. Original publisher може бачити gateway або інших peers, а не final reader; gateway бачить reader IP і requested CID. Native peer-to-peer retrieval відкриває client peers і DHT/routing participants.<sup>[[24]](#references)</sup>

**Pros:** publisher і reader можуть бути розділені caches; immutable content перевіряється hash; replicated data переживає втрату host; HTTP clients не потребують native peer stack.

**Cons:** public CIDs і gateway logs розкривають interests; timing першого retrieval може корелювати publisher/reader; malicious web content і path-style same-origin hazards; public gateways best-effort і забороняють abuse.

**Procedure:** (1) опублікувати harmless test file у власному private IPFS swarm або gateway; (2) записати CID; (3) отримати через окремий owned HTTP gateway із subdomain isolation; (4) перевірити bytes проти CID; (5) повторити після caching; (6) порівняти publisher/peer/gateway logs; (7) unpin і remove test content після завершення retention.

**Detection:** gateways логують source/CID; DHT/peer connections розкривають retrieval; endpoint history і file hashes ідентифікують content. **Capture-resilient OPSEC:** не зберігати private publishing key на read-only field client і encrypt sensitive content до content addressing. **Monitoring:** alert на unexpected pinning, peer-set change, CID requests поза allowlist або gateway account notices.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR) дозволяє client отримати один record із database, cryptographically приховуючи selected index від server у межах stated single- або multi-server threat model. Захищає query selection для bounded dataset; це не general web access і не IP anonymity.<sup>[[25]](#references)</sup>

**Pros:** strong application-specific query privacy; measurable leakage model; корисне для key directories, blocklists або small public databases; може зменшити потребу розкривати exact lookup terms.

**Cons:** computation/bandwidth overhead; server бачить connection time/IP без relay; dataset version, response size і application state можуть partition users; implementation maturity різниться.

**Procedure:** (1) розгорнути audited PIR implementation проти synthetic owned database; (2) опублікувати dataset version і parameters; (3) отримати кілька indices з identical request sizes; (4) локально перевірити correctness; (5) порівняти server logs і підтвердити відсутність index; (6) протестувати malicious/truncated responses і version mismatch; (7) документувати exact privacy assumption, не називаючи це anonymous browsing.

**Detection:** networks бачать service use і volume; endpoint telemetry розкриває client і final record use; compromised server може змінювати datasets/timing. **Capture-resilient OPSEC:** зберігати на client лише public database parameters і bounded cache. **Monitoring:** перевіряти signed dataset roots, fixed request shapes, зміни error-rate і server-key rotations.

## Constrained server-side fetcher, preview або rendering service

**Mechanics:** remote service отримує або renders URL і повертає screenshot, metadata або sanitized content. Destination бачить fetcher address; service бачить requester, URL і result. Зловживання link-preview bots, security scanners або third-party URL fetchers не є authorized proxy use.

**Pros:** ізолює active content від workstation; destination отримує controlled fetcher fingerprint; можна застосувати обмеження file type, size, destination і rendering; disposable execution environment.

**Cons:** service має повне знання request; account/API/billing records; SSRF і data-exfiltration risk; scripts, authentication та interactive sites можуть не працювати; unique URLs корелюють requester і fetch.

**Procedure:** (1) розгорнути organization-owned fetcher зі strict allowlist owned test domains; (2) block private, link-local, metadata і redirect-to-unapproved addresses; (3) обмежити methods, redirects, bytes і render time; (4) strip credentials/cookies; (5) submit owned URL; (6) порівняти requester/fetcher/target logs; (7) destroy render instance і зберегти central audit відповідно до policy.

**Detection:** target бачить service ASN/fingerprint; provider/controller logs пов’язують requester з URL; endpoint process/API calls показують submission. **Capture-resilient OPSEC:** використовувати один short-lived project token без arbitrary destination authority. **Monitoring:** alert на allowlist denials, redirect violations, fetches без controller job ID і provider abuse notices.

## Anycast rendezvous pool

**Mechanics:** кілька organization-controlled nodes advertise/front один stable service address, а routing вибирає nearby instance. Anycast підвищує availability і приховує individual back-end від client, але operator контролює всі instances, а service address стабільна.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress; відсутня field reconfiguration при failure instance; DDoS/load distribution; central policy може переміщати sessions між відомими nodes.

**Cons:** BGP/CDN/provider records ідентифікують organization; path changes можуть ламати stateful sessions; monitoring відрізняється за client location; stable address легко block/reputation-cluster.

**Procedure:** використовувати provider-supported organization project або isolated routing lab: (1) розгорнути два identical authenticated health endpoints; (2) expose один documented service address; (3) session state тримати на broker, не на edge; (4) withdraw один node і перевірити reconnection; (5) перевірити certificate, policy і log consistency; (6) alert на unauthorized origin/region; (7) remove advertisements і credentials під час closeout.

**Detection:** BGP/RPKI/history, provider tenancy, certificates і identical service behavior ідентифікують pool. **Capture-resilient OPSEC:** edge має містити лише regional service identity, без operator/fleet-enrollment key. **Monitoring:** probe кожен region з authorized monitors, порівнювати route origin і configuration digest; unexpected origin вважати incident.

## QUIC migration і Multipath TCP continuity

**Mechanics:** QUIC connection IDs підтримують client session через NAT rebinding або address changes; Multipath TCP переносить один reliable byte stream через кілька subflows. Вони покращують continuity між Wi-Fi/cellular transition, але розкривають old/new paths common peer і можуть полегшити cross-path correlation.<sup>[[27]](#references)</sup>

**Pros:** швидше відновлення під час uplink changes; application session не потрібно restart; MPTCP поєднує resilience і throughput; цінне для approved field nodes.

**Cons:** не anonymity; peer бачить migration/subflows; connection identifiers і simultaneous traffic пов’язують paths; middlebox/carrier support різниться; додаткові provider records збільшують exposure.

**Procedure:** (1) увімкнути supported transport лише між owned field client і rendezvous; (2) authenticate application незалежно від IP; (3) почати bounded transfer через approved Wi-Fi; (4) switch to organization cellular; (5) підтвердити path validation, data integrity і відсутність clear/direct fallback; (6) протестувати idle timeout і return; (7) зберегти broker records кожного path transition.

**Detection:** peer безпосередньо бачить address migration або MPTCP subflows; access providers бачать свої частини; connection IDs, TLS identity і timing об’єднують обидві. **Capture-resilient OPSEC:** зберігати лише device-scoped session material і швидко завершувати resumable state. **Monitoring:** alert на impossible path changes, simultaneous unapproved networks, migration storms і resumption after quarantine.

## Managed CI/CD або ephemeral automation runner egress

**Mechanics:** organization-owned workflow виконує bounded network check на hosted runner. Destination бачить cloud runner address, а platform зберігає repository, actor, workflow, token, log і billing attribution. Це remote execution із accountable egress, а не anonymity від provider.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment; reproducible job definition; inbound connection не потрібне; корисно для geographically distributed availability checks; strong controller audit.

**Cons:** platform і organization ідентифікують initiator; broad workflow tokens і untrusted pull requests небезпечні; shared IP reputation; logs/artifacts можуть зберігати secrets або target data.

**Procedure:** (1) створити private organization repository/environment для assessment; (2) дозволити лише manually approved, fixed benign jobs проти owned endpoints; (3) використати minimal read-only workflow permissions без production secrets; (4) виконати check; (5) порівняти workflow/provider/target records; (6) перевірити відсутність credentials в artifacts; (7) видалити environment token і зберегти необхідний audit.

**Detection:** provider audit і workflow logs дають direct attribution; targets ідентифікують runner ASNs/ranges і stable request grammar. **Capture-resilient OPSEC:** ніколи не зберігати field-device, signing, wallet або cloud-administrator secrets у runner variables. **Monitoring:** вимагати branch/environment approval і alert на workflow edits, fork execution, secret reads та unexpected destinations.

## Non-IP local first hop до власного gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio або serial/optical link передає bounded messages від nearby sensor до owner-approved Internet gateway. Field device не має Internet route; gateway — єдиний egress. Radio range/protocol limits роблять це telemetry/store-and-forward design, а не interactive anonymous Internet.

**Pros:** вилучає Internet stack і credentials із найменшого field device; low power; gateway централізує policy; може долати temporary dead zones.

**Cons:** RF/physical discovery, pairing і device identifiers; мала bandwidth/range; gateway усе одно пов’язує messages; spectrum/encryption restrictions різняться; capture може розкрити queued data.

**Procedure:** (1) отримати site і spectrum approval; (2) pair один owned sensor з одним owned gateway через unique keys; (3) визначити signed fixed-size message types, TTL і rate; (4) не давати sensor default IP route; (5) дозволити gateway forward лише до owned collector; (6) протестувати replay, range loss і gateway outage; (7) inventory/retrieve обидва devices.

**Detection:** RF survey, pairing database, physical inspection і gateway process/flow logs розкривають path. **Capture-resilient OPSEC:** sensor зберігає лише pairwise key і bounded encrypted queue, ніколи operator, Wi-Fi, cellular або controller credentials. **Monitoring:** alert на new peers, sequence rollback, key failure, unusual RF rate і messages через unregistered gateway.

## Матриця exposure від capture/compromise

Ця таблиця застосовує capture-resilience check до кожного сімейства вище. «Minimize» означає зменшувати secrets і blast radius на authorized assets; це ніколи не означає очищати evidence або приховуватися від investigation.

| Сімейство technique | Що може розкрити captured endpoint/relay | Мінімальний authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known networks, DHCP/portal history, MACs, tunnel peer | окремий organization device; private MAC; без personal accounts; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs, adjacent hop | одна identity на engagement; short TTL; narrow routes; broker-side revocation; без master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers, cached requests | мінімум payload identifiers; approved config; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software, bridge/onion material, local state, peer history | standard client; окремі service keys; encrypted minimal state; rotation compromised identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files, remote tenant | phishing-resistant MFA; disabled transfer channels; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider, approximate location | organization contract; no personal co-location; narrow APN/overlay; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | лише consented/owned nodes; signed agent; per-node credential; controller-held mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment/billing references | dedicated project; least-privilege role; short-lived deploy token; central audit |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results, custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical artifacts | written placement; unique identity; no operator secret; telemetry; revoke/recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route/uplink profiles | outbound-only narrow service; short-lived credential; independent operator login; fail-closed |
| IPv6 temporary addressing | profiles, prefix history, endpoint/application state | трактувати лише як anti-tracking; зберігати network logs; endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state, research keys | standard client або isolated lab; no personal browser state; no production signaling |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway/service token | encrypted bounded cache; public-only parameters; short-lived allowlisted token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state, known paths | regional identity only; short resumption; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs, artifacts | least-privilege workflow; no production/field/wallet secrets; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages, gateway identity | unique pairwise key; fixed schema; no Wi-Fi/cellular/operator credential |

## Monitoring можливої discovery для кожного access family

Жоден client-side test не доводить, що investigator або defender спостерігає. Monitor changes у системах, якими володіє engagement, corroborate їх із controller/client і зупиняйся замість probing observers. Наведені rows охоплюють усі techniques вище; поєднувати їх із [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation або provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback або out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer або provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health, owned canary page | personal-account crossover, unexpected non-Tor connection або compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association, content hash | unknown peer/gateway, sequence rollback, unauthorized content або missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export, cloud audit | unknown login/workflow edit, secret read, unexpected destination або project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature, TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use або site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation, broker session | impossible migration, simultaneous unapproved paths або resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root або provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Вибір і тестування path

1. Назвати observer, якого потрібно усунути, і data, яку потрібно приховати.
2. Вибрати найменш складне family, що усуває його.
3. Накреслити source, entry, traversal, exit, DNS, account і payment observers.
4. Використати окремі endpoint/application identities.
5. Перевірити IPv4, IPv6, DNS, WebRTC/application bypass і destination view.
6. Зламати кожен hop і підтвердити closed failure.
7. Порівняти logs кожного контрольованого компонента.
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
{{#include ../banners/hacktricks-training.md}}
