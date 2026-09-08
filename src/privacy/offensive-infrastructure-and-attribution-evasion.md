# Інфраструктура наступальних операцій та уникнення атрибуції

{{#include ../banners/hacktricks-training.md}}

Оператор рідко отримує значущу анонімність за допомогою одного proxy. Реальні кампанії будують **граф розділення**: оператор досягає вузла доступу, вузли транзиту приховують цей вузол від вихідного вузла, redirector захищають справжній C2, а одноразові імена вказують на публічний edge.

Скористайтеся [Каталогом методів анонімного доступу до Internet](anonymous-internet-access-techniques.md), щоб отримати нормалізований огляд переваг/недоліків, розгортання та виявлення для кожного шляху. На цій сторінці детальніше розглядається композиція adversarial infrastructure.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Остання адреса, яку бачить ціль, є доказом шляху, а не доказом того, хто керував клавіатурою. MITRE зіставляє основні компоненти з Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) і Web Service (T1102).<sup>[[1]](#references)</sup>

## Класи інфраструктури

| Клас | Навіщо actor це використовує | Тривала експозиція | Найкращий pivot для захисника |
|---|---|---|---|
| Орендований VPS/cloud | Швидкий, передбачуваний, маршрутизований, легко перебудовується | tenant, billing, console, source-login та історія image | події акаунта/control plane і повторюваний fingerprint сервера |
| Commercial VPN/Tor | Великий спільний набір egress; не потребує адміністрування сервера | видимість provider/guard і end-to-end timing | поведінка призначення, endpoint-докази та кореляція потоків |
| Residential/mobile proxy | Consumer ASN і географічна правдоподібність | записи broker/customer; поведінка proxyware або infected host | impossible travel, proxy-протоколи та зміна адрес за session |
| Compromised server/router/IoT | Запозичує репутацію та юрисдикцію жертви | implant, management flow і повторюваний upstream controller | телеметрія пристрою та ORB topology, а не одна exit IP |
| CDN/redirector | Відокремлює публічний edge від back-end C2 | TLS/HTTP grammar, certificate, routing та cloud-account артефакти | кореляція edge-to-origin і кластеризація форми запитів |
| Legitimate web service | Маскується під дозволений GitHub/cloud/social traffic | API token, tenant/object identifiers і незвична process lineage | процес endpoint і семантика service/API |
| Фізичний/cellular/satellite шлях | Змінює видиме фізичне походження | записи RF, carrier, subscriber, device та location | сукупність radio/physical і мережевих доказів |

## Мережі operational relay box

**ORB network** — це керований proxy fleet, що використовується як проміжний сервіс. Mandiant поділяє їх на provisioned networks з орендованих серверів, non-provisioned networks зі скомпрометованих router/IoT і hybrid networks. Зріла topology має чотири логічні ролі:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** підтримує inventory, credentials, health і routing policy.
2. **Access/relay node:** автентифікує customers або operators; це стабільна точка входу до mesh, що змінюється.
3. **Traversal nodes:** одна або кілька орендованих чи скомпрометованих систем ретранслюють opaque connections.
4. **Exit/staging node:** представляє фінальну source address для reconnaissance, exploitation або C2 targets.

Mesh може обирати exits за country, ASN, latency або availability і замінювати unhealthy nodes. Кілька threat groups можуть орендувати ту саму network. Mandiant спостерігала, що IPv4 address залишалася пов’язаною з деякими ORB лише 31 день; тому рекомендується розглядати **network як entity, що еволюціонує подібно до actor**, а не блокувати застарілий список IP.<sup>[[2]](#references)</sup>

### Що це дає — і що це leak

- Target бачить exit, який може бути географічно близьким і начебто residential.
- Exit бачить target і попередній hop, але не обов’язково operator.
- Access service бачить customer і route request. Незалежно керована mesh може відокремлювати customer від exits, але створює потужний запис про counterparty.
- Повторювані ports, handshake order, server banners, certificates, uptime windows і controller relationships можуть викрити fleet, навіть коли IP змінюються.
- Скомпрометованому router часто бракує endpoint telemetry, але його ISP усе одно має subscriber і flow data; вилучення розкриває implant/configuration artifacts.

{% hint style="info" %}
Для авторизованої вправи відтворіть topology за допомогою VM або router, що належать організації, і зберігайте attribution map controller. Не залучайте open proxies або пристрої третіх сторін. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) створює таку саму видиму для defender структуру hop без завдання шкоди intermediary.
{% endhint %}

## Residential і mobile proxy networks

Residential proxy services призначають sessions consumer broadband addresses; mobile proxies виходять через carrier NAT pools. Supply може надходити від спеціально зареєстрованих appliances, SDK/proxyware, вбудованого в consumer applications, resellers або malware. Ці джерела не є еквівалентними: відсутність informed consent перетворює privacy service на compromised infrastructure.

Режими rotation впливають на detection:

- **per-request rotation** створює швидкі розбіжності IP і ASN/geography, тоді як identity на вищих рівнях залишається стабільною;
- **sticky sessions** утримують exit протягом хвилин або годин, імітуючи звичайного subscriber;
- **backconnect gateways** показують customer одну broker endpoint і внутрішньо обирають exits;
- **mobile pools** розміщують багатьох справжніх subscribers за невеликою кількістю carrier NAT addresses, через що блокування IP стає дорогим.

Defenders мають корелювати IP з authenticated session, TLS/client fingerprint, HTTP ordering, device cookie та behavior. Нібито local residential login, після якого з’являється інша country, тоді як усі ознаки вищих рівнів залишаються ідентичними, є сильнішим сигналом, ніж одна лише reputation. Водночас address sharing і mobile handoff створюють легітимну зміну, тому ніколи не вважайте residential/proxy classification остаточним verdict.

## Multi-hop proxy chains

MITRE розрізняє external proxies і **multi-hop proxies (T1090.003)**. Важлива не кількість hops, а розділення knowledge та administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Якщо одна сторона керує A і B, спільні журнали або часова структура потоків можуть відтворити схему з'єднання. Додавання послідовних комерційних VPN з тієї самої кінцевої точки/облікового запису може збільшити затримку, водночас залишаючи спільні докази ідентичності, платежів і синхронізації. Tor зменшує цю проблему завдяки незалежно вибраним relay та спільній клієнтській архітектурі, але інтерактивна мережа з низькою затримкою не може гарантувати захист від спостерігача, який вимірює обидва кінці.

Поширеними збоями є обхід через DNS або IPv6, відкриття застосунками власних сокетів, безпосереднє надходження керувального трафіку до relay, синхронізована активність, повторне використання SSH-ключів і вхід до облікових записів, що дають змогу ідентифікувати користувача. Правильна перевірка — це тест відмови: по черзі зупинити кожен relay і продемонструвати, що workload не може перейти на відкритий шлях.

## Рівні redirector і формування трафіку

Публічний **redirector** приймає трафік, що відповідає специфічній для операції граматиці, і пересилає його на захищений командний сервер. Усе інше можна відхилити або обслуговувати нешкідливим вмістом.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Кілька рівнів обмежують exposure: втрата public domain не обов'язково розкриває team server. CDN додають anycast capacity і репутаційний outer domain, але CDN account та edge logs стають точками атрибуції. TLS fingerprints, certificate histories, distinctive paths/header order, response sizes, redirect behavior та origin allowlists можуть об'єднувати нібито непов'язані front-и.

Для detection записуйте поля reverse-proxy до normalization, порівнюйте SNI/Host/authority, перевіряйте рідкісні комбінації headers, кластеризуйте response bodies і TLS fingerprints та шукайте в cloud/CDN audit logs збіги конфігурацій. Для authorized red teams уникайте копіювання реального бренду або розміщення credential collection за unrelated third party.

## Domain fronting and domainless fronting

За класичного **domain fronting (T1090.004)** TLS connection рекламує дозволений front domain у SNI, тоді як зашифрований HTTP `Host` або HTTP/2 `:authority` запитує інший back-end domain. Cooperating CDN маршрутизує на основі внутрішнього значення. Network observer без TLS decryption бачить front; CDN бачить обидва значення та origin. У domainless variants SNI може бути порожнім, тоді як інше routing field обирає destination.<sup>[[4]](#references)</sup>

Це не магічна impersonation: метод працює лише тоді, коли intermediary навмисно або випадково дозволяє невідповідність і знає, як маршрутизувати внутрішнє ім'я. Major providers обмежили cross-account fronting. Encrypted ClientHello (ECH) змінює те, що може бачити on-path observer, але не усуває записи CDN, endpoint або application.

До detection points належать:

- process ancestry endpoint-а та destination, неочікуваний для цього application;
- невідповідність SNI та HTTP authority, якщо TLS inspection є законною й доступною;
- CDN logs, що показують routing одного tenant/front до іншого authority/origin;
- незвично довгі або періодичні sessions до сервісу, який зазвичай є interactive;
- стабільні розміри й cadence зашифрованих flows через змінні front domains.

Безпечна lab-версія імітує routing mismatch на власному reverse proxy; вона не зловживає public CDN.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution відокремлює логічний service від фіксованої infrastructure:

- **DDNS:** authenticated client оновлює stable name після зміни його address.
- **DGA:** endpoint і controller виводять candidate domain names із time/key seed; operator реєструє невелику підмножину.
- **Fast flux:** name повертає набір compromised/proxy addresses, що швидко змінюється, часто з низькими TTL.
- **Double flux:** обертаються і service addresses, і authoritative name-server addresses, приховуючи також control layer.

Fast flux — це adversarial pattern розподілу навантаження, а не просто «багато DNS-відповідей». Сильніші докази поєднують низький TTL, велику кількість унікальних addresses, значне розсіювання ASN/geography, короткий час життя nodes, повторювану application behavior і підозрілу registration history. CDN легітимно мають кілька з цих властивостей. MITRE рекомендує корелювати DNS behavior із process та подальшими connections.<sup>[[5]](#references)</sup>

DGA можна виявляти за lexical entropy, шаблонами consonant/digit, сплесками NXDOMAIN, синхронізованими first-seen domains і process context. Wordlist DGAs та generative models обходять прості entropy rules, тому fleet-wide temporal clustering і endpoint lineage стають важливішими.

## Compromised domains and domain shadowing

Actor може викрасти registrar/DNS account, захопити dangling subdomain або додати records під інакше reputable domain. **Domain shadowing** зберігає легітимний apex, тоді як велика кількість attacker-controlled subdomains вказує на змінні delivery або C2 hosts. Це використовує age і reputation та може обходити domain-wide blocking.<sup>[[6]](#references)</sup>

Defenders потрібні registrar і authoritative-DNS audit logs, MFA, registry/registrar locks, alerts для нових delegations/API tokens/name servers, certificate-transparency monitoring та inventory cloud resources, на які посилається DNS. Досліджуйте resolution і certificate history subdomain окремо від reputation apex-а.

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)** зберігає encoded pointer на поточний C2 у legitimate post, profile, document, repository, cloud object або blockchain field. Malware отримує public object, декодує domain/IP і підключається до next stage. Bidirectional variants обмінюються commands або files через service APIs.<sup>[[7]](#references)</sup>

Це забезпечує resilience і приховує back-end C2 від static binary analysis. Водночас створюються стабільні ідентифікатори object, tenant, repository, API та access patterns. Defenders мають об'єднати:

1. process, який звернувся до service;
2. точний API path/object і response hash;
3. decoding або string-processing activity;
4. нове outbound connection невдовзі після цього; і
5. ідентичну behavior в інших системах fleet-а.

Блокування всіх GitHub, cloud storage або social media рідко є життєздатним. Service-aware egress policy і process-level correlation ефективніші за blocking лише на рівні domain.

## Personas, accounts and procurement compartments

Infrastructure anonymity руйнується, коли persona, recovery email, phone, payment, browser або admin IP з'єднує compartments. State-linked operations вирощували social profiles, email identities і cloud accounts задовго до використання; ATT&CK фіксує це як Establish Accounts (T1585), включно із social, email і cloud sub-techniques.<sup>[[8]](#references)</sup>

Defender або investigator будує graph із:

- часу створення та першого login, locale, time zone і робочого розкладу;
- recovery fields, MFA devices, identity documents і payment instruments;
- browser/TLS fingerprints та історії source network;
- повторного використання avatar, provenance зображень, writing style і розвитку social graph;
- спільних domain registrant, name server, certificate, analytics ID або repository commit;
- management-plane actions, що обходять public relay architecture.

Для authorized red team synthetic personas мають бути задокументовані для exercise controller, використовувати organization-owned recovery/payment channels, не імітувати реальних непричетних людей і мати заплановане retirement. SOC може залишатися blind; операція не повинна ставати безвідповідальною.

## Emerging compound patterns to threat-model

Наведене нижче — **defender-driven compositions**, а не твердження, що певний named actor застосував кожен точний design. Вони поєднують уже спостережувані primitives і корисні як purple-team hypotheses.

### Asymmetric one-way tasking

Commands надходять через public, broadcast або append-only source, тоді як результати після затримки виходять через unrelated channel. Прикладами primitive є web-service one-way communication і dead drops. Розділення не дає одному flow виглядати bidirectional і ускладнює просту request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** зберігайте object-level reads, потім корелюйте process state changes і подальші outbound transfers у ширшому часовому вікні. Шукайте рідкісний process, який читає той самий public object, навіть якщо негайної відповіді немає.

### Multi-stage channel promotion

Тихий first stage виконує inventory і лише promotes selected systems до unrelated second-stage channel. Другий endpoint, protocol і process можуть не мати спільної infrastructure з першим. Це обмежує exposure capable infrastructure і явно моделюється як ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** об'єднуйте `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; не закривайте incident після blocking першого domain.

### Cross-protocol relay translation

Різні hops перетворюють HTTPS, QUIC, WebSocket, DNS, SSH або message-queue API, а не прозоро пересилають packets. Translation усуває єдиний end-to-end protocol fingerprint, але створює gateways із характерними timing, buffering і semantic conversion. Protocol tunneling (T1572) можна комбінувати з proxies та service impersonation.<sup>[[11]](#references)</sup>

**Detection:** шукайте gateway hosts, які отримують один protocol і ініціюють інший із тісно пов'язаною byte/time behavior; порівнюйте intent endpoint-а з protocol, який фактично передається.

### Passive activation on edge devices

Замість beaconing implant моніторить traffic, що вже надходить до router/VPN, і активується лише на magic value, source-port pattern або authenticated token. Нормальний traffic продовжує надходити до справжнього service. ATT&CK називає це Traffic Signaling (T1205), із задокументованими прикладами для network devices та APT.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture під час authorized hunt, неочікувані socket filters і differential service behavior. Відсутність періодичного beacon не доводить, що edge device чистий.

### Serverless and ephemeral origin rotation

Front зберігає stable logical identity, тоді як short-lived functions/containers обробляють окремі stages у кількох regions/accounts. Це скорочує disk lifetime і кількість fixed origin IPs, але control-plane creation, image/layer, role, secret, request ID і billing telemetry стають стійким graph.

**Detection:** зберігайте cloud audit та invocation logs поза workload; кластеризуйте deployment templates, roles, environment keys і front-to-origin relationships.

### Privacy-layer diversity

Operation може навмисно уникати одного homogeneous chain: наприклад, один channel використовує leased relay, tasking — public object, exit походить із власного lab cellular link, а administration виконується через окрему organization network. Це зменшує цінність компрометації одного provider, але збільшує cross-layer timing і ризик operational error.

**Detection:** будуйте campaign timelines між identity, DNS, SaaS, network і cloud sensors. Шукайте synchronized state transitions, а не ідентичні indicators.

### Decentralized or transparency-log dead drops

Actor може розмістити невеликий encrypted pointer у будь-якій довговічній public append-only system, content-addressed store або transparency-like feed. Public object є resilient, але його точні index/content hash і client polling behavior стають стабільними identifiers.

**Detection:** записуйте повні API/object identifiers і response hashes; створюйте alerts для nonstandard processes, які опитують immutable objects, після чого виконуються decoding або нові connections.

### Delayed store-and-forward operations

Interactive C2 створює сильну timing correlation. Store-and-forward design накопичує encrypted jobs і повертає результати через хвилини або години через іншу queue чи physical transfer. Він жертвує responsiveness заради слабшої end-to-end timing.

**Detection:** збільшуйте correlation windows, моделюйте periodic queue access і перевіряйте endpoint staging. Batching переносить signal із packet timing на scheduled process/file behavior; він не усуває його.

## Design review: think in observers

Для кожного path заповнюйте цю таблицю до deployment і після collection:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Якщо один звичайний provider може заповнити кожну колонку, architecture забезпечує concealment від target, але не надійне separation. Якщо жоден internal controller не може пов'язати activity з engagement, така architecture непридатна для professional red teaming.

## References

- [1] [MITRE ATT&CK — Придбання infrastructure (T1583), компрометація infrastructure (T1584) і Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Espionage actors, пов'язані з Китаєм, використовують ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Компрометація infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
