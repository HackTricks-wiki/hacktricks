# Offensive Infrastructure and Attribution Evasion

Оператор рідко отримує справжню анонімність за допомогою одного proxy. Реальні кампанії будують **граф розділення**: оператор підключається до вузла доступу, вузли транзиту приховують цей вузол від вихідного вузла, redirectors захищають справжній C2, а disposable names вказують на публічний edge.

Використовуйте [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) для нормалізованого огляду переваг/недоліків, розгортання та виявлення кожного шляху. Ця сторінка детальніше розглядає композицію adversarial infrastructure.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Остання адреса, яку бачить ціль, є доказом шляху, а не доказом того, хто керував клавіатурою. MITRE зіставляє основні компоненти з Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) і Web Service (T1102).<sup>[[1]](#references)</sup>

## Класи інфраструктури

| Клас | Чому суб'єкт використовує його | Стійкі сліди | Найкращий напрямок аналізу для захисника |
|---|---|---|---|
| Орендований VPS/cloud | Швидкий, передбачуваний, маршрутизований, його легко перебудувати | tenant, білінг, консоль, логіни до source і історія образів | події акаунта/control plane і повторюваний fingerprint сервера |
| Commercial VPN/Tor | Великий спільний набір вихідних адрес; відсутність адміністрування сервера | видимість провайдера/guard і end-to-end timing | поведінка призначення, докази на endpoint і кореляція потоків |
| Residential/mobile proxy | ASN споживача та географічна правдоподібність | записи брокера/клієнта; поведінка proxyware або зараженого хоста | неможливе переміщення, протоколи proxy і зміна адрес у межах сесії |
| Зламаний сервер/маршрутизатор/IoT | Використовує репутацію та юрисдикцію жертви | implant, потік керування і повторюваний upstream controller | телеметрія пристрою та топологія ORB, а не одна вихідна IP |
| CDN/redirector | Відокремлює публічний edge від back-end C2 | TLS/HTTP grammar, сертифікат, маршрутизація й артефакти cloud-акаунта | кореляція edge-to-origin і кластеризація форми запитів |
| Легітимний web service | Маскується під дозволений GitHub/cloud/social traffic | API token, ідентифікатори tenant/object і нетиповий process lineage | процес на endpoint разом із семантикою service/API |
| Фізичний/cellular/satellite шлях | Змінює уявне фізичне походження | записи RF, оператора, абонента, пристрою та місцезнаходження | сукупність radio/physical і мережевих доказів |

## Мережі операційних relay box

**ORB network** — це керований fleet proxy, який використовується як проміжний service. Mandiant поділяє їх на provisioned networks з орендованих серверів, non-provisioned networks зі зламаних маршрутизаторів/IoT і гібриди. Зріла топологія має чотири логічні ролі:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** підтримує inventory, credentials, health і routing policy.
2. **Access/relay node:** автентифікує клієнтів або операторів; це стабільна точка входу до змінної mesh-мережі.
3. **Traversal nodes:** одна або більше орендованих чи зламаних систем передають opaque connections.
4. **Exit/staging node:** представляє фінальну source address для reconnaissance, exploitation або C2 targets.

Mesh-мережа може обирати exits за країною, ASN, latency або availability і замінювати несправні nodes. Кілька threat groups можуть орендувати одну й ту саму мережу. Mandiant спостерігала, як IPv4-адреса залишалася пов'язаною з деякими ORB лише 31 день; тому вона рекомендує розглядати **мережу як сутність, подібну до суб'єкта, що еволюціонує**, а не блокувати застарілий список IP-адрес.<sup>[[2]](#references)</sup>

### Що це дає — і що це leak

- Ціль бачить exit, який може бути географічно близьким і здаватися residential.
- Exit бачить ціль і попередній hop, але не обов'язково оператора.
- Access service бачить клієнта та запит маршруту. Незалежно керована mesh-мережа може відокремлювати клієнта від exits, але водночас створює потужний запис у контрагента.
- Повторювані порти, порядок handshake, server banners, сертифікати, вікна uptime та зв'язки з controller можуть викрити fleet, навіть коли IP-адреси змінюються.
- Зламаний маршрутизатор часто не має endpoint telemetry, але його ISP все одно зберігає дані про абонента та потоки; вилучення пристрою відкриває артефакти implant/configuration.

{% hint style="info" %}
Для авторизованої вправи відтворіть топологію на VM або маршрутизаторах, що належать організації, і збережіть attribution map controller. Не залучайте відкриті proxy або пристрої третіх сторін. [Практичний посібник](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) створює таку саму видиму для захисника структуру hop без перетворення посередника на жертву.
{% endhint %}

## Residential і mobile proxy networks

Residential proxy services призначають сесії consumer broadband addresses; mobile proxies виходять через carrier NAT pools. Джерелами можуть бути навмисно зареєстровані appliances, SDK/proxyware, вбудовані в consumer applications, resellers або malware. Ці джерела не є рівнозначними: відсутність informed consent перетворює privacy service на compromised infrastructure.

Режими ротації впливають на виявлення:

- **per-request rotation** спричиняє швидкі розриви між IP та ASN/geography, тоді як ідентичність на вищому рівні залишається стабільною;
- **sticky sessions** зберігають exit протягом хвилин або годин, нагадуючи звичайного абонента;
- **backconnect gateways** показують клієнту одну broker endpoint і внутрішньо обирають exits;
- **mobile pools** розміщують багатьох справжніх абонентів за невеликою кількістю carrier NAT addresses, через що блокування IP стає дорогим.

Захисникам слід корелювати IP з authenticated session, TLS/client fingerprint, порядком HTTP, device cookie та поведінкою. Нібито локальний residential login, після якого з'являється інша країна, тоді як усі ознаки вищого рівня залишаються ідентичними, є сильнішим індикатором, ніж сама reputation. Водночас спільне використання адрес і mobile handoff створюють легітимні зміни, тому ніколи не вважайте residential/proxy classification остаточним вердиктом.

## Multi-hop proxy chains

MITRE розрізняє external proxies і **multi-hop proxies (T1090.003)**. Важлива не кількість hop, а розділення knowledge та administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Якщо одна сторона керує A і B, спільні журнали або часові характеристики потоків можуть відновити ланцюжок. Додавання послідовних комерційних VPN з тієї самої кінцевої точки/облікового запису може збільшити затримку, водночас залишаючи спільні докази ідентичності, платежів і часу. Tor зменшує цю проблему завдяки незалежно вибраним relay та спільній клієнтській архітектурі, але інтерактивна мережа з низькою затримкою не може гарантувати стійкість до спостерігача, який вимірює обидва кінці.

Поширеними помилками є обхід через DNS або IPv6, відкриття застосунками власних сокетів, пряме надходження management traffic до relay, синхронізована активність, повторне використання SSH-ключів і вхід до ідентифікованих облікових записів. Правильна перевірка — це failure test: по черзі зупинити кожен relay і показати, що workload не може перейти на незахищений шлях.

## Рівні redirector і формування трафіку

Публічний **redirector** приймає трафік, що відповідає специфічній для операції граматиці, і пересилає його до захищеного team server. Усе інше можна відхиляти або обслуговувати нешкідливим контентом.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Кілька рівнів обмежують розкриття: використання public domain не обов'язково розкриває team server. CDN додають anycast capacity і зовнішній domain із доброю репутацією, але акаунт CDN та edge logs стають точками attribution. TLS fingerprints, історія сертифікатів, характерні paths/порядок headers, розміри відповідей, поведінка redirects і origin allowlists можуть об'єднати нібито не пов'язані fronts.

Для виявлення записуйте поля reverse proxy до нормалізації, порівнюйте SNI/Host/authority, перевіряйте рідкісні комбінації headers, кластеризуйте тіла відповідей і TLS fingerprints та шукайте збіги конфігурацій у cloud/CDN audit logs. Для авторизованих red teams не копіюйте реальний бренд і не розміщуйте збір облікових даних за unrelated third party.

## Domain fronting and domainless fronting

За класичного **domain fronting (T1090.004)** TLS-з'єднання оголошує дозволений front domain у SNI, тоді як зашифрований HTTP `Host` або HTTP/2 `:authority` запитує інший back-end domain. Узгоджений CDN маршрутизує запит за внутрішнім значенням. Спостерігач у мережі без TLS decryption бачить front; CDN бачить обидва значення та origin. У domainless variants SNI може бути порожнім, тоді як інше поле маршрутизації вибирає destination.<sup>[[4]](#references)</sup>

Це не магічна impersonation: метод працює лише тоді, коли intermediary навмисно або випадково дозволяє невідповідність і знає, як маршрутизувати внутрішнє ім'я. Major providers обмежили cross-account fronting. Encrypted ClientHello (ECH) змінює те, що може бачити on-path observer, але не усуває записи CDN, endpoint або application.

Точки виявлення включають:

- ancestry процесу на endpoint і destination, неочікуваний для цього application;
- невідповідність SNI та HTTP authority, коли TLS inspection є законним і доступним;
- CDN logs, у яких один tenant/front маршрутизується до іншого authority/origin;
- незвично довгі або періодичні sessions до service, який зазвичай є інтерактивним;
- стабільні розміри та cadence зашифрованих flows між різними front domains.

Безпечна lab відтворює mismatch маршрутизації на власному reverse proxy; вона не зловживає public CDN.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution відокремлює logical service від фіксованої infrastructure:

- **DDNS:** authenticated client оновлює стабільне ім'я після зміни своєї address.
- **DGA:** endpoint і controller виводять candidate domain names із time/key seed; operator реєструє невелику їх підмножину.
- **Fast flux:** name повертає набір адрес compromised/proxy, що швидко змінюється, часто з низькими TTL.
- **Double flux:** обертаються і service addresses, і authoritative name-server addresses, додатково приховуючи control layer.

Fast flux — це pattern розподілу навантаження, який використовується adversarial, а не просто «багато DNS-відповідей». Переконливіші докази поєднують низький TTL, велику кількість унікальних addresses, значне розсіювання ASN/geography, короткий час життя nodes, повторювану application behavior і підозрілу registration history. CDN легітимно мають кілька з цих властивостей. MITRE рекомендує корелювати DNS behavior із process і подальшими connections.<sup>[[5]](#references)</sup>

DGA можна виявляти за lexical entropy, patterns приголосних/цифр, сплесками NXDOMAIN, синхронізованими first-seen domains і process context. Wordlist DGAs та generative models обходять прості entropy rules, тому fleet-wide temporal clustering і endpoint lineage стають важливішими.

## Compromised domains and domain shadowing

Actor може викрасти registrar/DNS account, захопити dangling subdomain або додати records під інакше reputable domain. **Domain shadowing** зберігає легітимний apex, тоді як велика кількість attacker-controlled subdomains вказує на змінні delivery або C2 hosts. Це використовує age та reputation і може обходити блокування на рівні всього domain.<sup>[[6]](#references)</sup>

Defenders потрібні registrar та authoritative-DNS audit logs, MFA, registry/registrar locks, alerts для нових delegations/API tokens/name servers, certificate-transparency monitoring і inventory cloud resources, на які посилається DNS. Досліджуйте resolution та certificate history subdomain окремо від reputation apex.

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)** зберігає encoded pointer на поточний C2 у legitimate post, profile, document, repository, cloud object або blockchain field. Malware отримує public object, декодує domain/IP і підключається до наступного stage. Bidirectional variants обмінюються commands або files через service APIs.<sup>[[7]](#references)</sup>

Це забезпечує resilience і приховує back-end C2 від static binary analysis. Водночас створюються стабільні identifiers об'єкта, tenant, repository, API та access patterns. Defenders мають об'єднувати:

1. process, який звертався до service;
2. точний API path/object і response hash;
3. decoding або string-processing activity;
4. нове outbound connection невдовзі після цього; і
5. ідентичну behavior в інших місцях fleet.

Блокувати весь GitHub, cloud storage або social media зазвичай нереалістично. Service-aware egress policy та process-level correlation ефективніші за blocking лише за domain.

## Personas, accounts and procurement compartments

Infrastructure anonymity руйнується, коли persona, recovery email, phone, payment, browser або admin IP з'єднує compartments. State-linked operations розвивали social profiles, email identities і cloud accounts задовго до використання; ATT&CK фіксує це як Establish Accounts (T1585), включно із social, email і cloud sub-techniques.<sup>[[8]](#references)</sup>

Defender або investigator будує graph із:

- часу створення та першого login, locale, time zone і робочого розкладу;
- recovery fields, MFA devices, identity documents і payment instruments;
- browser/TLS fingerprints та історії source network;
- повторного використання avatar, provenance зображень, writing style і зростання social graph;
- спільного domain registrant, name server, certificate, analytics ID або repository commit;
- дій management plane, які обходять architecture public relay.

Для авторизованої red team synthetic personas мають бути задокументовані для exercise controller, використовувати organization-owned recovery/payment channels, не видавати себе за реальних непричетних людей і мати заплановане retirement. SOC може залишатися blind; operation не повинна ставати безвідповідальною.

## Emerging compound patterns to threat-model

Наведене нижче — це **defender-driven compositions**, а не твердження, що певний named actor застосував кожен точний design. Вони поєднують уже спостережувані primitives і корисні як purple-team hypotheses.

### Asymmetric one-way tasking

Commands надходять через public, broadcast або append-only source, тоді як results виходять через unrelated channel із затримкою. Приклади primitive включають web-service one-way communication і dead drops. Розділення не дає одному flow виглядати bidirectional і ускладнює просту request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** зберігайте object-level reads, потім корелюйте зміни process state та пізніші outbound transfers у ширшому вікні. Шукайте рідкісний process, який читає той самий public object, навіть якщо негайної відповіді немає.

### Multi-stage channel promotion

Тихий first stage виконує inventory і лише підвищує selected systems до unrelated second-stage channel. Другі endpoint, protocol і process можуть не мати спільної infrastructure з першими. Це обмежує exposure capable infrastructure і явно моделюється як ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** об'єднуйте `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; не закривайте incident після блокування першого domain.

### Cross-protocol relay translation

Різні hops перетворюють HTTPS, QUIC, WebSocket, DNS, SSH або message-queue API, а не прозоро пересилають packets. Translation усуває єдиний end-to-end protocol fingerprint, але створює gateways із характерними timing, buffering та semantic conversion. Protocol tunneling (T1572) можна поєднувати з proxies і service impersonation.<sup>[[11]](#references)</sup>

**Detection:** шукайте gateway hosts, які отримують один protocol і ініціюють інший із тісно пов'язаною byte/time behavior; порівнюйте intent endpoint із protocol, який фактично передається.

### Passive activation on edge devices

Замість beaconing implant відстежує traffic, який уже надходить до router/VPN, і активується лише на magic value, source-port pattern або authenticated token. Normal traffic продовжує надходити до реального service. ATT&CK називає це Traffic Signaling (T1205), із задокументованими network-device та APT examples.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture під час authorized hunt, неочікувані socket filters і differential service behavior. Відсутність periodic beacon не доводить, що edge device чистий.

### Serverless and ephemeral origin rotation

Front зберігає стабільну logical identity, тоді як short-lived functions/containers обробляють окремі stages у кількох regions/accounts. Це зменшує disk lifetime і fixed origin IPs, але creation у control plane, image/layer, role, secret, request ID та billing telemetry стають довговічним graph.

**Detection:** зберігайте cloud audit та invocation logs поза workload; кластеризуйте deployment templates, roles, environment keys і front-to-origin relationships.

### Privacy-layer diversity

Operation може навмисно уникати одного homogeneous chain: наприклад, один channel використовує leased relay, tasking — public object, exit походить із owned lab cellular link, а administration здійснюється через окрему organization network. Це зменшує цінність компрометації одного provider, але збільшує cross-layer timing і ризик operational errors.

**Detection:** створюйте campaign timelines між identity, DNS, SaaS, network і cloud sensors. Шукайте synchronized state transitions, а не ідентичні indicators.

### Decentralized or transparency-log dead drops

Actor може розмістити невеликий encrypted pointer у будь-якій довговічній public append-only system, content-addressed store або transparency-like feed. Public object є resilient, але його точні index/content hash і client polling behavior стають стабільними identifiers.

**Detection:** записуйте повні API/object identifiers і response hashes; створюйте alerts для нестандартних processes, які опитують immutable objects, після чого виконують decoding або нові connections.

### Delayed store-and-forward operations

Interactive C2 створює сильну timing correlation. Store-and-forward design накопичує encrypted jobs пакетами і повертає results через кілька хвилин або годин через іншу queue чи physical transfer. Він жертвує responsiveness заради слабшого end-to-end timing.

**Detection:** збільшуйте correlation windows, моделюйте periodic queue access і перевіряйте endpoint staging. Batching переносить signal із packet timing до scheduled process/file behavior, але не усуває його.

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

Якщо один звичайний provider може заповнити кожну колонку, architecture забезпечує concealment від target, але не надійне separation. Якщо жоден internal controller не може пов'язати activity з engagement, така architecture непридатна для професійної red teaming.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), and Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
