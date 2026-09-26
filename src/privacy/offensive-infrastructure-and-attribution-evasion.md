# Наступальна інфраструктура та ухилення від атрибуції

{{#include ../banners/hacktricks-training.md}}

Оператор рідко отримує значущу анонімність за допомогою одного proxy. Реальні кампанії будують **граф розділення**: оператор досягає access node, traversal nodes приховують цей вузол від exit, redirectors захищають справжній C2, а disposable names вказують на public edge.

Використовуйте [Каталог технік анонімного доступу до Інтернету](anonymous-internet-access-techniques.md), щоб отримати нормалізований огляд переваг і недоліків, розгортання та виявлення для кожного шляху. На цій сторінці детальніше розглядається композиція adversarial infrastructure.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Остання адреса, яку бачить ціль, є доказом шляху, а не доказом того, хто керував клавіатурою. MITRE зіставляє основні компоненти з Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) і Web Service (T1102).<sup>[[1]](#references)</sup>

## Класи інфраструктури

| Клас | Навіщо це використовує actor | Стійкі сліди | Найкращий pivot для захисника |
|---|---|---|---|
| Орендований VPS/cloud | Швидкий, передбачуваний, маршрутизований, легко перебудовується | tenant, billing, console, source-login та історія образів | події облікового запису/control plane і повторюваний server fingerprint |
| Commercial VPN/Tor | Великий спільний набір вихідних адрес; не потребує адміністрування сервера | видимість провайдера/guard і end-to-end timing | поведінка призначення, докази на endpoint і кореляція потоків |
| Residential/mobile proxy | ASN споживчого провайдера та географічна правдоподібність | записи broker/customer; поведінка proxyware або зараженого хоста | impossible travel, proxy-протоколи та зміна адрес між сесіями |
| Compromised server/router/IoT | Використовує репутацію та юрисдикцію жертви | implant, management flow і повторюваний upstream controller | телеметрія пристрою та ORB topology, а не одна exit IP |
| CDN/redirector | Відокремлює публічний edge від back-end C2 | TLS/HTTP grammar, certificate, routing і cloud-account артефакти | кореляція edge-to-origin і кластеризація форми запитів |
| Legitimate web service | Маскується під дозволений GitHub/cloud/social traffic | API token, ідентифікатори tenant/object та незвична process lineage | процес на endpoint разом із семантикою service/API |
| Фізичний/cellular/satellite path | Змінює видиме фізичне походження | записи RF, carrier, subscriber, device та location | об’єднані радіо/фізичні та мережеві докази |

## Мережі operational relay box

**ORB network** — це керований proxy fleet, що використовується як проміжний сервіс. Mandiant поділяє їх на provisioned networks з орендованих серверів, non-provisioned networks зі скомпрометованих router/IoT і гібриди. Зріла топологія має чотири логічні ролі:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** підтримує інвентар, облікові дані, стан і routing policy.
2. **Access/relay node:** автентифікує customer або operator; це стабільна точка входу до mesh, що змінюється.
3. **Traversal nodes:** одна або кілька орендованих чи скомпрометованих систем ретранслюють непрозорі з’єднання.
4. **Exit/staging node:** представляє фінальну source address для reconnaissance, exploitation або C2 targets.

Mesh може вибирати exits за країною, ASN, latency або availability і замінювати вузли, що вийшли з ладу. Кілька threat groups можуть орендувати одну й ту саму network. Mandiant спостерігала, що IPv4 address залишалася пов’язаною з деякими ORB лише 31 день; тому вона рекомендує розглядати **network як evolving actor-like entity**, а не блокувати застарілий список IP.<sup>[[2]](#references)</sup>

### Що це дає — і що це витікає

- Ціль бачить exit, який може бути географічно близьким і, на перший погляд, residential.
- Exit бачить ціль і попередній hop, але не обов’язково operator.
- Access service бачить customer і route request. Незалежно керований mesh може відокремлювати customer від exits, але створює потужний запис про контрагента.
- Повторювані порти, порядок handshake, server banners, certificates, вікна uptime та зв’язки з controller можуть викрити fleet, навіть коли IP змінюються.
- Скомпрометованому router часто бракує endpoint telemetry, але його ISP усе одно має дані про subscriber і flow; вилучення розкриває артефакти implant/configuration.

{% hint style="info" %}
Для авторизованої вправи відтворіть topology за допомогою VM або router, що належать організації, і збережіть attribution map controller. Не залучайте open proxies або пристрої третіх сторін. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) створює таку саму видиму для захисника hop structure, не завдаючи шкоди intermediary.
{% endhint %}

## Residential і mobile proxy networks

Residential proxy services призначають сесії consumer broadband addresses; mobile proxies виходять через carrier NAT pools. Джерелом можуть бути спеціально зареєстровані appliances, SDK/proxyware, вбудовані в consumer applications, resellers або malware. Ці джерела не є еквівалентними: відсутність informed consent перетворює privacy service на compromised infrastructure.

Режими rotation впливають на detection:

- **per-request rotation** створює швидкі розбіжності IP та ASN/geography, тоді як identity на вищому рівні залишається стабільною;
- **sticky sessions** утримують exit протягом хвилин або годин, імітуючи звичайного subscriber;
- **backconnect gateways** показують customer одну broker endpoint і внутрішньо обирають exits;
- **mobile pools** розміщують багатьох справжніх subscribers за невеликою кількістю carrier NAT addresses, через що блокування IP стає витратним.

Захисникам слід корелювати IP з authenticated session, TLS/client fingerprint, HTTP ordering, device cookie та behavior. Нібито локальний residential login, після якого з’являється інша країна, тоді як усі features вищого рівня залишаються ідентичними, є сильнішим сигналом, ніж сама reputation. Водночас address sharing і mobile handoff створюють легітимну нестабільність, тому ніколи не вважайте residential/proxy classification остаточним висновком.

### Proxyware control planes і перетин reseller

Не моделюйте residential pool як плоский список exits. Аналіз екосистеми IPIDEA виявив придатний для повторного використання **two-tier control plane**: вбудований SDK спочатку передає metadata пристрою/enrollment до домену Tier One і отримує scheduling, а також пари Tier Two `connect`/`proxy` IP:port. Вузол періодично опитує Tier Two connect port щодо encoded task, відкриває друге з’єднання до відповідного proxy port і ретранслює передані bytes до запитаного destination. Нібито різні SDK та proxy brands мали окремі discovery domains, але сходилися на спільній Tier Two infrastructure та overlapping exit pools через спільне ownership і reseller relationships.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Це створює стійкіші точки для подальшого hunting, ніж блок residential IP:<sup>[[13]](#references)</sup>

- неочікуваний процес utility, VPN, гри або вбудованого пристрою надсилає стабільний ідентифікатор пристрою/ключ клієнта й отримує список серверів, що змінюється;
- endpoint опитує пряму IP-адресу на незвичному порту, а потім одразу підключається до іншого порту на тій самій адресі перед відкриттям нового destination socket;
- кілька нібито різних брендів використовують спільні адреси Tier Two, grammar протоколу, код SDK або перетин exit-node;
- різні застосунки, що звертаються до різних доменів Tier One, отримують адреси з того самого пулу Tier Two.

Такий перетин також обмежує attribution: наявність IP-адреси в рекламованому пулі одного vendor не встановлює, який reseller, клієнт або threat actor використовував її у відповідний момент. Зберігайте часові мітки flow, lineage процесів, тіла відповідей Tier One та ідентифікатори завдань Tier Two.<sup>[[13]](#references)</sup> У межах авторизованої вправи відтворюйте цю ієрархію лише за допомогою endpoint, що належать організації; ніколи не реєструйте споживчі пристрої або proxyware третіх сторін.

## Ланцюжки багатоступеневих proxy

MITRE розрізняє external proxies і **multi-hop proxies (T1090.003)**. Важливою властивістю є не кількість hop, а розділення знань і адміністрування.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Якщо одна сторона керує A і B, спільні логи або час проходження трафіку можуть відтворити circuit. Додавання послідовних комерційних VPN з тієї самої endpoint/account може збільшити latency, водночас залишаючи спільні докази ідентичності, оплати та часу. Tor зменшує цю проблему завдяки незалежно вибраним relay і спільному client design, але інтерактивна мережа з низькою latency не може гарантувати стійкість до спостерігача, який вимірює обидва кінці.

Поширені проблеми — це DNS- або IPv6-bypass, застосунки, що відкривають власні sockets, management traffic, який напряму досягає relay, синхронізована активність, повторно використані SSH keys і вхід до ідентифікованих акаунтів. Правильна перевірка — це failure test: по черзі зупинити кожен relay і показати, що workload не може перейти на clear path.

### Руйнування тунелю та витік upstream

Relay architecture часто має найбільшу атрибутивність саме під час збою. Unit 42 задокументувала багаторівневий espionage path із використанням VPS, орієнтованих на victim, relay VPS, residential proxies, Tor та інших proxy services; коли tunnel було пропущено або він зруйнувався, прихована upstream infrastructure напряму підключалася до relay і victim-facing systems. У тому самому розслідуванні також використовували X.509 certificate, який ненадовго був exposed на upstream infrastructure, як cross-tier pivot.<sup>[[14]](#references)</sup>

Тримайте **data plane** (`victim <-> exit`) окремо від **control plane** (`operator/upstream -> relay administration`). Зберігайте ingress і authentication logs на кожному контрольованому tier, історію сертифікатів і короткі невдалі підключення — не лише успішні C2 sessions. Джерело, яке з’являється лише під час relay outages або напряму адмініструє кілька victim-facing nodes, є сильнішим кандидатом на роль upstream, ніж звичайний exit, але його ASN/geolocation усе ще є гіпотезою, а не доказом ідентичності оператора.

Авторизована лабораторія має забезпечувати workload fail closed. Для workload, ізольованого в Linux network namespace, перший route має використовувати tunnel; після його видалення і request, і route lookup мають завершитися помилкою, а не вибрати physical uplink:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Повторіть тест для DNS та IPv6, а також на кожній межі relay. Якщо будь-яка probe успішна, зафіксуйте фактичний інтерфейс/source address до відновлення policy routing або firewall; це attribution leak, який побачив би investigator.

## Рівні redirector і shaping трафіку

Публічний **redirector** приймає трафік, що відповідає специфічній для операції grammar, і пересилає його на захищений team server. Усе інше можна відхилити або обслуговувати нешкідливим контентом.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Кілька рівнів обмежують розкриття: компрометація public domain не обов'язково розкриває team server. CDN додають anycast capacity і респектабельний outer domain, але CDN account та edge logs стають точками атрибуції. TLS fingerprints, certificate histories, distinctive paths/header order, response sizes, redirect behavior і origin allowlists можуть об'єднати нібито не пов'язані front-и.

Для detection записуйте поля reverse-proxy до normalization, порівнюйте SNI/Host/authority, перевіряйте рідкісні комбінації заголовків, кластеризуйте response bodies і TLS fingerprints, а також шукайте в cloud/CDN audit logs збіги конфігурацій. Для authorized red teams не копіюйте справжній бренд і не розміщуйте credential collection за unrelated third party.

## Domain fronting і domainless fronting

За класичного **domain fronting (T1090.004)** TLS connection оголошує дозволений front domain у SNI, тоді як зашифрований HTTP `Host` або HTTP/2 `:authority` запитує інший back-end domain. Співпрацюючий CDN маршрутизує за внутрішнім значенням. Network observer без TLS decryption бачить front; CDN бачить обидва значення та origin. У domainless variants SNI може бути порожнім, тоді як інше поле маршрутизації обирає destination.<sup>[[4]](#references)</sup>

Це не магічна impersonation: воно працює лише тоді, коли intermediary навмисно або випадково дозволяє невідповідність і знає, як маршрутизувати внутрішнє ім'я. Major providers обмежили cross-account fronting. Encrypted ClientHello (ECH) змінює те, що може бачити on-path observer, але не стирає записи CDN, endpoint або application.

Detection points включають:

- process ancestry endpoint-а та destination, неочікуваний для цього application;
- невідповідність SNI та HTTP authority, якщо TLS inspection є законною і доступною;
- CDN logs, що показують routing від одного tenant/front до іншого authority/origin;
- незвично довгі або періодичні sessions до service, який зазвичай є interactive;
- стабільні розміри та cadence зашифрованих потоків через front domains, що змінюються.

Безпечна lab імітує routing mismatch на власному reverse proxy; вона не зловживає public CDN.

## Dynamic resolution: DDNS, DGA і fast flux

Dynamic resolution відокремлює logical service від фіксованої infrastructure:

- **DDNS:** authenticated client оновлює стабільне ім'я після зміни його address.
- **DGA:** endpoint і controller виводять candidate domain names із time/key seed; operator реєструє невелику підмножину.
- **Fast flux:** name повертає набір compromised/proxy addresses, що швидко змінюється, часто з низькими TTL.
- **Double flux:** обертаються як service addresses, так і authoritative name-server addresses, приховуючи також control layer.

Fast flux — це load-distribution pattern, що використовується adversarially, а не просто «багато DNS-відповідей». Сильніші докази поєднують низький TTL, велику кількість unique addresses, широку дисперсію ASN/geography, короткий node lifetime, повторювану application behavior і підозрілу registration history. CDN легітимно мають кілька з цих властивостей. MITRE рекомендує корелювати DNS behavior із process і наступними connections.<sup>[[5]](#references)</sup>

DGA можна виявляти за lexical entropy, patterns consonant/digit, сплесками NXDOMAIN, синхронізованими first-seen domains і process context. Wordlist DGAs та generative models долають прості entropy rules, тому fleet-wide temporal clustering і endpoint lineage стають важливішими.

## Compromised domains і domain shadowing

Actor може hijack-нути registrar/DNS account, отримати контроль над dangling subdomain або додати records під загалом респектабельним domain. **Domain shadowing** зберігає legitimate apex, тоді як велика кількість attacker-controlled subdomains вказує на змінювані delivery або C2 hosts. Це використовує age та reputation і може обходити domain-wide blocking.<sup>[[6]](#references)</sup>

Defenders потрібні registrar та authoritative-DNS audit logs, MFA, registry/registrar locks, alerts для нових delegations/API tokens/name servers, certificate-transparency monitoring та inventory cloud resources, на які посилається DNS. Досліджуйте resolution і certificate history subdomain незалежно від reputation apex.

## Web services і dead-drop resolvers

**Dead-drop resolver (T1102.001)** зберігає encoded pointer на поточний C2 у legitimate post, profile, document, repository, cloud object або blockchain field. Malware отримує public object, декодує domain/IP і підключається до наступного stage. Bidirectional variants обмінюються commands або files через service APIs.<sup>[[7]](#references)</sup>

Це забезпечує resilience і приховує back-end C2 від static binary analysis. Водночас створюються стабільні ідентифікатори object, tenant, repository, API та access patterns. Defenders повинні об'єднувати:

1. process, який звернувся до service;
2. точний API path/object і response hash;
3. decoding або string-processing activity;
4. нове outbound connection невдовзі після цього; і
5. ідентичну behavior в інших частинах fleet.

Блокування всіх GitHub, cloud storage або social media рідко є життєздатним. Service-aware egress policy і process-level correlation ефективніші за domain-only blocking.

## Personas, accounts і procurement compartments

Infrastructure anonymity руйнується, коли persona, recovery email, phone, payment, browser або admin IP з'єднує compartments. State-linked operations створювали social profiles, email identities і cloud accounts задовго до використання; ATT&CK фіксує це як Establish Accounts (T1585), включно із social, email і cloud sub-techniques.<sup>[[8]](#references)</sup>

Defender або investigator будує graph із:

- часу створення та першого входу, locale, time zone і робочого розкладу;
- recovery fields, MFA devices, identity documents і payment instruments;
- browser/TLS fingerprints та history source network;
- повторного використання avatar, provenance зображень, writing style і зростання social graph;
- спільного domain registrant, name server, certificate, analytics ID або repository commit;
- management-plane actions, що обходять public relay architecture.

Для authorized red team synthetic personas мають бути задокументовані для exercise controller, використовувати organization-owned recovery/payment channels, не імітувати реальних непричетних людей і мати заплановане retirement. SOC може залишатися blind, але operation не має ставати безконтрольною.

## Emerging compound patterns to threat-model

Наведене нижче — **defender-driven compositions**, а не твердження, що певний named actor розгорнув кожен конкретний design. Вони поєднують уже спостережувані primitives і корисні як purple-team hypotheses.

### Asymmetric one-way tasking

Commands надходять через public, broadcast або append-only source, тоді як results виходять через unrelated channel із затримкою. Прикладами primitive є web-service one-way communication і dead drops. Розділення не дає одному flow виглядати bidirectional і ускладнює просту request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** зберігайте object-level reads, потім корелюйте process state changes і пізніші outbound transfers у ширшому window. Шукайте рідкісний process, що читає той самий public object, навіть якщо негайної відповіді немає.

### Multi-stage channel promotion

Тихий first stage виконує inventory і лише підвищує selected systems до unrelated second-stage channel. Другий endpoint, protocol і process можуть не мати спільної infrastructure з першим. Це обмежує exposure capable infrastructure і явно моделюється як ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** об'єднуйте `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; не завершуйте incident після блокування першого domain.

### Cross-protocol relay translation

Різні hops перетворюють HTTPS, QUIC, WebSocket, DNS, SSH або message-queue API замість прозорого forwarding packets. Translation усуває єдиний end-to-end protocol fingerprint, але створює gateways із distinctive timing, buffering і semantic conversion. Protocol tunneling (T1572) можна поєднувати з proxies та service impersonation.<sup>[[11]](#references)</sup>

**Detection:** шукайте gateway hosts, які отримують один protocol і ініціюють інший із тісно пов'язаною byte/time behavior; порівнюйте intent endpoint-а з protocol, який фактично передається.

### Passive activation on edge devices

Замість beaconing implant monitors traffic, що вже надходить до router/VPN, і активується лише за magic value, source-port pattern або authenticated token. Normal traffic продовжує надходити до реального service. ATT&CK називає це Traffic Signaling (T1205), із задокументованими прикладами network-device та APT.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture під час authorized hunt, unexpected socket filters і differential service behavior. Відсутність periodic beacon не доводить, що edge device clean.

### Serverless and ephemeral origin rotation

Front зберігає стабільну logical identity, тоді як short-lived functions/containers обробляють окремі stages у кількох regions/accounts. Це скорочує disk lifetime і fixed origin IPs, але control-plane creation, image/layer, role, secret, request ID та billing telemetry стають durable graph.

**Detection:** зберігайте cloud audit та invocation logs поза workload; кластеризуйте deployment templates, roles, environment keys і front-to-origin relationships.

### Privacy-layer diversity

Operation може навмисно уникати одного homogeneous chain: наприклад, один channel використовує leased relay, tasking — public object, exit походить із owned lab cellular link, а administration використовує окрему organization network. Це зменшує користь від компрометації одного provider, але збільшує cross-layer timing та operational-error risk.

**Detection:** будуйте campaign timelines за даними identity, DNS, SaaS, network і cloud sensors. Шукайте synchronized state transitions, а не identical indicators.

### Decentralized or transparency-log dead drops

Actor може розмістити small encrypted pointer у будь-якій durable public append-only system, content-addressed store або transparency-like feed. Public object є resilient, але його exact index/content hash і client polling behavior стають стабільними identifiers.

**Detection:** записуйте повні API/object identifiers і response hashes; створюйте alerts для nonstandard processes, які опитують immutable objects, після чого виконуються decoding або нові connections.

### Delayed store-and-forward operations

Interactive C2 створює сильну timing correlation. Store-and-forward design накопичує encrypted jobs і повертає results через кілька хвилин або годин через іншу queue або physical transfer. Це жертвує responsiveness заради слабшого end-to-end timing.

**Detection:** збільшуйте correlation windows, моделюйте periodic queue access і перевіряйте endpoint staging. Batching переносить signal із packet timing до scheduled process/file behavior; він не стирає його.

## Design review: думайте про observers

Для кожного path заповнюйте цю таблицю до deployment і після collection:

| Layer | Бачить source? | Бачить destination? | Бачить content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Якщо один звичайний provider може заповнити кожну колонку, architecture забезпечує concealment від target, але не robust separation. Якщо жоден internal controller не може зіставити activity з engagement, така architecture непридатна для professional red teaming.

## References

- [1] [MITRE ATT&CK — Отримання інфраструктури (T1583), компрометація інфраструктури (T1584) і Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Espionage actors, пов'язані з Китаєм, використовують ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Компрометація інфраструктури: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Припинення роботи найбільшої у світі residential proxy network](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Виявлення глобального espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
