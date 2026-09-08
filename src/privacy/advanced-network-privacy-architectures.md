# Розширені архітектури мережевої приватності

{{#include ../banners/hacktricks-training.md}}

Складність корисна лише тоді, коли вона усуває конкретного спостерігача або режим відмови. Унікальний набір тунелів, нестандартна форма пакетів, рідкісний user agent або інфраструктура, що часто змінюється, можуть стати сильнішим fingerprint, ніж стандартна конфігурація, якою користуються тисячі людей.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) містить загальну схему `Pros`/`Cons`/`Procedure`/`Detection`. Ця сторінка розширює опис складніших архітектур і меж довіри.

Отже, розширена мета — **розділення знань**: жоден звичайний компонент не повинен одночасно володіти ідентичністю користувача, призначенням, plaintext і довгостроковою історією активності. Це не невидимість: collusion, legal process, компрометація endpoint або end-to-end кореляція трафіку все ще можуть відновити цей шлях.

## Вибір архітектури

| Pattern | Отримана властивість | Нова довіра/відмова | Придатне використання |
|---|---|---|---|
| Standard Tor Browser | Спільний browser fingerprint і шлях через кілька relay | Низька затримка допускає кореляцію трафіку | Загальний anonymous web browsing |
| Tor bridge + pluggable transport | Ускладнює пряме блокування/класифікацію Tor | Bridge/transport усе ще можна виявити; bridge дізнається source | Цензуровані мережі |
| Onion service | Приховує IP сервісу; уникає exit; автентифікує onion identity | Onion key і server endpoint стають критичними активами | Приватна публікація, приймання даних або адміністрування |
| Independent ingress + egress relays | Жоден окремий relay зазвичай не бачить source і destination | Оператори можуть collude; timing проходить через обидва | Високопродуктивні підтримувані застосунки |
| Oblivious HTTP | Відокремлює source IP від зашифрованого stateless HTTP request | Потрібна підтримка з боку застосунку, relay і gateway | Telemetry, queries, submissions без session state |
| VPN-only workload namespace | Відсутність маршруту до clear-network забезпечується kernel | VPN усе ще бачить обидва кінці; host/root залишається довіреним | Authorized engagement tools і фіксований egress |
| Disposable remote browser | Destination ізольовано від локального browser/endpoint | Workspace provider бачить активність і login identity | Недовірені сайти/файли та контрольовані дослідження |
| I2P internal service | Окремі inbound/outbound overlay tunnels; без official exits | Менша/інша екосистема; поведінка довготривалих peer | Сервіси, нативні для I2P, а не заміна звичайного web |
| Mixnet/asynchronous delivery | Затримка, batching і cover traffic протидіють timing analysis | Висока затримка, обмежені застосунки та зрілість | Повідомлення/завдання, які не потребують інтерактивності |

## Relay із розділенням знань

Схема relay із двома операторами може перевершити один VPN для вузькоспеціалізованого застосунку:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay є розгорнутим прикладом: Apple керує ingress, тоді як інший постачальник контенту керує egress, тому зазвичай жодна зі сторін не бачить одночасно IP-адресу клієнта та призначення browsing.<sup>[[1]](#references)</sup> Це специфічна для продукту служба приватності Safari/DNS, а не загальномережева мережа анонімності для всіх пристроїв, і вона навмисно зберігає приблизний регіон.

Oblivious HTTP (OHTTP) стандартизує вужчий шаблон застосунку. Relay бачить клієнта й зашифрований трафік до gateway; gateway розшифровує HTTP-повідомлення, але бачить relay, а не клієнта. RFC 9458 попереджає, що для цього потрібна підтримка з боку relay/gateway, найкраще підходять запити без cookies/автентифікації/стану сесії, а аналіз трафіку не входить до гарантованого захисту.<sup>[[2]](#references)</sup>

### Контрольний список проєктування

1. Визначте точні повідомлення застосунку, які потрібно захистити; не проксуюйте непомітно довільні автентифіковані web-сесії.
2. Використовуйте незалежно керовані організації ingress та egress з окремим адмініструванням, обліковими даними, журналюванням і юридичним контролем, де це можливо.
3. Шифруйте запит застосунку для gateway, щоб ingress не міг його прочитати.
4. Видаляйте заголовки пересилання, похідні від клієнта, ідентифікатори TLS та стабільні токени користувача на відповідному рівні.
5. Уникайте унікальних ключів, cookies або полів payload, які дають gateway змогу повторно пов’язувати запити попри розділення транспорту.
6. Агрегуйте, мінімізуйте та видаляйте журнали з обох боків; документуйте ризики змови й примусового розкриття.
7. Застосовуйте padding або batching лише відповідно до перевіреного протоколу. Саморобне формування трафіку може створити унікальний signature, не перешкоджаючи кореляції.
8. Тестуйте за допомогою контрольованих canary-запитів і порівнюйте, що саме записують клієнт, ingress, gateway та target.

Для звичайного інтерактивного browsing використовуйте Tor Browser, а не вигадуйте приватний OHTTP proxy. OHTTP захищає підтримувану транзакцію застосунку, а не повну ідентичність браузера.

## Забезпечення маршруту для кожного workload

Kill switch, що спирається лише на змінні host routes, може відмовити під час поновлення DHCP, переходу в режим сну/пробудження, змін IPv6 або збою tunnel. Надійніший Linux-підхід надає container або network namespace лише loopback-інтерфейс і tunnel-інтерфейс. WireGuard документує, що інтерфейс можна створити у physical namespace, перемістити до workload namespace, а його зашифрований UDP socket залишити в початковому namespace.<sup>[[3]](#references)</sup>

### Шаблон розгортання

1. Спочатку створіть це на одноразовому хості або хості з локальною консоллю; помилки в namespace можуть позбавити віддаленого доступу.
2. Розмістіть фізичний Ethernet/Wi-Fi-інтерфейс і DHCP/supplicant у **physical** namespace.
3. Створіть інтерфейс WireGuard там, щоб його зашифрований transport socket мав доступ до фізичної мережі.
4. Перемістіть лише інтерфейс WireGuard до **workload** namespace і зробіть його єдиним default route.
5. Надайте workload специфічний для namespace resolver, доступний лише через tunnel. Окремо врахуйте IPv6.
6. Запускайте browser/tool container у цьому namespace без host networking, privileged capability, спільної директорії браузера або персонального credential agent.
7. Зупиніть tunnel і перевірте, що workload не може виконувати resolve або підключатися до контрольованої кінцевої точки IPv4 чи IPv6.
8. Тестуйте roaming endpoint, поновлення DHCP, suspend/resume та обробку captive portal поза workload namespace.
9. Журнальте hash конфігурації namespace/tunnel і схвалену egress-адресу для accountability під час engagement.

Це забезпечує **примусове дотримання маршруту**, а не анонімність від VPN або engagement bastion. Скомпрометований host/root може перевіряти або змінювати namespaces.

## Tor bridges і pluggable transports

Bridges — це непублічні вхідні relay Tor. Pluggable transports змінюють трафік першого переходу, ускладнюючи просте блокування або класифікацію протоколу. Вони не додають анонімних relay-шарів після входу й не протидіють спостерігачеві, здатному виконувати ширшу часову кореляцію.

| Transport | Підхід до першого переходу | Практичний компроміс |
|---|---|---|
| **obfs4** | Робить трафік схожим на випадковий і протидіє активному probing | Відомий bridge address усе ще можна заблокувати |
| **Snowflake** | Використовує короткоживучі volunteer WebRTC proxies для досягнення bridge | Продуктивність змінюється; існують broker/STUN/WebRTC patterns |
| **WebTunnel** | Передає bridge-трафік через HTTPS-подібний WebSocket tunnel | Залежить від доступного web front і все ще може бути класифікований |

Tor Project описує Snowflake і WebTunnel як transports для обходу цензури, а не як засоби ідеальної невідрізнюваності.<sup>[[4]](#references)</sup>

### Безпечний workflow

1. Почніть із прямого підключення Tor Browser. Додавайте bridge лише тоді, коли блокування або видимість у моделі локального спостерігача це виправдовує.
2. Використовуйте вбудовані transports або bridge lines, отримані через канали Tor Project. Не завантажуйте випадкові transport binaries або публічні списки bridge з форумів.
3. Спробуйте найменш складний підтримуваний варіант, який надійно підключається; зафіксуйте причину вибору.
4. В іншому зберігайте Tor Browser стандартним. Bridge не робить безпечними custom extensions, входи в облікові записи або незвичайні налаштування браузера.
5. Перевіряйте повторне підключення та коректність годинника. Не перемикайте transports багаторазово так, щоб надсилати тому самому локальному спостерігачеві характерну послідовність.
6. Повторно оцінюйте ситуацію, якщо змінюється цензор або мережева політика; у деяких місцях саме використання може бути чутливим або обмеженим.

## Onion services як приватна точка зустрічі

Onion service створює вихідні Tor circuits до introduction points і rendezvous relays, тому йому не потрібен публічний вхідний порт, а його server IP не розкривається через onion protocol. Трафік client-to-service залишається всередині Tor, а onion address автентифікує service key.<sup>[[5]](#references)</sup>

Для законного intake portal, приватного repository, адміністративного інтерфейсу або сховища evidence під час engagement:

1. Запускайте застосунок на виділеному host/VM і прив’язуйте його до loopback або ізольованого Unix socket.
2. Встановіть Tor з його офіційного repository та дотримуйтеся офіційного налаштування v3 onion-service; ніколи не використовуйте застарілі інструкції v2.
3. Захищайте приватний ключ onion service як TLS/signing key. Створюйте резервну копію лише за потреби стабільної ідентичності.
4. Додайте client authorization onion service для закритої групи та передавайте credentials через незалежно автентифікований канал.<sup>[[6]](#references)</sup>
5. Не дозволяйте origin отримувати сторонні fonts, analytics, updates або webhooks, які розкривають його public IP чи обліковий запис оператора.
6. Реалізуйте authentication та authorization також у застосунку; володіння onion address не є контролем доступу.
7. Встановлюйте patches, застосовуйте rate limits і monitor service без вбудовування сторонньої telemetry.
8. В окремому тестовому контексті переконайтеся, що DNS, email, сторінки помилок, metadata файлів і response headers не розкривають origin.
9. Для red-team використання зазначте service, owner, purpose і час вимкнення в ROE. Не використовуйте його для приховування C2 поза межами scope.

## Remote browser і одноразовий workspace

Remote browser переносить rendering і ризикований контент подалі від локальної кінцевої точки та може надати специфічний для engagement cloud egress. Він захищає локальний пристрій від частини контенту й persistence, але не робить оператора анонімним для workspace provider. Наприклад, AWS документує збір даних порталу, ідентичності, policy, preference і session-log, навіть якщо disposable browser instance видаляється після завершення сесії.<sup>[[7]](#references)</sup>

Використовуйте по одному workspace під контролем організації для кожного engagement, обмежуйте downloads/uploads/clipboard, вимикайте персональні identity providers, спрямовуйте його fixed egress через схвалений bastion і видаляйте workspace після export evidence. Вважайте provider console, IdP та administrator спостерігачами.

## I2P та внутрішні overlays

I2P створює окремі односпрямовані inbound і outbound tunnels і не має офіційних network-layer exits; він призначений переважно для services усередині I2P.<sup>[[8]](#references)</sup> Це не швидший спосіб безпосереднього browsing у public Internet. Outproxies створюють trust point, а офіційна threat model прямо закликає до подальших досліджень і не заявляє про ідеальну анонімність.

Використовуйте I2P лише тоді, коли обидві сторони навмисно його підтримують, ізолюйте його long-lived router від персональних applications і розумійте, що peers/local networks можуть спостерігати участь в I2P. Не збільшуйте кількість hops і не налаштовуйте peer selection без доказів: незвичайні параметри можуть погіршити продуктивність і зменшити anonymity set.

## Операції, стійкі до кореляції

- Надавайте перевагу поширеній підтримуваній конфігурації клієнта, а не унікальній збірці.
- Розділяйте ідентичності на кінцевій точці; жодна routing topology не виправить повторне використання account, payment, recovery або content.
- Для non-interactive tasks надавайте перевагу перевіреному asynchronous protocol/mixnet, а не ручному додаванню затримок або fake traffic.
- Уникайте синхронізованого керування нібито окремими ідентичностями з того самого фізичного контексту.
- Використовуйте one-way export gate: untrusted content надходить до disposable renderer; назовні виходить лише перевірений sanitized result.
- Підтримуйте коректний час для безпеки протоколу, але видаляйте непотрібні точні timestamps із опублікованих artifacts.
- Мінімізуйте тривалість сесій і застарілу інфраструктуру без швидкої ротації «fast-flux», яка помітна та шкодить accountability.

## Техніки, які не можуть використовувати непричетних третіх сторін

Це справжні adversary techniques, а не вигадані чи неважливі методи. Їхню механіку та виявлення описано в [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) і [APT case studies](government-and-apt-case-studies.md). Під час авторизованої вправи відтворюйте їхню спостережувану поведінку за допомогою власних замінників:

- моделюйте churn residential/mobile exit за допомогою контрольованих relay pools, а не ринків із незрозумілою згодою;
- моделюйте open proxies, compromised routers і botnets за допомогою власних VM/routers;
- моделюйте stolen cloud accounts за допомогою designated exercise tenant і synthetic victim identity;
- моделюйте domain fronting на власному reverse proxy, а не на CDN, який цього не погоджував;
- моделюйте third-party Wi-Fi за допомогою двох ізольованих AP, що належать лабораторії;
- розглядайте custom encryption, multi-VPN chains і identifier rotation як test hypotheses, потік, account та endpoint artifacts яких залишаються виявлюваними.

Для авторизованої red team будь-яка спроба зробити трафік менш розпізнаваним має бути явно визначеною detection objective у ROE, мати attribution map під контролем контролера та містити механізм зупинки/deconfliction.

## Матриця перевірки

| Тест | Очікуваний результат | Це означає помилку |
|---|---|---|
| Tunnel/bridge зупинено | Workload не має прямого шляху IPv4/IPv6/DNS | Route enforcement неповне |
| Перевірено target log | Відображається лише запланована egress/application identity | Header, route або account leak |
| Перевірено ingress log | Source присутній; чіткі target/request відсутні | Trust split failed at ingress |
| Перевірено egress log | Relay/request присутні; source identity відсутня | Trust split failed at egress |
| Onion origin проскановано externally | Жоден public origin service недоступний і не пов’язаний | Origin leaked або має dual-homed конфігурацію |
| Disposable session завершено | Стан instance зник; схвалене evidence збережено окремо | Межа persistence не спрацювала |
| Виконано controller lookup | Activity оперативно пов’язується з engagement/operator | Red-team accountability failed |

## References

- [1] [Безпека Apple Platform Security — безпека iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — маршрутизація та Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake і pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — як працюють Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — розширені налаштування Onion Service і client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — шифрування даних в Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
