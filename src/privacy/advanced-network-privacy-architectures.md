# Розширені архітектури мережевої приватності

Складність корисна лише тоді, коли вона усуває конкретного спостерігача або режим відмови. Унікальний стек тунелів, спеціальна форма пакетів, рідкісний user agent або інфраструктура, що часто змінюється, можуть стати сильнішим fingerprint, ніж стандартна конфігурація, яку використовують тисячі людей.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) містить загальну схему `Pros`/`Cons`/`Procedure`/`Detection`. Ця сторінка розширює опис складніших архітектур і меж довіри.

Отже, розширена мета — це **розділення знань**: жоден звичайний компонент не повинен одночасно володіти ідентичністю користувача, призначенням, plaintext і довгостроковою історією активності. Це не невидимість: collusion, legal process, компрометація endpoint або end-to-end кореляція трафіку все ще можуть відновити маршрут.

## Вибір архітектури

| Pattern | Набута властивість | Новий рівень довіри/відмови | Придатне використання |
|---|---|---|---|
| Standard Tor Browser | Спільний fingerprint браузера та маршрут через кілька relay | Низька затримка дає змогу корелювати трафік | Загальний анонімний вебсерфінг |
| Tor bridge + pluggable transport | Ускладнює пряме блокування/класифікацію Tor | Bridge/transport все ще можна виявити; bridge дізнається джерело | Цензуровані мережі |
| Onion service | Приховує IP сервісу; усуває потребу в exit; автентифікує onion identity | Onion key і server endpoint стають критичними активами | Приватна публікація, приймання даних або адміністрування |
| Independent ingress + egress relays | Жоден окремий relay зазвичай не бачить одночасно джерело й призначення | Оператори можуть вступити в collusion; часові характеристики проходять через обидва | Підтримувані застосунки з високою продуктивністю |
| Oblivious HTTP | Відокремлює source IP від зашифрованого stateless HTTP request | Потрібна підтримка з боку застосунку, relay і gateway | Телеметрія, запити, надсилання даних без стану сесії |
| VPN-only workload namespace | Відсутність маршруту до clear-network забезпечується kernel | VPN усе ще бачить обидва кінці; host/root залишається довіреним | Авторизовані engagement tools і фіксований egress |
| Disposable remote browser | Призначення ізольоване від локального браузера/endpoint | Workspace provider бачить активність та login identity | Недовірені сайти/файли та контрольовані дослідження |
| I2P internal service | Окремі вхідні/вихідні overlay tunnels; офіційних exit немає | Менша/інша екосистема; поведінка однорангових вузлів протягом тривалого часу | Сервіси, нативні для I2P, а не заміна звичайного вебу |
| Mixnet/asynchronous delivery | Затримка, пакетування та cover traffic протидіють часовому аналізу | Висока затримка, обмежена кількість застосунків і зрілість | Повідомлення/завдання, яким не потрібна інтерактивність |

## Ретранслятори з розділенням знань

Модель relay із двома операторами може перевершувати один VPN для вузького застосунку:
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
Apple Private Relay є розгорнутим прикладом: Apple керує ingress, тоді як інший постачальник контенту керує egress, тому зазвичай жодна зі сторін не бачить одночасно IP-адресу клієнта та призначення перегляду.<sup>[[1]](#references)</sup> Це спеціалізований сервіс приватності Safari/DNS, а не мережа анонімності для всього пристрою, і він навмисно зберігає приблизний регіон.

Oblivious HTTP (OHTTP) стандартизує вужчий шаблон для застосунків. Relay бачить клієнта та зашифрований трафік до gateway; gateway розшифровує HTTP-повідомлення, але бачить relay, а не клієнта. RFC 9458 попереджає, що для цього потрібна підтримка з боку relay/gateway, найкраще підходять запити без cookies/authentication/session state, а аналіз трафіку не входить до гарантованих властивостей.<sup>[[2]](#references)</sup>

### Контрольний список проєктування

1. Визначте точні повідомлення застосунку, які потрібно захистити; не проксуюйте непомітно довільні автентифіковані web-сесії.
2. Використовуйте незалежно керовані ingress- та egress-організації з окремим адмініструванням, обліковими даними, журналюванням і юридичним контролем, де це можливо.
3. Шифруйте запит застосунку для gateway, щоб ingress не міг його прочитати.
4. Видаляйте forwarding headers, ідентифікатори TLS та стабільні токени на користувача, отримані від клієнта, на відповідному рівні.
5. Уникайте унікальних ключів, cookies або полів payload, які дають gateway змогу повторно пов’язувати запити попри розділення транспорту.
6. Агрегуйте, мінімізуйте та своєчасно видаляйте журнали з обох сторін; документуйте ризик змови й примусового розкриття.
7. Виконуйте padding або batching лише відповідно до перевіреного протоколу. Саморобне формування трафіку може створити унікальний підпис, не зупинивши кореляцію.
8. Тестуйте за допомогою контрольованих canary-запитів і порівнюйте, що саме записують клієнт, ingress, gateway та target.

Для звичайного інтерактивного перегляду використовуйте Tor Browser, а не створюйте власний приватний OHTTP proxy. OHTTP захищає підтримувану транзакцію застосунку, а не повну ідентичність браузера.

## Забезпечення маршруту для кожного workload

Kill switch, що ґрунтується лише на змінних host routes, може не спрацювати під час оновлення DHCP, переходу в режим сну/пробудження, змін IPv6 або падіння тунелю. Надійніший Linux-підхід надає container або network namespace лише loopback-інтерфейс і tunnel-інтерфейс. WireGuard документує, що інтерфейс можна створити у фізичному namespace, перемістити до workload namespace, а його зашифрований UDP-сокет залишити в початковому namespace.<sup>[[3]](#references)</sup>

### Шаблон розгортання

1. Спочатку створіть це на одноразовому хості з локальною консоллю; помилки в namespace можуть позбавити віддаленого доступу.
2. Помістіть фізичний Ethernet/Wi-Fi-інтерфейс і DHCP/supplicant у **physical** namespace.
3. Створіть інтерфейс WireGuard там, щоб його зашифрований transport socket мав доступ до фізичної мережі.
4. Перемістіть лише інтерфейс WireGuard до **workload** namespace і зробіть його єдиним default route.
5. Надайте workload спеціальний для namespace resolver, доступний лише через тунель. Окремо врахуйте IPv6.
6. Запускайте browser/tool container у цьому namespace без host networking, privileged capability, спільної browser directory або personal credential agent.
7. Зупиніть тунель і перевірте, що workload не може виконати resolve або під’єднатися до контрольованої кінцевої точки IPv4 чи IPv6.
8. Тестуйте roaming кінцевої точки, оновлення DHCP, suspend/resume та обробку captive portal поза workload namespace.
9. Записуйте hash конфігурації namespace/tunnel і схвалену egress-адресу для accountability під час engagement.

Це забезпечує **примусове використання маршруту**, а не анонімність від VPN або engagement bastion. Скомпрометований host/root може перевіряти або змінювати namespaces.

## Tor bridges і pluggable transports

Bridges — непублічні entry relays Tor. Pluggable transports змінюють трафік першого переходу, ускладнюючи просте блокування або класифікацію протоколу. Вони не додають анонімних relay-шарів після входу й не протидіють спостерігачеві, здатному виконувати ширшу кореляцію за часом.

| Transport | Підхід для першого переходу | Практичний компроміс |
|---|---|---|
| **obfs4** | Робить трафік схожим на випадковий і протидіє активному probing | Відомі bridge-адреси все одно можна заблокувати |
| **Snowflake** | Використовує короткоживучі volunteer WebRTC proxies для доступу до bridge | Продуктивність змінюється; існують broker/STUN/WebRTC-патерни |
| **WebTunnel** | Передає bridge-трафік через WebSocket tunnel, схожий на HTTPS | Залежить від доступного web front і все ще може бути класифікований |

Tor Project описує Snowflake і WebTunnel як transport-и для обходу цензури, а не як засоби ідеальної невідрізнюваності.<sup>[[4]](#references)</sup>

### Безпечний робочий процес

1. Почніть із прямого під’єднання Tor Browser. Додавайте bridge лише тоді, коли блокування або видимість у моделі локального спостерігача це виправдовують.
2. Використовуйте вбудовані transport-и або bridge lines, отримані через канали Tor Project. Не завантажуйте випадкові transport binaries або публічні списки bridge з форумів.
3. Спробуйте найменш складний підтримуваний варіант, який стабільно під’єднується; зафіксуйте причину вибору.
4. В інших аспектах залишайте Tor Browser стандартним. Bridge не робить безпечними custom extensions, account logins або незвичні налаштування браузера.
5. Перевіряйте повторне під’єднання та правильність часу. Не перемикайте transport-и багаторазово так, щоб надсилати тому самому локальному спостерігачеві характерну послідовність.
6. Повторно оцініть ситуацію, якщо змінюється censor або мережева політика; у деяких місцях саме використання може бути чутливим або обмеженим.

## Onion services як приватна точка зустрічі

Onion service створює вихідні Tor circuits до introduction points і rendezvous relays, тому йому не потрібен публічний вхідний порт, а IP-адреса сервера не розкривається через onion protocol. Трафік між клієнтом і сервісом залишається всередині Tor, а onion-адреса автентифікує ключ сервісу.<sup>[[5]](#references)</sup>

Для законного intake portal, приватного repository, адміністративного інтерфейсу або сховища доказів engagement:

1. Запускайте застосунок на виділеному host/VM і прив’язуйте його до loopback або ізольованого Unix socket.
2. Встановіть Tor з офіційного repository та дотримуйтеся офіційних інструкцій для onion service v3; ніколи не використовуйте застарілі інструкції v2.
3. Захищайте приватний ключ onion service як TLS/signing key. Створюйте backup лише якщо потрібна стабільна ідентичність.
4. Додайте client authorization onion service для закритої групи та передайте облікові дані через незалежно автентифікований канал.<sup>[[6]](#references)</sup>
5. Не дозволяйте origin отримувати сторонні fonts, analytics, updates або webhooks, які розкривають його публічну IP-адресу чи обліковий запис оператора.
6. Реалізуйте authentication та authorization також у застосунку; володіння onion-адресою не є контролем доступу.
7. Встановлюйте patches, застосовуйте rate limits і моніторте сервіс без вбудовування telemetry третіх сторін.
8. В окремому тестовому контексті переконайтеся, що DNS, email, error pages, file metadata та response headers не розкривають origin.
9. Для red-team використання зазначте сервіс, власника, мету та час вимкнення в ROE. Не використовуйте його для приховування C2 поза межами scope.

## Remote browser і одноразовий workspace

Remote browser переміщує rendering і небезпечний контент подалі від локальної кінцевої точки та може надавати egress із cloud, специфічний для engagement. Він захищає локальний пристрій від частини контенту й persistence, але не робить оператора анонімним для workspace provider. Наприклад, AWS документує збір даних portal, identity, policy, preference і session-log, навіть якщо одноразовий browser instance видаляється після завершення сесії.<sup>[[7]](#references)</sup>

Використовуйте один workspace під контролем організації для кожного engagement, обмежуйте downloads/uploads/clipboard, вимикайте personal identity providers, спрямовуйте його фіксований egress через схвалений bastion і видаляйте workspace після експорту доказів. Вважайте provider console, IdP та administrator спостерігачами.

## I2P і внутрішні overlays

I2P створює окремі односпрямовані inbound та outbound tunnels і не має офіційних network-layer exits; переважно він призначений для сервісів усередині I2P.<sup>[[8]](#references)</sup> Це не готовий швидший спосіб перегляду публічного Internet. Outproxies створюють точку довіри, а офіційна threat model прямо закликає до подальших досліджень і не заявляє про ідеальну анонімність.

Використовуйте I2P лише коли обидві сторони навмисно його підтримують, ізолюйте його довгоживучий router від персональних застосунків і розумійте, що peers/локальні мережі можуть бачити участь у I2P. Не збільшуйте кількість hop-ів і не налаштовуйте вибір peer без доказів: незвичні параметри можуть погіршити продуктивність і зменшити anonymity set.

## Операції, стійкі до кореляції

- Віддавайте перевагу типовій підтримуваній конфігурації клієнта, а не унікальній збірці.
- Розділяйте ідентичності на кінцевій точці; жодна routing topology не виправить повторне використання account, payment, recovery або content.
- Для non-interactive tasks віддавайте перевагу перевіреному asynchronous protocol/mixnet, а не ручному додаванню затримок або fake traffic.
- Не керуйте нібито окремими ідентичностями синхронно з одного фізичного контексту.
- Використовуйте односторонній export gate: untrusted content потрапляє до disposable renderer; назовні виходить лише перевірений, sanitized result.
- Підтримуйте правильний час для protocol security, але видаляйте непотрібні точні timestamps із опублікованих artifacts.
- Мінімізуйте тривалість сесій і застарілу інфраструктуру без швидкої ротації «fast-flux», яка привертає увагу та шкодить accountability.

## Techniques that cannot use uninvolved third parties

Це справжні adversary techniques, а не вигадані чи неважливі методи. Їхню механіку й виявлення описано в [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) та [APT case studies](government-and-apt-case-studies.md). Під час авторизованої вправи відтворюйте їхню спостережувану поведінку за допомогою власних замінників:

- моделюйте churn residential/mobile exit за допомогою контрольованих relay pools, ніколи не використовуйте ринки з незрозумілою згодою;
- моделюйте open proxies, compromised routers і botnets за допомогою власних VM/routers;
- моделюйте stolen cloud accounts за допомогою визначеного exercise tenant і synthetic victim identity;
- моделюйте domain fronting на власному reverse proxy, а не на CDN без його згоди;
- моделюйте сторонній Wi-Fi за допомогою двох ізольованих AP, що належать лабораторії;
- розглядайте custom encryption, multi-VPN chains і identifier rotation як тестові гіпотези, потоки, account artifacts і endpoint artifacts яких залишаються виявлюваними.

Для авторизованої red team будь-яка спроба зробити трафік менш упізнаваним має бути окремою detection objective у ROE, мати attribution map під контролем controller і включати механізм stop/deconfliction.

## Матриця перевірки

| Тест | Очікуваний результат | Невдача означає |
|---|---|---|
| Tunnel/bridge зупинено | Workload не має прямого IPv4/IPv6/DNS-шляху | Route enforcement неповне |
| Перевірено target log | Відображається лише запланована egress/application identity | Header, route або account leak |
| Перевірено ingress log | Source присутній; clear target/request відсутній | Trust split не спрацював на ingress |
| Перевірено egress log | Relay/request присутні; source identity відсутня | Trust split не спрацював на egress |
| Onion origin проскановано externally | Жоден public origin service не доступний/не пов’язаний | Origin leaked або має dual-homing |
| Disposable session завершено | Instance state зник; схвалені докази збережено окремо | Межа persistence не спрацювала |
| Виконано controller lookup | Activity оперативно пов’язується з engagement/operator | Red-team accountability не спрацювала |

## References

- [1] [Безпека Apple Platform Security — безпека iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — маршрутизація та Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake і pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — як працюють Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — розширені налаштування Onion Service та client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — шифрування даних в Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
