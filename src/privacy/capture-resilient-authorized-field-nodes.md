# Вузли авторизованого польового доступу, стійкі до захоплення

{{#include ../banners/hacktricks-training.md}}

Raspberry Pi, mini-PC, travel router або cellular appliance, розміщені на об'єкті, можуть надати авторизованій red team довготривалу точку присутності. Водночас це ймовірна точка виявлення, крадіжки та атрибуції. Тому правильною метою дизайну є **стабільний контрольований доступ із мінімальними повноваженнями на польовому вузлі**, а не невідстежуваний implant.

Цей посібник стосується лише обладнання, розміщеного з письмового дозволу власника об'єкта. Кав'ярня, сусід, готель або спільна будівля не входять до scope лише через те, що їхня мережа доступна. Не приховуйте обладнання в місці, власник якого не надав згоди, не обходьте captive portal, не використовуйте облікові дані іншої особи, не втручайтеся в моніторинг і не намагайтеся стирати докази після виявлення.

{% hint style="warning" %}
Надійного режиму «не залишати слідів» не існує. Записи про radio association, DHCP/NAT, carrier, camera, purchase, device, provider, controller і destination можуть зберегтися після вилучення пристрою. Відповідальна red team натомість видаляє з вузла **особисті та не пов'язані із завданням секрети**, зберігає захищену атрибуцію на стороні controller і робить захоплення дешевим для локалізації.
{% endhint %}

## Переваги та недоліки

**Переваги:** реалістичне внутрішнє або суміжне з ціллю джерело; стабільне високошвидкісне тестування; перевірка NAC, egress, фізичного обліку та покриття SOC; робота попри зміни адреси оператора; можливість централізовано відкликати обмежений доступ.

**Недоліки:** фізичне розміщення створює вагомі докази; втрата може розкрити облікові дані пристрою, мережеві профілі та зібрані дані; повторюваний control traffic можна виявити; живлення, портали та зміни радіосередовища погіршують надійність; широкий tunnel може перетворитися на неконтрольований pivot.

## Модель загроз та інваріанти дизайну

Припускайте, що той, хто знайшов пристрій, може вилучити storage, перевірити firmware, скопіювати кожен секрет, що зберігається програмним забезпеченням, спостерігати подальшу мережеву поведінку та передати пристрій клієнту або правоохоронним органам. Full-disk encryption захищає вимкнений пристрій лише в межах заявленої моделі загроз; запущений розблокований вузол і ключі, передані в пам'ять, є різними випадками.

| Інваріант | Практичний наслідок |
|---|---|
| Відсутня пряма ідентичність оператора та вузла | Оператор входить до organization gateway; вузол має іншу ідентичність пристрою |
| Відсутні матеріали особистої робочої станції | Немає особистого SSH key, browser profile, email, password manager, phone pairing або cloud CLI cache |
| Відсутній controller master secret | Один вузол не може зареєструвати інший, змінити policy або розшифрувати інші engagements |
| Лише вихідні з'єднання та вузький доступ | Польова мережа не приймає management listener; вузол підключається лише до вказаних rendezvous/update/time services |
| Короткоживучі повноваження з обмеженою сферою дії | Кожен credential має один пристрій, audience, service, expiry та негайний шлях відкликання |
| Мінімум локальних даних | Результати передаються до controller; caches зашифровані, мають обмежені size/TTL і не є authoritative |
| Відповідальність controller зберігається після захоплення | Відповідність asset-to-engagement, approvals, доступ операторів і команди зберігаються централізовано та контролюються |
| Втрата зупиняє роботу | Виявлення або незрозуміла зміна стану запускає зупинку, revoke, notify та збереження доказів, а не remote destruction |

Базовий профіль NIST для IoT об'єднує ідентифікацію пристрою, configuration, захист даних, logical access, secure software update та cybersecurity-state awareness як основні можливості. У ньому окремо зазначено, що awareness стану та записи подій поза пристроєм підтримують розслідування компрометації.<sup>[[1]](#references)</sup>

## Довідкова архітектура
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Шлюз має знати, який саме іменований оператор отримав доступ до якого саме іменованого пристрою. Польовому вузлу для rendezvous потрібні лише облікові дані пристрою. Він ніколи не дізнається адресу джерела або секрет автентифікації оператора, а оператор ніколи не копіює на нього приватний ключ керування. Це зменшує обсяг персонального зв'язку, який можна відновити **з польового сховища**, не знищуючи підзвітність вправи.

Для більшого парку система workload identity може видавати короткоживучі X.509-ідентичності й автоматично ротувати ключі. SPIFFE рекомендує X.509 SVID, де це можливо, і описує короткі терміни дії та часту ротацію як засоби обмеження наслідків компрометації ключа.<sup>[[2]](#references)</sup> Невелика команда може застосувати ті самі властивості за допомогою приватного CA та автоматизованих сертифікатів для кожного пристрою; встановлювати SPIRE не потрібно лише для дотримання цього шаблону.

## Крок 1: авторизуйте та зареєструйте розміщення

1. Зафіксуйте власника, майданчик, точну дозволену зону розміщення, дозволені мережі, вікно оцінювання, дозволені призначення/дії та екстрені контакти.
2. Зафіксуйте модель, серійний номер, серійний номер сховища, дротові/бездротові MAC-адреси, IMEI/eSIM або ICCID SIM-картки модема, джерело живлення та актуальну фотографію.
3. Надайте пристрою неперсональний ідентифікатор завдання, наприклад `E2026-014-DROP03`. Не кодуйте назву клієнта в широкомовних іменах хостів або SSID.
4. Повідомте керівника вправи та найменшу необхідну групу фізичної безпеки/SOC, що для цього тесту означають «втрачено», «переміщено» та «виявлено».
5. Заздалегідь узгодьте, хто може його забрати і як особа, яка його знайшла, може повідомити про це. На безпечній етикетці можна не вказувати конфіденційні відомості про клієнта, але надати контрольований зворотний номер.
6. Встановіть автоматичне завершення авторизації. Продовження підключення після завершення меж дозволеного не повинно продовжувати дозвіл.

## Крок 2: створіть мінімальний образ, придатний для відновлення

Використовуйте підтримуваний образ ОС, перевіряйте його підпис/контрольну суму через задокументований постачальником канал, встановлюйте security updates і зберігайте відтворюваний маніфест збірки. Якщо це дозволяє програмне забезпечення, надавайте перевагу read-only або immutable базі з невеликим доступним для запису розділом даних.

1. Видаліть облікові записи за замовчуванням, демонстраційні служби, компілятори та пакети, не потрібні для авторизованого workload.
2. Вимкніть локальний GUI, Bluetooth, протоколи виявлення, спільний доступ до файлів, Wi-Fi P2P і вхідне адміністрування, якщо цього явно не вимагає вправа.
3. Увімкніть secure boot і measured boot/видачу ключів на основі TPM, якщо апаратне забезпечення справді це підтримує; не стверджуйте, що конфігурація Raspberry Pi має measured boot класу ПК, не перевіривши точну модель.
4. Шифруйте локальний доступний для запису стан і налаштуйте суворі максимальний розмір та час зберігання. Шифрування є засобом затримки/локалізації, а не доказом того, що запущений вузол нічого не розкриває.
5. Надсилайте важливі журнали за межі пристрою. Обмежуйте розмір локальних журналів, щоб запобігти вичерпанню сховища, але не налаштовуйте очищення журналів або anti-forensic видалення.
6. Зберігайте маніфест образу, версії пакетів, хеш конфігурації та інструкції з відновлення у контролера.
7. Перевстановіть образ на запасний пристрій із маніфесту та виконайте той самий health test. Конструкція, яку може відновити лише її автор, не готова до використання в польових умовах.

## Крок 3: видавайте ідентичності з односторонньою довірою

Створіть три різні ідентичності:

- **ідентичність пристрою**, прийнятну лише rendezvous для цього пристрою;
- **ідентичність оператора**, прийнятну шлюзом організації та захищену phishing-resistant MFA; і
- **ідентичність контролера/розгортання**, що використовується для підпису схвалених завдань або конфігурації та зберігається окремо від оператора й польового вузла.

Вузол має містити відкритий ключ, потрібний для перевірки підписаних завдань, але ніколи не ключ підпису. Скомпрометовані облікові дані пристрою не повинні забезпечувати автентифікацію до cloud consoles, source repositories, платіжних облікових записів, інших вузлів або production клієнта.

Використовуйте короткі терміни дії сертифікатів, якщо автоматичне поновлення працює надійно. Коли довгоживучий ключ WireGuard операційно необхідний, розглядайте його відкритий ключ як ідентифікатор відкликання та обмежуйте його адресою тунелю, специфічною для peer, політикою firewall і авторизацією broker. Підтримуйте перевірену дію контролера, яка негайно видаляє цей peer.

## Крок 4: стабільний outbound rendezvous

Наведений нижче шаблон власної лабораторії забезпечує стабільне керування через NAT без відкриття вхідної служби. Це звичайна мережа WireGuard, а не covert reverse shell. Використовуйте документаційні адреси й замінюйте їх лише на endpoints, що належать організації.

На rendezvous організації призначте `10.77.0.1/32`; польовому вузлу призначте `10.77.0.20/32`. Запис peer на шлюзі має приймати лише одну адресу вузла:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Вузол встановлює вихідне з'єднання з rendezvous і зберігає NAT-відображення лише за потреби:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard визначає 25 секунд як доцільний інтервал keepalive для багатьох реалізацій NAT/firewall, коли потрібна постійна доступність; коли це не потрібно, краще залишити параметр вимкненим.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` навмисно робить це шляхом керування, а не pivot через default route.

Потім застосуйте засоби контролю поза WireGuard:

1. Розв'яжіть `vpn.redteam.example` через затверджений bootstrap DNS path і зафіксуйте очікувану endpoint організації в deployment records.
2. На node дозвольте вихідні DHCP/RA, необхідні DNS/NTP, rendezvous endpoint і мінімальний затверджений update path. Забороніть unsolicited inbound traffic на кожному uplink.
3. На rendezvous дозвольте `10.77.0.20` звертатися лише до broker/health service, необхідного для вправи. Не переспрямовуйте його загалом у client network.
4. Розмістіть інтерактивний operator access за organization gateway. Не відкривайте SSH з node через tunnel, якщо для assessment достатньо signed pull-job interface.
5. Налаштуйте service manager запускати tunnel після networking, перезапускати його після збою з обмеженим backoff і надсилати alert після повторних збоїв. Restart loop не повинен перевантажувати venue або приховувати першопричину.
6. Перевіряйте latest handshake peer, але не використовуйте наявність “handshake exists” як доказ того, що device не скомпрометовано.

TURN може забезпечити лише relay reachability для спеціально створеного WebRTC control plane, а message queue може витримувати переривчастий service. TURN явно надає client public relay address за NAT; його server залишається observer.<sup>[[4]](#references)</sup> Оберіть одну control architecture, а не нашаровуйте tunnels без визначеного observer або переваги в надійності.

## Step 5: стабільність uplink без personal links

Для authorized venue node надавайте перевагу такому порядку:

1. wired connection або dedicated test VLAN, надані client;
2. enterprise/guest Wi-Fi profile, схвалений owner;
3. cellular/private APN fallback, наданий організацією за contract.

Ніколи не налаштовуйте його через personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account або Wi-Fi profile, експортований із daily laptop. Саме до таких артефактів capture спробує під'єднатися.

Для кожного approved uplink:

- запишіть SSID/BSSID або switch/VLAN і очікувану поведінку captive portal;
- встановіть детермінований пріоритет і health check до endpoint, що належить організації;
- зробіть так, щоб failover змінював лише underlay; ідентичності device та operator залишаються на broker;
- переконайтеся, що DNS, IPv6 і application traffic не обходять rendezvous під час переходу;
- надсилайте alert про невідомі SSID/BSSID, зміну SIM, новий default gateway, зміну public IP/ASN або одночасні uplinks;
- перед deployment протестуйте power loss, DHCP renewal, AP restart, public-IP change, 24-hour idle, tunnel loss і відновлення за схемою primary-to-secondary-to-primary.

Private MAC addressing може зменшити випадкове cross-network tracking, але для authorized NAC часто потрібен стабільний per-network MAC. Зафіксуйте фактичну поведінку обраної OS і не змінюйте MAC в обхід access control власника.

## Step 6: обмеження роботи та даних

Безпечний field node не повинен приймати довільний shell text із mailbox. Визначте signed job types, наприклад `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` або іншу дію, прямо зазначену в rules of engagement. Повторно перевіряйте destination, duration, rate, output size і scope на node.

1. Надайте кожному job унікальний ID, device audience, issue time, expiry, scope reference і maximum output.
2. Підписуйте його ідентичністю controller/deployment.
3. Відхиляйте невідомі fields, expired/replayed jobs і jobs для іншого device.
4. Передавайте results до owned collector; неминучий local spool шифруйте та обмежуйте TTL.
5. Записуйте на controller accepted/rejected job ID і result hash. Не розміщуйте sensitive command parameters у public monitoring channel.
6. Припиняйте processing після завершення authorization, помилки identity rotation або переведення device у quarantine controller-ом.

## Monitoring для виявлення, втрати або compromise

Monitoring може повідомити controller, що observed state змінився. Він не може надійно довести, що “investigators found the device”, а спроби стежити за responders або зондувати їхні systems виходили б за межі authorized assessment.

### Збір off-device state

Надсилайте controller signed low-volume health record через рандомізований, але обмежений operational interval. Включайте лише те, що потрібно controller:

- device ID, boot ID/counter і monotonic uptime;
- configuration/image hash і software version;
- device-certificate serial і renewal state;
- uplink class, interface, BSSID або switch context, якщо це дозволено, hash default-gateway і public IP/ASN, зафіксовані owned service;
- tunnel handshake age, packet counters і queue depth;
- стан enclosure switch або hardware-tamper, якщо owner схвалив sensor;
- disk pressure, temperature, clock-offset estimate і last successful job ID;
- sequence number і signature для виявлення replay або gaps.

Зберігайте gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events і alerts централізовано. CISA рекомендує централізувати logs, захищати їх від видалення, створювати baseline нормальної активності та визначати contacts для incident response.<sup>[[5]](#references)</sup>

### Індикатори discovery/compromise

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking або removal | зіставте з provider/site state; не підключайтеся повторно через unapproved path |
| Boot counter changed unexpectedly | power cut, crash, removal або maintenance | quarantine jobs; порівняйте час і site events |
| Config/image hash changed | update error, storage fault або tampering | припиніть роботу; revoke, якщо це не controller-approved release |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device або interception | порівняйте з approved inventory; quarantine unexplained transition |
| Repeated rejected job/signature | corruption, replay або unauthorized controller | припиніть processing і дослідіть gateway/controller logs |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse або network transition | revoke негайно; збережіть обидва session records |
| Unexpected local login, interface, process or privilege event | maintenance або compromise | ізолюйте через broker policy; збережіть evidence |
| Enclosure switch/state transition | service, movement або discovery | повідомте named site contact; не запускайте destructive action |
| Provider abuse notice/account query or SOC alert | detection, misconfiguration або out-of-scope traffic | припиніть activity і запустіть deconfliction/incident process |
| Sentinel credential touched | хтось прочитав no-privilege decoy secret, унікальний для цього node | revoke реальну device identity і збережіть alert trail |

Sentinel credential не повинен надавати **жодного доступу**, звертатися лише до organization-owned alert service і має бути розкритий у rules of engagement. Це tripwire для unauthorized reading, а не beacon для tracking того, хто знайшов equipment.

### Alert thresholds

Використовуйте stateful rules, а не один драматичний alert “caught”:

- **warning:** один пропущений interval, нормальна зміна address або зростання queue;
- **degraded:** три послідовні пропуски, затримка renewal, втрата primary-uplink або повторний restart;
- **quarantine:** неузгоджена зміна hash/boot/uplink, duplicate credential, sentinel use або unexpected privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, recovery device не запланованою особою або validated provider/SOC escalation.

Тестуйте доставку alerts через channel, незалежний від field node. Не надсилайте sensitive client/device detail до personal messaging або consumer push accounts.

## Runbook для suspected discovery або capture

1. **Stop:** призупиніть нові jobs і operator sessions. Не надсилайте probe “check if watched”.
2. **Quarantine:** налаштуйте broker відхиляти device identity та її routes, зберігаючи наявні logs.
3. **Revoke:** revoke device certificate/key, queue token, update credential і будь-який single-purpose service token. Призупиніть organization SIM, якщо можлива фізична втрата.
4. **Preserve:** створіть snapshot controller, gateway, provider і alert records; зафіксуйте trusted time, виконавця та last known configuration. Не очищайте й не виконуйте remote wipe node.
5. **Notify:** зв'яжіться з exercise controller, client incident contact і legal/privacy contacts, визначеними в authorization. Якщо його знайшла third party, використайте попередньо узгоджений recovery process.
6. **Assess:** вважайте всі secrets і cached results на node exposed. Точно визначте, до чого міг отримати доступ кожен secret і чи використовувався він після suspicious event.
7. **Contain downstream:** rotate affected service credentials, invalidate pending jobs і перевірте owned target/provider logs на unexpected behavior.
8. **Recover safely:** забирайте лише через authorized person; сфотографуйте й упакуйте node, зафіксуйте custody та отримайте forensic evidence відповідно до вказівок client.
9. **Resume with a new identity:** ніколи не вмикайте captured credential повторно непомітно. Rebuild з відомого manifest, виправте control failure і отримайте explicit approval.

Поточні рекомендації NIST щодо incident response інтегрують preparation, detection, response і recovery в organization-wide cybersecurity risk management; спочатку зберігайте evidence, щоб client міг визначити, що сталося, та обрати належну response.<sup>[[6]](#references)</sup>

## Capture drill перед deployment

Передайте unlocked test unit або копію його storage окремому reviewer і попросіть його перелічити:

1. device/site/engagement identifiers;
2. operator names, personal accounts, home/workstation networks і recovery contacts;
3. controller/broker destinations і credentials;
4. client network profiles і cached results;
5. інші devices/projects, доступні з кожним secret;
6. value або payment credentials;
7. що controller може revoke і як швидко;
8. яка activity залишається attributable за central logs.

Критерії проходження: нуль personal accounts/workstation keys; нуль cross-engagement або enrollment authority; відсутність payment credential; bounded encrypted cache; одна задокументована device-revocation action; повна controller-side accountability. Будь-який неочікуваний personal link або lateral capability вважайте release blocker.

## Closeout

1. Зупиніть jobs і вимкніть broker route після завершення scope.
2. Отримайте та звірте точний inventory; повідомте про все відсутнє.
3. Збережіть logs/results і, якщо потрібно, forensic image відповідно до engagement retention plan.
4. Revoke device, SIM, queue, update і service identities, навіть якщо hardware було recovered.
5. Лише після preservation/acceptance sanitize або знищте media через approved data-disposal process власника та зафіксуйте completion. Це lifecycle management, а не concealment.
6. Видаліть venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules і тимчасові contacts.
7. Задокументуйте виявлене detection, пропущену telemetry, time to quarantine і кожен artifact, який capture розкрив.

## References

- [1] [NIST — Каталог можливостей кібербезпеки IoT-пристроїв](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Концепції та короткоживучі workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Використання Logging у бізнес-системах](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Рекомендації та міркування щодо Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
