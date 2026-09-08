# Стійкі до захоплення авторизовані польові вузли

Raspberry Pi, mini-PC, travel router або cellular appliance, розміщені на об'єкті, можуть надати авторизованій red team надійну точку присутності. Водночас це ймовірна точка виявлення, викрадення та атрибуції. Тому правильною метою проєктування є **стабільний контрольований доступ із мінімальними повноваженнями на польовому вузлі**, а не невідстежуваний implant.

Цей посібник стосується лише обладнання, розміщеного за письмовим дозволом власника об'єкта. Кав'ярня, сусід, готель або будівля спільного користування не входять до scope лише через те, що їхня мережа доступна. Не приховуйте обладнання в місці, власник якого не дав згоди, не обходьте captive portal, не використовуйте облікові дані іншої особи, не втручайтеся в моніторинг і не намагайтеся стирати докази після виявлення.

{% hint style="warning" %}
Надійного режиму «не залишати слідів» не існує. Записи про radio association, DHCP/NAT, carrier, camera, purchase, device, provider, controller і destination можуть зберегтися після вилучення пристрою. Відповідальна red team натомість видаляє з вузла **особисті та сторонні секрети**, зберігає захищену атрибуцію на стороні controller і робить захоплення недорогим для локалізації.
{% endhint %}

## Переваги та недоліки

**Переваги:** реалістичне джерело всередині мережі або поруч із ціллю; стабільне високошвидкісне тестування; перевірка NAC, egress, фізичного обліку та покриття SOC; можливість продовжувати роботу після зміни оператором адрес; можливість централізовано відкликати обмежений доступ.

**Недоліки:** фізичне розміщення створює вагомі докази; втрата може розкрити облікові дані пристрою, мережеві профілі та зібрані дані; повторюваний control traffic можна виявити; зміни живлення, portal і radio погіршують надійність; широкий tunnel може перетворитися на неконтрольований pivot.

## Модель загроз та інваріанти проєктування

Припускайте, що особа, яка знайшла пристрій, може вилучити сховище, перевірити firmware, скопіювати всі секрети, що зберігаються у software, спостерігати подальшу мережеву поведінку та передати пристрій клієнту або правоохоронним органам. Full-disk encryption захищає вимкнений пристрій лише в межах визначеної для нього моделі загроз; запущений розблокований вузол і ключі, передані в пам'ять, — це різні випадки.

| Інваріант | Практичний наслідок |
|---|---|
| Відсутня пряма ідентичність operator-to-node | Operator входить до organization gateway; вузол має іншу ідентичність пристрою |
| Відсутні матеріали особистої workstation | Немає особистого SSH key, browser profile, email, password manager, phone pairing або cloud CLI cache |
| Відсутній controller master secret | Один вузол не може зареєструвати інший, змінити policy або розшифрувати інші engagements |
| Лише outbound і вузький scope | Field network не приймає management listener; вузол звертається лише до іменованих rendezvous/update/time services |
| Короткоживучі повноваження з обмеженим scope | Кожен credential має один device, audience, service, expiry і негайний шлях до revocation |
| Мінімум локальних даних | Результати передаються до controller; caches зашифровані, мають обмеження за розміром/TTL і не є authoritative |
| Відповідальність controller зберігається після capture | Asset-to-engagement mapping, approvals, operator access і commands зберігаються централізовано та контролюються за доступом |
| Втрата зупиняє роботу | Виявлення або незрозуміла зміна стану запускає зупинку, revoke, notify і збереження доказів, а не remote destruction |

Базовий профіль IoT від NIST об'єднує ідентифікацію пристрою, configuration, захист даних, logical access, безпечне оновлення software та awareness щодо стану cybersecurity як основні можливості. У ньому окремо зазначено, що awareness щодо стану та записи подій поза пристроєм підтримують розслідування compromise.<sup>[[1]](#references)</sup>

## Еталонна архітектура
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
Шлюз має знати, який саме іменований оператор отримав доступ до якого саме іменованого пристрою. Польовому вузлу для rendezvous потрібні лише облікові дані пристрою. Він ніколи не дізнається адресу джерела або секрет автентифікації оператора, а оператор ніколи не копіює на нього приватний ключ керування. Це зменшує обсяг персонального зв’язку, який можна відновити **з польового сховища**, не знищуючи підзвітність вправи.

Для більшого парку система workload-identity може видавати короткоживучі X.509 identities і автоматично роту­вати ключі. SPIFFE рекомендує X.509 SVIDs, де це можливо, і описує короткі терміни дії та часту ротацію як засоби обмеження наслідків компрометації ключа.<sup>[[2]](#references)</sup> Невелика команда може застосувати ті самі властивості за допомогою приватного CA та автоматизованих сертифікатів для кожного пристрою; встановлення SPIRE не є обов’язковим лише для дотримання цього патерну.

## Step 1: authorize and register the placement

1. Зафіксуйте власника, об’єкт, точну дозволену зону розміщення, дозволені мережі, вікно оцінювання, дозволені призначення/дії та екстрені контакти.
2. Зафіксуйте модель, серійний номер, серійний номер сховища, дротові/бездротові MAC-адреси, IMEI/eSIM або ICCID SIM-картки модема, джерело живлення та актуальну фотографію.
3. Присвойте пристрою неперсональний ідентифікатор engagement, наприклад `E2026-014-DROP03`. Не кодуйте назву клієнта в broadcast hostnames або SSIDs.
4. Повідомте контролера вправи та найменшу необхідну групу фізичної безпеки/SOC, залучену до deconfliction, що саме означають “lost”, “moved” і “discovered” у цьому тесті.
5. Заздалегідь погодьте, хто може його забрати і як особа, що його знайшла, може повідомити про це. На safety label можна не вказувати конфіденційні дані клієнта, але надати контрольований callback.
6. Встановіть автоматичне завершення авторизації. Продовження connectivity після завершення scope не повинно продовжувати дозвіл.

## Step 2: build a minimal recoverable image

Використовуйте підтримуваний образ ОС, перевіряйте його підпис/checksum через документований канал постачальника, встановлюйте security updates і зберігайте відтворюваний build manifest. Якщо програмне забезпечення це дозволяє, віддавайте перевагу read-only або immutable base з невеликим writable data partition.

1. Видаліть default accounts, demo services, compilers і пакети, не потрібні для авторизованого workload.
2. Вимкніть local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P та inbound administration, якщо exercise прямо не вимагає чогось із цього.
3. Увімкніть secure boot і measured boot/TPM-backed key release, якщо hardware справді це підтримує; не стверджуйте, що конфігурація Raspberry Pi має measured boot рівня ПК, не перевіривши точну модель.
4. Зашифруйте local writable state і налаштуйте суворі максимальний розмір та час зберігання. Encryption — це засіб затримки/стримування, а не доказ того, що запущений node нічого не розкриває.
5. Надсилайте важливі logs за межі пристрою. Обмежте local journals, щоб запобігти вичерпанню сховища, але не налаштовуйте log wiping або anti-forensic deletion.
6. Зберігайте image manifest, версії пакетів, configuration hash та recovery instructions у controller.
7. Перепрошийте запасний пристрій з manifest і виконайте той самий health test. Дизайн, який може відновити лише його розробник, не готовий до використання в польових умовах.

## Step 3: issue identities with one-way trust

Створіть три різні identities:

- **device identity**, яку приймає лише rendezvous для цього пристрою;
- **operator identity**, яку приймає organization gateway і яка захищена phishing-resistant MFA; та
- **controller/deployment identity**, яку використовують для підписування approved jobs або configuration і яка зберігається окремо від operator та field node.

Node має містити public key, потрібний для перевірки signed jobs, але ніколи не signing key. Захоплені device credentials не повинні автентифікуватися до cloud consoles, source repositories, payment accounts, інших nodes або client production.

Використовуйте короткі терміни дії сертифікатів, якщо automatic renewal є надійним. Якщо long-lived WireGuard key операційно необхідний, вважайте його public key handle для revocation і обмежте його peer-specific tunnel address, firewall policy та broker authorization. Підтримуйте перевірену controller action, яка негайно видаляє цей peer.

## Step 4: stable outbound rendezvous

Наведений нижче owned-lab pattern забезпечує стабільне керування через NAT без відкриття inbound service. Це звичайна WireGuard networking, а не covert reverse shell. Використовуйте documentation addresses і замінюйте їх лише на endpoints, що належать організації.

В organization rendezvous призначте `10.77.0.1/32`; field node призначте `10.77.0.20/32`. Запис gateway peer має приймати лише одну адресу node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Вузол встановлює вихідне з’єднання з rendezvous і підтримує відображення NAT лише за потреби:
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
WireGuard визначає 25 секунд як доцільний інтервал keepalive для багатьох реалізацій NAT/firewall, коли потрібна постійна доступність; коли це не потрібно, краще залишити його вимкненим.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` навмисно робить це шляхом керування, а не pivot через default-route.

Потім застосуйте controls поза WireGuard:

1. Розв'язуйте `vpn.redteam.example` через затверджений bootstrap DNS path і зафіксуйте очікувану endpoint організації в deployment records.
2. На node дозвольте вихідний DHCP/RA, необхідні DNS/NTP, rendezvous endpoint і мінімально необхідний затверджений update path. Забороніть unsolicited inbound traffic на кожному uplink.
3. На rendezvous дозвольте `10.77.0.20` доступ лише до broker/health service, необхідного для вправи. Не маршрутизуйте його загалом у client network.
4. Розмістіть інтерактивний доступ операторів за organization gateway. Не відкривайте SSH з node через tunnel, якщо для assessment достатньо signed pull-job interface.
5. Налаштуйте service manager запускати tunnel після підняття network, перезапускати його після збою з обмеженим backoff і надсилати alert після повторних збоїв. Цикл перезапусків не повинен перевантажувати майданчик або приховувати основну несправність.
6. Перевіряйте latest handshake peer, але не використовуйте наявність “handshake exists” як доказ того, що device не скомпрометований.

TURN може забезпечити relay-only reachability для спеціально створеного WebRTC control plane, а message queue може витримувати переривчасту роботу service. TURN явно надає client публічну relay address за NAT; його server залишається observer.<sup>[[4]](#references)</sup> Оберіть одну control architecture замість бездумного накладання tunnel без визначеного observer або переваги в надійності.

## Крок 5: стабільність uplink без особистих link

Для авторизованого venue node надавайте перевагу такому порядку:

1. дротовий connection або виділений test VLAN, наданий client;
2. owner-approved enterprise/guest Wi-Fi profile;
3. fallback через organization-contracted cellular/private APN.

Ніколи не додавайте personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account або Wi-Fi profile, експортований із повсякденного laptop. Саме до цих artifacts capture і підключиться.

Для кожного затвердженого uplink:

- запишіть SSID/BSSID або switch/VLAN і очікувану поведінку captive-portal;
- встановіть детермінований пріоритет і health check до endpoint, яким володіє організація;
- зробіть так, щоб failover змінював лише underlay; ідентичності device та operator залишаються на broker;
- переконайтеся, що DNS, IPv6 і application traffic не обходять rendezvous під час переходу;
- надсилайте alert про невідомі SSID/BSSID, зміну SIM, новий default gateway, зміну public-IP/ASN або одночасні uplink;
- перед deployment протестуйте втрату живлення, DHCP renewal, перезапуск AP, зміну public-IP, 24-годинний idle, втрату tunnel і відновлення за схемою primary-to-secondary-to-primary.

Private MAC addressing може зменшити поверхневе cross-network tracking, але для авторизованого NAC часто потрібен стабільний MAC для кожної network. Зафіксуйте, що саме робить обрана OS, і не змінюйте MAC навколо access control власника.

## Крок 6: обмеження роботи та data

Безпечний field node не повинен приймати довільний shell text із mailbox. Визначте signed job types, наприклад `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` або іншу дію, явно названу в правилах engagement. Повторно перевіряйте destination, duration, rate, output size і scope на node.

1. Надайте кожному job унікальний ID, device audience, issue time, expiry, scope reference і maximum output.
2. Підписуйте його identity контролера/deployment.
3. Відхиляйте невідомі fields, прострочені або повторно відтворені jobs і jobs для іншого device.
4. Передавайте результати до owned collector; шифруйте та встановлюйте TTL для будь-якого неминучого local spool.
5. Логуйте accepted/rejected job ID і result hash на controller. Не розміщуйте sensitive command parameters у public monitoring channel.
6. Припиняйте обробку, коли authorization спливає, identity rotation завершується помилкою або controller позначає device як quarantined.

## Моніторинг discovery, втрати або compromise

Monitoring може повідомити controller, що observed state змінився. Він не може надійно довести, що “investigators знайшли device”, а спроби стежити за responders або probe їхні systems виходили б за межі authorized assessment.

### Збір off-device state

Надсилайте controller signed low-volume health record через рандомізований, але обмежений operational interval. Включайте лише те, що потрібне controller:

- device ID, boot ID/counter і monotonic uptime;
- configuration/image hash і software version;
- device-certificate serial і renewal state;
- uplink class, interface, BSSID або switch context у дозволених межах, default-gateway hash і public IP/ASN за даними owned service;
- tunnel handshake age, packet counters і queue depth;
- стан enclosure switch або hardware-tamper, якщо owner схвалив sensor;
- disk pressure, temperature, оцінку clock-offset і last successful job ID;
- sequence number і signature для виявлення replay або пропусків.

Зберігайте gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events і alerts централізовано. CISA рекомендує централізувати logs, захищати їх від deletion, встановлювати baseline нормальної активності та призначати incident-response contacts.<sup>[[5]](#references)</sup>

### Індикатори discovery/compromise

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking або removal | corroborate provider/site state; не підключатися повторно через unapproved path |
| Boot counter змінено несподівано | power cut, crash, removal або maintenance | quarantine jobs; порівняти час і site events |
| Config/image hash змінено | update error, storage fault або tampering | припинити роботу; revoke, якщо це не controller-approved release |
| Нові uplink/BSSID/gateway/ASN | AP replacement, roaming, переміщення device або interception | порівняти з approved inventory; quarantine незрозумілий transition |
| Repeated rejected job/signature | corruption, replay або unauthorized controller | припинити обробку та перевірити gateway/controller logs |
| Device credential використано двічі або з incompatible paths | cloned key, snapshot reuse або network transition | негайно revoke; зберегти обидва session records |
| Неочікувані local login, interface, process або privilege event | maintenance або compromise | ізолювати через broker policy; зберегти evidence |
| Перехід enclosure switch/state | service, movement або discovery | повідомити названий site contact; не запускати destructive action |
| Provider abuse notice/account query або SOC alert | detection, misconfiguration або out-of-scope traffic | припинити activity та запустити deconfliction/incident process |
| Sentinel credential використано | хтось прочитав decoy secret без privilege, унікальний для цього node | revoke справжню device identity і зберегти alert trail |

Sentinel credential не повинен надавати **жодного access**, викликати лише alert service, яким володіє організація, і бути розкритим у правилах engagement. Це tripwire для unauthorized reading, а не beacon для tracking того, хто знайшов equipment.

### Пороги alert

Використовуйте stateful rules, а не один драматичний alarm “caught”:

- **warning:** один пропущений interval, нормальна зміна address або зростання queue;
- **degraded:** три послідовні пропуски, затримка renewal, втрата primary-uplink або повторний restart;
- **quarantine:** unapproved hash/boot/uplink change, duplicate credential, sentinel use або unexpected privileged event;
- **confirmed discovery/loss:** site/controller report, невідповідність physical inventory, recovery device незапланованою стороною або validated provider/SOC escalation.

Тестуйте доставку alert через channel, незалежний від field node. Не надсилайте sensitive client/device detail до personal messaging або consumer push accounts.

## Runbook для підозрюваного discovery або capture

1. **Stop:** призупиніть нові jobs і operator sessions. Не надсилайте probe “check if watched”.
2. **Quarantine:** змусьте broker заборонити device identity та її routes, зберігаючи наявні logs.
3. **Revoke:** відкличте device certificate/key, queue token, update credential і всі single-purpose service tokens. Призупиніть organization SIM, якщо фізична втрата ймовірна.
4. **Preserve:** створіть snapshot записів controller, gateway, provider і alerts; зафіксуйте trusted time, виконавця дії та останню відому configuration. Не очищайте й не виконуйте remote wipe node.
5. **Notify:** зв'яжіться з exercise controller, client incident contact і legal/privacy contacts, визначеними в authorization. Якщо його знайшла третя сторона, використайте заздалегідь узгоджений recovery process.
6. **Assess:** вважайте exposed кожен secret і cached result на node. Точно визначте, до чого міг отримати access кожен secret і чи використовувався він після підозрілої події.
7. **Contain downstream:** rotate affected service credentials, invalidate pending jobs і перевірте owned target/provider logs на unexpected behavior.
8. **Recover safely:** забирайте device лише через authorized person; сфотографуйте/упакуйте його, зафіксуйте custody та отримайте forensic evidence згідно з вказівками client.
9. **Resume with a new identity:** ніколи непомітно не вмикайте повторно captured credential. Відновіть систему з відомого manifest, виправте control failure та отримайте explicit approval.

Поточні рекомендації NIST щодо incident-response інтегрують preparation, detection, response і recovery в загальне cybersecurity risk management організації; спочатку збережіть дані, щоб client міг визначити, що сталося, і обрати належну response.<sup>[[6]](#references)</sup>

## Capture drill перед deployment

Передайте окремому reviewer розблокований test unit або копію його storage і попросіть перелічити:

1. ідентифікатори device/site/engagement;
2. імена operator, personal accounts, home/workstation networks і recovery contacts;
3. destinations і credentials controller/broker;
4. client network profiles і cached results;
5. інші devices/projects, доступні з кожним secret;
6. value або payment credentials;
7. що саме controller може revoke і як швидко;
8. яка activity залишається attributable з central logs.

Критерії проходження: zero personal accounts/workstation keys; zero cross-engagement або enrollment authority; no payment credential; bounded encrypted cache; одна задокументована device-revocation action; повна controller-side accountability. Будь-який unexpected personal link або lateral capability вважайте blocker для release.

## Closeout

1. Зупиніть jobs і вимкніть broker route після завершення scope.
2. Отримайте та звірте точний inventory; повідомте про все відсутнє.
3. Збережіть logs/results і, якщо потрібно, forensic image відповідно до engagement retention plan.
4. Revoke device, SIM, queue, update і service identities, навіть якщо hardware було recovered.
5. Лише після preservation/acceptance санітизуйте або знищте media за approved data-disposal process власника та зафіксуйте завершення. Це lifecycle management, а не concealment.
6. Видаліть venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules і тимчасові contacts.
7. Задокументуйте observed detection, missed telemetry, time to quarantine і кожен artifact, exposed під час capture.

## References

- [1] [NIST — Каталог можливостей кібербезпеки IoT-пристроїв](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
