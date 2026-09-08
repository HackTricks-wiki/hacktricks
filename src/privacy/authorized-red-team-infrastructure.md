# Authorized Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

Для довговічних пристроїв на об'єкті використовуйте дизайн [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) і runbook для випадку підозри на виявлення.

Для професійної red team метою є **контрольована атрибуція**, а не уникнення відповідальності. Ціль не повинна безпосередньо бачити домашню IP-адресу оператора або його особисті облікові записи, водночас власник engagement має мати змогу встановити джерело, зупинити операцію, обробити повідомлення про зловживання, зберегти докази та підтвердити наявність authorization.

Ця сторінка є базовою конфігурацією розгортання для lawful engagement. Щоб відтворити tradecraft противника, зокрема скомпрометовані ORB, residential relay, fronting, dead drop і nearby wireless pivot, почніть з [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) і [Government and APT Case Studies](government-and-apt-case-studies.md), а потім відтворіть необхідну telemetry в [authorized labs](authorized-adversary-emulation-labs.md).

NIST визначає правила взаємодії (ROE) як заздалегідь установлені обмеження, що надають authority для визначених testing activities.<sup>[[1]](#references)</sup> Privacy architecture не може розширювати ці повноваження.

## Choose an egress pattern

| Pattern | Best use | Target sees | Provider/local observer sees | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | Більшість assessments | Діапазон адрес клієнта | Ідентичність клієнта та доступ оператора | Найвищий |
| Red-team organization bastion | Повторюваний контрольований egress | Діапазон організації | Hosting provider і організація | Високий |
| Engagement-specific VPS | Ізоляція клієнтів/кампаній | Адресу VPS | Обліковий запис хоста, billing, control-plane і access logs | Високий за наявності документації |
| Approved commercial VPN | Research/scanning, дозволені provider і ROE | Спільний/виділений VPN egress | VPN account і source connection | Середній |
| Tor Browser | Web research, що потребує unlinkability призначення | Tor exit | Локальна мережа бачить Tor/bridge; призначення бачить Tor | Погано підходить для allowlisted source attribution |
| Client-approved on-site drop | Внутрішня симуляція | On-site device/address | Мережа об'єкта та remote tunnel provider | Високий за умови інвентаризації |
| Lawful guest Wi-Fi | Низькоризикове administrative/research використання | Публічну IP-адресу закладу або tunnel egress | Заклад, ISP, VPN/Tor | Слабкий і фізично помітний |

Для більшості робіт client-provided або organization-controlled fixed egress є безпечнішим і швидшим за consumer anonymity services. Це також дає змогу defenders allowlist, monitor або навмисно **не додавати до allowlist** відомі source ranges відповідно до дизайну вправи.

## ROE infrastructure annex

Зафіксуйте до deployment:

- legal entities, що надають і отримують authorization;
- точні targets та explicit exclusions;
- час початку/завершення, часовий пояс і дозволені techniques;
- source IPs, назви autonomous system/provider, domains, redirectors, mail infrastructure та ідентифікатори on-site devices;
- чи дозволені phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence або third-party services;
- client і provider approvals, включно з будь-яким pre-notification reference;
- emergency stop phrase, цілодобові client і provider abuse contacts та максимальний час response;
- класи даних, які можна збирати, encryption, access, retention і deletion;
- вимоги до evidence і logging, зокрема інформацію про те, хто зберігає mapping між public infrastructure та operator;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery і final attestation.

Переконайтеся, що public IPs і domains фактично контролюються authorizing party або явно включені до scope. NIST SP 800-115 рекомендує підтвердити, що public target addresses перебувають у зоні відповідальності організації, до початку testing.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Створіть engagement account/project** під керуванням red-team organization, використовуючи точні billing і ownership details. Відокремте roles, API keys, budgets і audit logs інших клієнтів.
2. **Перевірте policy кожного provider.** Cloud, VPS, CDN, domain, email і VPN providers мають різні правила. Наприклад, AWS дозволяє визначені assessments, але вимагає prior approval для hosted C2/covert simulations і забороняє перелічені activities.<sup>[[3]](#references)</sup>
3. **Виділіть fixed egress addresses** і внесіть їх до ROE annex. Уникайте швидкої зміни IP/resources; це ускладнює incident response і може порушувати provider policy.
4. **Захистіть management:** key-only SSH або identity-aware management plane, phishing-resistant MFA, окрема admin network, least privilege, patched images, відсутність public admin ports та encrypted secret storage.
5. **Створіть full-tunnel path** від operator endpoint до bastion. Навмисно налаштуйте routing DNS і IPv6 та застосуйте firewall deny, коли tunnel недоступний.
6. **Обмежте outbound destinations і ports** межами authorized scope, якщо це можливо. Встановіть rate limit для scanners і помістіть irreversible/destructive techniques за окремий approval gate.
7. **Здійснюйте logging для accountability, а не surveillance:** operator authentication, configuration changes, start/stop, source address, scoped destination та tool/job identifiers. Уникайте capture payload/credentials, якщо цього не вимагає exercise і це не захищено data plan.
8. **Перевірте через controlled endpoint**, що належить організації: observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect і provider abuse contact.
9. **Безпечно передайте attribution map** exercise controller або погодженому escrow contact. Не публікуйте його для target team, якщо blind detection є частиною test.

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPS є псевдонімним лише для пункту призначення. Хост може зберігати контактні, платіжні дані, дані про особу, вихідну IP-адресу, API, пристрій, місцезнаходження та використання; сама історія AWS CloudTrail, видима клієнту, може розкрити адміністративну активність.<sup>[[4]](#references)</sup> Оплата hosting за допомогою cryptocurrency не стирає ці записи.

## Домени та сертифікати

- Використовуйте обліковий запис реєстратора, призначений для конкретного engagement, власником якого є організація.
- Увімкніть блокування реєстратора, DNSSEC, якщо підтримується, MFA/security keys, а також auto-renew лише на затверджений період.
- Використовуйте privacy реєстрації, щоб зменшити публічне розкриття даних, а не для спотворення інформації про реєстранта. Політика ICANN вимагає від реєстраторів збирати реєстраційні дані, навіть коли їх публічне відображення приховане або проксійоване.<sup>[[5]](#references)</sup>
- Уникайте назв, які незаконно імітують сторонні організації. Typosquatting/lookalike domains потребують явного схвалення клієнта та провайдера.
- Інвентаризуйте DNS, сертифікати, конфігурацію CDN/redirector і сторонню аналітику, які можуть leak операторів або клієнтів.
- Під час teardown видаліть записи, відкличте сертифікати/токени, збережіть узгоджені докази та вирішіть, чи слід зберегти домен для захисту.

## Авторизовані on-site drop nodes

Raspberry Pi або подібний appliance прийнятний лише тоді, коли власник приміщення/мережі та клієнт явно авторизували його точне розміщення й поведінку. Безпечний план:

1. Зафіксуйте серійний номер пристрою, MAC/private-MAC policy, фотографію, власника, точне затверджене місце, джерело живлення, крайній термін вилучення та контакт для повідомлення про втручання.
2. Використовуйте мінімальний підписаний image, зашифровані secrets, read-only або відновлюване сховище, host firewall, automatic security updates, де це практично, і жодних default credentials.
3. Налаштуйте комунікацію лише назовні з іменованим engagement endpoint. Не відкривайте неавтентифікований listener.
4. Дозволяйте лише затверджені destinations і capabilities. Packet capture, credential collection, wireless impersonation і lateral movement мають бути окремо явно авторизовані.
5. Використовуйте взаємну автентифікацію, короткоживучі ключі, remote kill, health reporting і bandwidth limits.
6. Переконайтеся, що втрата або крадіжка не розкриє придатні для повторного використання credentials чи дані клієнта.
7. Заплануйте вилучення та secure wipe/decommission у календарі; отримайте підписаний запис про повернення.

Не приховуйте hardware у кафе, готелі, спільному офісі, на території сусіда або в публічному місці без письмового дозволу власника/оператора.

## Гостьові мережі та travel routers

Якщо авторизований сценарій вимагає guest access:

- перевірте SSID і acceptable-use policy із представником закладу/клієнта;
- використовуйте travel router, що належить організації, або low-trust bridge device для ізоляції privileged workstation;
- проходьте captive portals поза privileged workstation;
- запустіть схвалений tunnel до початку assessment traffic;
- переконайтеся, що tethered devices справді використовують цей tunnel;
- припускайте, що заклад може зіставити radio association, portal, фізичну присутність і записи з камер/платежів;
- ніколи не обходьте access control, не клонуйте інший пристрій, не атакуйте Wi-Fi і не залишайте обладнання.

## Операційне розділення

- Один клієнт/engagement на кожен endpoint compartment, cloud project, secrets set, domain group, redirector set і evidence store.
- Не використовуйте personal email, browser sync, номер телефону, cloud drive, SSH/GPG key, code-signing identity або payment reimbursement поза схваленими системами організації.
- Не використовуйте повторно distinctive payload configuration, callback paths, certificates або public repositories між клієнтами, якщо дизайн вправи не допускає fingerprinting.
- Встановіть для infrastructure kill date і budget alert. Покинуті системи стають ризиком і для клієнта, і для Internet.
- Зберігайте достатню внутрішню атрибуцію для розслідування інцидентів. “No logs” зазвичай несумісне з професійними вимогами до доказів і безпеки.

## Невидимі для захисників, але атрибутовані контролеру

Коли мета вправи — виміряти detection, а не перевірити allowlist, цільовий SOC може залишатися blind, не роблячи операцію безвідповідальною:

1. Контролер вправи схвалює кожне public source, domain, certificate та on-site device, але приховує цей список від SOC.
2. Контролер зберігає відповідність source-to-engagement/operator в окремому зашифрованому vault із emergency access для двох осіб.
3. Кожне завдання оператора отримує підписаний manifest, що містить scope, time window, source compartment і незворотний job identifier. Цільовій стороні не потрібно бачити manifest під час нормальної роботи.
4. Події аудиту bastion об’єднуються в ланцюжок або надсилаються append-only до сховища контролера, щоб оператор не міг непомітно переписати атрибуцію після інциденту.
5. 24/7 provider-abuse contact зберігає verification phrase/reference, яка підтверджує авторизацію без публічного розкриття клієнта.
6. Кожен path реалізує out-of-band stop channel, який не залежить від assessment C2, target network або облікового запису одного оператора.
7. Перед live testing надішліть benign canaries з кожного source. Переконайтеся, що контролер може ідентифікувати та зупинити їх у межах response time, визначеного ROE.
8. Після вправи порівняйте SOC telemetry з ledger контролера, розкрийте список sources і поясніть пропущені/помилкові detections.

Не додавайте anti-forensics, log destruction, compromised relays або false subscriber identities. Вони перетворюють accountable testing на протилежне, а не покращують його.

## Чекліст teardown

- [ ] Контролер вправи підтверджує зупинку.
- [ ] C2, tunnels, redirectors, mail, VPN і scheduled jobs вимкнено.
- [ ] On-site devices фізично вилучено та звірено.
- [ ] Tokens, API keys, SSH keys, certificates і captured credentials відкликано/замінено.
- [ ] DNS і cloud resources видалено або передано для defensive retention.
- [ ] Дані клієнта повернуто, збережено або знищено відповідно до договору.
- [ ] Необхідні financial, audit та authorization records залишаються зашифрованими й захищеними контролем доступу.
- [ ] Provider abuse cases закрито, а клієнт отримав фінальні source indicators.
- [ ] Другий оператор перевіряє, що жодна infrastructure не залишається активною.

## References

- [1] [NIST CSRC — Правила взаємодії](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Технічний посібник із тестування та оцінювання безпеки інформації](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Політика підтримки клієнтів щодо Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Повідомлення про конфіденційність](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Політика реєстраційних даних](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
