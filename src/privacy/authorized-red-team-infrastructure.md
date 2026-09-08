# Інфраструктура Authorized Red-Team

Для довговічних пристроїв на об'єкті використовуйте дизайн [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) і runbook для підозрюваного виявлення.

Для професійного red team метою є **контрольована атрибуція**, а не звільнення від відповідальності. Ціль не повинна тривіально бачити домашню IP-адресу оператора або його особисті облікові записи, водночас власник engagement має мати змогу встановити джерело, зупинити операцію, опрацювати повідомлення про зловживання, зберегти докази та довести наявність дозволу.

Ця сторінка є базовим планом розгортання для законного engagement. Для adversary tradecraft, який він має імітувати, зокрема скомпрометованих ORB, residential relay, fronting, dead drop і nearby wireless pivot, почніть з [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) і [Government and APT Case Studies](government-and-apt-case-studies.md), а потім відтворіть необхідну телеметрію в [authorized labs](authorized-adversary-emulation-labs.md).

NIST визначає правила взаємодії (ROE) як заздалегідь установлені обмеження, що надають повноваження для визначених тестових дій.<sup>[[1]](#references)</sup> Архітектура приватності не може розширювати ці повноваження.

## Вибір шаблону egress

| Шаблон | Найкраще застосування | Що бачить ціль | Що бачить provider/local observer | Підзвітність |
|---|---|---|---|---|
| Client-provided VPN/jump host | Більшість assessment | Діапазон адрес клієнта | Ідентичність клієнта та доступ оператора | Найвища |
| Red-team organization bastion | Повторюваний контрольований egress | Діапазон організації | Hosting provider і організація | Висока |
| Engagement-specific VPS | Ізоляція клієнтів/кампаній | Адресу VPS | Обліковий запис хоста, billing, control-plane і access logs | Висока за наявності документації |
| Approved commercial VPN | Research/scanning, дозволені provider і ROE | Спільний/виділений VPN egress | VPN account і source connection | Середня |
| Tor Browser | Web research, що потребує unlinkability призначення | Tor exit | Локальна мережа бачить Tor/bridge; призначення бачить Tor | Погано підходить для allowlisted source attribution |
| Client-approved on-site drop | Внутрішня симуляція | Пристрій/адресу на об'єкті | Мережу об'єкта та remote tunnel provider | Висока за умови інвентаризації |
| Lawful guest Wi-Fi | Адміністративне/research-використання з низьким ризиком | Публічну IP-адресу закладу або tunnel egress | Заклад, ISP, VPN/Tor | Низька та фізично спостережувана |

Для більшості робіт client-provided або organization-controlled fixed egress є безпечнішим і швидшим за consumer anonymity services. Це також дає змогу захисникам allowlist, monitor або навмисно **не allowlist** відомі source ranges відповідно до дизайну вправи.

## ROE infrastructure annex

Зафіксуйте до розгортання:

- юридичні особи, що надають і отримують дозвіл;
- точні цілі та явні виключення;
- час початку/завершення, часовий пояс і дозволені техніки;
- source IPs, назви autonomous-system/provider, домени, redirectors, mail infrastructure та ідентифікатори пристроїв на об'єкті;
- чи дозволені phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence або third-party services;
- погодження клієнта й provider, включно з будь-яким посиланням на pre-notification;
- emergency stop phrase, цілодобові abuse contacts клієнта й provider та максимальний час реагування;
- класи даних, які можна збирати, encryption, access, retention і deletion;
- вимоги до evidence і logging, включно з тим, хто зберігає mapping між public infrastructure та оператором;
- teardown, завершення терміну дії домену, відкликання сертифікатів, rotation облікових даних, повернення пристроїв і фінальне підтвердження.

Перевірте, що public IPs і домени справді контролюються стороною, яка надає дозвіл, або явно включені до scope. NIST SP 800-115 рекомендує підтверджувати, що public target addresses перебувають у віданні організації, перш ніж розпочинати тестування.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Створіть engagement account/project** у межах red-team organization, використовуючи точні billing і ownership details. Відокремте roles, API keys, budgets та audit logs від інших клієнтів.
2. **Перевірте політику кожного provider.** Cloud, VPS, CDN, domain, email і VPN providers мають різні правила. Наприклад, AWS дозволяє визначені assessment, але вимагає попереднього погодження для hosted C2/covert simulations і забороняє перелічені дії.<sup>[[3]](#references)</sup>
3. **Виділіть fixed egress addresses** і внесіть їх до ROE annex. Уникайте швидкої зміни IP/resource; це ускладнює incident response і може порушувати політику provider.
4. **Захистіть management:** SSH лише за ключами або identity-aware management plane, phishing-resistant MFA, окрема admin network, least privilege, patched images, відсутність public admin ports та encrypted secret storage.
5. **Створіть full-tunnel path** від operator endpoint до bastion. Цілеспрямовано маршрутизуйте DNS та IPv6 і застосуйте firewall deny, коли tunnel не працює.
6. **Обмежте outbound destinations і ports** межами дозволеного scope, якщо це можливо. Встановіть rate limit для scanner і винесіть irreversible/destructive techniques за окремий approval gate.
7. **Ведіть log для підзвітності, а не спостереження:** operator authentication, configuration changes, start/stop, source address, scoped destination та tool/job identifiers. Уникайте payload/credential capture, якщо цього не вимагає вправа і якщо це не захищено data plan.
8. **Перевірте через контрольований endpoint**, що належить організації: observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect і provider abuse contact.
9. **Безпечно передайте attribution map** exercise controller або погодженому escrow contact. Не публікуйте його для target team, якщо blind detection є частиною тесту.

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
VPS є псевдонімним лише для призначення. Хост може зберігати контактні, платіжні дані, відомості про особу, вихідні IP-адреси, API, пристрої, місцезнаходження та використання; сама історія AWS CloudTrail, доступна клієнту, може розкрити адміністративну активність.<sup>[[4]](#references)</sup> Оплата hosting за допомогою cryptocurrency не стирає ці записи.

## Domains and certificates

- Використовуйте обліковий запис реєстратора, специфічний для engagement, власником якого є організація.
- Увімкніть блокування реєстратора, DNSSEC, де він підтримується, MFA/security keys, а також auto-renew лише на затверджений період.
- Використовуйте реєстраційну конфіденційність для зменшення публічного розкриття, а не для викривлення інформації про реєстранта. Політика ICANN вимагає від реєстраторів збирати реєстраційні дані, навіть коли їхнє публічне відображення приховане або проксійоване.<sup>[[5]](#references)</sup>
- Уникайте назв, які незаконно імітують неналежні вам сторони. Typosquatting/lookalike domains потребують прямого схвалення клієнта та провайдера.
- Інвентаризуйте DNS, certificates, конфігурацію CDN/redirector і сторонню analytics, які можуть розкрити операторів або клієнтів.
- Під час teardown видаліть записи, відкличте certificates/tokens, збережіть узгоджені докази та вирішіть, чи слід зберегти domain для захисту.

## Authorized on-site drop nodes

Raspberry Pi або подібний appliance прийнятний лише тоді, коли власник об'єкта/мережі та клієнт прямо схвалили його точне розміщення й поведінку. Безпечний план:

1. Зафіксуйте серійний номер пристрою, MAC/private-MAC policy, фотографію, власника, точне затверджене місце, джерело живлення, кінцевий термін вилучення та контакт для повідомлення про втручання.
2. Використовуйте мінімальний підписаний image, зашифровані secrets, доступне лише для читання або відновлюване сховище, host firewall, automatic security updates, де це практично, і жодних default credentials.
3. Налаштуйте лише вихідний зв'язок із вказаним engagement endpoint. Не відкривайте unauthenticated listener.
4. Дозволяйте лише затверджені destinations і capabilities. Packet capture, credential collection, wireless impersonation і lateral movement мають бути окремо прямо дозволені.
5. Використовуйте mutual authentication, короткоживучі keys, remote kill, health reporting і bandwidth limits.
6. Переконайтеся, що втрата або крадіжка не розкриє придатні для повторного використання credentials чи дані клієнта.
7. Заплануйте вилучення та secure wipe/decommission у календарі; отримайте підписаний запис про повернення.

Не приховуйте hardware у кафе, готелі, спільному офісі, на території сусіда або в публічному місці без письмового дозволу власника/оператора.

## Guest networks and travel routers

Якщо авторизований сценарій потребує guest access:

- перевірте SSID і acceptable-use policy з представником закладу/клієнта;
- використовуйте travel router, що належить організації, або low-trust bridge device для ізоляції privileged workstation;
- проходьте captive portals поза privileged workstation;
- запустіть approved tunnel до початку assessment traffic;
- підтвердьте, що tethered devices справді використовують цей tunnel;
- виходьте з припущення, що заклад може зіставити radio association, portal, фізичну присутність і записи з камер/платежів;
- ніколи не обходьте access control, не клоновуйте інший пристрій, не атакуйте Wi-Fi і не залишайте обладнання.

## Operational separation

- Один клієнт/engagement на endpoint compartment, cloud project, secrets set, domain group, redirector set і evidence store.
- Не використовуйте особисту email-адресу, browser sync, номер телефону, cloud drive, SSH/GPG key, code-signing identity або payment reimbursement поза схваленими системами організації.
- Не повторно використовуйте distinctive payload configuration, callback paths, certificates або public repositories між клієнтами, якщо дизайн вправи не допускає fingerprinting.
- Визначте для infrastructure kill date і budget alert. Покинуті системи створюють ризик і для клієнта, і для Internet.
- Зберігайте достатню внутрішню атрибуцію для розслідування інцидентів. “No logs” зазвичай несумісне з професійними вимогами до доказів і безпеки.

## Blind to defenders, attributable to the controller

Коли мета вправи полягає у вимірюванні detection, а не в тестуванні allowlist, цільовий SOC може залишатися blind, не роблячи операцію безвідповідальною:

1. Exercise controller затверджує кожне public source, domain, certificate і on-site device, але приховує цей список від SOC.
2. Controller зберігає мапу source-to-engagement/operator в окремому зашифрованому vault із emergency access для двох осіб.
3. Кожне завдання оператора отримує підписаний manifest, що містить scope, time window, source compartment і незворотний job identifier. Цільовій стороні не потрібно бачити manifest під час нормальної роботи.
4. Bastion audit events об'єднуються в ланцюжок або надсилаються append-only до controller storage, щоб оператор не міг непомітно змінити атрибуцію після інциденту.
5. Контакт провайдера для provider-abuse, доступний 24/7, зберігає verification phrase/reference, яка підтверджує авторизацію без публічного розкриття клієнта.
6. Кожен path реалізує out-of-band stop channel, який не залежить від assessment C2, target network або облікового запису одного оператора.
7. До live testing надішліть benign canaries з кожного source. Підтвердьте, що controller може визначити їх і зупинити протягом response time, встановленого ROE.
8. Після вправи порівняйте SOC telemetry з controller ledger, розкрийте список sources і поясніть пропущені/неправильні detections.

Не додавайте anti-forensics, знищення logs, compromised relays або false subscriber identities. Вони перетворюють accountable testing на неaccountable, а не покращують його.

## Teardown checklist

- [ ] Exercise controller підтверджує зупинку.
- [ ] C2, tunnels, redirectors, mail, VPN і scheduled jobs вимкнено.
- [ ] On-site devices фізично вилучено та звірено.
- [ ] Tokens, API keys, SSH keys, certificates і captured credentials відкликано/замінено.
- [ ] DNS і cloud resources видалено або передано для defensive retention.
- [ ] Дані клієнта повернуто, збережено або знищено відповідно до contract.
- [ ] Необхідні financial, audit та authorization records залишаються зашифрованими й доступними лише уповноваженим особам.
- [ ] Provider abuse cases закрито, а клієнт отримав фінальні source indicators.
- [ ] Другий оператор перевіряє, що жодна infrastructure не залишається активною.

## References

- [1] [NIST CSRC — Правила проведення робіт](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Технічний посібник з тестування та оцінювання інформаційної безпеки](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Політика Customer Support щодо Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Повідомлення про конфіденційність](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Політика реєстраційних даних](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
