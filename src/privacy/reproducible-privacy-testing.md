# Відтворюване тестування приватності

Налаштування приватності не є завершеним, коли воно просто підключається. Воно завершене, коли заявлену межу перевірено під час звичайного використання, збоїв, відновлення та демонтажу. Тестуйте інфраструктуру, якою ви володієте або яку маєте право перевіряти; публічні сайти для “leak test” стають ще одним спостерігачем.

## Створіть невелике авторизоване тестове середовище

Використовуйте три ролі, бажано в окремих провайдерів/мережах:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Записуйте перед кожним тестом:

- ID тесту, час початку/завершення за UTC, оператора та авторизацію;
- версії й конфігурацію endpoint/OS/client, а також хеш конфігурації;
- очікувані спостереження щодо IPv4, IPv6, DNS, TLS, облікового запису, платежів і фізичного середовища;
- які логи перевірятимуться, а також їхні годинники й часові зони;
- правило pass/fail і час teardown.

Ніколи не тестуйте спочатку чутливу ідентичність. Використовуйте synthetic account і безпечні унікальні canary values, що належать тестувальнику.

## Тест мережевого шляху

### 1. Зафіксуйте baseline

Перед увімкненням privacy path зафіксуйте локальні маршрути та resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
У macOS використовуйте `route -n get default`, `netstat -rn -f inet6` і `scutil --dns`. Зберігайте вивід лише у контрольованому сховищі доказів; він може містити локальні ідентифікатори.

### 2. Підключення та перевірка маршрутизації

Увімкніть VPN/Tor/workload namespace, а потім перевірте маршрут, вибраний для контрольованих публічних адрес:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Замініть адреси в документації на адреси тестового сервера. Переконайтеся, що вибраний інтерфейс/таблиця відповідає дизайну.

### 3. Спостереження з обох кінців

Установіть URL контрольованої кінцевої точки, а потім запитайте унікальний нешкідливий шлях:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Використовуйте домен, контрольований реальним тестувальником, автентифікований TLS і нечутливий токен у шляху. Перевірте журнал сервера на наявність:

- адреси джерела/ASN і очікуваного egress;
- IPv4 проти IPv6;
- поведінки Host/SNI, видимої на endpoint;
- user agent і заголовків застосунку;
- точного часу та повторного використання запиту.

Не додавайте `X-Forwarded-For`, унікальні debug-заголовки або cookies, що містять ідентифікаційні дані, до запиту, який нібито має бути відокремленим.

### 4. Тестуйте DNS за допомогою контрольованого canary

Налаштуйте авторитетну тестову зону, журнали запитів якої ви контролюєте. Виконайте запит унікальної випадкової мітки через compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Перевірте authoritative log. Зазвичай він бачить recursive resolver, а не обов’язково клієнта. Порівняйте цей resolver із передбаченою DNS-архітектурою VPN/Tor/application. Випадковий публічний сайт для перевірки DNS leak не потрібен.

### 5. Перевірте fail-closed поведінку

Залиште безпечний цикл запитів, спрямований на endpoint, яким ви володієте, а потім зупиніть privacy path. Workload має завершитися помилкою, а не переключитися на фізичний інтерфейс. Перевірте обидва сімейства адрес і DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Повторюйте під час:

- crash процесу tunnel;
- перемикання з Wi-Fi на Ethernet або hotspot;
- переходу в режим сну/пробудження;
- оновлення DHCP;
- зміни стану captive portal;
- повторного підключення provider/завершення терміну дії key.

Для Linux namespace/container зупиніть його tunnel і переконайтеся, що він не має іншого default route або resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Назви та команди відрізняються залежно від розгортання. Не вставляйте їх на віддалений production host без можливості відновлення через консоль.

### 6. Перевірка локальних сокетів і пакетів

Маючи дозвіл, перевірте, який процес/інтерфейс фактично здійснює обмін даними:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Замініть `TEST_SERVER_IP` на явну адресу, якою ви володієте; уникайте широкого захоплення даних сторонніх користувачів. Фізичний інтерфейс має бачити tunnel/bridge peer, а clear destination traffic має існувати лише на призначеному рівні.

## Tor та onion-service test

1. У Tor Browser відкрийте сторінку перевірки підключення Tor Project і підтвердьте використання Tor. Не сприймайте це як підтвердження особи.<sup>[[1]](#references)</sup>
2. Відкрийте власний HTTPS endpoint з унікальним canary і підтвердьте, що він бачить Tor exit, неідентифікаційні cookies та стандартний browser context.
3. Виберіть **New Identity**, відкрийте сторінку повторно з іншим canary і перевірте, що локальний стан було очищено очікуваним чином. Зміна exit IP не гарантована й не є метою New Identity.
4. Для onion service отримуйте доступ до нього лише через Tor Browser. Підтвердьте за допомогою авторизованого external scan, що service host не має public listener, а відповіді application не містять public hostname/IP.
5. Перевірте вихідні DNS/HTTP-запити origin, templates, error pages, email/webhooks і third-party assets. Будь-який прямий fetch може розкрити origin або обліковий запис оператора.
6. Якщо client authorization увімкнено, підтвердьте, що неавторизований чистий Tor Browser не може підключитися, а авторизований може.
7. Ротуйте тестовий authorization key і підтвердьте, що revoked client втрачає доступ без зміни onion identity.

## Browser-compartment test

Створіть контрольовану сторінку, яка записує лише потрібні для тесту поля, із коротким періодом зберігання. Порівняйте personal та privacy compartments для:

- cookies/local storage/service workers і cache;
- browser sync/login state;
- language, time zone, screen/window dimensions і fonts;
- WebRTC/network candidates;
- permissions і modifications, видимих extension;
- TLS/HTTP user-agent data на server.

Не намагайтеся зробити Tor Browser «більш випадковим». Умовою проходження є схожість із його стандартним anonymity set і відсутність personal state, а не максимальна відмінність від personal browser.

Перевірте copy/paste, drag/drop, відкриття downloaded-file, password-manager suggestions і identity-provider buttons. Це часті мости між compartments.

## Operating-system isolation test

### Tails

1. Почніть із benign file/canary у session без Persistent Storage.
2. Повністю завершіть роботу, перезавантажте систему й підтвердьте, що його більше немає.
3. Увімкніть лише одну потрібну persistence category, повторіть тест і підтвердьте, що сторонній browser/application state не зберігається.
4. Перевірте, що Unsafe Browser не можна використовувати після portal login для чутливих дій і що Tor applications нормально підключаються повторно.

### Whonix/Qubes

1. Зупиніть Gateway/net qube і доведіть, що Workstation/app qube не може отримати доступ до IPv4, IPv6 або DNS.
2. Спробуйте лише явно налаштований inter-qube clipboard/file path і підтвердьте відсутність інших shared-folder/device paths.
3. Відкрийте benign test document у disposable qube, закрийте його й підтвердьте, що його стан зникає.
4. Перевірте, що vault qube не має NetVM і не може отримати його через зміну template/default.
5. Створіть snapshot/restore тестової VM і перевірте, чи несподівано повертається identity-bearing state.

## Communications metadata test

Для кожного вибраного messenger:

1. Створіть учасників, призначених лише для тесту, на контрольованих пристроях.
2. Зафіксуйте, що потрібно для реєстрації: phone, app-store account, IP, push service, username або invitation.
3. Надішліть одне benign message, перевіряючи notification previews, linked desktops, wearables і backups.
4. Перевірте safety/security codes через незалежний канал.
5. По одному вимикайте receipts/push або вмикайте Tor/local transports і спостерігайте за змінами надійності та metadata.
6. Експортуйте або відновіть тестову backup і точно задокументуйте, які profile, contacts та history вона містить.
7. Втратьте або відкличте тестовий пристрій і підтвердьте, що решта учасників бачить очікувану зміну key/device.

Не проводьте тестування, контактуючи з непричетними людьми або генеруючи abusive traffic.

## File-sanitization test

1. Обчисліть hash оригіналу та збережіть його в encrypted evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Створіть очищену копію, використовуючи процес для відповідного формату з розділу [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Порівняйте інвентаризації метаданих:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Відрендеріть/відкрийте копію в disposable context. Перевірте прихований вміст, вкладення, links, форми, шари, мініатюри та візуальні ідентифікатори.
5. Виконуйте пошук відомих рядків canary author/email/path лише у підготовленій копії.
6. Обчисліть hash фінального результату та попросіть другу особу перевірити точний файл, який публікується.

Відсутність даних у виводі ExifTool не є доказом анонімності; внутрішні дані формату, пікселі, текст і записи про поширення залишаються.

## Тест privacy платежів

Використовуйте найменшу дозволену суму або офіційну test network/sandbox:

1. Опишіть очікуване представлення для платника, отримувача/merchant, емітента/exchange, network/node, публічного ledger та бухгалтера/контролера.
2. Створіть унікальний тестовий invoice/merchant context без неправдивої ідентичності.
3. Виконайте оплату один раз, потім зберіть **власні** receipt, statement, merchant dashboard, wallet/node log і представлення публічного chain, де це застосовно.
4. Перевірте, чи відповідають таблиці спостерігачів сума, timestamp, address/token, account, IP/device, доставка та маршрут refund.
5. Для Bitcoin перевірте повторне використання address, вибрані inputs, change і подальше об’єднання в wallet's coin-control view.
6. Для shielded протоколів перевірте фактичні pool/path і те, що розкриває viewing key; не робіть висновків про privacy на підставі branding wallet.
7. Для e-cash/Taler протестуйте backup/recovery, refund і redemption на невеликій сумі; задокументуйте записи на межах mint/exchange/federation.
8. Відкличте virtual card/test credential і підтвердьте, що подальша авторизація не проходить, водночас легітимна обробка refund залишається зрозумілою.
9. Звірте дані та зберігайте необхідні податкові/авторизаційні докази в зашифрованому вигляді.

Ніколи не створюйте circular transfers, threshold-splitting, fake purchases або підозрілі refunds як «тест privacy».

## Вправа з підзвітності Authorized red-team

Перед вправою проведіть tabletop і технічне тестування:

1. Оператор запускає benign canary з кожного затвердженого source path.
2. Цільовий SOC фіксує виявлене, не отримуючи ідентичність оператора, якщо передбачено blind testing.
3. Контролер вправи встановлює відповідність source → engagement → operator за escrowed map і підписаним job record.
4. Контролер надсилає emergency stop; оператор і власник інфраструктури демонструють shutdown протягом часу, визначеного ROE.
5. Provider abuse отримує правильний цілодобовий контакт і reference авторизації.
6. Докази містять target, time, tool/job та operator без збереження зайвого payload content.
7. Другий оператор перевіряє credential revocation і resource teardown.

Не пройдено readiness review, якщо SOC може без труднощів побачити особисту/домашню інфраструктуру **АБО** якщо контролер не може швидко встановити джерело та зупинити його.

## Шаблон запису тесту
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Перевірка підключення](https://check.torproject.org/)
- [2] [WireGuard — Маршрутизація та мережеві простори імен](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ та рекомендації щодо метаданих](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Технічний посібник з тестування та оцінювання безпеки інформації](https://csrc.nist.gov/pubs/sp/800/115/final)
