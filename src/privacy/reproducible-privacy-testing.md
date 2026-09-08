# Відтворюване тестування приватності

{{#include ../banners/hacktricks-training.md}}

Налаштування приватності не завершене, коли воно підключається. Воно завершене, коли заявлену межу перевірено під час звичайного використання, відмов, відновлення та демонтажу. Тестуйте інфраструктуру, якою ви володієте або яку маєте право перевіряти; публічні сайти для “leak test” стають ще одним спостерігачем.

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

- ID тесту, час початку/завершення в UTC, оператора та авторизацію;
- версії й конфігурацію endpoint/OS/client, а також хеш конфігурації;
- очікувані спостереження щодо IPv4, IPv6, DNS, TLS, облікового запису, платежів і фізичного середовища;
- які логи буде перевірено, а також їхні годинники й часові пояси;
- правило pass/fail і час teardown.

Ніколи не тестуйте спочатку чутливу ідентичність. Використовуйте synthetic account і безпечні унікальні canary values, що належать тестувальнику.

## Тест мережевого шляху

### 1. Зафіксуйте baseline

Перед увімкненням шляху приватності запишіть локальні маршрути та резолвери:
```bash
ip route
ip -6 route
resolvectl status
```
У macOS використовуйте `route -n get default`, `netstat -rn -f inet6` і `scutil --dns`. Зберігайте вивід лише в контрольованому сховищі доказів; він може містити локальні ідентифікатори.

### 2. Підключення та перевірка маршрутизації

Увімкніть VPN/Tor/простір імен workload, потім перевірте маршрут, вибраний для контрольованих публічних адрес:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Замініть адреси в документації на адреси тестового сервера. Переконайтеся, що вибраний інтерфейс/таблиця відповідає дизайну.

### 3. Спостереження з обох кінців

Установіть URL контрольованої кінцевої точки, потім запитайте унікальний безпечний шлях:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Використовуйте домен, контрольований реальним тестувальником, автентифікований TLS і нетривіальний токен шляху, що не містить чутливих даних. Перевірте server log на наявність:

- адреси джерела/ASN і очікуваного egress;
- IPv4 порівняно з IPv6;
- поведінки Host/SNI, видимої на endpoint;
- user agent і заголовків application;
- точного часу та повторного використання запиту.

Не додавайте `X-Forwarded-For`, унікальні debug-заголовки або cookies, що містять ідентифікаційні дані, до запиту, який начебто має бути відокремленим.

### 4. Перевірте DNS за допомогою контрольованого canary

Налаштуйте authoritative test zone, журнали запитів якої ви контролюєте. Виконайте запит унікального випадкового label через compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Перевірте authoritative log. Зазвичай він бачить recursive resolver, а не обов’язково client. Порівняйте цей resolver із запланованою DNS-архітектурою VPN/Tor/application. Випадковий публічний сайт для перевірки DNS leak не потрібен.

### 5. Перевірте fail-closed поведінку

Підтримуйте цикл нешкідливих запитів, спрямованих до власної кінцевої точки, а потім зупиніть privacy path. Workload має завершитися з помилкою, а не перемкнутися на фізичний інтерфейс. Перевірте обидві address families і DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Повторюйте під час:

- аварійного завершення процесу tunnel;
- перемикання з Wi-Fi на Ethernet або на hotspot;
- переходу в режим сну/пробудження;
- поновлення DHCP;
- зміни стану captive portal;
- повторного підключення провайдера/завершення терміну дії ключа.

Для Linux namespace/container зупиніть його tunnel і перевірте, що в ньому немає іншого маршруту за замовчуванням або resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Назви та команди відрізняються залежно від розгортання. Не вставляйте їх у віддалений production host без можливості відновлення через консоль.

### 6. Перевірка локальних сокетів і пакетів

Маючи дозвіл, перевірте, який процес/інтерфейс фактично здійснює обмін даними:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Замініть `TEST_SERVER_IP` на явну адресу, якою ви володієте; уникайте широкого захоплення даних, що стосуються інших користувачів. Фізичний інтерфейс має бачити peer тунелю/bridge, тоді як трафік із відкритим призначенням має існувати лише на передбаченому рівні.

## Тест Tor та onion-service

1. У Tor Browser відвідайте сторінку перевірки підключення Tor Project і підтвердьте використання Tor. Не вважайте це доказом ідентичності.<sup>[[1]](#references)</sup>
2. Відвідайте контрольовану HTTPS endpoint з унікальним canary та підтвердьте, що вона бачить вихідний вузол Tor, не бачить ідентифікаційних cookies і працює у стандартному browser context.
3. Виберіть **New Identity**, повторно відвідайте endpoint з іншим canary та перевірте, що локальний стан було очищено належним чином. Зміна exit IP не гарантується і не є призначенням New Identity.
4. Для onion service підключайтеся до нього лише через Tor Browser. Підтвердьте, що host service не має public listener, за допомогою авторизованого external scan, і що відповіді application не містять public hostname/IP.
5. Перевірте вихідні DNS/HTTP-запити origin, templates, error pages, email/webhooks і third-party assets. Будь-який прямий fetch може розкрити origin або обліковий запис оператора.
6. Якщо client authorization увімкнено, підтвердьте, що неавторизований чистий Tor Browser не може підключитися, а авторизований може.
7. Виконайте ротацію тестового authorization key і підтвердьте, що відкликаний client втрачає доступ без зміни onion identity.

## Тест browser compartment

Створіть контрольовану сторінку, яка записує лише поля, необхідні для тесту, з коротким періодом зберігання. Порівняйте personal і privacy compartments щодо:

- cookies/local storage/service workers і cache;
- browser sync/login state;
- мови, часового поясу, розмірів екрана/вікна та fonts;
- WebRTC/network candidates;
- permissions і змін, видимих extensions;
- даних TLS/HTTP user-agent на server.

Не намагайтеся зробити Tor Browser «більш випадковим». Умовою успішного проходження є подібність до його стандартного anonymity set і відсутність personal state, а не максимальна відмінність від personal browser.

Перевірте copy/paste, drag/drop, відкриття завантажених файлів, пропозиції password-manager і кнопки identity-provider. Це часті мости між compartments.

## Тест ізоляції operating system

### Tails

1. Почніть із нешкідливого файлу/canary у session без Persistent Storage.
2. Повністю вимкніть систему, перезавантажте її та підтвердьте, що файл зник.
3. Увімкніть лише одну потрібну категорію persistence, повторіть тест і підтвердьте, що unrelated browser/application state не зберігається.
4. Перевірте, що Unsafe Browser не можна використовувати після portal login для чутливої діяльності, а Tor applications нормально підключаються повторно.

### Whonix/Qubes

1. Зупиніть Gateway/net qube і доведіть, що Workstation/app qube не може отримати доступ до IPv4, IPv6 або DNS.
2. Виконайте спробу лише явно налаштованого inter-qube clipboard/file path і підтвердьте відсутність інших shared-folder/device paths.
3. Відкрийте нешкідливий тестовий документ у disposable qube, закрийте його та підтвердьте, що його state зникає.
4. Перевірте, що vault qube не має NetVM і не може отримати його через зміну template/default.
5. Створіть snapshot/restore тестової VM і перевірте, чи не повертається неочікувано state, пов’язаний з identity.

## Тест metadata комунікацій

Для кожного вибраного messenger:

1. Створіть учасників лише для тесту на контрольованих devices.
2. Запишіть, що потрібно для registration: phone, app-store account, IP, push service, username або invitation.
3. Надішліть одне нешкідливе повідомлення, перевіряючи notification previews, linked desktops, wearables і backups.
4. Перевірте safety/security codes через незалежний path.
5. По черзі вимкніть receipts/push або увімкніть Tor/local transports і спостерігайте за змінами reliability/metadata.
6. Export або restore тестового backup і точно задокументуйте, які profile, contacts та history він містить.
7. Втратьте або відкличте тестовий device і підтвердьте, що решта учасників бачить очікувану зміну key/device.

Не проводьте тестування, зв’язуючись із непричетними людьми або генеруючи abusive traffic.

## Тест санітизації файлів

1. Обчисліть hash і збережіть оригінал у зашифрованому evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Створіть очищену копію, використовуючи процес для відповідного формату в [Комунікації та обмін даними із захистом приватності](privacy-preserving-communications-and-sharing.md).
3. Порівняйте інвентаризації metadata:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Відрендеріть/відкрийте копію в одноразовому контексті. Перевірте прихований вміст, вкладення, links, форми, шари, мініатюри та візуальні ідентифікатори.
5. Виконуйте пошук лише в підготовленій копії за відомими canary-рядками автора/email/path.
6. Обчисліть hash фінального результату, а друга особа нехай перевірить точний файл, який буде опубліковано.

Відсутність даних у виводі ExifTool не є доказом анонімності; внутрішні дані формату, пікселі, текст і записи про розповсюдження залишаються.

## Тест конфіденційності платежу

Використовуйте найменшу дозволену суму або офіційну тестову мережу/sandbox:

1. Запишіть очікуване представлення для платника, отримувача/merchant, емітента/exchange, мережі/node, публічного ledger і бухгалтера/контролера.
2. Створіть унікальний тестовий invoice/merchant-контекст без неправдивої ідентичності.
3. Виконайте платіж один раз, потім зберіть **власні** receipt, statement, merchant dashboard, wallet/node log і представлення публічного chain, де це застосовно.
4. Перевірте, чи відповідають таблиці спостерігачів сума, timestamp, address/token, account, IP/device, доставка та маршрут refund.
5. Для Bitcoin перевірте повторне використання address, вибрані inputs, change і подальшу консолідацію в поданні coin-control wallet.
6. Для shielded-протоколів перевірте фактичний pool/path і те, що розкриває viewing key; не робіть висновків про конфіденційність на підставі branding wallet.
7. Для e-cash/Taler протестуйте backup/recovery, refund і redemption на невеликій сумі; задокументуйте записи про межі mint/exchange/federation.
8. Відкличте virtual card/test credential і підтвердьте, що подальша авторизація не проходить, водночас порядок обробки legitimate refund залишається зрозумілим.
9. Проведіть reconciliation і зберігайте необхідні податкові/авторизаційні докази в зашифрованому вигляді.

Ніколи не створюйте circular transfers, threshold-splitting, fake purchases або підозрілі refunds як «тест конфіденційності».

## Вправа з підзвітності авторизованої red-team

Перед вправою проведіть tabletop і технічну вправу:

1. Operator запускає benign canary з кожного затвердженого source path.
2. Цільовий SOC фіксує виявлене, не отримуючи ідентичність operator, якщо передбачено blind testing.
3. Контролер вправи визначає source → engagement → operator за escrowed map і підписаним job record.
4. Контролер надсилає emergency stop; operator і власник інфраструктури демонструють shutdown протягом часу, визначеного ROE.
5. Provider abuse отримує правильний цілодобовий контакт і reference авторизації.
6. Докази містять target, time, tool/job і operator, не зберігаючи непотрібний payload content.
7. Другий operator перевіряє credential revocation і teardown ресурсів.

Проваліть readiness review, якщо SOC може без особливих зусиль побачити personal/home infrastructure **АБО** якщо контролер не може швидко атрибутувати та зупинити source.

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

- [1] [Tor Project — Перевірка з'єднання](https://check.torproject.org/)
- [2] [WireGuard — Маршрутизація та мережеві простори імен](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ та рекомендації щодо метаданих](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Технічний посібник із тестування та оцінювання інформаційної безпеки](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
