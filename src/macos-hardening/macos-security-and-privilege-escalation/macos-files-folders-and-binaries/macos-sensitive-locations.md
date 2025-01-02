# macOS Чутливі Локації та Цікаві Демони

{{#include ../../../banners/hacktricks-training.md}}

## Паролі

### Тіньові Паролі

Тіньовий пароль зберігається з конфігурацією користувача в plists, розташованих у **`/var/db/dslocal/nodes/Default/users/`**.\
Наступний однорядковий код можна використовувати для вивантаження **всіх відомостей про користувачів** (включаючи інформацію про хеш):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Скрипти, подібні до цього**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) або [**цього**](https://github.com/octomagon/davegrohl.git) можуть бути використані для перетворення хешу в **формат** **hashcat**.

Альтернативна однорядкова команда, яка виведе облікові дані всіх не-сервісних облікових записів у форматі hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Інший спосіб отримати `ShadowHashData` користувача - це використання `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Цей файл **використовується тільки** коли система працює в **однокористувацькому режимі** (тому не дуже часто).

### Вивантаження ключів

Зверніть увагу, що при використанні бінарного файлу безпеки для **вивантаження розшифрованих паролів**, кілька запитів попросять користувача дозволити цю операцію.
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
> Відповідно до цього коментаря [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), здається, що ці інструменти більше не працюють у Big Sur.

### Огляд Keychaindump

Інструмент під назвою **keychaindump** був розроблений для витягування паролів з ключниць macOS, але він стикається з обмеженнями на новіших версіях macOS, таких як Big Sur, як зазначено в [обговоренні](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Використання **keychaindump** вимагає від атакуючого отримати доступ і підвищити привілеї до **root**. Інструмент використовує той факт, що ключниця за замовчуванням розблокована під час входу користувача для зручності, що дозволяє додаткам отримувати до неї доступ без повторного введення пароля користувача. Однак, якщо користувач вирішить заблокувати свою ключницю після кожного використання, **keychaindump** стає неефективним.

**Keychaindump** працює, націлюючись на конкретний процес під назвою **securityd**, який Apple описує як демон для авторизації та криптографічних операцій, що є критично важливим для доступу до ключниці. Процес витягування включає в себе ідентифікацію **Master Key**, отриманого з пароля для входу користувача. Цей ключ є необхідним для читання файлу ключниці. Щоб знайти **Master Key**, **keychaindump** сканує купу пам'яті **securityd** за допомогою команди `vmmap`, шукаючи потенційні ключі в областях, позначених як `MALLOC_TINY`. Для перевірки цих пам'яткових місць використовується наступна команда:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Після ідентифікації потенційних майстер-ключів, **keychaindump** шукає в купах певний шаблон (`0x0000000000000018`), який вказує на кандидата для майстер-ключа. Подальші кроки, включаючи деобфускацію, необхідні для використання цього ключа, як зазначено в вихідному коді **keychaindump**. Аналітики, які зосереджуються на цій області, повинні звернути увагу на те, що критичні дані для розшифровки ключа зберігаються в пам'яті процесу **securityd**. Приклад команди для запуску **keychaindump**:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) може бути використаний для витягування наступних типів інформації з ключниці OSX у судово допустимий спосіб:

- Хешований пароль ключниці, придатний для злому за допомогою [hashcat](https://hashcat.net/hashcat/) або [John the Ripper](https://www.openwall.com/john/)
- Інтернет паролі
- Загальні паролі
- Приватні ключі
- Публічні ключі
- X509 сертифікати
- Захищені нотатки
- Паролі Appleshare

Знаючи пароль для розблокування ключниці, майстер-ключ, отриманий за допомогою [volafox](https://github.com/n0fate/volafox) або [volatility](https://github.com/volatilityfoundation/volatility), або файл розблокування, такий як SystemKey, Chainbreaker також надасть паролі у відкритому вигляді.

Без одного з цих методів розблокування ключниці Chainbreaker відобразить всю іншу доступну інформацію.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Вивантаження ключів ключниці (з паролями) за допомогою SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Витягування ключів з ключниці (з паролями) шляхом злому хешу**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Вивантаження ключів ключниці (з паролями) за допомогою дампу пам'яті**

[Слідуйте цим крокам](../#dumping-memory-with-osxpmem), щоб виконати **дамп пам'яті**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Вивантаження ключів ключниці (з паролями) за допомогою пароля користувача**

Якщо ви знаєте пароль користувача, ви можете використовувати його для **вивантаження та розшифровки ключниць, що належать користувачу**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Файл **kcpassword** - це файл, який містить **пароль для входу користувача**, але тільки якщо власник системи **увімкнув автоматичний вхід**. Тому користувач буде автоматично увійдений без запиту пароля (що не є дуже безпечним).

Пароль зберігається у файлі **`/etc/kcpassword`** xored з ключем **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Якщо пароль користувача довший за ключ, ключ буде повторно використано.\
Це робить пароль досить легким для відновлення, наприклад, за допомогою скриптів, як [**цей**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Ви можете знайти дані Сповіщень у `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Більшість цікавої інформації буде в **blob**. Тому вам потрібно буде **витягнути** цей вміст і **перетворити** його на **людську** **читабельність** або використати **`strings`**. Щоб отримати доступ до нього, ви можете зробити:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notes

Користувацькі **ноти** можна знайти в `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Налаштування

У додатках macOS налаштування розташовані в **`$HOME/Library/Preferences`**, а в iOS вони знаходяться в `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

У macOS інструмент командного рядка **`defaults`** може бути використаний для **модифікації файлу налаштувань**.

**`/usr/sbin/cfprefsd`** заявляє про XPC сервіси `com.apple.cfprefsd.daemon` та `com.apple.cfprefsd.agent` і може бути викликаний для виконання дій, таких як модифікація налаштувань.

## OpenDirectory permissions.plist

Файл `/System/Library/OpenDirectory/permissions.plist` містить дозволи, застосовані до атрибутів вузлів, і захищений SIP.\
Цей файл надає дозволи конкретним користувачам за UUID (а не uid), щоб вони могли отримувати доступ до конкретної чутливої інформації, такої як `ShadowHashData`, `HeimdalSRPKey` та `KerberosKeys` серед інших:
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

Головний демон для сповіщень - **`/usr/sbin/notifyd`**. Щоб отримувати сповіщення, клієнти повинні зареєструватися через Mach-порт `com.apple.system.notification_center` (перевірте їх за допомогою `sudo lsmp -p <pid notifyd>`). Демон налаштовується за допомогою файлу `/etc/notify.conf`.

Імена, що використовуються для сповіщень, є унікальними зворотними DNS-нотаціями, і коли сповіщення надсилається одному з них, клієнти, які вказали, що можуть його обробити, отримають його.

Можливо скинути поточний статус (і побачити всі імена), надіславши сигнал SIGUSR2 процесу notifyd і прочитавши згенерований файл: `/var/run/notifyd_<pid>.status`:
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

**Розподілений центр сповіщень**, основний бінарний файл якого **`/usr/sbin/distnoted`**, є ще одним способом надсилання сповіщень. Він надає деякі XPC сервіси і виконує певні перевірки, щоб спробувати перевірити клієнтів.

### Сповіщення Apple Push (APN)

У цьому випадку програми можуть реєструватися для **тем**. Клієнт згенерує токен, зв'язавшись із серверами Apple через **`apsd`**.\
Потім постачальники також згенерують токен і зможуть підключитися до серверів Apple, щоб надсилати повідомлення клієнтам. Ці повідомлення будуть локально отримані **`apsd`**, який передасть сповіщення програмі, що його чекає.

Налаштування розташовані в `/Library/Preferences/com.apple.apsd.plist`.

Існує локальна база даних повідомлень, розташована в macOS у `/Library/Application\ Support/ApplePushService/aps.db` і в iOS у `/var/mobile/Library/ApplePushService`. Вона має 3 таблиці: `incoming_messages`, `outgoing_messages` та `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Також можливо отримати інформацію про демон та з'єднання, використовуючи:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Сповіщення користувача

Це сповіщення, які користувач повинен бачити на екрані:

- **`CFUserNotification`**: Цей API надає спосіб показати на екрані спливаюче вікно з повідомленням.
- **Дошка оголошень**: Це показує в iOS банер, який зникає і буде збережений у Центрі сповіщень.
- **`NSUserNotificationCenter`**: Це дошка оголошень iOS у MacOS. База даних зі сповіщеннями знаходиться в `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
