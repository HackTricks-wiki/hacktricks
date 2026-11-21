# Трюки з файловою системою macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Комбінації дозволів POSIX

Для **каталогу** три біти дозволів означають дещо інше, ніж для звичайного файла. `chmod(1)` називає біт виконання «**пошуком**», коли його застосовано до каталогу:<sup>[[2]](#references)</sup>

> `0100` Для файлів — дозволити власнику виконання. Для каталогів — дозволити власнику **шукати** в каталозі.

- **читання** — можна **перелічувати** записи каталогу (список назв).
- **запис** — можна **створювати, перейменовувати й видаляти записи** в каталозі. Зверніть увагу: це властивість *батьківського* каталогу, а не файла: можна видалити файл, який не вдається читати чи змінювати, якщо є право запису до його батьківського каталогу.
  - Щоб видалити **підкаталог**, він має бути порожнім, а для цього потрібні достатні права, щоб видалити все всередині нього.
  - Якщо для каталогу встановлено **sticky bit** (`S_ISVTX`, як у `/tmp`), це обмеження діє — POSIX зазначає, що процес може видаляти або перейменовувати файли в ньому лише за умови, що він є власником файла, власником каталогу або має відповідні привілеї.<sup>[[1]](#references)</sup>
- **виконання / пошук** — дозволяє **проходити** каталог. Під час розв’язання шляху кожен компонент шукається «в каталозі, указаному його попередником», тому **втрата права пошуку на будь-якому компоненті префікса шляху робить усе нижче недоступним через шлях**, навіть якщо кінцевий файл доступний для читання всім.<sup>[[1]](#references)</sup>

### Небезпечні комбінації

**Як перезаписати файл/каталог, власником якого є root**, якщо:

- Власником одного з батьківських **каталогів** у шляху є користувач
- Власником одного з батьківських **каталогів** у шляху є **група користувачів**, яка має **доступ на запис**
- **Група** користувачів має **доступ на запис** до **файла**

За будь-якої з попередніх комбінацій зловмисник може **вставити** **символічне/жорстке посилання** за очікуваним шляхом, щоб отримати довільний запис із підвищеними привілеями.

### Особливий випадок: R+X для каталогу root

Це безпосередньо випливає з правила розв’язання шляхів вище. Якщо **каталог надає права R+X лише root**, файли всередині нього недоступні *через шлях* для всіх інших — але **біти дозволів самих файлів можуть бути досить відкритими**. Перешкодою є лише каталог.

Тож будь-який примітив, що дає змогу витягти файл **із цього каталогу** — привілейований процес, який **переміщує/перейменовує/копіює** вибраний зловмисником шлях у місце, яке можна переглядати, — дає змогу довільно читати файл, не долаючи його власний режим доступу:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Шукайте привілейовані процеси, що переміщують файли (інсталятори, ротатори журналів, збирачі аварійних звітів і діагностичних даних, функції резервного копіювання та «експорту») і приймають шлях до джерела від користувача з нижчими привілеями.

## Symbolic Link / Hard Link

### Файл/папка з недостатніми обмеженнями

Якщо привілейований процес записує дані у **файл**, який може **контролювати** користувач із **нижчими привілеями** або який такий користувач міг **створити заздалегідь**, він може просто **вказати на інший файл** за допомогою Symbolic або Hard link, і привілейований процес записуватиме саме в цей файл.

Перевірте інші розділи, де зловмисник може **зловживати довільним записом для підвищення привілеїв**.

### Open `O_NOFOLLOW`

Згідно з [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *«Якщо в масці використано `O_NOFOLLOW`, а цільовий файл, переданий у `open()`, є symbolic link, виклик `open()` завершиться помилкою».* Перевіряється лише **кінцевий** компонент — усі **проміжні** компоненти, як і раніше, розв’язуються та проходяться. Отже, розробника, який «захистив» запис за допомогою `O_NOFOLLOW`, усе ще можна атакувати, створивши symlink у будь-якому **батьківському каталозі** цільового шляху.<sup>[[3]](#references)</sup>

На тій самій сторінці man описано прапорці, які справді усувають цю вразливість:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *«якщо ... будь-який компонент шляху, переданого в `open()`, є symbolic link, виклик `open()` завершиться помилкою».*
- **`O_RESOLVE_BENEATH`** — *«якщо ... під час розв’язання вказаного шляху відбувається вихід за межі каталогу, пов’язаного з fd, виклик `openat()` завершиться помилкою».*

В інших випадках, щоб запобігти підміні symlink у проміжній частині шляху, можна використовувати `openat()` відносно вже перевіреного дескриптора каталогу або `realpath()` із повторною перевіркою.

## .fileloc

Файли з розширенням **`.fileloc`** можуть вказувати на інші програми або бінарні файли, тож під час їх відкриття запускається відповідна програма або бінарний файл.\
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

### Leak FD (no `O_CLOEXEC`)

Якщо виклик `open` не містить прапорця `O_CLOEXEC`, файловий дескриптор успадкує дочірній процес. Тож якщо привілейований процес відкриває привілейований файл і запускає процес, контрольований зловмисником, зловмисник **успадкує FD привілейованого файлу**.

Класичний приклад — **LPE через `DYLD_PRINT_TO_FILE` в OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` враховував `DYLD_PRINT_TO_FILE=/path` навіть у **restricted-бінарних файлах (suid root)**, оскільки цю змінну розбирали поза `processDyldEnvironmentVariable()`.
- Він виконував `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, тож **створював файл, власником якого був root, за довільним шляхом**.
- FD **ніколи не закривався й не мав прапорця close-on-exec**, тому кожен дочірній процес suid-бінарного файлу успадковував **доступний для запису FD до файлу, власником якого був root**.
- Наприклад, запуск `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, а потім читання номера успадкованого FD у дочірньому процесі давали змогу довільно записувати у файли, власником яких був root; `fcntl(fd, F_SETFL, 0)` навіть скидав `O_APPEND`, дозволяючи перезаписувати дані, а не дописувати їх.

Така сама схема трапляється, коли привілейований процес відкриває файл **до** виконання через `exec` того, що ви контролюєте (допоміжні інструменти, редактори в стилі `crontab`, запущені через `$EDITOR`, файли журналів/налагодження, відкриті зі шляху в змінній середовища...). Перелічіть успадковані FD за допомогою:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Будь-який файловий дескриптор із номером понад `2`, який вказує на файл, який ви не можете відкрити самостійно, є примітивом довільного запису (або довільного читання).

## Уникайте трюків із quarantine xattrs

### Видаліть його

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### прапорець uchg / uchange / uimmutable

Якщо файл/папка має цей атрибут незмінності, додати до нього xattr буде неможливо.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Файлові системи без підтримки xattr

Не кожна файлова система, яку macOS може підключити, нативно зберігає **розширені атрибути**. HFS+ і APFS це вміють; **FAT32, exFAT і (більшість) підключень NFS — ні**: macOS емулює їх, записуючи допоміжний файл **AppleDouble** з назвою `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Це важливо для карантину, оскільки xattr зберігається лише тоді, коли його справді можна **записати й прочитати назад** із того самого тому:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Якщо пізніше прочитати том через шлях, який ігнорує супутній файл `._` (або супутній файл буде видалено), файл надійде **без прапорця quarantine** — а відсутності quarantine у `.app` достатньо, щоб обійти App Sandbox, як описано в [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### Поведінка writeextattr ACL і AppleDouble quarantine

Приклад ACL `writeextattr`, механізм AppleDouble `com.apple.acl.text`, а також кроки зі створення та перевірки sidecar-файла описано в [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Обхід перевірок підпису

### Обхід перевірок platform binaries

Деякі перевірки з’ясовують, чи є binary **platform binary**, наприклад, щоб дозволити підключення до XPC service. Однак, як показано в описі обходу на https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, цю перевірку можна обійти, отримавши platform binary (наприклад, /bin/ls) і впровадивши exploit через dyld за допомогою змінної середовища `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

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



## Обхід підписів коду

У bundle є файл **`_CodeSignature/CodeResources`**, який містить **хеш** кожного **файлу** в **bundle**. Зверніть увагу, що хеш CodeResources також **вбудований у виконуваний файл**, тож змінити його теж не можна.

Однак є файли, підпис яких не перевірятиметься. Для них у plist є ключ omit, наприклад:

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

Можна обчислити підпис ресурсу за допомогою командного рядка:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Монтування dmg-файлів

Користувач може змонтувати власний dmg, навіть поверх деяких наявних папок. Ось як можна створити власний пакет dmg із власним вмістом:

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

Зазвичай macOS монтує диски, взаємодіючи зі службою Mach `com.apple.DiskArbitrarion.diskarbitrariond` (яку надає `/usr/libexec/diskarbitrationd`). Якщо додати параметр `-d` до файлу plist у LaunchDaemons і перезапустити службу, журнали зберігатимуться у `/var/log/diskarbitrationd.log`.\
Однак можна використовувати такі інструменти, як `hdik` і `hdiutil`, щоб взаємодіяти безпосередньо з kext `com.apple.driver.DiskImages`.

## Довільний запис

### Періодичні sh-скрипти

Якщо ваш скрипт можна інтерпретувати як **shell script**, ви можете перезаписати shell script **`/etc/periodic/daily/999.local`**, який запускатиметься щодня.

Ви можете **імітувати** запуск цього скрипту за допомогою: **`sudo periodic daily`**

### Демони

Створіть довільний **LaunchDaemon**, наприклад **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, із plist-файлом, який запускає довільний скрипт, наприклад:

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

Якщо у вас є **довільний запис**, ви можете створити файл у каталозі **`/etc/sudoers.d/`**, щоб надати собі привілеї **sudo**.

### Файли PATH

Файл **`/etc/paths`** — одне з основних місць, звідки заповнюється змінна середовища PATH. Щоб перезаписати його, потрібні права root, але якщо скрипт **привілейованого процесу** виконує якусь **команду без повного шляху**, можливо, ви зможете її **перехопити**, змінивши цей файл.

Ви також можете записувати файли в **`/etc/paths.d`**, щоб додавати нові каталоги до змінної середовища `PATH`.

### cups-files.conf

Цю техніку використали в [цьому writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Створіть файл `/etc/cups/cups-files.conf` із таким вмістом:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Це створить файл `/etc/sudoers.d/lpe` з правами 777. Зайвий текст у кінці потрібен, щоб спровокувати створення журналу помилок.

Потім запишіть у `/etc/sudoers.d/lpe` потрібну конфігурацію для підвищення привілеїв, наприклад `%staff ALL=(ALL) NOPASSWD:ALL`.

Потім знову змініть файл `/etc/cups/cups-files.conf`, задавши `LogFilePerm 700`, щоб новий файл sudoers став дійсним після виклику `cupsctl`.

### Вихід із sandbox

За допомогою довільного запису у FS можна вийти із sandbox macOS. Приклади наведено на сторінці [macOS Auto Start](../../../../macos-auto-start-locations.md), але поширений спосіб — записати файл налаштувань Terminal у `~/Library/Preferences/com.apple.Terminal.plist`, який виконує команду під час запуску, а потім викликати його за допомогою `open`.

## Створення файлів, доступних для запису, від імені інших користувачів

Дуже поширений примітив privesc — змусити **привілейований процес створити для вас файл** у каталозі, який ви контролюєте, а потім зберегти **доступ на запис** до цього файлу. Для цього потрібні дві умови:

1. Каталог, власником якого ви є (або в якому можна встановити **ACL зі спадкуванням**), щоб будь-який створений у ньому об’єкт успадковував ваші дозволи.
2. Привілейований процес або процес із `suid`, якому можна вказати, **де** створити файл — зазвичай за допомогою змінної середовища для налагодження/журналювання, конфігураційного файла або XPC API допоміжного процесу.

Саме **ACL зі спадкуванням** дає змогу записувати у створений файл, навіть якщо його власником є інший користувач. Прапорці спадкування `file_inherit` / `directory_inherit` описано в [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Тепер будь-який файл, створений привілейованим процесом у `$DIRNAME`, **доступний для запису вам**. Якщо цей каталог також є місцем, звідки файли згодом **виконуються від імені root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, каталог LaunchDaemon...), це прямий шлях до ескалації привілеїв до root. Див. розділи [Sudoers File](#sudoers-file) і [cups-files.conf](#cups-filesconf) вище, щоб дізнатися, що записати у файл, коли отримаєте до нього доступ.

Повний приклад ланцюжка «змінна середовища змушує процес root створити файл, а FD витікає до вас» див. у розділі [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) вище.

## Спільна пам’ять POSIX

**Спільна пам’ять POSIX** дає змогу процесам в операційних системах, сумісних із POSIX, отримувати доступ до спільної ділянки пам’яті, забезпечуючи швидший обмін даними порівняно з іншими способами міжпроцесної взаємодії. Для цього спільний об’єкт пам’яті створюють або відкривають за допомогою `shm_open()`, задають його розмір за допомогою `ftruncate()` і відображають у адресний простір процесу за допомогою `mmap()`. Після цього процеси можуть безпосередньо читати з цієї ділянки пам’яті та записувати в неї. Для керування одночасним доступом і запобігання пошкодженню даних часто використовують механізми синхронізації, як-от mutex або семафори. Насамкінець процеси скасовують відображення спільної пам’яті та закривають її за допомогою `munmap()` і `close()`, а також за потреби видаляють об’єкт пам’яті за допомогою `shm_unlink()`. Ця система особливо ефективна для швидкої IPC у середовищах, де кільком процесам потрібно оперативно отримувати доступ до спільних даних.

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

## Захищені дескриптори macOS

**Захищені дескриптори macOS** — це функція безпеки, запроваджена в macOS для підвищення безпеки та надійності **операцій із файловими дескрипторами** в користувацьких програмах. Ці захищені дескриптори дають змогу пов’язувати з файловими дескрипторами певні обмеження або «захисти», які забезпечує ядро.

Ця функція особливо корисна для запобігання певним класам вразливостей безпеки, як-от **несанкціонований доступ до файлів** або **перегони**. Такі вразливості виникають, наприклад, коли потік звертається до опису файлу, надаючи **іншому вразливому потоку доступ до нього**, або коли файловий дескриптор **успадковує** вразливий дочірній процес. Деякі функції, пов’язані з цією можливістю:

- `guarded_open_np`: Відкриває файловий дескриптор із захистом
- `guarded_close_np`: Закриває його
- `change_fdguard_np`: Змінює прапорці захисту дескриптора (навіть знімаючи захист)

## References

- [1] [POSIX.1-2024 — Основні визначення, розд. 4 (права доступу до файлів, захист каталогів, розв’язання шляхів)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` сторінка довідки](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` сторінка довідки](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins — локальне підвищення привілеїв через DYLD_PRINT_TO_FILE в OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company — Які файлові системи та хмарні сервіси зберігають розширені атрибути?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) — Нова ера обходів macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji — Виявлення вразливостей Apple: аудит diskarbitrationd і storagekitd, частина 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
