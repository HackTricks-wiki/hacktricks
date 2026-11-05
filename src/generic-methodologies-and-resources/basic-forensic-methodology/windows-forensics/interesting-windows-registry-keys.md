# Цікаві розділи реєстру Windows

{{#include ../../../banners/hacktricks-training.md}}

Розділи реєстру Windows — один із найшвидших способів перейти від запитання _що сталося?_ до запитань _який користувач, коли й звідки?_. Для аналізу запущеної системи використовуйте `CurrentControlSet`; для аналізу автономного розділу спершу з’ясуйте, який `ControlSet00x` був активним, а не використовуйте `ControlSet001` без перевірки.

### Відомості про версію Windows і власника

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: редакція/збірка Windows, час встановлення, зареєстрований власник, назва продукту та інші метадані збірки.
- `SYSTEM\Select`: зіставляє `Current`, `Default` і `LastKnownGood` із фактичними значеннями `ControlSet00x`, які використовувала система.

### Ім’я комп’ютера

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: поточне ім’я хоста.

### Налаштування часового поясу

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: налаштований часовий пояс і значення, пов’язані з переходом на літній час.

### Відстеження часу доступу

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` вказує, чи оновлюються часові позначки останнього доступу NTFS.
- Щоб увімкнути це, виконайте: `fsutil behavior set disablelastaccess 0`

### Відомості про завершення роботи

- `SYSTEM\CurrentControlSet\Control\Windows`: час останнього завершення роботи.
- У старіших системах також можуть бути лічильники завершення роботи в `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Конфігурація мережі

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP-адреси інтерфейсу, DHCP-оренди, шлюз і дані DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: назва профілю мережі/SSID, а також час першого й останнього підключення.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` і `...\Unmanaged\{GUID}`: дані для зіставлення профілів, як-от MAC-адреса шлюзу та суфікс DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: локальні спільні папки, опубліковані хостом.

### Віддалений доступ і історія мережевих ресурсів

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: список MRU вихідних RDP-підключень (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: історія вихідних RDP-підключень для кожного хоста. У підрозділах зазвичай зберігається `UsernameHint`, а час `LastWrite` цього розділу допомагає визначити подальший напрямок пошуку.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: підключені мережеві диски, UNC-ресурси та точки монтування знімних носіїв, пов’язані з конкретним користувачем.

### Програми, що запускаються автоматично, і заплановане закріплення

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` і `...\Tasks\{GUID}`: метадані запланованих завдань. Якщо завдання є тут, але у `Tree\<TaskName>` відсутнє значення `SD`, підозрюйте приховане втручання в завдання на кшталт Tarrask і зіставте дані з `C:\Windows\System32\Tasks\<TaskName>`.

### Пошукові запити, введені шляхи та MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: пошукові запити у Провіднику файлів.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: шляхи, вручну введені у Провіднику.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: останні 26 команд `Win + R`. `MRUList` зберігає їхній порядок.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: нещодавно відкриті документи й папки.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: нещодавно відкриті файли Office.

### Відстеження активності користувача

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: історія запуску через графічний інтерфейс. Назви значень закодовані ROT13, а двійкові дані містять лічильники запусків і час останнього запуску.<sup>[[1]](#references)</sup>
- Розглядайте `UserAssist` як вагомий допоміжний доказ, а не остаточний висновок: він переважно відстежує програми або файли `.lnk`, запущені через Провідник, і може не фіксувати запуск із командного рядка або служб. У Windows 10 і новіших версіях деякі записи не обов’язково означають, що процес справді запустився.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` і `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: сучасні сліди запуску у Windows 10/11 із прив’язкою до SID і часом останнього виконання. Вони особливо корисні для бінарних файлів, запущених локально, але старі записи можуть швидко зникати, а дані про запуск із мережевих ресурсів або знімних носіїв менш надійні.
- Інші артефакти запуску, як-от Prefetch, Amcache, ShimCache і SRUM, описано в основному [огляді комп’ютерної криміналістики Windows](./#programs-executed).

### Shellbags

- Shellbags зберігаються і в `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, і в `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Записи `NTUSER.DAT` особливо корисні для перегляду UNC-ресурсів/мережі, а в `UsrClass.dat` Windows Vista і новіших версій зазвичай зберігає shellbags локальних папок і папок на знімних носіях.
- Вони можуть свідчити про існування папки, навігацію до неї та параметри її подання, навіть після її видалення. Перегляд архівних файлів через Провідник або подібні засоби також може залишати сліди shellbags.<sup>[[1]](#references)</sup>
- Не кожен shellbag доводить успішний доступ до папки, тож перевіряйте його разом із LNK-файлами, Jump Lists, часовими позначками або зіставленнями томів.
- Використовуйте **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** або **SBECmd** для їх аналізу.

### Відомості про USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: основний перелік USB-накопичувачів (виробник, продукт, ревізія, серійний номер/екземпляр пристрою).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ширший перелік USB-пристроїв, зокрема пристроїв, що не є накопичувачами.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: у новіших збірках Windows 10/11 тут часто містяться важливі часові позначки життєвого циклу пристрою, як-от час встановлення, першого встановлення, останнього підключення та останнього від’єднання.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: зіставляє томи та ідентифікатори пристроїв із літерами дисків/ідентифікаторами GUID томів. Для певної літери диска може зберегтися лише останнє зіставлення.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: корисне джерело для пошуку серійних номерів томів і метаданих попередніх носіїв.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: історія взаємодії конкретного користувача з літерами дисків і мережевими ресурсами.<sup>[[2]](#references)</sup>
- Сучасні телефони й планшети, підключені через MTP/PTP, можуть **не** відображатися в `USBSTOR`. Також перевірте `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` і `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Щоб пов’язати пристрій із користувачем, перейдіть від ідентифікаторів пристрою або тому до артефактів конкретного користувача, як-от shellbags, LNK-файлів, Jump Lists, `RecentDocs` і `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Пам’ятка з комп’ютерної криміналістики реєстру Windows, 2026 — Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Комп’ютерна криміналістика USB-пристроїв у Windows 10 і 11 — ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
