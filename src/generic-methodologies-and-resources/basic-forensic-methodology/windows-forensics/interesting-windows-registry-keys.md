# Цікаві ключі реєстру Windows

{{#include ../../../banners/hacktricks-training.md}}

Кущі реєстру Windows є одним із найшвидших способів перейти від питання _що сталося?_ до питань _який користувач, коли і звідки?_. Для аналізу запущеної системи надавайте перевагу `CurrentControlSet`; під час аналізу автономного куща спочатку визначте, який `ControlSet00x` був активним, замість жорстко задавати `ControlSet001`.

### Версія Windows та інформація про власника

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: редакція/збірка Windows, час інсталяції, зареєстрований власник, назва продукту та інші метадані збірки.
- `SYSTEM\Select`: зіставляє `Current`, `Default` і `LastKnownGood` із фактичними значеннями `ControlSet00x`, які використовує система.

### Ім'я комп'ютера

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: поточне ім'я хоста.

### Налаштування часового поясу

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: налаштований часовий пояс і значення, пов'язані з переходом на літній час.

### Відстеження часу доступу

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` вказує, чи оновлюються часові мітки останнього доступу NTFS.
- Щоб увімкнути це, використайте: `fsutil behavior set disablelastaccess 0`

### Відомості про завершення роботи

- `SYSTEM\CurrentControlSet\Control\Windows`: час останнього завершення роботи.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: старіші системи також можуть містити лічильники завершення роботи.

### Конфігурація мережі

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP-адреси інтерфейсу, DHCP-оренди, дані шлюзу та DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: назва мережевого профілю/SSID, а також час першого й останнього підключення.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` і `...\Unmanaged\{GUID}`: дані для зіставлення профілю, як-от MAC-адреса шлюзу та DNS-суфікс.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: локальні спільні папки, опубліковані хостом.

### Історія віддаленого доступу та мережевих спільних ресурсів

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: список вихідних RDP MRU (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: історія вихідних RDP-підключень для окремих хостів. Підрозділи зазвичай містять `UsernameHint`, а час `LastWrite` ключа є корисною точкою для подальшого аналізу.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: підключені мережеві диски, UNC-спільні ресурси та точки підключення змінних носіїв, пов'язані з конкретним користувачем.

### Програми, що запускаються автоматично, та заплановане закріплення

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` і `...\Tasks\{GUID}`: метадані запланованих завдань. Якщо завдання існує тут, але значення `SD` відсутнє в `Tree\<TaskName>`, припускайте приховане втручання в завдання за схемою Tarrask і зіставте це з `C:\Windows\System32\Tasks\<TaskName>`.

### Пошукові запити, введені шляхи та MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: пошукові терміни File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: шляхи Explorer, введені вручну.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: останні 26 команд `Win + R`. `MRUList` зберігає їхній порядок.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: нещодавно відкриті документи й папки.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: нещодавні файли Office.

### Відстеження активності користувача

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: історія запуску через GUI. Назви значень закодовані за допомогою ROT13, а двійкові дані містять лічильники запусків і час останнього запуску.<sup>[[1]](#references)</sup>
- Розглядайте `UserAssist` як вагомий допоміжний доказ, а не як самостійний остаточний висновок: він переважно відстежує програми або `.lnk`-файли, запущені через Explorer, і може не фіксувати виконання з командного рядка або службами. У Windows 10+ деякі записи не обов'язково означають, що процес повністю виконався.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` і `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: сучасні сліди виконання у Windows 10/11 із прив'язкою до SID і часом останнього виконання. Вони особливо корисні для бінарних файлів, запущених локально, але старі записи можуть швидко видалятися, а дані про виконання з мережевих спільних ресурсів/змінних носіїв є менш надійними.
- Щоб отримати ширший набір артефактів виконання, як-от Prefetch, Amcache, ShimCache і SRUM, дивіться основний [огляд форензики Windows](README.md#programs-executed).

### Shellbags

- Shellbags зберігаються і в `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, і в `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Записи `NTUSER.DAT` особливо корисні для перегляду UNC/мережевих ресурсів, тоді як `UsrClass.dat` — це місце, де Windows Vista+ зазвичай зберігає shellbags локальних папок і папок на змінних носіях.
- Вони можуть показувати існування папки, навігацію нею та налаштування її перегляду навіть після видалення папки. Доступ до архівних файлів через Explorer також може залишати сліди shellbags.<sup>[[1]](#references)</sup>
- Не кожен shellbag доводить успішний доступ до папки, тому підтверджуйте дані за допомогою LNK, Jump Lists, часових міток або зіставлень томів.
- Використовуйте **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** або **SBECmd** для їхнього аналізу.

### Інформація про USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: основний перелік USB-пристроїв масової пам'яті (виробник, продукт, версія, серійний номер/екземпляр пристрою).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ширший перелік USB-пристроїв, зокрема пристроїв, що не є накопичувачами.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: у нових збірках Windows 10/11 це важливе місце для часових міток життєвого циклу окремого пристрою, як-от час інсталяції, першої інсталяції, останнього підключення та останнього від'єднання.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: зіставляє томи та ідентифікатори пристроїв із літерами дисків / GUID томів. Для певної літери диска може зберегтися лише останнє зіставлення.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: корисна точка для подальшого аналізу серійних номерів томів і метаданих попередніх носіїв.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: історія взаємодії конкретного користувача з літерами дисків і спільними ресурсами.<sup>[[2]](#references)</sup>
- Сучасні телефони та планшети, підключені через MTP/PTP, можуть **не** відображатися в `USBSTOR`. Також перевіряйте `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` і `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Щоб пов'язати пристрій із користувачем, переходьте від ідентифікаторів пристрою або тому до артефактів конкретного користувача, як-от shellbags, LNK, Jump Lists, `RecentDocs` і `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Шпаргалка з форензики реєстру Windows 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Форензика USB-пристроїв у Windows 10 і 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
