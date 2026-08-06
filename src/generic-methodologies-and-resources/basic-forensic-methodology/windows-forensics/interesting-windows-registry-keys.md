# Цікаві ключі реєстру Windows

{{#include ../../../banners/hacktricks-training.md}}

Кущі реєстру Windows — один із найшвидших способів перейти від _що сталося?_ до _який користувач, коли та звідки?_. Для live-аналізу надавайте перевагу `CurrentControlSet`; під час offline-аналізу куща спочатку визначте, який `ControlSet00x` був активним, замість жорстко задавати `ControlSet001`.

### Версія Windows та інформація про власника

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: редакція/збірка Windows, час встановлення, зареєстрований власник, назва продукту та інші метадані збірки.
- `SYSTEM\Select`: зіставляє `Current`, `Default` і `LastKnownGood` із фактичними значеннями `ControlSet00x`, які використовувала система.

### Ім'я комп'ютера

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: поточне hostname.

### Налаштування часового поясу

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: налаштований часовий пояс і значення, пов'язані з DST.

### Відстеження часу доступу

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` вказує, чи оновлюються часові мітки останнього доступу NTFS.
- Щоб увімкнути його, використайте: `fsutil behavior set disablelastaccess 0`

### Відомості про вимкнення

- `SYSTEM\CurrentControlSet\Control\Windows`: час останнього вимкнення.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: старіші системи також можуть містити лічильники вимкнень.

### Конфігурація мережі

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP-адреси інтерфейсу, DHCP leases, дані шлюзу та DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: назва мережевого профілю/SSID, а також час першого й останнього підключення.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` і `...\Unmanaged\{GUID}`: дані для кореляції профілю, як-от MAC-адреса шлюзу та DNS-суфікс.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: локальні спільні папки, опубліковані host.

### Історія віддаленого доступу та мережевих share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: вихідний список RDP MRU (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: історія вихідних RDP-підключень для окремих host. Підрозділи зазвичай містять `UsernameHint`, а час `LastWrite` ключа є корисною точкою для pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: підключені мережеві диски, UNC shares і точки підключення змінних носіїв, пов'язані з конкретним користувачем.

### Програми, які запускаються автоматично, та Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` і `...\Tasks\{GUID}`: метадані scheduled task. Якщо task існує тут, але значення `SD` відсутнє в `Tree\<TaskName>`, підозрюйте приховане втручання в task за стилем Tarrask і зіставте його з `C:\Windows\System32\Tasks\<TaskName>`.

### Пошукові запити, введені шляхи та MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: пошукові запити File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: шляхи Explorer, введені вручну.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: останні 26 команд `Win + R`. `MRUList` зберігає їхній порядок.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: нещодавно відкриті документи та папки.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: нещодавні файли Office.

### Відстеження активності користувача

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: історія запусків через GUI. Назви значень закодовані за допомогою ROT13, а бінарні дані містять лічильники запусків і час останнього запуску.<sup>[[1]](#references)</sup>
- Розглядайте `UserAssist` як вагомий допоміжний доказ, а не як самостійний вердикт: він переважно відстежує програми або `.lnk`-файли, запущені через Explorer, і може пропускати виконання через командний рядок або service. У Windows 10+ деякі записи не обов'язково означають, що process повністю виконався.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` і `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: traces виконання в сучасних Windows 10/11 із прив'язкою до SID і часом останнього виконання. Вони особливо корисні для локально виконаних бінарних файлів, але старі записи можуть швидко видалятися, а дані про виконання з мережевих shares/змінних носіїв є менш надійними.
- Ширший огляд артефактів виконання, як-от Prefetch, Amcache, ShimCache і SRUM, наведено в основному [огляді Windows forensics](README.md#programs-executed).

### Shellbags

- Shellbags зберігаються і в `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, і в `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Записи `NTUSER.DAT` особливо корисні для перегляду UNC/мережевих шляхів, тоді як `UsrClass.dat` — це місце, де Windows Vista+ зазвичай зберігає Shellbags локальних папок і папок на змінних носіях.
- Вони можуть показувати існування папки, навігацію та налаштування її вигляду навіть після видалення папки. Доступ до archive-файлів через Explorer-подібні засоби також може залишати traces Shellbags.<sup>[[1]](#references)</sup>
- Не кожен Shellbag доводить успішний доступ до папки, тому підтверджуйте дані за допомогою LNK, Jump Lists, часових міток або зіставлення томів.
- Використовуйте **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** або **SBECmd** для їхнього парсингу.

### Інформація про USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: основний inventory USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ширший inventory USB-пристроїв, зокрема пристроїв, що не є storage-пристроями.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: у сучасних збірках Windows 10/11 це цінне місце для часових міток життєвого циклу окремого пристрою, як-от встановлення, перше встановлення, остання поява та останнє вилучення.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: зіставляє томи та ідентифікатори пристроїв із літерами дисків / GUID томів. Для певної літери диска може зберегтися лише останнє зіставлення.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: корисна точка для pivot до серійних номерів томів і попередніх метаданих носіїв.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: історія взаємодії конкретного користувача з літерами дисків і shares.<sup>[[2]](#references)</sup>
- Сучасні телефони та планшети, підключені через MTP/PTP, можуть **не** відображатися в `USBSTOR`. Також перевіряйте `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` і `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Щоб пов'язати пристрій із користувачем, виконайте pivot від ідентифікаторів пристрою або тому до per-user артефактів, як-от Shellbags, LNK, Jump Lists, `RecentDocs` і `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
