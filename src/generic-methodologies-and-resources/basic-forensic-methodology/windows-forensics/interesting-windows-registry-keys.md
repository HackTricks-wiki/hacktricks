# Interesujące klucze rejestru Windows

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives to jeden z najszybszych sposobów przejścia od _co się stało?_ do _który użytkownik, kiedy i skąd?_. Do analizy na żywo preferuj `CurrentControlSet`; przy analizie offline najpierw ustal, który `ControlSet00x` był aktywny, zamiast hardcodować `ControlSet001`.

### Wersja Windows i informacje o właścicielu

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edycja/build Windows, czas instalacji, zarejestrowany właściciel, nazwa produktu i inne metadane builda.
- `SYSTEM\Select`: mapuje `Current`, `Default` i `LastKnownGood` na rzeczywiste wartości `ControlSet00x` używane przez system.

### Nazwa komputera

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: bieżąca nazwa hosta.

### Ustawienia strefy czasowej

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: skonfigurowana strefa czasowa i wartości związane z DST.

### Śledzenie czasu dostępu

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` wskazuje, czy znaczniki czasu ostatniego dostępu NTFS są aktualizowane.
- Aby to włączyć, użyj: `fsutil behavior set disablelastaccess 0`

### Szczegóły zamknięcia systemu

- `SYSTEM\CurrentControlSet\Control\Windows`: czas ostatniego zamknięcia systemu.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: starsze systemy mogą też ujawniać liczniki zamknięcia systemu.

### Konfiguracja sieci

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: adresy IP interfejsu, dzierżawy DHCP, brama i dane DNS.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nazwa profilu sieci/SSID oraz czasy pierwszego i ostatniego połączenia.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: dane korelacyjne profilu, takie jak adres MAC bramy i sufiks DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalne udostępnione foldery opublikowane przez hosta.

### Zdalny dostęp i historia udostępnień sieciowych

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: wychodząca lista RDP MRU (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia wychodzących połączeń RDP per host. Podklucze często przechowują `UsernameHint`, a czas `LastWrite` klucza jest przydatnym punktem pivotu.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: zamapowane dyski sieciowe, udziały UNC i punkty montowania nośników wymiennych powiązane z konkretnym użytkownikiem.

### Programy uruchamiane automatycznie i zaplanowana trwałość

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metadane zaplanowanych zadań. Jeśli zadanie istnieje tutaj, ale wartość `SD` jest brakująca w `Tree\<TaskName>`, podejrzewaj ukrytą manipulację zadaniem w stylu Tarrask i skoreluj to z `C:\Windows\System32\Tasks\<TaskName>`.

### Wyszukiwania, wpisane ścieżki i MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: wyszukiwane hasła w File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: ręcznie wpisane ścieżki w Explorerze.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: ostatnie 26 poleceń `Win + R`. `MRUList` zachowuje ich kolejność.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ostatnio otwierane dokumenty i foldery.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: ostatnie pliki Office.

### Śledzenie aktywności użytkownika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia uruchomień z GUI. Nazwy wartości są kodowane w ROT13, a dane binarne zawierają liczniki uruchomień i czas ostatniego uruchomienia.
- Traktuj `UserAssist` jako mocny materiał pomocniczy, a nie samodzielny werdykt: śledzi głównie aplikacje lub pliki `.lnk` uruchamiane przez Explorer i może nie uwzględniać uruchomień z linii poleceń lub przez usługę. W Windows 10+ niektóre wpisy nie muszą oznaczać, że proces faktycznie zakończył pełne uruchomienie.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: nowoczesne ślady wykonania w Windows 10/11 z przypisaniem do SID i czasem ostatniego uruchomienia. Są szczególnie przydatne dla lokalnie uruchamianych binarek, ale starsze wpisy mogą szybko wygasać, a uruchomienia z udziałów sieciowych/nośników wymiennych są mniej wiarygodne.
- Dla szerszych artefaktów wykonania, takich jak Prefetch, Amcache, ShimCache i SRUM, zobacz główny [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags są przechowywane zarówno w `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, jak i w `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Wpisy z `NTUSER.DAT` są szczególnie przydatne dla przeglądania UNC/sieci, natomiast `UsrClass.dat` to miejsce, gdzie Windows Vista+ zwykle przechowuje shellbags lokalnych folderów i folderów na nośnikach wymiennych.
- Mogą pokazać istnienie folderu, jego przeglądanie i preferencje widoku folderu nawet po usunięciu folderu. Dostęp w stylu Explorer do plików archiwów również może zostawić ślady shellbag.
- Nie każdy shellbag dowodzi udanego dostępu do folderu, więc potwierdzaj to z LNKs, Jump Lists, timestampami lub mapowaniami wolumenów.
- Użyj **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** lub **SBECmd**, aby je sparsować.

### Informacje o USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: podstawowy spis urządzeń masowej pamięci USB (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: szerszy spis urządzeń USB, w tym urządzeń innych niż storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: na nowszych buildach Windows 10/11 to miejsce o wysokiej wartości dla znaczników czasu cyklu życia per urządzenie, takich jak install, first install, last arrival i last removal.
- `HKLM\SYSTEM\MountedDevices`: mapuje wolumeny i identyfikatory urządzeń na litery dysków / GUID wolumenów. Może przetrwać tylko ostatnie mapowanie dla danej litery dysku.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: przydatny punkt pivotu dla numerów seryjnych wolumenów i metadanych wcześniejszych nośników.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia interakcji użytkownika z literami dysków i udziałami.
- Nowoczesne telefony i tablety podłączane przez MTP/PTP mogą **nie** pojawić się w `USBSTOR`. Sprawdź też `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` oraz `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Aby powiązać urządzenie z użytkownikiem, przejdź od identyfikatorów urządzenia lub wolumenu do artefaktów per-user, takich jak shellbags, LNKs, Jump Lists, `RecentDocs` i `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
