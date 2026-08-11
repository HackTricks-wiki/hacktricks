# Interesujące klucze Rejestru Windows

{{#include ../../../banners/hacktricks-training.md}}

Hives Rejestru Windows to jeden z najszybszych sposobów przejścia od pytania _co się wydarzyło?_ do ustalenia _który użytkownik, kiedy i skąd?_. W przypadku analizy działającego systemu preferuj `CurrentControlSet`; podczas analizy hive offline najpierw ustal, który `ControlSet00x` był aktywny, zamiast wpisywać na sztywno `ControlSet001`.

### Informacje o wersji Windows i właścicielu

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edycja/kompilacja Windows, czas instalacji, zarejestrowany właściciel, nazwa produktu i inne metadane kompilacji.
- `SYSTEM\Select`: mapuje wartości `Current`, `Default` i `LastKnownGood` na rzeczywiste wartości `ControlSet00x` używane przez system.

### Nazwa komputera

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: bieżąca nazwa hosta.

### Ustawienia strefy czasowej

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: skonfigurowana strefa czasowa i wartości związane z DST.

### Śledzenie czasu dostępu

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` wskazuje, czy znaczniki czasu ostatniego dostępu NTFS są aktualizowane.
- Aby to włączyć, użyj: `fsutil behavior set disablelastaccess 0`

### Szczegóły zamykania systemu

- `SYSTEM\CurrentControlSet\Control\Windows`: czas ostatniego zamknięcia systemu.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: starsze systemy mogą również udostępniać liczniki zamknięć systemu.

### Konfiguracja sieci

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: adresy IP interfejsu, dzierżawy DHCP, dane bramy i DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nazwa profilu sieciowego/SSID oraz czas pierwszego i ostatniego połączenia.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` oraz `...\Unmanaged\{GUID}`: dane korelacji profilu, takie jak adres MAC bramy i sufiks DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalne foldery współdzielone publikowane przez hosta.

### Zdalny dostęp i historia udziałów sieciowych

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: wychodząca lista MRU RDP (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia wychodzących połączeń RDP dla poszczególnych hostów. Podklucze zwykle przechowują `UsernameHint`, a czas `LastWrite` klucza jest użytecznym punktem odniesienia.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapowane dyski sieciowe, udziały UNC i punkty montowania nośników wymiennych powiązane z konkretnym użytkownikiem.

### Programy uruchamiane automatycznie i zaplanowana persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` oraz `...\Tasks\{GUID}`: metadane zaplanowanych zadań. Jeśli zadanie istnieje tutaj, ale wartość `SD` nie występuje w `Tree\<TaskName>`, podejrzewaj ukryte manipulacje zadaniami w stylu Tarrask i skoreluj je z `C:\Windows\System32\Tasks\<TaskName>`.

### Wyszukiwania, wpisywane ścieżki i MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: wyszukiwane hasła w File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: ścieżki w Explorer wpisane ręcznie.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: ostatnie 26 poleceń `Win + R`. `MRUList` zachowuje ich kolejność.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ostatnio otwierane dokumenty i foldery.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: ostatnie pliki Office.

### Śledzenie aktywności użytkownika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia uruchomień wykonywanych za pośrednictwem GUI. Nazwy wartości są zakodowane za pomocą ROT13, a dane binarne zawierają liczniki uruchomień i czas ostatniego uruchomienia.<sup>[[1]](#references)</sup>
- Traktuj `UserAssist` jako silny dowód pomocniczy, a nie samodzielną podstawę wnioskowania: śledzi głównie aplikacje lub pliki `.lnk` uruchamiane przez Explorer i może pomijać wykonanie z wiersza poleceń lub przez usługę. W Windows 10+ niektóre wpisy nie muszą oznaczać, że proces faktycznie został w pełni wykonany.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` oraz `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: ślady wykonania w nowszych wersjach Windows 10/11 z przypisaniem SID i czasem ostatniego wykonania. Są szczególnie przydatne dla plików binarnych wykonywanych lokalnie, ale starsze wpisy mogą szybko wygasać, a wykonanie z udziałów sieciowych/nośników wymiennych jest mniej wiarygodne.
- W przypadku szerszych artefaktów wykonania, takich jak Prefetch, Amcache, ShimCache i SRUM, zobacz główny [przegląd Windows forensics](README.md#programs-executed).

### Shellbags

- Shellbags są przechowywane zarówno w `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, jak i w `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Wpisy `NTUSER.DAT` są szczególnie przydatne do badania przeglądania UNC/sieci, natomiast `UsrClass.dat` jest miejscem, w którym Windows Vista+ zwykle przechowuje shellbags lokalnych folderów i folderów na nośnikach wymiennych.
- Mogą wskazywać istnienie folderu, poruszanie się po nim i preferencje widoku folderu, nawet po usunięciu folderu. Dostęp podobny do działania Explorera do plików archiwów również może pozostawiać ślady shellbags.<sup>[[1]](#references)</sup>
- Nie każdy shellbag dowodzi pomyślnego dostępu do folderu, dlatego potwierdzaj ustalenia za pomocą LNK, Jump Lists, znaczników czasu lub mapowań woluminów.
- Użyj **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** lub **SBECmd**, aby je przeanalizować.

### Informacje o USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: główny inwentarz urządzeń pamięci masowej USB (producent, produkt, wersja, numer seryjny/instancja urządzenia).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: szerszy inwentarz urządzeń USB, obejmujący również urządzenia niebędące nośnikami danych.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: w nowszych kompilacjach Windows 10/11 jest to cenne miejsce zawierające znaczniki czasu cyklu życia poszczególnych urządzeń, takie jak czas instalacji, pierwszej instalacji, ostatniego podłączenia i ostatniego odłączenia.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: mapuje woluminy i identyfikatory urządzeń na litery dysków / GUID-y woluminów. Może przetrwać tylko ostatnie mapowanie dla danej litery dysku.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: przydatny punkt odniesienia dla numerów seryjnych woluminów i metadanych wcześniejszych nośników.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: specyficzna dla użytkownika historia interakcji z literami dysków i udziałami.<sup>[[2]](#references)</sup>
- Nowoczesne telefony i tablety podłączone za pomocą MTP/PTP mogą **nie** pojawiać się w `USBSTOR`. Sprawdź również `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` oraz `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Aby powiązać urządzenie z użytkownikiem, przejdź od identyfikatorów urządzenia lub woluminu do artefaktów właściwych dla użytkownika, takich jak shellbags, LNK, Jump Lists, `RecentDocs` i `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
