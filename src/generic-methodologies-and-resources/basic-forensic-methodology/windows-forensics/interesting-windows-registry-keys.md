# Interesujące klucze rejestru Windows

{{#include ../../../banners/hacktricks-training.md}}

Ule rejestru Windows są jednym z najszybszych sposobów przejścia od _co się wydarzyło?_ do _który użytkownik, kiedy i skąd?_. W przypadku analizy systemu na żywo preferuj `CurrentControlSet`; podczas analizy offline najpierw ustal, który `ControlSet00x` był aktywny, zamiast zakładać `ControlSet001`.

### Informacje o wersji Windows i właścicielu

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edycja/kompilacja Windows, czas instalacji, zarejestrowany właściciel, nazwa produktu i inne metadane kompilacji.
- `SYSTEM\Select`: mapuje `Current`, `Default` i `LastKnownGood` na rzeczywiste wartości `ControlSet00x` używane przez system.

### Nazwa komputera

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: bieżąca nazwa hosta.

### Ustawienia strefy czasowej

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: skonfigurowana strefa czasowa i wartości związane z DST.

### Śledzenie czasu dostępu

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` wskazuje, czy znaczniki czasu ostatniego dostępu NTFS są aktualizowane.
- Aby je włączyć, użyj: `fsutil behavior set disablelastaccess 0`

### Informacje o wyłączaniu systemu

- `SYSTEM\CurrentControlSet\Control\Windows`: czas ostatniego wyłączenia systemu.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: starsze systemy mogą również udostępniać liczniki wyłączeń.

### Konfiguracja sieci

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: adresy IP interfejsu, dzierżawy DHCP, dane bramy i DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nazwa profilu sieciowego/SSID oraz czasy pierwszego i ostatniego połączenia.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: dane korelacyjne profilu, takie jak adres MAC bramy i sufiks DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalne foldery udostępnione przez hosta.

### Historia zdalnego dostępu i udziałów sieciowych

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: wychodząca lista MRU RDP (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia wychodzących połączeń RDP dla poszczególnych hostów. Podklucze zwykle przechowują `UsernameHint`, a czas `LastWrite` klucza jest przydatnym punktem odniesienia.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapowane dyski sieciowe, udziały UNC i punkty montowania nośników wymiennych powiązane z konkretnym użytkownikiem.

### Programy uruchamiane automatycznie i zaplanowana persystencja

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metadane zadań zaplanowanych. Jeśli zadanie istnieje tutaj, ale wartość `SD` jest nieobecna w `Tree\<TaskName>`, podejrzewaj ukryte manipulowanie zadaniami w stylu Tarrask i skoreluj je z `C:\Windows\System32\Tasks\<TaskName>`.

### Wyszukiwania, wpisywane ścieżki i MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: wyszukiwane hasła w Eksploratorze plików.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: ręcznie wpisywane ścieżki Eksploratora.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: ostatnie 26 poleceń `Win + R`. `MRUList` zachowuje ich kolejność.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ostatnio otwierane dokumenty i foldery.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: ostatnio używane pliki Office.

### Śledzenie aktywności użytkownika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia uruchamiania z poziomu GUI. Nazwy wartości są zakodowane za pomocą ROT13, a dane binarne zawierają liczniki uruchomień i czas ostatniego uruchomienia.<sup>[[1]](#references)</sup>
- Traktuj `UserAssist` jako silny dowód pomocniczy, a nie samodzielną podstawę do wyciągania wniosków: śledzi głównie aplikacje lub pliki `.lnk` uruchamiane przez Eksplorator i może pomijać wykonanie z wiersza poleceń lub przez usługę. W systemie Windows 10 i nowszych niektóre wpisy nie muszą oznaczać, że proces rzeczywiście został wykonany.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: współczesne ślady wykonywania w Windows 10/11 z przypisaniem SID i czasem ostatniego wykonania. Są szczególnie przydatne dla plików binarnych wykonywanych lokalnie, ale starsze wpisy mogą szybko wygasać, a wykonanie z udziałów sieciowych/nośników wymiennych jest mniej wiarygodne.
- Informacje o szerszym zakresie artefaktów wykonania, takich jak Prefetch, Amcache, ShimCache i SRUM, znajdziesz w głównym [przeglądzie Windows forensics](README.md#programs-executed).

### Shellbags

- Shellbags są przechowywane zarówno w `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, jak i w `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Wpisy `NTUSER.DAT` są szczególnie przydatne do badania przeglądania ścieżek UNC/sieciowych, natomiast `UsrClass.dat` to miejsce, w którym Windows Vista+ zwykle przechowuje shellbags lokalnych folderów i folderów na nośnikach wymiennych.
- Mogą wskazywać istnienie folderu, poruszanie się po nim i preferencje widoku folderu, nawet po jego usunięciu. Dostęp do plików archiwów za pomocą interfejsu podobnego do Eksploratora również może pozostawić ślady shellbags.<sup>[[1]](#references)</sup>
- Nie każdy shellbag dowodzi pomyślnego dostępu do folderu, dlatego potwierdzaj ustalenia za pomocą plików LNK, Jump Lists, znaczników czasu lub mapowań woluminów.
- Użyj **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** lub **SBECmd**, aby je przeanalizować.

### Informacje o USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: główny spis urządzeń USB pamięci masowej (producent, produkt, wersja, numer seryjny/instancja urządzenia).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: szerszy spis urządzeń USB, obejmujący również urządzenia niebędące pamięcią masową.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: w nowszych kompilacjach Windows 10/11 jest to cenne miejsce do wyszukiwania znaczników czasu cyklu życia poszczególnych urządzeń, takich jak instalacja, pierwsza instalacja, ostatnie podłączenie i ostatnie odłączenie.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: mapuje woluminy i identyfikatory urządzeń na litery dysków / identyfikatory GUID woluminów. Może przetrwać tylko ostatnie mapowanie danej litery dysku.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: przydatny punkt odniesienia dla numerów seryjnych woluminów i metadanych wcześniejszych nośników.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia interakcji konkretnego użytkownika z literami dysków i udziałami.<sup>[[2]](#references)</sup>
- Nowoczesne telefony i tablety połączone przez MTP/PTP mogą **nie** pojawiać się w `USBSTOR`. Sprawdź również `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` oraz `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Aby powiązać urządzenie z użytkownikiem, przejdź od identyfikatorów urządzenia lub woluminu do artefaktów konkretnego użytkownika, takich jak shellbags, pliki LNK, Jump Lists, `RecentDocs` i `MountPoints2`.<sup>[[2]](#references)</sup>

## Referencje

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
