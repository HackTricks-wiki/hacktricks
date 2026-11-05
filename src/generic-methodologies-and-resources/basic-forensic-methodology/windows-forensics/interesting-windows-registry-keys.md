# Interesujące klucze rejestru Windows

{{#include ../../../banners/hacktricks-training.md}}

Hives rejestru Windows to jeden z najszybszych sposobów, by przejść od pytania _co się stało?_ do ustalenia _który użytkownik, kiedy i skąd?_. Podczas analizy na żywo preferuj `CurrentControlSet`; w przypadku analizy offline hive najpierw ustal, który `ControlSet00x` był aktywny, zamiast na sztywno zakładać `ControlSet001`.

### Informacje o wersji Windows i właścicielu

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edycja/kompilacja systemu Windows, czas instalacji, zarejestrowany właściciel, nazwa produktu i inne metadane kompilacji.
- `SYSTEM\Select`: mapuje wartości `Current`, `Default` i `LastKnownGood` na rzeczywiste wartości `ControlSet00x` używane przez system.

### Nazwa komputera

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: bieżąca nazwa hosta.

### Ustawienia strefy czasowej

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: skonfigurowana strefa czasowa i wartości związane z DST.

### Śledzenie czasu dostępu

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` wskazuje, czy aktualizowane są znaczniki czasu ostatniego dostępu NTFS.
- Aby to włączyć, użyj: `fsutil behavior set disablelastaccess 0`

### Szczegóły zamknięcia systemu

- `SYSTEM\CurrentControlSet\Control\Windows`: czas ostatniego zamknięcia systemu.
- Starsze systemy mogą również udostępniać liczniki zamknięć w `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Konfiguracja sieci

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: adresy IP interfejsu, dzierżawy DHCP, brama i dane DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nazwa profilu sieciowego/SSID oraz czasy pierwszego i ostatniego połączenia.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: dane korelacyjne profilu, takie jak adres MAC bramy i sufiks DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalne foldery udostępnione przez hosta.

### Historia dostępu zdalnego i udziałów sieciowych

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU wychodzących połączeń RDP (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia wychodzących połączeń RDP dla poszczególnych hostów. Podklucze często przechowują `UsernameHint`, a czas `LastWrite` klucza to przydatny punkt odniesienia.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: zmapowane dyski sieciowe, udziały UNC i punkty montowania nośników wymiennych powiązane z konkretnym użytkownikiem.

### Programy uruchamiane automatycznie i zaplanowana persystencja

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metadane zaplanowanych zadań. Jeśli zadanie istnieje tutaj, ale brakuje wartości `SD` w `Tree\<TaskName>`, podejrzewaj ukryte manipulacje zadaniami w stylu Tarrask i skoreluj je z `C:\Windows\System32\Tasks\<TaskName>`.

### Wyszukiwania, wpisane ścieżki i MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: wyszukiwane frazy w Eksploratorze plików.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: ścieżki ręcznie wpisane w Eksploratorze.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: ostatnie 26 poleceń uruchomionych za pomocą `Win + R`. `MRUList` zachowuje ich kolejność.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ostatnio otwierane dokumenty i foldery.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: ostatnio używane pliki pakietu Office.

### Śledzenie aktywności użytkownika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia uruchomień z interfejsu graficznego. Nazwy wartości są zakodowane za pomocą ROT13, a dane binarne zawierają liczniki uruchomień i czas ostatniego uruchomienia.<sup>[[1]](#references)</sup>
- Traktuj `UserAssist` jako mocne dowody pomocnicze, a nie samodzielną podstawę do oceny: śledzi głównie aplikacje lub pliki `.lnk` uruchamiane przez Eksplorator i może nie odnotowywać uruchomień z wiersza poleceń lub usług. W systemie Windows 10 i nowszych niektóre wpisy nie muszą oznaczać, że proces faktycznie się uruchomił.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: ślady uruchomień w nowoczesnych systemach Windows 10/11 z przypisaniem do SID i czasem ostatniego uruchomienia. Są szczególnie przydatne w przypadku plików binarnych uruchamianych lokalnie, ale starsze wpisy mogą szybko znikać, a dane o uruchomieniach z udziałów sieciowych/nośników wymiennych są mniej wiarygodne.
- Więcej informacji o artefaktach uruchamiania, takich jak Prefetch, Amcache, ShimCache i SRUM, znajdziesz w głównym [omówieniu analizy śledczej systemu Windows](./#programs-executed).

### Shellbags

- Shellbags są przechowywane zarówno w `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`, jak i w `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Wpisy `NTUSER.DAT` są szczególnie przydatne przy przeglądaniu UNC/sieci, natomiast w systemie Windows Vista i nowszych Shellbags dotyczące folderów lokalnych/nośników wymiennych są zazwyczaj przechowywane w `UsrClass.dat`.
- Mogą wskazywać istnienie folderu, nawigowanie po nim i preferencje widoku folderu, nawet po jego usunięciu. Dostęp do plików archiwów za pomocą Eksploratora lub podobnych narzędzi może również pozostawić ślady Shellbags.<sup>[[1]](#references)</sup>
- Nie każdy Shellbag dowodzi, że dostęp do folderu zakończył się powodzeniem, dlatego potwierdź ustalenia za pomocą plików LNK, Jump Lists, znaczników czasu lub mapowań woluminów.
- Użyj **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** lub **SBECmd**, aby je przeanalizować.

### Informacje o USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: podstawowy wykaz urządzeń pamięci masowej USB (producent, produkt, wersja, numer seryjny/instancja urządzenia).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: szerszy wykaz urządzeń USB, także tych, które nie służą do przechowywania danych.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: w nowszych kompilacjach Windows 10/11 to cenne miejsce z sygnaturami czasowymi cyklu życia poszczególnych urządzeń, takimi jak instalacja, pierwsza instalacja, ostatnie podłączenie i ostatnie odłączenie.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: mapuje woluminy i identyfikatory urządzeń na litery dysków / GUID-y woluminów. Dla danej litery dysku może przetrwać tylko ostatnie mapowanie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: przydatny punkt odniesienia dla numerów seryjnych woluminów i metadanych poprzednio używanych nośników.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia interakcji konkretnego użytkownika z literami dysków i udziałami.<sup>[[2]](#references)</sup>
- Nowoczesne telefony i tablety podłączone przez MTP/PTP mogą **nie** pojawić się w `USBSTOR`. Sprawdź również `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` i `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Aby powiązać urządzenie z użytkownikiem, przejdź od identyfikatorów urządzenia lub woluminu do artefaktów poszczególnych użytkowników, takich jak Shellbags, pliki LNK, Jump Lists, `RecentDocs` i `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
