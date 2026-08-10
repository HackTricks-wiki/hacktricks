# Zanimljivi Windows Registry ključevi

Windows Registry hive-ovi su jedan od najbržih načina da se pređe sa _šta se dogodilo?_ na _koji korisnik, kada i odakle?_. Za analizu uživo preferirajte `CurrentControlSet`; za offline analizu hive-ova prvo utvrdite koji `ControlSet00x` je bio aktivan, umesto da unapred pretpostavite `ControlSet001`.

### Informacije o Windows verziji i vlasniku

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows izdanje/build, vreme instalacije, registrovani vlasnik, naziv proizvoda i drugi build metapodaci.
- `SYSTEM\Select`: mapira `Current`, `Default` i `LastKnownGood` na stvarne `ControlSet00x` vrednosti koje sistem koristi.

### Naziv računara

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: trenutni hostname.

### Podešavanje vremenske zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurisana vremenska zona i vrednosti povezane sa letnjim računanjem vremena.

### Praćenje vremena pristupa

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` pokazuje da li se NTFS vremenske oznake poslednjeg pristupa ažuriraju.
- Da biste ga omogućili, koristite: `fsutil behavior set disablelastaccess 0`

### Detalji isključivanja

- `SYSTEM\CurrentControlSet\Control\Windows`: vreme poslednjeg isključivanja.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: stariji sistemi mogu sadržati i brojače isključivanja.

### Mrežna konfiguracija

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP adrese interfejsa, DHCP lease-ovi, gateway i DNS podaci.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: naziv mrežnog profila/SSID, kao i vreme prve i poslednje konekcije.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: podaci za povezivanje profila, kao što su MAC adresa gateway-a i DNS sufiks.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalni deljeni folderi koje host objavljuje.

### Istorija udaljenog pristupa i mrežnih deljenja

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: odlazna RDP MRU lista (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: istorija odlaznih RDP konekcija po hostu. Podključevi obično čuvaju `UsernameHint`, a vreme `LastWrite` ključa predstavlja koristan pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapirani mrežni diskovi, UNC deljenja i tačke montiranja prenosivih medija povezane sa konkretnim korisnikom.

### Programi koji se automatski pokreću i zakazana perzistencija

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metapodaci zakazanih zadataka. Ako zadatak postoji ovde, ali vrednost `SD` nedostaje iz `Tree\<TaskName>`, posumnjajte na prikriveno manipulisanje zadatkom u Tarrask stilu i povežite ga sa `C:\Windows\System32\Tasks\<TaskName>`.

### Pretrage, ukucane putanje i MRU liste

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termini pretrage u File Explorer-u.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer putanje koje su ručno ukucane.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: poslednjih 26 `Win + R` komandi. `MRUList` čuva njihov redosled.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: nedavno otvoreni dokumenti i folderi.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: nedavno korišćeni Office fajlovi.

### Praćenje aktivnosti korisnika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: istorija pokretanja putem GUI-ja. Nazivi vrednosti su kodirani pomoću ROT13, a binarni podaci sadrže brojače pokretanja i vreme poslednjeg pokretanja.<sup>[[1]](#references)</sup>
- Tretirajte `UserAssist` kao snažan pomoćni dokaz, a ne kao konačan zaključak: uglavnom prati aplikacije ili `.lnk` fajlove pokrenute kroz Explorer i može propustiti izvršavanje putem command-line-a ili servisa. Na Windows 10+, neki unosi ne znače nužno da je proces u potpunosti pokrenut.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: tragovi izvršavanja na modernim verzijama Windows 10/11, sa atribucijom SID-a i vremenom poslednjeg izvršavanja. Naročito su korisni za lokalno izvršene binarne fajlove, ali stariji unosi mogu brzo biti uklonjeni, a izvršavanja sa mrežnih deljenja/prenosivih medija su manje pouzdana.
- Za šire artefakte izvršavanja, kao što su Prefetch, Amcache, ShimCache i SRUM, pogledajte glavni [pregled Windows forensics-a](README.md#programs-executed).

### Shellbags

- Shellbags se čuvaju i u `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` i u `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Unosi iz `NTUSER.DAT` naročito su korisni za UNC/mrežno pregledanje, dok je `UsrClass.dat` mesto na kom Windows Vista+ obično čuva shellbags lokalnih/prenosivih foldera.
- Mogu pokazati postojanje foldera, kretanje kroz njih i podešavanja prikaza foldera čak i nakon brisanja foldera. Pristup arhivskim fajlovima nalik Explorer-u takođe može ostaviti shellbag tragove.<sup>[[1]](#references)</sup>
- Ne dokazuje svaki shellbag uspešan pristup folderu, zato nalaze potvrdite pomoću LNK-ova, Jump Lists, vremenskih oznaka ili mapiranja volumena.
- Koristite **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ili **SBECmd** za njihovo parsiranje.

### USB informacije

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primarni inventar USB uređaja za masovno skladištenje (proizvođač, proizvod, revizija, serijski broj/instanca uređaja).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: širi inventar USB uređaja, uključujući uređaje koji nisu za skladištenje.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: na novijim build-ovima Windows 10/11 ovo je veoma vredno mesto za vremenske oznake životnog ciklusa pojedinačnih uređaja, kao što su instalacija, prva instalacija, poslednje povezivanje i poslednje uklanjanje.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: mapira volumene i identifikatore uređaja na slovne oznake diskova / volume GUID-ove. Možda će opstati samo poslednje mapiranje za datu slovnu oznaku diska.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: koristan pivot za serijske brojeve volumena i metapodatke prethodnih medija.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: istorija interakcije konkretnog korisnika sa slovnim oznakama diskova i deljenjima.<sup>[[2]](#references)</sup>
- Moderni telefoni i tableti povezani putem MTP/PTP možda se **neće** pojaviti pod `USBSTOR`. Proverite i `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` i `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Da biste povezali uređaj sa korisnikom, pređite sa identifikatora uređaja ili volumena na artefakte po korisniku, kao što su shellbags, LNK-ovi, Jump Lists, `RecentDocs` i `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
