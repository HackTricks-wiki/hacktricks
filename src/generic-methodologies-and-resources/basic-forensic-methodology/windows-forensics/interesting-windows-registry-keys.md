# Zanimljivi Windows Registry ključevi

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive-ovi su jedan od najbržih načina da se pređe sa _šta se dogodilo?_ na _koji korisnik, kada i odakle?_. Za analizu uživo prednost dajte `CurrentControlSet`; pri offline analizi hive-ova prvo utvrdite koji je `ControlSet00x` bio aktivan, umesto da unapred pretpostavite `ControlSet001`.

### Informacije o verziji Windows-a i vlasniku

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows izdanje/build, vreme instalacije, registrovani vlasnik, naziv proizvoda i drugi build metapodaci.
- `SYSTEM\Select`: povezuje `Current`, `Default` i `LastKnownGood` sa stvarnim vrednostima `ControlSet00x` koje sistem koristi.

### Naziv računara

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: trenutni hostname.

### Podešavanje vremenske zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurisana vremenska zona i vrednosti povezane sa DST-om.

### Praćenje vremena pristupa

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` pokazuje da li se NTFS timestamp-ovi poslednjeg pristupa ažuriraju.
- Da biste ga omogućili, koristite: `fsutil behavior set disablelastaccess 0`

### Detalji isključivanja

- `SYSTEM\CurrentControlSet\Control\Windows`: vreme poslednjeg isključivanja.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: stariji sistemi mogu sadržati i brojače isključivanja.

### Mrežna konfiguracija

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP adrese interfejsa, DHCP lease-ovi, gateway i DNS podaci.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: naziv mrežnog profila/SSID, kao i vreme prve i poslednje konekcije.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: podaci za povezivanje profila, kao što su MAC adresa gateway-a i DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalni shared folder-i koje host objavljuje.

### Istorija udaljenog pristupa i network share-ova

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: odlazna RDP MRU lista (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: istorija odlaznih RDP konekcija po hostu. Subkeys obično čuvaju `UsernameHint`, a vreme `LastWrite` ključa predstavlja koristan pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapirani network drive-ovi, UNC share-ovi i mount points uklonjivih medija povezani sa određenim korisnikom.

### Programi koji se automatski pokreću i zakazana persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metapodaci zakazanih task-ova. Ako task postoji ovde, ali vrednost `SD` nedostaje iz `Tree\<TaskName>`, posumnjajte na skrivenu manipulaciju task-om u Tarrask stilu i povežite je sa `C:\Windows\System32\Tasks\<TaskName>`.

### Pretrage, unete putanje i MRU-ovi

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termini pretrage u File Explorer-u.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer putanje ručno unete preko tastature.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: poslednjih 26 `Win + R` komandi. `MRUList` čuva njihov redosled.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: nedavno otvoreni dokumenti i folder-i.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: nedavno korišćeni Office fajlovi.

### Praćenje aktivnosti korisnika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: istorija pokretanja preko GUI-ja. Nazivi vrednosti su kodirani pomoću ROT13, a binarni podaci sadrže brojače pokretanja i vreme poslednjeg pokretanja.<sup>[[1]](#references)</sup>
- Posmatrajte `UserAssist` kao snažan pomoćni dokaz, a ne kao samostalan zaključak: uglavnom prati aplikacije ili `.lnk` fajlove pokrenute kroz Explorer i može propustiti izvršavanje preko komandne linije ili servisa. Na Windows 10+, neki entries ne moraju nužno značiti da je proces u potpunosti izvršen.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: tragovi izvršavanja na modernim verzijama Windows 10/11, sa SID atribucijom i vremenom poslednjeg izvršavanja. Posebno su korisni za lokalno izvršene binarne fajlove, ali stariji entries mogu brzo biti uklonjeni, a izvršavanja sa network share-ova ili uklonjivih medija su manje pouzdana.
- Za širi pregled artefakata izvršavanja, kao što su Prefetch, Amcache, ShimCache i SRUM, pogledajte glavni [Windows forensics pregled](README.md#programs-executed).

### Shellbags

- Shellbags se čuvaju i u `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` i u `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Entries iz `NTUSER.DAT` posebno su korisni za UNC/network browsing, dok je `UsrClass.dat` mesto gde Windows Vista+ obično čuva shellbags lokalnih/uklonjivih folder-a.
- Mogu pokazati postojanje folder-a, kretanje kroz njih i podešavanja prikaza folder-a čak i nakon brisanja folder-a. Pristup archive fajlovima sličan Explorer-u takođe može ostaviti shellbag tragove.<sup>[[1]](#references)</sup>
- Svaki shellbag ne dokazuje uspešan pristup folder-u, zato nalaze potvrdite pomoću LNK-ova, Jump Lists, timestamp-ova ili mapiranja volumena.
- Za njihovo parsiranje koristite **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ili **SBECmd**.

### USB informacije

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primarni inventar USB mass-storage uređaja (vendor, proizvod, revizija, serijski broj/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: širi inventar USB uređaja, uključujući uređaje koji nisu storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: na novijim build-ovima Windows 10/11 ovo je važno mesto za timestamp-ove životnog ciklusa pojedinačnog uređaja, kao što su instalacija, prva instalacija, poslednje povezivanje i poslednje uklanjanje.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: povezuje volumene i identifikatore uređaja sa slovima diskova / volume GUID-ovima. Za dato slovo diska može opstati samo poslednje mapiranje.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: koristan pivot za serijske brojeve volumena i metapodatke prethodnih medija.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: istorija interakcije korisnika sa slovima diskova i share-ovima.<sup>[[2]](#references)</sup>
- Moderni telefoni i tableti povezani preko MTP/PTP možda se **neće** pojaviti pod `USBSTOR`. Proverite i `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` i `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Da biste povezali uređaj sa korisnikom, napravite pivot od identifikatora uređaja ili volumena ka artefaktima po korisniku, kao što su shellbags, LNK-ovi, Jump Lists, `RecentDocs` i `MountPoints2`.<sup>[[2]](#references)</sup>

## Reference

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
