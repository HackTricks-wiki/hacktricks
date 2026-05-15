# Zanimljivi Windows Registry ključevi

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive-ovi su jedan od najbržih načina da pređete sa _šta se desilo?_ na _koji korisnik, kada i odakle?_. Za live analizu preferirajte `CurrentControlSet`; za offline hive analizu prvo utvrdite koji je `ControlSet00x` bio aktivan umesto da hardkodujete `ControlSet001`.

### Verzija Windowsa i informacije o vlasniku

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, vreme instalacije, registrovani vlasnik, naziv proizvoda i drugi build metapodaci.
- `SYSTEM\Select`: mapira `Current`, `Default` i `LastKnownGood` na stvarne `ControlSet00x` vrednosti koje koristi sistem.

### Ime računara

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: trenutno hostname.

### Podešavanje vremenske zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurisana vremenska zona i vrednosti povezane sa DST.

### Praćenje vremena pristupa

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` označava da li se ažuriraju NTFS last-access timestamp-ovi.
- Da biste ga omogućili, koristite: `fsutil behavior set disablelastaccess 0`

### Detalji gašenja

- `SYSTEM\CurrentControlSet\Control\Windows`: vreme poslednjeg gašenja.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: stariji sistemi mogu takođe izložiti brojače gašenja.

### Mrežna konfiguracija

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP adrese interfejsa, DHCP lease-ovi, gateway i DNS podaci.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: naziv mrežnog profila/SSID plus vreme prve i poslednje veze.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: podaci za korelaciju profila kao što su MAC adresa gateway-a i DNS sufiks.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalni shared folder-i objavljeni od strane hosta.

### Istorija daljinskog pristupa i mrežnih share-ova

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU lista (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: outbound RDP istorija po hostu. Podključevi obično čuvaju `UsernameHint`, a vreme `LastWrite` ključa je koristan pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapirani network drive-ovi, UNC share-ovi i mount point-i za removable media vezani za određenog korisnika.

### Programi koji se automatski pokreću i zakazani persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metapodaci o zakazanim task-ovima. Ako task postoji ovde, ali `SD` vrednost nedostaje iz `Tree\<TaskName>`, posumnjajte na skriven Tarrask-style manipulaciju task-om i povežite to sa `C:\Windows\System32\Tasks\<TaskName>`.

### Pretrage, typed paths i MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: pojmovi pretrage u File Explorer-u.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: ručno unete Explorer putanje.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: poslednjih 26 `Win + R` komandi. `MRUList` čuva njihov redosled.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: nedavno otvoreni dokumenti i folder-i.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent files.

### Praćenje aktivnosti korisnika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: istorija izvršavanja pokrenuta kroz GUI. Imena vrednosti su ROT13-enkodirana, a binarni podaci uključuju brojače pokretanja i vreme poslednjeg pokretanja.
- Tretirajte `UserAssist` kao snažan podržavajući dokaz, ne kao samostalan zaključak: uglavnom prati aplikacije ili `.lnk` fajlove pokrenute kroz Explorer i može da propusti izvršavanje iz command-line-a ili servisa. Na Windows 10+, neki unosi ne znače nužno da je proces u potpunosti izvršen.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderni Windows 10/11 execution tragovi sa SID atribucijom i vremenom poslednjeg izvršavanja. Ovo je posebno korisno za lokalno izvršene binarije, ali stariji unosi mogu brzo da zastare, a izvršavanja sa network share-ova/removable media su manje pouzdana.
- Za šire execution artefakte kao što su Prefetch, Amcache, ShimCache i SRUM, pogledajte glavni [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags se čuvaju i u `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` i u `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- `NTUSER.DAT` unosi su posebno korisni za UNC/network pregledanje, dok `UsrClass.dat` je mesto gde Windows Vista+ obično čuva lokalne/removable-folder shellbags.
- Mogu da pokažu postojanje foldera, traversiranje i preferencije prikaza foldera čak i nakon što je folder obrisan. Explorer-like pristup arhivskim fajlovima takođe može ostaviti shellbag tragove.
- Ne dokazuje svaki shellbag uspešan pristup folderu, zato to potvrdite sa LNK-ovima, Jump Lists, timestamp-ovima ili volume mapiranjima.
- Koristite **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ili **SBECmd** za parsiranje.

### USB informacije

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primarni inventar USB mass-storage uređaja (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: širi inventar USB uređaja, uključujući non-storage uređaje.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: na novijim Windows 10/11 build-ovima ovo je mesto visoke vrednosti za lifecycle timestamp-ove po uređaju kao što su install, first install, last arrival i last removal.
- `HKLM\SYSTEM\MountedDevices`: mapira volume i device identifikatore na drive letters / volume GUID-ove. Može da opstane samo poslednje mapiranje za dato slovo diska.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: koristan pivot za volume serial brojeve i prethodne media metapodatke.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: istorija interakcije sa drive-letter i share-ovima specifična za korisnika.
- Moderni telefoni i tableti povezani preko MTP/PTP možda se **neće** pojaviti pod `USBSTOR`. Proverite i `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` i `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Da biste povezali uređaj sa korisnikom, pivotujte od identifikatora uređaja ili volume-a ka per-user artefaktima kao što su shellbags, LNK-ovi, Jump Lists, `RecentDocs` i `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
