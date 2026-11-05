# Zanimljivi ključevi Windows Registry-ja

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive-ovi jedan su od najbržih načina da pređete sa pitanja _šta se dogodilo?_ na pitanja _koji korisnik, kada i odakle?_. Za analizu sistema koji je u radu koristite `CurrentControlSet`; pri analizi hive-ova van sistema prvo utvrdite koji je `ControlSet00x` bio aktivan, umesto da unapred pretpostavite `ControlSet001`.

### Informacije o verziji Windows-a i vlasniku

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: izdanje/verzija Windows-a, vreme instalacije, registrovani vlasnik, naziv proizvoda i drugi metapodaci o verziji.
- `SYSTEM\Select`: povezuje vrednosti `Current`, `Default` i `LastKnownGood` sa stvarnim vrednostima `ControlSet00x` koje sistem koristi.

### Ime računara

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: trenutno ime računara.

### Podešavanje vremenske zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurisana vremenska zona i vrednosti povezane sa letnjim računanjem vremena.

### Praćenje vremena pristupa

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` pokazuje da li se ažuriraju NTFS vremenske oznake poslednjeg pristupa.
- Da biste ovo omogućili, koristite: `fsutil behavior set disablelastaccess 0`

### Detalji o isključivanju

- `SYSTEM\CurrentControlSet\Control\Windows`: vreme poslednjeg isključivanja.
- Stariji sistemi mogu da sadrže i brojače isključivanja u `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Mrežna konfiguracija

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP adrese interfejsa, DHCP zakupi, podaci o gateway-u i DNS-u.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: naziv/SSID mrežnog profila i vreme prvog i poslednjeg povezivanja.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` i `...\Unmanaged\{GUID}`: podaci za povezivanje profila, kao što su MAC adresa gateway-a i DNS sufiks.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokalne deljene fascikle koje host objavljuje.

### Istorija udaljenog pristupa i mrežnih deljenih resursa

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: odlazna RDP MRU lista (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: istorija odlaznih RDP veza za pojedinačne hostove. Potključevi obično sadrže `UsernameHint`, a vreme `LastWrite` ključa korisna je polazna tačka za istragu.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapirani mrežni diskovi, UNC deljeni resursi i tačke montiranja prenosivih medija povezane sa određenim korisnikom.

### Programi koji se automatski pokreću i planirana perzistencija

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` i `...\Tasks\{GUID}`: metapodaci planiranih zadataka. Ako zadatak postoji ovde, ali vrednost `SD` nedostaje iz `Tree\<TaskName>`, posumnjajte na skriveno manipulisanje zadatkom u stilu Tarrask-a i proverite ga u korelaciji sa `C:\Windows\System32\Tasks\<TaskName>`.

### Pretrage, ručno unete putanje i MRU liste

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: pojmovi za pretragu u File Explorer-u.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: putanje ručno unete u Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: poslednjih 26 komandi unetih pomoću `Win + R`. `MRUList` čuva njihov redosled.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: nedavno otvoreni dokumenti i fascikle.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: nedavno korišćene Office datoteke.

### Praćenje aktivnosti korisnika

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: istorija pokretanja preko grafičkog interfejsa. Nazivi vrednosti kodirani su pomoću ROT13, a binarni podaci sadrže brojače pokretanja i vreme poslednjeg pokretanja.<sup>[[1]](#references)</sup>
- Tretirajte `UserAssist` kao snažan potkrepljujući dokaz, a ne kao samostalan zaključak: uglavnom prati aplikacije ili `.lnk` datoteke pokrenute preko Explorer-a i može da propusti izvršavanje iz komandne linije ili kao servis. U Windows-u 10 i novijim verzijama, neki unosi ne znače nužno da je proces zaista pokrenut.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` i `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: tragovi izvršavanja u novijim verzijama Windows-a 10/11, sa pripisivanjem SID-u i vremenom poslednjeg izvršavanja. Posebno su korisni za lokalno pokrenute binarne datoteke, ali stariji unosi mogu brzo da isteknu, a podaci o izvršavanjima sa mrežnih deljenih resursa/prenosivih medija manje su pouzdani.
- Za širi pregled tragova izvršavanja, kao što su Prefetch, Amcache, ShimCache i SRUM, pogledajte glavni [pregled Windows forenzike](./#programs-executed).

### Shellbags

- Shellbags se čuvaju i u `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` i u `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Unosi u `NTUSER.DAT` naročito su korisni za pregledanje UNC/mrežnih lokacija, dok Windows Vista i novije verzije obično čuvaju shellbags za lokalne/prenosive fascikle u `UsrClass.dat`.
- Mogu da pokažu postojanje fascikle, pristupanje fascikli i podešavanja prikaza fascikle čak i nakon njenog brisanja. Pristup arhivskim datotekama preko Explorer-a ili sličnog programa takođe može da ostavi shellbag tragove.<sup>[[1]](#references)</sup>
- Ne dokazuje svaki shellbag da je pristup fascikli bio uspešan, zato proverite i LNK datoteke, Jump Lists, vremenske oznake ili mapiranja volumena.
- Za njihovu obradu koristite **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ili **SBECmd**.

### Informacije o USB uređajima

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primarni inventar USB uređaja za masovno skladištenje podataka (proizvođač, proizvod, revizija, serijski broj/instanca uređaja).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: širi inventar USB uređaja, uključujući uređaje koji nisu za skladištenje podataka.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: u novijim verzijama Windows-a 10/11 ovo je važno mesto za vremenske oznake životnog ciklusa pojedinačnog uređaja, kao što su vreme instalacije, prve instalacije, poslednjeg povezivanja i poslednjeg uklanjanja.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: povezuje volumene i identifikatore uređaja sa slovima diskova / GUID-ovima volumena. Može da se sačuva samo poslednje mapiranje za dato slovo diska.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: korisna polazna tačka za serijske brojeve volumena i metapodatke o prethodnim medijima.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: istorija interakcije sa slovima diskova i deljenim resursima specifična za korisnika.<sup>[[2]](#references)</sup>
- Moderni telefoni i tableti povezani preko MTP/PTP protokola možda se **neće** pojaviti u `USBSTOR`. Proverite i `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` i `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Da biste povezali uređaj sa korisnikom, pređite sa identifikatora uređaja ili volumena na artefakte specifične za korisnika, kao što su shellbags, LNK datoteke, Jump Lists, `RecentDocs` i `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
