# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Napadač može biti zainteresovan za **promenu vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Moguće je pronaći vremenske oznake unutar MFT u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **Modifikacija**, **pristup**, **kreiranje** i **modifikacija MFT registra** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Ovaj alat **modifikuje** informacije o vremenskim oznakama unutar **`$STANDARD_INFORMATION`** **ali** **ne** informacije unutar **`$FILE_NAME`**. Stoga, moguće je **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (Dnevnik broja ažuriranja) je funkcija NTFS (Windows NT datotečni sistem) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje ovih promena.

![](<../../images/image (801).png>)

Prethodna slika je **izlaz** prikazan od strane **alata** gde se može primetiti da su neke **promene izvršene** na datoteci.

### $LogFile

**Sve promene metapodataka na datotečnom sistemu se beleže** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Beleženi metapodaci se čuvaju u datoteci nazvanoj `**$LogFile**`, koja se nalazi u korenskom direktorijumu NTFS datotečnog sistema. Alati kao što su [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za analizu ove datoteke i identifikaciju promena.

![](<../../images/image (137).png>)

Ponovo, u izlazu alata moguće je videti da su **neke promene izvršene**.

Korišćenjem istog alata moguće je identifikovati **na koji način su vremenske oznake modifikovane**:

![](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme modifikacije datoteke
- MTIME: Modifikacija MFT registra datoteke
- RTIME: Vreme pristupa datoteci

### `$STANDARD_INFORMATION` i `$FILE_NAME` poređenje

Još jedan način da se identifikuju sumnjivo modifikovane datoteke bio bi da se uporede vremena na oba atributa tražeći **neusklađenosti**.

### Nanosekunde

**NTFS** vremenske oznake imaju **preciznost** od **100 nanosekundi**. Stoga, pronalaženje datoteka sa vremenskim oznakama kao što je 2010-10-10 10:10:**00.000:0000 je veoma sumnjivo**.

### SetMace - Anti-forensic Tool

Ovaj alat može modifikovati oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Vista, potrebno je da OS bude aktivan da bi se modifikovale ove informacije.

## Data Hiding

NFTS koristi klaster i minimalnu veličinu informacija. To znači da ako datoteka koristi i klaster i po jedan i po, **preostala polovina nikada neće biti korišćena** dok se datoteka ne obriše. Tada je moguće **sakriti podatke u ovom slobodnom prostoru**.

Postoje alati poput slacker koji omogućavaju skrivanje podataka u ovom "skrivenom" prostoru. Međutim, analiza `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![](<../../images/image (1060).png>)

Tada je moguće povratiti slobodan prostor koristeći alate poput FTK Imager. Imajte na umu da ovaj tip alata može sačuvati sadržaj obfuskovan ili čak enkriptovan.

## UsbKill

Ovo je alat koji će **isključiti računar ako se otkrije bilo kakva promena na USB** portovima.\
Jedan od načina da se to otkrije bio bi da se ispita pokrenuti procesi i **pregleda svaki python skript koji se izvršava**.

## Live Linux Distributions

Ove distribucije su **izvršene unutar RAM** memorije. Jedini način da ih otkrijete je **ako je NTFS datotečni sistem montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Moguće je onemogućiti nekoliko metoda beleženja u Windows-u kako bi se forenzička istraga učinila mnogo težom.

### Disable Timestamps - UserAssist

Ovo je ključ registra koji održava datume i sate kada je svaki izvršni program pokrenut od strane korisnika.

Onemogućavanje UserAssist zahteva dva koraka:

1. Postavite dva ključa registra, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na nulu kako bi se signalizovalo da želimo da onemogućimo UserAssist.
2. Očistite svoje podključeve registra koji izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Ovo će sačuvati informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, ovo može biti korisno i za forenzičke prakse.

- Izvršite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Desni klik na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Izmeni na svakom od ovih da promenite vrednost sa 1 (ili 3) na 0
- Ponovo pokrenite

### Disable Timestamps - Last Access Time

Kad god se folder otvori sa NTFS volumena na Windows NT serveru, sistem uzima vreme da **ažurira polje vremenske oznake na svakom navedenom folderu**, koje se zove vreme poslednjeg pristupa. Na NTFS volumenu koji se često koristi, ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Pretražite do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite njegovu vrednost na 1, što će onemogućiti proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.

### Delete USB History

Sve **USB Device Entries** se čuvaju u Windows Registry pod **USBSTOR** ključem registra koji sadrži podključeve koji se kreiraju svaki put kada priključite USB uređaj u svoj PC ili laptop. Ovaj ključ možete pronaći ovde `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog** obrišete USB istoriju.\
Takođe možete koristiti alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) da biste bili sigurni da ste ih obrisali (i da ih obrišete).

Još jedna datoteka koja čuva informacije o USB-ima je datoteka `setupapi.dev.log` unutar `C:\Windows\INF`. Ova datoteka takođe treba da bude obrisana.

### Disable Shadow Copies

**List** shadow kopije sa `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem `vssadmin delete shadow`

Takođe ih možete obrisati putem GUI prateći korake predložene u [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili shadow kopije [koraci su ovde](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete otkucati "services" u tekstualnu pretragu nakon što kliknete na Windows dugme za pokretanje.
2. Na listi pronađite "Volume Shadow Copy", izaberite ga, a zatim pristupite Svojstvima desnim klikom.
3. Izaberite Onemogućeno iz padajućeg menija "Tip pokretanja", a zatim potvrdite promenu klikom na Primeni i U redu.

Takođe je moguće modifikovati konfiguraciju koje datoteke će biti kopirane u shadow kopiju u registru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Možete koristiti **Windows alat**: `cipher /w:C` Ovo će označiti cipher da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku unutar C diska.
- Takođe možete koristiti alate poput [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Proširite "Windows Logs" --> Desni klik na svaku kategoriju i izaberite "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Unutar sekcije servisa onemogućite servis "Windows Event Log"
- `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Nedavne verzije Windows 10/11 i Windows Server čuvaju **bogate forenzičke artefakte PowerShell-a** pod
`Microsoft-Windows-PowerShell/Operational` (događaji 4104/4105/4106).
Napadači mogu onemogućiti ili obrisati ih u hodu:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Defenderi bi trebali pratiti promene na tim registrima i visoki obim uklanjanja PowerShell događaja.

### ETW (Event Tracing for Windows) Patch

Proizvodi za bezbednost krajnjih tačaka se u velikoj meri oslanjaju na ETW. Popularna metoda izbegavanja iz 2024. godine je patchovanje `ntdll!EtwEventWrite`/`EtwEventWriteFull` u memoriji tako da svaki ETW poziv vraća `STATUS_SUCCESS` bez emitovanja događaja:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) implement the same primitive in PowerShell or C++.  
Zbog toga što je zakrpa **lokalna za proces**, EDR-ovi koji rade unutar drugih procesa mogu je propustiti.  
Detekcija: uporediti `ntdll` u memoriji naspram na disku, ili hook pre korisničkog moda.

### Oživljavanje alternativnih podataka (ADS)

Kampanje malvera u 2023. (npr. **FIN12** loaderi) su primećene kako postavljaju binarne datoteke druge faze unutar ADS-a da bi ostale van vidokruga tradicionalnih skenera:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerišite tokove sa `dir /R`, `Get-Item -Stream *`, ili Sysinternals `streams64.exe`. Kopiranje host fajla na FAT/exFAT ili putem SMB će ukloniti skriveni tok i može se koristiti od strane istražitelja za oporavak payload-a.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forensics** u ransomware
upadima. Open-source alat **AuKill** učitava potpisani, ali ranjivi drajver (`procexp152.sys`) da
suspenduje ili prekine EDR i forenzičke senzore **pre nego što dođe do enkripcije i uništavanja logova**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Vozač se uklanja nakon toga, ostavljajući minimalne artefakte.  
Mere zaštite: omogućite Microsoftovu blok listu ranjivih vozača (HVCI/SAC) i obavestite o kreiranju kernel-servisa iz putanja koje korisnik može da piše.

---

## Reference

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (mart 2023)  
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (jun 2024)  
https://redcanary.com/blog/etw-patching-detection

{{#include ../../banners/hacktricks-training.md}}
