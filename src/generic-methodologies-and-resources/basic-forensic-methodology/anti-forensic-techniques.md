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

Još jedan način da se identifikuju sumnjive modifikovane datoteke bio bi da se uporede vremena na oba atributa tražeći **neusklađenosti**.

### Nanosekunde

**NTFS** vremenske oznake imaju **preciznost** od **100 nanosekundi**. Stoga, pronalaženje datoteka sa vremenskim oznakama kao što je 2010-10-10 10:10:**00.000:0000 je veoma sumnjivo**.

### SetMace - Anti-forensic Tool

Ovaj alat može modifikovati oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Vista, potrebno je da OS bude aktivan da bi se modifikovale ove informacije.

## Data Hiding

NFTS koristi klaster i minimalnu veličinu informacija. To znači da ako datoteka koristi i klaster i po jedan i po, **preostala polovina nikada neće biti korišćena** dok se datoteka ne obriše. Stoga, moguće je **sakriti podatke u ovom slobodnom prostoru**.

Postoje alati kao što je slacker koji omogućavaju skrivanje podataka u ovom "skrivenom" prostoru. Međutim, analiza `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![](<../../images/image (1060).png>)

Stoga, moguće je povratiti slobodan prostor koristeći alate kao što je FTK Imager. Imajte na umu da ovaj tip alata može sačuvati sadržaj obfuskovan ili čak enkriptovan.

## UsbKill

Ovo je alat koji će **isključiti računar ako se otkrije bilo kakva promena na USB** portovima.\
Jedan od načina da se to otkrije bio bi da se ispita pokrenuti procesi i **pregleda svaki python skript koji se izvršava**.

## Live Linux Distributions

Ove distribucije su **izvršene unutar RAM** memorije. Jedini način da ih otkrijete je **ako je NTFS datotečni sistem montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Moguće je onemogućiti nekoliko metoda beleženja u Windows-u kako bi se otežala forenzička istraga.

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

Sve **USB Device Entries** se čuvaju u Windows Registry pod **USBSTOR** ključem registra koji sadrži podključeve koji se kreiraju svaki put kada priključite USB uređaj u svoj PC ili laptop. Možete pronaći ovaj ključ ovde `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog** obrišete USB istoriju.\
Takođe možete koristiti alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) da biste bili sigurni da ste ih obrisali (i da ih obrišete).

Još jedna datoteka koja čuva informacije o USB-ima je datoteka `setupapi.dev.log` unutar `C:\Windows\INF`. Ova datoteka takođe treba da bude obrisana.

### Disable Shadow Copies

**Lista** senčnih kopija sa `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem `vssadmin delete shadow`

Takođe ih možete obrisati putem GUI prateći korake predložene u [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili senčne kopije [koraci su ovde](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete otkucati "services" u tekstualnu pretragu nakon što kliknete na Windows dugme za pokretanje.
2. Iz liste pronađite "Volume Shadow Copy", izaberite ga, a zatim pristupite Svojstvima desnim klikom.
3. Izaberite Onemogućeno iz padajućeg menija "Tip pokretanja", a zatim potvrdite promenu klikom na Primeni i U redu.

Takođe je moguće modifikovati konfiguraciju koje datoteke će biti kopirane u senčnu kopiju u registru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Možete koristiti **Windows alat**: `cipher /w:C` Ovo će označiti cipher da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku unutar C diska.
- Takođe možete koristiti alate kao što je [**Eraser**](https://eraser.heidi.ie)

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
Defenderi bi trebali pratiti promene na tim registrima i visoko obimno uklanjanje PowerShell događaja.

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
Zbog toga što je zakrpa **lokalna za proces**, EDR-ovi koji rade unutar drugih procesa mogu to propustiti.
Detekcija: uporediti `ntdll` u memoriji naspram na disku, ili hook pre korisničkog moda.

### Oživljavanje alternativnih podataka (ADS)

Kampanje malvera u 2023. (npr. **FIN12** loaderi) su primećene kako postavljaju binarne datoteke druge faze
unutar ADS-a da bi ostale van vidokruga tradicionalnih skenera:
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

## Linux Anti-Forensics: Samo-popravljanje i Cloud C2 (2023–2025)

### Samo-popravljanje kompromitovanih servisa za smanjenje detekcije (Linux)  
Protivnici sve više "samo-popravljaju" servis odmah nakon što ga iskoriste kako bi sprečili ponovnu eksploataciju i suprimirali detekcije zasnovane na ranjivostima. Ideja je da se ranjivi komponenti zamene najnovijim legitimnim upstream binarnim datotekama/JAR-ovima, tako da skeneri prijavljuju host kao popravljen dok persistencija i C2 ostaju.

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Nakon eksploatacije, napadači su preuzeli legitimne JAR-ove sa Maven Central (repo1.maven.org), obrisali ranjive JAR-ove u ActiveMQ instalaciji i ponovo pokrenuli broker.  
- Ovo je zatvorilo inicijalni RCE dok su se održavali drugi pristupi (cron, promene SSH konfiguracije, odvojeni C2 implantati).

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
Forenzička/istraživačka uputstva
- Pregledajte direktorijume usluga za neplanirane zamene binarnih/JAR datoteka:
- Debian/Ubuntu: `dpkg -V activemq` i uporedite heš/putanje datoteka sa repozitorijumima.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Potražite JAR verzije prisutne na disku koje nisu u vlasništvu menadžera paketa, ili simboličke linkove ažurirane van kanala.
- Vremenska linija: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` za korelaciju ctime/mtime sa vremenom kompromitacije.
- Istorija ljuske/telemetrija procesa: dokazi o `curl`/`wget` ka `repo1.maven.org` ili drugim CDN-ovima artefakata odmah nakon inicijalne eksploatacije.
- Upravljanje promenama: validirajte ko je primenio “zakrpu” i zašto, ne samo da je prisutna verzija sa zakrpom.

### Cloud‑service C2 sa bearer tokenima i anti‑analitičkim stagerima
Posmatrano trgovanje kombinovalo je više dugoročnih C2 puteva i anti‑analitičko pakovanje:
- Lozinkom zaštićeni PyInstaller ELF loaderi kako bi se otežalo korišćenje sandboxes i statička analiza (npr., enkriptovani PYZ, privremena ekstrakcija pod `/_MEI*`).
- Indikatori: `strings` hitovi kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefakti u vreme izvršavanja: ekstrakcija u `/tmp/_MEI*` ili prilagođene `--runtime-tmpdir` putanje.
- C2 podržan Dropbox-om koristeći hardkodirane OAuth Bearer tokene
- Mrežni markeri: `api.dropboxapi.com` / `content.dropboxapi.com` sa `Authorization: Bearer <token>`.
- Istražujte u proxy/NetFlow/Zeek/Suricata za izlazni HTTPS ka Dropbox domenima iz serverskih radnih opterećenja koja obično ne sinhronizuju datoteke.
- Paralelni/rezervni C2 putem tunelovanja (npr., Cloudflare Tunnel `cloudflared`), zadržavajući kontrolu ako je jedan kanal blokiran.
- Host IOCs: `cloudflared` procesi/jedinice, konfiguracija na `~/.cloudflared/*.json`, izlazni 443 ka Cloudflare ivicama.

### Postojanost i “hardening rollback” za održavanje pristupa (primeri za Linux)
Napadači često kombinuju samopročišćavanje sa trajnim pristupnim putevima:
- Cron/Anacron: izmene u `0anacron` stubu u svakom `/etc/cron.*/` direktorijumu za periodičnu izvršavanje.
- Istražujte:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH konfiguracija hardening rollback: omogućavanje root prijava i menjanje podrazumevanih ljuski za nisko privilegovane naloge.
- Istražujte za omogućavanje root prijava:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# vrednosti zastavica kao što su "yes" ili previše permisivne postavke
```
- Istražujte sumnjive interaktivne ljuske na sistemskim nalozima (npr., `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Nasumični, kratko imenovani beacon artefakti (8 slova) postavljeni na disk koji takođe kontaktiraju cloud C2:
- Istražujte:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Odbrambeni timovi treba da koreliraju ove artefakte sa spoljnim izlaganjem i događajima zakrpa usluga kako bi otkrili anti‑forenzičko samopročišćavanje korišćeno za prikrivanje inicijalne eksploatacije.

## Reference

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (mart 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (jun 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
