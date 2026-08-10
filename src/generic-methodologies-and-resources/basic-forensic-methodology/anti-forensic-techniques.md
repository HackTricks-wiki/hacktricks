# Anti-Forenzičke Tehnike

## Vremenske oznake

Napadač može biti zainteresovan za **promenu vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Vremenske oznake je moguće pronaći unutar MFT-a u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **izmena**, **pristup**, **kreiranje** i **izmena MFT registra** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz atributa **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forenzički alat

Ovaj alat **menja** informacije o vremenskim oznakama unutar **`$STANDARD_INFORMATION`**, ali **ne** i informacije unutar **`$FILE_NAME`**. Zbog toga je moguće **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija NTFS-a (Windows NT file system) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje ovih promena.

![TimeStomp - Anti-forenzički alat - Usnjrnl: USN Journal (Update Sequence Number Journal) je funkcija NTFS-a (Windows NT file system) koja prati promene na volumenu. ...](<../../images/image (801).png>)

Prethodna slika prikazuje **izlaz** koji je prikazao **alat**, gde se može uočiti da su na datoteci izvršene **neke promene**.

### $LogFile

**Sve promene metapodataka sistema datoteka se evidentiraju** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Evidentirani metapodaci čuvaju se u datoteci pod nazivom `**$LogFile**`, koja se nalazi u root direktorijumu NTFS sistema datoteka. Alati kao što je [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za parsiranje ove datoteke i identifikovanje promena.

![Usnjrnl - $LogFile: Sve promene metapodataka sistema datoteka se evidentiraju u procesu poznatom kao write-ahead logging. Evidentirani metapodaci čuvaju se u datoteci pod nazivom $LogFile , koja se nalazi u root...](<../../images/image (137).png>)

Ponovo, u izlazu alata moguće je videti da su izvršene **neke promene**.

Korišćenjem istog alata moguće je identifikovati **u koje vreme su vremenske oznake izmenjene**:

![Usnjrnl - $LogFile: Korišćenjem istog alata moguće je identifikovati u koje vreme su vremenske oznake izmenjene](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Vreme izmene MFT registra datoteke
- RTIME: Vreme pristupa datoteci

### Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Drugi način za identifikovanje sumnjivo izmenjenih datoteka bio bi poređenje vremena u oba atributa, tražeći **nepodudaranja**.

### Nanosekunde

Vremenske oznake sistema **NTFS** imaju **preciznost** od **100 nanosekundi**. Zato je pronalaženje datoteka sa vremenskim oznakama kao što je 2010-10-10 10:10:**00.000:0000 veoma sumnjivo**.

### SetMace - Anti-forenzički alat

Ovaj alat može da izmeni oba atributa, `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Vista sistema uživo je neophodan da bi se ove informacije izmenile.

## Skrivanje podataka

NFTS koristi klaster i minimalnu veličinu informacije. To znači da, ako datoteka zauzima jedan i po klaster, **preostala polovina se nikada neće koristiti** dok se datoteka ne obriše. Zatim je moguće **sakriti podatke u ovom slack prostoru**.

Postoje alati kao što je slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza datoteka `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![SetMace - Anti-forenzički alat - Skrivanje podataka: Postoje alati kao što je slacker koji omogućavaju skrivanje podataka u ovom "skrivenom" prostoru. Međutim, analiza datoteka $logfile i $usnjrnl može pokazati da su...](<../../images/image (1060).png>)

Zatim je moguće preuzeti slack prostor pomoću alata kao što je FTK Imager. Imajte na umu da ova vrsta alata može sačuvati sadržaj u obfuskiranom ili čak šifrovanom obliku.

## UsbKill

Ovo je alat koji će **isključiti računar ako se otkrije bilo kakva promena na USB** portovima.\
Jedan od načina za otkrivanje ovoga jeste pregled pokrenutih procesa i **provera svake pokrenute Python skripte**.

## Live Linux distribucije

Ove distribucije se **izvršavaju unutar RAM** memorije. Jedini način za njihovo otkrivanje jeste **u slučaju da je NTFS sistem datoteka montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, upad neće biti moguće otkriti.

## Bezbedno brisanje

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows konfiguracija

Moguće je onemogućiti nekoliko Windows metoda evidentiranja kako bi se forenzička istraga znatno otežala.

### Onemogućavanje vremenskih oznaka - UserAssist

Ovo je registry ključ koji održava datume i vremena kada je korisnik pokrenuo svaku izvršnu datoteku.

Onemogućavanje funkcije UserAssist zahteva dva koraka:

1. Postavite dva registry ključa, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, na nulu kako biste označili da želimo da UserAssist bude onemogućen.
2. Obrišite svoje registry podstabla koja izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Onemogućavanje vremenskih oznaka - Prefetch

Ovo čuva informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, ove informacije mogu biti korisne i za forenzičke prakse.

- Pokrenite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknite desnim tasterom na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Modify za svaku od ovih stavki da biste promenili vrednost sa 1 (ili 3) na 0
- Ponovo pokrenite sistem

### Onemogućavanje vremenskih oznaka - vreme poslednjeg pristupa

Kad god se fascikla otvori sa NTFS volumena na Windows NT serveru, sistem beleži vreme kako bi **ažurirao polje vremenske oznake u svakoj navedenoj fascikli**, koje se naziva vreme poslednjeg pristupa. Na intenzivno korišćenom NTFS volumenu ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Idite na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite njegovu vrednost na 1, čime ćete onemogućiti proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.

### Brisanje USB istorije

Svi **unosi USB uređaja** čuvaju se u Windows Registry-ju, ispod registry ključa **USBSTOR**, koji sadrži podključeve koji se kreiraju svaki put kada priključite USB uređaj na računar ili laptop. Ovaj ključ možete pronaći ovde `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog ključa** obrisaćete USB istoriju.\
Možete koristiti i alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) kako biste bili sigurni da ste ih obrisali (i da biste ih obrisali).

Druga datoteka koja čuva informacije o USB uređajima jeste datoteka `setupapi.dev.log` unutar `C:\Windows\INF`. I nju bi trebalo obrisati.

### Onemogućavanje Shadow Copies

**Izlistajte** shadow copies pomoću komande `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem komande `vssadmin delete shadow`

Možete ih obrisati i putem GUI-ja, prateći korake predložene na stranici [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili shadow copies, pratite [korake sa ove stranice](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete nakon klika na Windows start dugme uneti „services“ u polje za tekstualnu pretragu.
2. Na listi pronađite „Volume Shadow Copy“, izaberite ga, a zatim otvorite Properties klikom desnim tasterom.
3. U padajućem meniju „Startup type“ izaberite Disabled, a zatim potvrdite promenu klikom na Apply i OK.

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

### Onemogućavanje $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Napredno evidentiranje i neovlašćeno menjanje tragova (2023-2025)

### PowerShell ScriptBlock/Module Logging

Novije verzije Windows 10/11 i Windows Server sistema čuvaju **bogate PowerShell forenzičke artefakte** u okviru
`Microsoft-Windows-PowerShell/Operational` (događaji 4104/4105/4106).
Napadači ih mogu onemogućiti ili obrisati tokom rada:
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
Branioci treba da nadziru promene tih ključeva registrija i uklanjanje velikog broja PowerShell događaja.

### ETW (Event Tracing for Windows) Patch

Endpoint security proizvodi se u velikoj meri oslanjaju na ETW. Popularna metoda za evasion iz 2024. godine jeste patchovanje `ntdll!EtwEventWrite`/`EtwEventWriteFull` u memoriji, tako da svaki ETW poziv vraća `STATUS_SUCCESS` bez emitovanja događaja:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Javni PoCs (npr. `EtwTiSwallow`) implementiraju isti primitive u PowerShell-u ili C++-u.  
Pošto je patch **lokalan za proces**, EDR-ovi koji rade unutar drugih procesa mogu da ga ne detektuju.<sup>[[5]](#references)</sup>  
Detekcija: uporediti `ntdll` u memoriji sa verzijom na disku ili postaviti hook pre user-mode-a.

### Alternate Data Streams (ADS) Revival

U malware kampanjama iz 2023. godine (npr. **FIN12** loaderi), primećeno je smeštanje binarnih fajlova druge faze
unutar ADS-a kako bi ostali van domašaja tradicionalnih skenera:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Izlistajte stream-ove pomoću `dir /R`, `Get-Item -Stream *` ili Sysinternals alata `streams64.exe`.
Kopiranje host fajla na FAT/exFAT ili putem SMB-a ukloniće skriveni stream i može se koristiti
da istražitelji povrate payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forensics** tokom ransomware
upada.
Open-source alat **AuKill** učitava potpisani, ali ranjivi driver (`procexp152.sys`) kako bi
suspendovao ili prekinuo EDR i forenzičke senzore **pre enkripcije i uništavanja logova**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Driver se nakon toga uklanja, ostavljajući minimalne tragove.<sup>[[1]](#references)</sup>  
Mere zaštite: omogućite Microsoft vulnerable-driver blocklist (HVCI/SAC)  
i postavite upozorenje za kreiranje kernel-service iz putanja u koje korisnik može da upisuje.

---

## Linux Anti-Forensics: Self-Patching i Cloud C2 (2023–2025)

### Self-patching kompromitovanih servisa radi smanjenja detekcije (Linux)
Napadači sve češće „self-patch-uju“ servis odmah nakon njegovog iskorišćavanja, kako bi sprečili ponovnu eksploataciju i potisnuli detekcije zasnovane na ranjivostima. Ideja je da se ranjive komponente zamene najnovijim legitimnim upstream binarnim datotekama/JAR-ovima, tako da skeneri prijave da je host zakrpljen, dok persistence i C2 ostaju aktivni.<sup>[[3]](#references)</sup>

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nakon eksploatacije, napadači su preuzeli legitimne JAR-ove sa Maven Central (repo1.maven.org), obrisali ranjive JAR-ove u ActiveMQ instalaciji i ponovo pokrenuli broker.
- Time je početni RCE zatvoren, dok su drugi foothold-i ostali aktivni (cron, izmene SSH konfiguracije, zasebni C2 implants).

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
- Pregledajte servisne direktorijume u potrazi za neplaniranim zamenama binarnih/JAR fajlova:
- Debian/Ubuntu: `dpkg -V activemq` i uporedite hash vrednosti/putanje fajlova sa repo mirrorima.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Potražite verzije JAR fajlova koje postoje na disku, ali nisu u vlasništvu package managera, kao i simboličke linkove ažurirane van predviđenog procesa.
- Vremenska linija: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` za korelaciju ctime/mtime sa periodom kompromitovanja.
- Shell history/process telemetrija: dokaze o korišćenju `curl`/`wget` ka `repo1.maven.org` ili drugim artifact CDN-ovima neposredno nakon početne eksploatacije.
- Change management: proverite ko je primenio „patch“ i zašto, a ne samo da li je patched verzija prisutna.

### C2 putem cloud servisa sa bearer tokenima i anti-analysis stagerima
Uočeni tradecraft kombinovao je više dugotrajnih C2 putanja i anti-analysis pakovanje:<sup>[[3]](#references)</sup>
- PyInstaller ELF loaderi zaštićeni lozinkom, radi otežavanja sandboxing-a i statičke analize (npr. šifrovani PYZ, privremena ekstrakcija u `/_MEI*`).
- Indikatori: `strings` rezultati kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artefakti: ekstrakcija u `/tmp/_MEI*` ili prilagođene putanje navedene pomoću `--runtime-tmpdir`.
- Dropbox-backed C2 koji koristi hardkodovane OAuth Bearer tokene
- Mrežni markeri: `api.dropboxapi.com` / `content.dropboxapi.com` sa `Authorization: Bearer <token>`.
- Tražite u proxy/NetFlow/Zeek/Suricata podatke za izlazni HTTPS ka Dropbox domenima sa server workload-a koji inače ne sinhronizuju fajlove.
- Paralelni/rezervni C2 putem tunneling-a (npr. Cloudflare Tunnel `cloudflared`), čime se zadržava kontrola ako je jedan kanal blokiran.
- Host IOC-ovi: `cloudflared` procesi/jedinice, konfiguracija u `~/.cloudflared/*.json`, izlazni saobraćaj na portu 443 ka Cloudflare edge čvorovima.

### Persistence i „hardening rollback“ za održavanje pristupa (Linux primeri)
Napadači često kombinuju self-patching sa trajnim putanjama za pristup:<sup>[[3]](#references)</sup>
- Cron/Anacron: izmene `0anacron` stub-a u svakom `/etc/cron.*/` direktorijumu radi periodičnog izvršavanja.
- Potraga:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: omogućavanje root prijavljivanja i promena podrazumevanih shell-ova za naloge sa niskim privilegijama.
- Potražite omogućeno root prijavljivanje:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Potražite sumnjive interaktivne shell-ove na system nalozima (npr. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Nasumični beacon artefakti sa kratkim imenima (8 abecednih znakova) koji se upisuju na disk i istovremeno kontaktiraju cloud C2:
- Potraga:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders bi trebalo da korelišu ove artefakte sa izloženošću spolja i događajima patching-a servisa kako bi otkrili anti-forensic self-remediation korišćen za prikrivanje početne eksploatacije.

## References

- [1] [Sophos X-Ops – AuKill: Weaponized ranjivi drajver za onemogućavanje EDR-a (mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite za stealth: detekcija i hunting (jun 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching za persistence: Kako se DripDropper Linux malware kreće kroz cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Sakrivanje .NET-a – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
