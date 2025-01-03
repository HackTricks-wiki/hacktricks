# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## How It Works Explained

प्रक्रियाएँ उन होस्ट पर खोली जा सकती हैं जहाँ उपयोगकर्ता नाम और या तो पासवर्ड या हैश ज्ञात हैं WMI के उपयोग के माध्यम से। Wmiexec द्वारा WMI का उपयोग करके आदेश निष्पादित किए जाते हैं, जो एक अर्ध-इंटरएक्टिव शेल अनुभव प्रदान करता है।

**dcomexec.py:** विभिन्न DCOM एंडपॉइंट्स का उपयोग करते हुए, यह स्क्रिप्ट wmiexec.py के समान एक अर्ध-इंटरएक्टिव शेल प्रदान करती है, विशेष रूप से ShellBrowserWindow DCOM ऑब्जेक्ट का लाभ उठाते हुए। यह वर्तमान में MMC20 का समर्थन करता है। एप्लिकेशन, शेल विंडोज़, और शेल ब्राउज़र विंडो ऑब्जेक्ट। (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Fundamentals

### Namespace

डायरेक्टरी-शैली की पदानुक्रम में संरचित, WMI का शीर्ष-स्तरीय कंटेनर \root है, जिसके अंतर्गत अतिरिक्त निर्देशिकाएँ, जिन्हें namespaces कहा जाता है, व्यवस्थित की जाती हैं।  
Namespaces की सूची बनाने के लिए आदेश:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
एक नामस्थान के भीतर कक्षाओं को सूचीबद्ध करने के लिए:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **क्लासेस**

WMI क्लास नाम, जैसे win32_process, और जिस नामस्थान में यह स्थित है, जानना किसी भी WMI ऑपरेशन के लिए महत्वपूर्ण है।  
`win32` से शुरू होने वाली क्लासेस की सूची बनाने के लिए कमांड:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
क्लास का आह्वान:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methods

विधियाँ, जो WMI कक्षाओं के एक या अधिक निष्पादन योग्य कार्य हैं, को निष्पादित किया जा सकता है।
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

### WMI सेवा स्थिति

WMI सेवा के संचालन की पुष्टि करने के लिए आदेश:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### सिस्टम और प्रक्रिया की जानकारी

WMI के माध्यम से सिस्टम और प्रक्रिया की जानकारी इकट्ठा करना:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
हमलावरों के लिए, WMI सिस्टम या डोमेन के बारे में संवेदनशील डेटा की गणना करने के लिए एक शक्तिशाली उपकरण है।
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
WMI के लिए विशिष्ट जानकारी, जैसे स्थानीय प्रशासक या लॉग-ऑन उपयोगकर्ताओं की दूरस्थ क्वेरी करना, सावधानीपूर्वक कमांड निर्माण के साथ संभव है।

### **मैनुअल रिमोट WMI क्वेरीिंग**

दूरस्थ मशीन पर स्थानीय प्रशासकों और लॉग-ऑन उपयोगकर्ताओं की चुपचाप पहचान विशिष्ट WMI क्वेरियों के माध्यम से की जा सकती है। `wmic` एक टेक्स्ट फ़ाइल से पढ़ने का समर्थन भी करता है ताकि एक साथ कई नोड्स पर कमांड निष्पादित किए जा सकें।

WMI के माध्यम से एक प्रक्रिया को दूरस्थ रूप से निष्पादित करने के लिए, जैसे कि एक साम्राज्य एजेंट को तैनात करना, निम्नलिखित कमांड संरचना का उपयोग किया जाता है, जिसमें सफल निष्पादन "0" के लौटने वाले मान द्वारा संकेतित होता है:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
यह प्रक्रिया WMI की दूरस्थ निष्पादन और प्रणाली गणना की क्षमता को दर्शाती है, जो प्रणाली प्रशासन और पेनटेस्टिंग दोनों के लिए इसकी उपयोगिता को उजागर करती है।

## संदर्भ

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## स्वचालित उपकरण

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
