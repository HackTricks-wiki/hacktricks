# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो यह पता लगाने में मदद करता है कि running game की memory में महत्वपूर्ण values कहाँ save हैं और उन्हें बदला जा सकता है।\
जब आप इसे download करके run करते हैं, तो आपको tool का उपयोग करने का एक **tutorial** दिखाया जाता है। यदि आप tool का उपयोग करना सीखना चाहते हैं, तो इसे पूरा करना अत्यधिक recommended है।<sup>[[3]](#references)</sup>

## आप क्या search कर रहे हैं?

![Cheat Engine - आप क्या search कर रहे हैं?: आप क्या search कर रहे हैं?](<../../images/image (762).png>)

यह tool किसी program की memory में **किसी value** (आमतौर पर number) के **stored होने का स्थान** खोजने के लिए बहुत उपयोगी है।\
**आमतौर पर numbers** को **4bytes** form में store किया जाता है, लेकिन आप उन्हें **double** या **float** formats में भी खोज सकते हैं, या हो सकता है कि आप **number से अलग कुछ** खोजना चाहते हों। इसलिए आपको यह सुनिश्चित करना होगा कि आप वह चीज़ **select** करें जिसे आप **search करना** चाहते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आमतौर पर numbers को 4bytes form में store किया जाता है, लेकिन आप उन्हें double या float formats में भी खोज सकते हैं, या हो सकता है कि आप कुछ और खोजना चाहते हों...](<../../images/image (324).png>)

आप **अलग-अलग** प्रकार के **searches** भी निर्दिष्ट कर सकते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आप अलग-अलग प्रकार के searches भी निर्दिष्ट कर सकते हैं](<../../images/image (311).png>)

आप memory scan करते समय **game को रोकने** के लिए checkbox को भी check कर सकते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आप memory scan करते समय game को रोकने के लिए checkbox को भी check कर सकते हैं](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ में आप अलग-अलग उद्देश्यों के लिए अलग-अलग **hotkeys** set कर सकते हैं, जैसे **game को रोकना** (जो काफी उपयोगी है, यदि किसी समय आप memory scan करना चाहते हैं)। अन्य options भी उपलब्ध हैं:

![आप क्या search कर रहे हैं? - Hotkeys: Edit -- Settings -- Hotkeys में आप अलग-अलग उद्देश्यों के लिए अलग-अलग hotkeys set कर सकते हैं, जैसे game को रोकना (जो काफी उपयोगी है, यदि किसी समय आप...](<../../images/image (864).png>)

## Value को modify करना

जब आपको वह **value** मिल जाए जिसे आप **खोज रहे हैं** (इसके बारे में अधिक जानकारी अगले steps में है), तो आप उस पर double click करके और फिर उसकी value पर double click करके उसे **modify** कर सकते हैं:

![Hotkeys - Value को modify करना: जब आपको वह value मिल जाए जिसे आप खोज रहे हैं (इसके बारे में अधिक जानकारी अगले steps में है), तो आप उस पर double click करके और फिर double click करके...](<../../images/image (563).png>)

अंत में **check mark** करके memory में modification लागू करें:

![Hotkeys - Value को modify करना: अंत में check mark करके memory में modification लागू करें](<../../images/image (385).png>)

**Memory** में किया गया **change** तुरंत **apply** हो जाएगा (ध्यान दें कि जब तक game इस value को दोबारा use नहीं करता, तब तक game में value **update नहीं होगी**)।

## Value को search करना

मान लेते हैं कि कोई महत्वपूर्ण value (जैसे आपके user की life) है जिसे आप बढ़ाना चाहते हैं और आप इस value को memory में खोज रहे हैं।

### ज्ञात change के माध्यम से

मान लें कि आप value 100 खोज रहे हैं। आप उस value को search करते हुए **scan perform** करते हैं और आपको बहुत-सी coincidences मिलती हैं:

![Value को search करना - ज्ञात change के माध्यम से: मान लें कि आप value 100 खोज रहे हैं, आप उस value को search करते हुए scan perform करते हैं और आपको बहुत-सी coincidences मिलती हैं](<../../images/image (108).png>)

फिर आप ऐसा कुछ करते हैं जिससे **value change** हो जाती है, और आप **game रोककर** एक **next scan perform** करते हैं:

![Value को search करना - ज्ञात change के माध्यम से: फिर आप ऐसा कुछ करते हैं जिससे value change हो जाती है, और आप game रोककर एक next scan perform करते हैं](<../../images/image (684).png>)

Cheat Engine उन **values** को search करेगा जो **100 से नई value में बदल गई हैं**। बधाई हो, आपको अपनी खोजी जा रही value का **address** मिल गया है; अब आप इसे modify कर सकते हैं।\
_यदि अभी भी कई values हैं, तो उस value को फिर से modify करने के लिए कुछ करें और addresses को filter करने के लिए एक और "next scan" perform करें।_

### अज्ञात Value, ज्ञात change

ऐसी स्थिति में जहाँ आपको **value का पता नहीं** है, लेकिन आप जानते हैं कि उसे **कैसे change करना है** (और change की value भी जानते हैं), आप अपना number खोज सकते हैं।

सबसे पहले "**Unknown initial value**" type का scan perform करें:

![ज्ञात change के माध्यम से - अज्ञात Value, ज्ञात change: सबसे पहले " Unknown initial value " type का scan perform करें](<../../images/image (890).png>)

फिर value को change करें, बताएं कि **value** **कैसे बदली** (मेरे मामले में यह 1 से कम हुई) और एक **next scan** perform करें:

![ज्ञात change के माध्यम से - अज्ञात Value, ज्ञात change: फिर value को change करें, बताएं कि value कैसे बदली (मेरे मामले में यह 1 से कम हुई) और एक next scan perform करें](<../../images/image (371).png>)

आपको चुने गए तरीके से **modify की गई सभी values** दिखाई जाएंगी:

![ज्ञात change के माध्यम से - अज्ञात Value, ज्ञात change: आपको चुने गए तरीके से modify की गई सभी values दिखाई जाएंगी](<../../images/image (569).png>)

जब आपको अपनी value मिल जाए, तो आप उसे modify कर सकते हैं।

ध्यान दें कि **बहुत-से संभावित changes** होते हैं और results को filter करने के लिए आप इन **steps को जितनी बार चाहें** कर सकते हैं:

![ज्ञात change के माध्यम से - अज्ञात Value, ज्ञात change: ध्यान दें कि बहुत-से संभावित changes होते हैं और results को filter करने के लिए आप इन steps को जितनी बार चाहें कर सकते हैं](<../../images/image (574).png>)

### Random Memory Address - Code खोजना

अब तक हमने सीखा कि किसी value को store करने वाला address कैसे खोजते हैं, लेकिन यह बहुत संभव है कि **game के अलग-अलग executions में वह address memory में अलग-अलग स्थानों पर हो**। इसलिए आइए जानें कि उस address को हमेशा कैसे खोजा जाए।

ऊपर बताए गए कुछ tricks का उपयोग करके वह address खोजें जहाँ आपका current game महत्वपूर्ण value store कर रहा है। फिर (यदि चाहें तो game रोककर) मिले हुए **address** पर **right click** करें और "**Find out what accesses this address**" या "**Find out what writes to this address**" select करें:

![अज्ञात Value, ज्ञात change - Random Memory Address - Code खोजना: ऊपर बताए गए कुछ tricks का उपयोग करके वह address खोजें जहाँ आपका current game महत्वपूर्ण value store कर रहा है। फिर...](<../../images/image (1067).png>)

**पहला option** यह जानने के लिए उपयोगी है कि **code** के कौन-से **parts** इस **address का use** कर रहे हैं (यह अन्य चीज़ों के लिए भी उपयोगी है, जैसे यह जानना कि आप game के **code को कहाँ modify कर सकते हैं**)।\
**दूसरा option** अधिक **specific** है और इस स्थिति में अधिक helpful होगा, क्योंकि हमारी रुचि यह जानने में है कि **यह value कहाँ से write की जा रही है**।

इनमें से किसी एक option को select करने के बाद **debugger** program से **attach** हो जाएगा और एक नई **empty window** दिखाई देगी। अब **game खेलें** और उस **value को modify** करें (game को restart किए बिना)। **Window** उन **addresses** से भर जानी चाहिए जो **value को modify** कर रहे हैं:

![अज्ञात Value, ज्ञात change - Random Memory Address - Code खोजना: इनमें से किसी एक option को select करने के बाद debugger program से attach हो जाएगा और एक नई empty window दिखाई देगी। अब...](<../../images/image (91).png>)

अब जब आपको वह address मिल गया है जो value को modify कर रहा है, तो आप अपनी **इच्छा के अनुसार code को modify** कर सकते हैं (Cheat Engine आपको इसे NOPs के लिए बहुत जल्दी modify करने देता है):

![अज्ञात Value, ज्ञात change - Random Memory Address - Code खोजना: अब जब आपको वह address मिल गया है जो value को modify कर रहा है, तो आप अपनी इच्छा के अनुसार code को modify कर सकते हैं (Cheat Engine...](<../../images/image (1057).png>)

अब आप इसे इस तरह modify कर सकते हैं कि code आपके number को affect न करे, या उसे हमेशा positive तरीके से affect करे।

### Random Memory Address - Pointer खोजना

पिछले steps को follow करते हुए अपनी रुचि वाली value का स्थान खोजें। फिर "**Find out what writes to this address**" का उपयोग करके पता लगाएँ कि कौन-सा address इस value को write करता है और disassembly view पाने के लिए उस पर double click करें:

![Random Memory Address - Code खोजना - Random Memory Address - Pointer खोजना: पिछले steps को follow करते हुए अपनी रुचि वाली value का स्थान खोजें। फिर " Find out...](<../../images/image (1039).png>)

फिर **"\[]" के बीच मौजूद hex value** को **search** करते हुए एक नया scan perform करें (इस मामले में $edx की value):

![Random Memory Address - Code खोजना - Random Memory Address - Pointer खोजना: फिर " ()" के बीच मौजूद hex value को search करते हुए एक नया scan perform करें (इस मामले में $edx की value)](<../../images/image (994).png>)

(_यदि कई results दिखाई दें, तो आमतौर पर सबसे छोटे address वाला result चाहिए_)\
अब हमें वह **pointer मिल गया है जो हमारी रुचि वाली value को modify करेगा**।

"**Add Address Manually**" पर click करें:

![Random Memory Address - Code खोजना - Random Memory Address - Pointer खोजना: " Add Address Manually " पर click करें](<../../images/image (990).png>)

अब "Pointer" checkbox पर click करें और मिले हुए address को text box में add करें (इस scenario में, पिछली image में मिला address "Tutorial-i386.exe"+2426B0 था):

![Random Memory Address - Code खोजना - Random Memory Address - Pointer खोजना: अब "Pointer" checkbox पर click करें और मिले हुए address को text box में add करें (इस scenario में,...](<../../images/image (392).png>)

(ध्यान दें कि पहला "Address" आपके द्वारा दिए गए pointer address से automatically populate हो जाता है।)

OK पर click करें और एक नया pointer create हो जाएगा:

![Random Memory Address - Code खोजना - Random Memory Address - Pointer खोजना: OK पर click करें और एक नया pointer create हो जाएगा](<../../images/image (308).png>)

अब हर बार जब आप उस value को modify करेंगे, तो आप **महत्वपूर्ण value को modify कर रहे होंगे, भले ही वह memory address अलग हो जहाँ value मौजूद है।**

### Code Injection

Code injection एक technique है जिसमें target process में code का एक हिस्सा inject किया जाता है और फिर code का execution इस तरह reroute किया जाता है कि वह आपके लिखे हुए code से होकर गुज़रे (जैसे points घटाने के बजाय आपको points देना)।

मान लें कि आपको वह address मिल गया है जो आपके player की life में से 1 घटा रहा है:

![Random Memory Address - Pointer खोजना - Code Injection: मान लें कि आपको वह address मिल गया है जो आपके player की life में से 1 घटा रहा है](<../../images/image (203).png>)

**disassemble code** पाने के लिए Show disassembler पर click करें।\
फिर Auto assemble window खोलने के लिए **CTRL+a** दबाएँ और _**Template --> Code Injection**_ select करें।

![Random Memory Address - Pointer खोजना - Code Injection: फिर Auto assemble window खोलने के लिए CTRL+a दबाएँ और Template -- Code Injection select करें](<../../images/image (902).png>)

जिस instruction को आप modify करना चाहते हैं उसका **address भरें** (यह आमतौर पर autofill होता है):

![Random Memory Address - Pointer खोजना - Code Injection: जिस instruction को आप modify करना चाहते हैं उसका address भरें (यह आमतौर पर autofill होता है)](<../../images/image (744).png>)

एक template generate होगा:

![Random Memory Address - Pointer खोजना - Code Injection: एक template generate होगा](<../../images/image (944).png>)

अब "**newmem**" section में अपना नया assembly code डालें और यदि आप original code को execute नहीं करना चाहते, तो "**originalcode**" से original code हटा दें**।** इस example में injected code 1 घटाने के बजाय 2 points add करेगा:

![Random Memory Address - Pointer खोजना - Code Injection: अब " newmem " section में अपना नया assembly code डालें और यदि आप original code को execute नहीं करना चाहते, तो " originalcode " से original code...](<../../images/image (521).png>)

**execute आदि पर click करें और आपका code program में inject हो जाना चाहिए, जिससे functionality का behaviour बदल जाएगा!**

## Cheat Engine 7.x में Advanced features (2023-2025)

Cheat Engine version 7.0 के बाद से लगातार evolve हुआ है और modern software (और केवल games ही नहीं!) का analysis करते समय कई quality-of-life और *offensive-reversing* features जोड़े गए हैं। नीचे उन additions का **बहुत संक्षिप्त field guide** दिया गया है, जिनका red-team/CTF work के दौरान आप सबसे अधिक उपयोग करेंगे।<sup>[[1]](#references)</sup>

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` और नया **Deviation** slider (≥7.4), update के बाद rescan करते समय false positives को काफी कम करते हैं। इसे multi-map comparison (`.PTR` → *Compare results with other saved pointer map*) के साथ use करके कुछ ही minutes में एक **single resilient base-pointer** प्राप्त करें।
* Bulk-filter shortcut: पहले scan के बाद `Ctrl+A → Space` दबाकर सब कुछ mark करें, फिर rescan में fail हुए addresses को deselect करने के लिए `Ctrl+I` (invert) दबाएँ।

### Ultimap 3 – Intel PT tracing
*7.5 से पुराने Ultimap को **Intel Processor-Trace (IPT)** के आधार पर re-implement किया गया है।* इसका अर्थ है कि अब आप target द्वारा लिए गए **हर branch को record** कर सकते हैं, **single-stepping** के बिना (केवल user-mode; यह अधिकांश anti-debug gadgets को trigger नहीं करेगा)।
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
कुछ सेकंड बाद capture रोकें और **right-click → Save execution list to file** चुनें। Branch addresses को `Find out what addresses this instruction accesses` session के साथ मिलाकर high-frequency game-logic hotspots को बेहद तेज़ी से खोजें।

### 1-byte `jmp` / auto-patch templates
Version 7.5 ने एक *one-byte* JMP stub (0xEB) पेश किया, जो एक SEH handler इंस्टॉल करता है और original location पर INT3 रखता है। यह तब अपने-आप generate होता है जब आप ऐसे instructions पर **Auto Assembler → Template → Code Injection** का उपयोग करते हैं जिन्हें 5-byte relative jump से patch नहीं किया जा सकता। इससे packed या size-constrained routines के अंदर “tight” hooks संभव हो जाते हैं।

### DBVM (AMD & Intel) के साथ Kernel-level stealth
*DBVM* CE का built-in Type-2 hypervisor है। हाल के builds में आखिरकार **AMD-V/SVM support** जोड़ा गया है, इसलिए आप Ryzen/EPYC hosts पर `Driver → Load DBVM` चला सकते हैं। DBVM आपको यह करने देता है:
1. Ring-3/anti-debug checks से invisible hardware breakpoints create करना।
2. User-mode driver disabled होने पर भी pageable या protected kernel memory regions को read/write करना।
3. VM-EXIT-less timing-attack bypasses करना (जैसे hypervisor से `rdtsc` query करना)।

**Tip:** Windows 11 पर HVCI/Memory-Integrity enabled होने पर DBVM load होने से मना कर देगा → इसे बंद करें या dedicated VM-host boot करें।

### **ceserver** के साथ Remote / cross-platform debugging
CE अब *ceserver* का full rewrite ship करता है और **Linux, Android, macOS & iOS** targets से TCP के ज़रिए attach कर सकता है। एक लोकप्रिय fork *Frida* को integrate करता है, जिससे dynamic instrumentation को CE के GUI के साथ combine किया जा सकता है - यह तब ideal है जब आपको phone पर चल रहे Unity या Unreal games को patch करना हो:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridge के लिए GitHub पर `bb33bb/frida-ceserver` देखें।<sup>[[2]](#references)</sup>

### अन्य उल्लेखनीय सुविधाएँ
* **Patch Scanner** (MemView → Tools) – executable sections में अप्रत्याशित code changes का पता लगाता है; malware analysis के लिए उपयोगी।
* **Structure Dissector 2** – किसी address को drag करें → `Ctrl+D`, फिर C-structures का auto-evaluation करने के लिए *Guess fields* चुनें।
* **.NET & Mono Dissector** – बेहतर Unity game support; CE Lua console से सीधे methods call करें।
* **Big-Endian custom types** – उलटे byte order में scan/edit (console emulators और network packet buffers के लिए उपयोगी)।
* AutoAssembler/Lua windows के लिए **Autosave & tabs**, साथ ही multi-line instruction rewrite के लिए `reassemble()`।

### Installation और OPSEC notes (2024-2025)
* Official installer InnoSetup **ad-offers** (`RAV` आदि) के साथ bundled है। PUPs से बचने के लिए **हमेशा *Decline* पर click करें** *या source से compile करें*। AVs फिर भी `cheatengine.exe` को *HackTool* के रूप में flag करेंगे, जो expected है।
* Modern anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) rename किए जाने पर भी CE की window class detect कर लेते हैं। अपनी reversing copy को **disposable VM के अंदर** चलाएँ या network play disable करने के बाद चलाएँ।
* यदि आपको केवल user-mode access चाहिए, तो CE के unsigned driver को load करने से बचने के लिए **`Settings → Extra → Kernel mode debug = off`** चुनें, जो Windows 11 24H2 Secure-Boot पर BSOD कर सकता है।

---

## संदर्भ

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, Cheat Engine के साथ शुरुआत करना सीखने के लिए इसे पूरा करें

{{#include ../../banners/hacktricks-training.md}}
