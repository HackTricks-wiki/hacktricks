# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जिससे running game की memory में important values कहाँ save हैं, यह पता लगाया जा सकता है और उन्हें बदला जा सकता है।\
जब आप इसे download करके run करते हैं, तो आपको tool का उपयोग करने का एक **tutorial** दिखाया जाता है। यदि आप tool का उपयोग करना सीखना चाहते हैं, तो इसे पूरा करना अत्यधिक recommended है।

## आप क्या search कर रहे हैं?

![Cheat Engine - आप क्या search कर रहे हैं?: आप क्या search कर रहे हैं?](<../../images/image (762).png>)

यह tool किसी program की **memory में कोई value** (आमतौर पर कोई number) **कहाँ stored है**, यह पता लगाने के लिए बहुत उपयोगी है।\
**आमतौर पर numbers** को **4bytes** form में stored किया जाता है, लेकिन आप उन्हें **double** या **float** formats में भी खोज सकते हैं, या हो सकता है कि आप **number के अलावा कुछ अलग** खोजना चाहें। इसलिए आपको यह सुनिश्चित करना होगा कि आप किस चीज़ को **search करना चाहते हैं**, उसे **select** करें:

![Cheat Engine - आप क्या search कर रहे हैं?: आमतौर पर numbers को 4bytes form में stored किया जाता है, लेकिन आप उन्हें double या float formats में भी खोज सकते हैं, या हो सकता है कि आप कुछ अलग खोजना चाहें...](<../../images/image (324).png>)

आप **different** प्रकार के **searches** भी specify कर सकते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आप different प्रकार के searches भी specify कर सकते हैं](<../../images/image (311).png>)

आप memory scan करते समय **game को रोकने** के लिए checkbox को select कर सकते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आप memory scan करते समय game को रोकने के लिए checkbox को select कर सकते हैं](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ में आप अलग-अलग उद्देश्यों के लिए अलग-अलग **hotkeys** set कर सकते हैं, जैसे **game को रोकना** (जो काफी उपयोगी है, यदि किसी समय आप memory scan करना चाहते हैं)। अन्य options भी उपलब्ध हैं:

![आप क्या search कर रहे हैं? - Hotkeys: Edit -- Settings -- Hotkeys में आप अलग-अलग उद्देश्यों के लिए अलग-अलग hotkeys set कर सकते हैं, जैसे game को रोकना (जो काफी उपयोगी है, यदि किसी समय आप...](<../../images/image (864).png>)

## Value को modify करना

जब आपको वह **value** मिल जाए जिसे आप **ढूँढ रहे हैं** (इसके बारे में अगले steps में अधिक जानकारी दी गई है), तो आप उस पर double click करके और फिर उसकी value पर double click करके उसे **modify** कर सकते हैं:

![Hotkeys - Value को modify करना: जब आपको वह value मिल जाए जिसे आप ढूँढ रहे हैं (इसके बारे में अगले steps में अधिक जानकारी दी गई है), तो आप उस पर double click करके और फिर उसकी value पर double click...](<../../images/image (563).png>)

अंत में modification को memory में लागू करने के लिए **check mark** करें:

![Hotkeys - Value को modify करना: अंत में modification को memory में लागू करने के लिए check mark करें](<../../images/image (385).png>)

**Memory** में किया गया **change** तुरंत **apply** हो जाएगा (ध्यान दें कि जब तक game इस value का फिर से उपयोग नहीं करता, तब तक game में value **update नहीं होगी**)।

## Value को search करना

मान लेते हैं कि कोई important value (जैसे आपके user का life) है जिसे आप बढ़ाना चाहते हैं और आप इस value को memory में खोज रहे हैं।

### ज्ञात change के माध्यम से

मान लें कि आप value 100 खोज रहे हैं। आप उस value के लिए **scan perform** करते हैं और आपको बहुत-सी matches मिलती हैं:

![Value को search करना - ज्ञात change के माध्यम से: मान लें कि आप value 100 खोज रहे हैं। आप उस value के लिए scan perform करते हैं और आपको बहुत-सी matches मिलती हैं](<../../images/image (108).png>)

फिर आप कुछ ऐसा करते हैं जिससे **value change** हो जाती है, और आप game को **stop** करके एक **next scan perform** करते हैं:

![Value को search करना - ज्ञात change के माध्यम से: फिर आप कुछ ऐसा करते हैं जिससे value change हो जाती है, और आप game को stop करके एक next scan perform करते हैं](<../../images/image (684).png>)

Cheat Engine उन **values** को search करेगा जो **100 से नई value में बदल गई हैं**। बधाई हो, आपको उस value का **address** मिल गया जिसे आप खोज रहे थे; अब आप इसे modify कर सकते हैं।\
_यदि अभी भी कई values हैं, तो उस value को फिर से modify करने के लिए कुछ करें और addresses को filter करने के लिए एक और "next scan" perform करें।_

### Unknown Value, ज्ञात change

ऐसी स्थिति में, जब आपको **value पता नहीं होती**, लेकिन आप जानते हैं कि उसे **कैसे change करना है** (और change की value भी पता है), तो आप अपना number खोज सकते हैं।

सबसे पहले "**Unknown initial value**" type का scan perform करें:

![ज्ञात change के माध्यम से - Unknown Value, ज्ञात change: सबसे पहले " Unknown initial value " type का scan perform करें](<../../images/image (890).png>)

फिर value को change करें, specify करें कि **value** **कैसे बदली** (मेरे मामले में यह 1 से decrease हुई थी) और एक **next scan** perform करें:

![ज्ञात change के माध्यम से - Unknown Value, ज्ञात change: फिर value को change करें, specify करें कि value कैसे बदली (मेरे मामले में यह 1 से decrease हुई थी) और एक next scan perform करें](<../../images/image (371).png>)

आपको चुने गए तरीके से **modify की गई सभी values** दिखाई जाएँगी:

![ज्ञात change के माध्यम से - Unknown Value, ज्ञात change: आपको चुने गए तरीके से modify की गई सभी values दिखाई जाएँगी](<../../images/image (569).png>)

जब आपको अपनी value मिल जाए, तो आप उसे modify कर सकते हैं।

ध्यान दें कि कई **possible changes** उपलब्ध हैं और results को filter करने के लिए आप इन **steps** को जितनी बार चाहें दोहरा सकते हैं:

![ज्ञात change के माध्यम से - Unknown Value, ज्ञात change: ध्यान दें कि कई possible changes उपलब्ध हैं और results को filter करने के लिए आप इन steps को जितनी बार चाहें दोहरा सकते हैं](<../../images/image (574).png>)

### Random Memory Address - code ढूँढना

अब तक हमने सीखा कि किसी value को store करने वाला address कैसे ढूँढते हैं, लेकिन यह बहुत संभव है कि **game के अलग-अलग executions में वह address memory में अलग-अलग स्थानों पर हो**। इसलिए अब पता लगाते हैं कि उस address को हमेशा कैसे ढूँढा जाए।

ऊपर बताए गए कुछ tricks का उपयोग करके वह address ढूँढें जहाँ आपका current game important value store कर रहा है। फिर (यदि चाहें तो game को stop करके) मिले हुए **address** पर **right click** करें और "**Find out what accesses this address**" या "**Find out what writes to this address**" select करें:

![Unknown Value, ज्ञात change - Random Memory Address - code ढूँढना: ऊपर बताए गए कुछ tricks का उपयोग करके वह address ढूँढें जहाँ आपका current game important value store कर रहा है। फिर...](<../../images/image (1067).png>)

**पहला option** यह जानने के लिए उपयोगी है कि **code** के कौन-से **parts** इस **address** का **उपयोग** कर रहे हैं (यह अन्य कार्यों के लिए भी उपयोगी है, जैसे यह जानना कि game के **code को कहाँ modify किया जा सकता है**)।\
**दूसरा option** अधिक **specific** है और इस स्थिति में अधिक helpful होगा, क्योंकि हम यह जानना चाहते हैं कि यह value **कहाँ से write की जा रही है**।

इनमें से कोई option select करने के बाद **debugger** program से **attach** हो जाएगा और एक नई **empty window** दिखाई देगी। अब **game खेलें** और उस **value को modify** करें (game को restart किए बिना)। **Window** में उस **value को modify करने वाले addresses** दिखाई देने चाहिए:

![Unknown Value, ज्ञात change - Random Memory Address - code ढूँढना: इनमें से कोई option select करने के बाद debugger program से attach हो जाएगा और एक नई empty window दिखाई देगी। अब...](<../../images/image (91).png>)

अब जब आपको वह address मिल गया है जो value को modify कर रहा है, तो आप अपनी इच्छा के अनुसार **code modify** कर सकते हैं (Cheat Engine इसे NOPs के लिए बहुत जल्दी modify करने की सुविधा देता है):

![Unknown Value, ज्ञात change - Random Memory Address - code ढूँढना: अब जब आपको वह address मिल गया है जो value को modify कर रहा है, तो आप अपनी इच्छा के अनुसार code modify कर सकते हैं (Cheat Engine...](<../../images/image (1057).png>)

अब आप इसे इस तरह modify कर सकते हैं कि code आपके number को affect न करे या उसे हमेशा positive तरीके से affect करे।

### Random Memory Address - pointer ढूँढना

पिछले steps का पालन करते हुए वह स्थान ढूँढें जहाँ आपकी इच्छित value है। फिर "**Find out what writes to this address**" का उपयोग करके पता लगाएँ कि कौन-सा address इस value को write करता है और disassembly view देखने के लिए उस पर double click करें:

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: पिछले steps का पालन करते हुए वह स्थान ढूँढें जहाँ आपकी इच्छित value है। फिर " Find out...](<../../images/image (1039).png>)

फिर **"\[]" के बीच मौजूद hex value** को **search** करते हुए एक नया scan perform करें (इस मामले में $edx की value):

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: फिर " ()" के बीच मौजूद hex value को search करते हुए एक नया scan perform करें (इस मामले में $edx की value)](<../../images/image (994).png>)

(_यदि कई results दिखाई दें, तो आमतौर पर सबसे छोटा address चुनना होता है_)\
अब हमें वह **pointer मिल गया है जो उस value को modify करेगा जिसमें हमारी रुचि है**।

"**Add Address Manually**" पर click करें:

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: " Add Address Manually " पर click करें](<../../images/image (990).png>)

अब "Pointer" checkbox पर click करें और मिले हुए address को text box में add करें (इस scenario में, पिछली image में मिला address "Tutorial-i386.exe"+2426B0 था):

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: अब "Pointer" checkbox पर click करें और मिले हुए address को text box में add करें (इस scenario में,...](<../../images/image (392).png>)

(ध्यान दें कि पहला "Address" आपके द्वारा enter किए गए pointer address से automatically populate हो जाता है।)

OK पर click करें और एक नया pointer create हो जाएगा:

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: OK पर click करें और एक नया pointer create हो जाएगा](<../../images/image (308).png>)

अब जब भी आप उस value को modify करेंगे, आप important value को modify कर रहे होंगे, **भले ही वह memory address अलग हो जहाँ value मौजूद है।**

### Code Injection

Code injection एक technique है जिसमें target process में code का एक हिस्सा inject किया जाता है और फिर code के execution को reroute करके आपके लिखे हुए code से execute कराया जाता है (जैसे points घटाने के बजाय आपको points देना)।

मान लें कि आपको वह address मिल गया है जो आपके player के life से 1 subtract कर रहा है:

![Random Memory Address - pointer ढूँढना - Code Injection: मान लें कि आपको वह address मिल गया है जो आपके player के life से 1 subtract कर रहा है](<../../images/image (203).png>)

**disassemble code** प्राप्त करने के लिए Show disassembler पर click करें।\
फिर Auto assemble window खोलने के लिए **CTRL+a** दबाएँ और _**Template --> Code Injection**_ select करें।

![Random Memory Address - pointer ढूँढना - Code Injection: Auto assemble window खोलने के लिए CTRL+a दबाएँ और Template -- Code Injection select करें](<../../images/image (902).png>)

जिस instruction को आप modify करना चाहते हैं उसका **address भरें** (यह आमतौर पर autofill होता है):

![Random Memory Address - pointer ढूँढना - Code Injection: जिस instruction को आप modify करना चाहते हैं उसका address भरें (यह आमतौर पर autofill होता है)](<../../images/image (744).png>)

एक template generate होगा:

![Random Memory Address - pointer ढूँढना - Code Injection: एक template generate होगा](<../../images/image (944).png>)

अब "**newmem**" section में अपना नया assembly code insert करें और यदि आप original code को execute नहीं करना चाहते, तो "**originalcode**" से original code हटा दें**।** इस example में injected code 1 subtract करने के बजाय 2 points add करेगा:

![Random Memory Address - pointer ढूँढना - Code Injection: अब " newmem " section में अपना नया assembly code insert करें और यदि आप original code को execute नहीं करना चाहते, तो " originalcode " से original code हटा दें...](<../../images/image (521).png>)

**execute आदि पर click करें और आपका code program में inject हो जाना चाहिए, जिससे functionality का behaviour बदल जाएगा!**

## Cheat Engine 7.x में Advanced features (2023-2025)

Cheat Engine version 7.0 के बाद से लगातार evolve हुआ है और कई quality-of-life तथा *offensive-reversing* features जोड़े गए हैं, जो modern software (और केवल games ही नहीं!) का analysis करते समय अत्यंत उपयोगी हैं। नीचे उन additions का **बहुत condensed field guide** दिया गया है, जिनका उपयोग आप red-team/CTF work के दौरान सबसे अधिक करेंगे।<sup>[[1]](#references)</sup>

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` और नया **Deviation** slider (≥7.4), update के बाद rescan करते समय false positives को काफी कम करते हैं। इसे multi-map comparison (`.PTR` → *Compare results with other saved pointer map*) के साथ उपयोग करके केवल कुछ मिनटों में एक **single resilient base-pointer** प्राप्त करें।
* Bulk-filter shortcut: पहले scan के बाद `Ctrl+A → Space` दबाकर सब कुछ mark करें, फिर `Ctrl+I` दबाकर उन addresses को deselect करें जो rescan में fail हुए।

### Ultimap 3 – Intel PT tracing
*7.5 से पुराने Ultimap को **Intel Processor-Trace (IPT)** के आधार पर re-implement किया गया है।* इसका मतलब है कि अब आप target द्वारा लिए गए **हर branch को record** कर सकते हैं, **single-stepping** के बिना (केवल user-mode; यह अधिकांश anti-debug gadgets को trigger नहीं करेगा)।
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
कुछ सेकंड बाद capture रोकें और **right-click → Save execution list to file** चुनें। branch addresses को `Find out what addresses this instruction accesses` session के साथ मिलाकर high-frequency game-logic hotspots को बेहद तेज़ी से खोजें।

### 1-byte `jmp` / auto-patch templates
Version 7.5 ने एक *one-byte* JMP stub (0xEB) पेश किया, जो SEH handler इंस्टॉल करता है और original location पर INT3 रखता है। यह तब अपने-आप generate होता है जब आप ऐसे instructions पर **Auto Assembler → Template → Code Injection** का उपयोग करते हैं जिन्हें 5-byte relative jump से patch नहीं किया जा सकता। इससे packed या size-constrained routines के अंदर “tight” hooks संभव हो जाते हैं।<sup>[[1]](#references)</sup>

### Kernel-level stealth with DBVM (AMD & Intel)
*DBVM*, CE का built-in Type-2 hypervisor है। हाल के builds में आखिरकार **AMD-V/SVM support** जोड़ा गया है, इसलिए आप Ryzen/EPYC hosts पर `Driver → Load DBVM` चला सकते हैं। DBVM आपको यह करने देता है:
1. Ring-3/anti-debug checks से invisible hardware breakpoints बनाना।
2. User-mode driver disabled होने पर भी pageable या protected kernel memory regions को read/write करना।
3. VM-EXIT-less timing-attack bypasses करना (उदाहरण के लिए hypervisor से `rdtsc` query करना)।

**Tip:** Windows 11 पर HVCI/Memory-Integrity enabled होने पर DBVM load होने से मना कर देगा → इसे बंद करें या dedicated VM-host boot करें।

### Remote / cross-platform debugging with **ceserver**
CE अब *ceserver* का full rewrite ship करता है और **Linux, Android, macOS & iOS** targets से TCP पर attach कर सकता है। एक लोकप्रिय fork *Frida* को integrate करता है, जिससे dynamic instrumentation को CE’s GUI के साथ combine किया जा सकता है – यह phone पर चल रहे Unity या Unreal games को patch करने के लिए आदर्श है:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridge के लिए GitHub पर `bb33bb/frida-ceserver` देखें।<sup>[[1]](#references)[[2]](#references)</sup>

### अन्य उल्लेखनीय सुविधाएँ
* **Patch Scanner** (MemView → Tools) – executable sections में अनपेक्षित code changes का पता लगाता है; malware analysis के लिए उपयोगी।
* **Structure Dissector 2** – किसी address को drag करें → `Ctrl+D`, फिर *Guess fields* चुनें ताकि C-structures का auto-evaluation हो सके।
* **.NET & Mono Dissector** – बेहतर Unity game support; CE Lua console से सीधे methods call करें।
* **Big-Endian custom types** – reversed byte order scan/edit (console emulators और network packet buffers के लिए उपयोगी)।
* AutoAssembler/Lua windows के लिए **Autosave & tabs**, साथ ही multi-line instruction rewrite के लिए `reassemble()`।<sup>[[1]](#references)</sup>

### Installation और OPSEC notes (2024-2025)
* Official installer InnoSetup **ad-offers** (`RAV` आदि) के साथ wrapped है। PUPs से बचने के लिए **हमेशा *Decline* पर click करें** *या source से compile करें*। AVs फिर भी `cheatengine.exe` को *HackTool* के रूप में flag करेंगे, जो expected है।
* Modern anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) rename किए जाने पर भी CE की window class detect करते हैं। अपनी reversing copy को **disposable VM के अंदर** चलाएँ या network play disable करने के बाद चलाएँ।
* यदि आपको केवल user-mode access चाहिए, तो CE के unsigned driver को load करने से बचने के लिए **`Settings → Extra → Kernel mode debug = off`** चुनें, जो Windows 11 24H2 Secure-Boot पर BSOD कर सकता है।

---

## References

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
