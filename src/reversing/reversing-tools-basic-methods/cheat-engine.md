# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो यह पता लगाने और बदलने में मदद करता है कि किसी running game की memory में महत्वपूर्ण values कहाँ save हैं।\
जब आप इसे download करके run करते हैं, तो tool का उपयोग कैसे करना है, इसका एक **tutorial** आपके सामने प्रस्तुत किया जाता है। यदि आप इस tool का उपयोग करना सीखना चाहते हैं, तो इसे पूरा करने की अत्यधिक अनुशंसा की जाती है।

## आप क्या search कर रहे हैं?

![Cheat Engine - आप क्या search कर रहे हैं?: आप क्या search कर रहे हैं?](<../../images/image (762).png>)

यह tool किसी program की **memory में कोई value** (आमतौर पर कोई number) **कहाँ stored है**, यह पता लगाने के लिए बहुत उपयोगी है।\
**आमतौर पर numbers** को **4bytes** form में store किया जाता है, लेकिन आप उन्हें **double** या **float** formats में भी ढूँढ सकते हैं, या हो सकता है कि आप **number से अलग** कुछ खोजना चाहते हों। इसलिए आपको यह सुनिश्चित करना होगा कि आप वह चीज़ **select** करें जिसे आप **search** करना चाहते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आमतौर पर numbers को 4bytes form में store किया जाता है, लेकिन आप उन्हें double या float formats में भी ढूँढ सकते हैं, या हो सकता है कि आप कुछ और खोजना चाहते हों...](<../../images/image (324).png>)

आप **searches** के अलग-अलग **types** भी चुन सकते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आप searches के अलग-अलग types भी चुन सकते हैं](<../../images/image (311).png>)

आप **memory scan करते समय game को रोकने** के लिए checkbox भी select कर सकते हैं:

![Cheat Engine - आप क्या search कर रहे हैं?: आप memory scan करते समय game को रोकने के लिए checkbox भी select कर सकते हैं](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ में आप अलग-अलग उद्देश्यों के लिए विभिन्न **hotkeys** set कर सकते हैं, जैसे **game को रोकना** (जो उस समय काफी उपयोगी होता है जब आप memory scan करना चाहते हैं)। अन्य options भी उपलब्ध हैं:

![आप क्या search कर रहे हैं? - Hotkeys: Edit -- Settings -- Hotkeys में आप अलग-अलग उद्देश्यों के लिए विभिन्न hotkeys set कर सकते हैं, जैसे game को रोकना (जो उस समय काफी उपयोगी होता है जब आप...](<../../images/image (864).png>)

## Value को modify करना

जब आप वह **value** **ढूँढ लेते हैं** जिसे आप **search** कर रहे हैं (इसके बारे में आगे के steps में अधिक जानकारी दी गई है), तो आप उस पर double-click करके और फिर उसकी value पर double-click करके उसे **modify** कर सकते हैं:

![Hotkeys - Value को modify करना: जब आप वह value ढूँढ लेते हैं जिसे आप search कर रहे हैं (इसके बारे में आगे के steps में अधिक जानकारी दी गई है), तो आप उस पर double-click करके और फिर उसकी value पर double-click करके...](<../../images/image (563).png>)

अंत में memory में modification करने के लिए **checkmark select** करें:

![Hotkeys - Value को modify करना: अंत में memory में modification करने के लिए checkmark select करें](<../../images/image (385).png>)

**Memory** में किया गया **change** तुरंत **apply** हो जाएगा (ध्यान दें कि जब तक game इस value का दोबारा उपयोग नहीं करता, तब तक यह value game में **update नहीं होगी**)।

## Value को search करना

मान लेते हैं कि कोई महत्वपूर्ण value (जैसे आपके user की life) है जिसे आप बढ़ाना चाहते हैं और आप इस value को memory में ढूँढ रहे हैं।

### ज्ञात change के माध्यम से

मान लेते हैं कि आप value 100 खोज रहे हैं। आप उस value को search करके **scan perform** करते हैं और आपको बहुत-से matches मिलते हैं:

![Value को search करना - ज्ञात change के माध्यम से: मान लेते हैं कि आप value 100 खोज रहे हैं। आप उस value को search करके scan perform करते हैं और आपको बहुत-से matches मिलते हैं](<../../images/image (108).png>)

फिर आप ऐसा कुछ करते हैं जिससे **value बदल जाती है**, और आप game को **रोककर** एक **next scan perform** करते हैं:

![Value को search करना - ज्ञात change के माध्यम से: फिर आप ऐसा कुछ करते हैं जिससे value बदल जाती है, और आप game को रोककर next scan perform करते हैं](<../../images/image (684).png>)

Cheat Engine उन **values** को search करेगा जो **100 से नई value में बदल गई हैं**। बधाई हो, आपको उस value का **address** मिल गया है जिसे आप खोज रहे थे; अब आप इसे modify कर सकते हैं।\
_यदि अभी भी कई values हैं, तो उस value को फिर से modify करने के लिए कुछ करें और addresses को filter करने के लिए एक और "next scan" perform करें।_

### Unknown Value, known change

ऐसी स्थिति में जहाँ आपको **value का पता नहीं है**, लेकिन आप जानते हैं कि इसे **कैसे बदला जा सकता है** (और change की value भी पता है), आप अपना number खोज सकते हैं।

सबसे पहले "**Unknown initial value**" type का scan perform करें:

![ज्ञात change के माध्यम से - Unknown Value, known change: सबसे पहले " Unknown initial value " type का scan perform करें](<../../images/image (890).png>)

फिर value को बदलें, बताएं कि **value** **कैसे बदली** (मेरे मामले में यह 1 से कम हुई थी) और एक **next scan** perform करें:

![ज्ञात change के माध्यम से - Unknown Value, known change: फिर value को बदलें, बताएं कि value कैसे बदली (मेरे मामले में यह 1 से कम हुई थी) और next scan perform करें](<../../images/image (371).png>)

आपके सामने वे सभी **values** प्रस्तुत की जाएँगी जो चुने गए तरीके से **modify हुई हैं**:

![ज्ञात change के माध्यम से - Unknown Value, known change: आपके सामने वे सभी values प्रस्तुत की जाएँगी जो चुने गए तरीके से modify हुई हैं](<../../images/image (569).png>)

जब आपको अपनी value मिल जाए, तो आप उसे modify कर सकते हैं।

ध्यान दें कि **बहुत-से possible changes** हो सकते हैं और results को filter करने के लिए आप इन **steps** को जितनी बार चाहें perform कर सकते हैं:

![ज्ञात change के माध्यम से - Unknown Value, known change: ध्यान दें कि बहुत-से possible changes हो सकते हैं और results को filter करने के लिए आप इन steps को जितनी बार चाहें perform कर सकते हैं](<../../images/image (574).png>)

### Random Memory Address - code ढूँढना

अब तक हमने सीखा कि किसी value को store करने वाला address कैसे ढूँढते हैं, लेकिन बहुत संभव है कि **game के अलग-अलग executions में वह address memory में अलग-अलग स्थानों पर हो**। इसलिए आइए जानें कि उस address को हमेशा कैसे ढूँढा जाए।

ऊपर बताए गए कुछ तरीकों का उपयोग करके वह address ढूँढें जहाँ आपका current game महत्वपूर्ण value store कर रहा है। फिर (यदि आप चाहें तो game को रोककर) मिले हुए **address** पर **right-click** करें और "**Find out what accesses this address**" या "**Find out what writes to this address**" select करें:

![Unknown Value, known change - Random Memory Address - code ढूँढना: ऊपर बताए गए कुछ तरीकों का उपयोग करके वह address ढूँढें जहाँ आपका current game महत्वपूर्ण value store कर रहा है। फिर...](<../../images/image (1067).png>)

**पहला option** यह जानने के लिए उपयोगी है कि **code के कौन-से parts** इस **address** का **उपयोग** कर रहे हैं (यह अन्य चीज़ों के लिए भी उपयोगी है, जैसे यह जानना कि game के **code को कहाँ modify किया जा सकता है**)।\
**दूसरा option** अधिक **specific** है और इस मामले में अधिक उपयोगी होगा, क्योंकि हम यह जानना चाहते हैं कि **यह value कहाँ से write की जा रही है**।

इनमें से किसी एक option को select करने के बाद **debugger** program से **attach** हो जाएगा और एक नई **empty window** दिखाई देगी। अब **game खेलें** और उस **value को modify** करें (game को restart किए बिना)। **Window** में उन **addresses** की list आ जानी चाहिए जो **value को modify** कर रहे हैं:

![Unknown Value, known change - Random Memory Address - code ढूँढना: इनमें से किसी एक option को select करने के बाद debugger program से attach हो जाएगा और एक नई empty window दिखाई देगी। अब...](<../../images/image (91).png>)

अब जब आपको वह address मिल गया है जो value को modify कर रहा है, तो आप अपनी इच्छा के अनुसार **code modify** कर सकते हैं (Cheat Engine इसे NOPs के लिए बहुत जल्दी modify करने की सुविधा देता है):

![Unknown Value, known change - Random Memory Address - code ढूँढना: अब जब आपको वह address मिल गया है जो value को modify कर रहा है, तो आप अपनी इच्छा के अनुसार code modify कर सकते हैं (Cheat Engine...](<../../images/image (1057).png>)

अब आप इसे इस तरह modify कर सकते हैं कि code आपके number को प्रभावित न करे या हमेशा positive तरीके से प्रभावित करे।

### Random Memory Address - pointer ढूँढना

पिछले steps का पालन करते हुए वह स्थान ढूँढें जहाँ आपकी रुचि वाली value है। फिर "**Find out what writes to this address**" का उपयोग करके पता लगाएँ कि कौन-सा address इस value को write करता है और disassembly view खोलने के लिए उस पर double-click करें:

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: पिछले steps का पालन करते हुए वह स्थान ढूँढें जहाँ आपकी रुचि वाली value है। फिर " Find out...](<../../images/image (1039).png>)

फिर **"\[]"** के बीच मौजूद hex value को **search** करके एक नया scan perform करें (इस मामले में $edx की value):

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: फिर " ()" के बीच मौजूद hex value को search करके एक नया scan perform करें (इस मामले में $edx की value)](<../../images/image (994).png>)

(_यदि कई results दिखाई दें, तो आमतौर पर सबसे छोटे address वाला result आवश्यक होता है_)\
अब हमें वह **pointer मिल गया है जो हमारी रुचि वाली value को modify करेगा**।

"**Add Address Manually**" पर click करें:

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: " Add Address Manually " पर click करें](<../../images/image (990).png>)

अब "Pointer" checkbox पर click करें और मिले हुए address को text box में add करें (इस स्थिति में, पिछली image में मिला address "Tutorial-i386.exe"+2426B0 था):

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: अब "Pointer" checkbox पर click करें और मिले हुए address को text box में add करें (इस स्थिति में,...](<../../images/image (392).png>)

(ध्यान दें कि आपके द्वारा दिए गए pointer address से पहला "Address" अपने-आप populate हो जाता है।)

OK पर click करें और एक नया pointer create हो जाएगा:

![Random Memory Address - code ढूँढना - Random Memory Address - pointer ढूँढना: OK पर click करें और एक नया pointer create हो जाएगा](<../../images/image (308).png>)

अब हर बार जब आप उस value को modify करेंगे, तो आप महत्वपूर्ण value को modify कर रहे होंगे, भले ही वह memory address अलग हो जहाँ value मौजूद है।

### Code Injection

Code injection एक technique है जिसमें आप target process में code का एक हिस्सा inject करते हैं और फिर code के execution को अपने लिखे हुए code से होकर जाने के लिए reroute करते हैं (जैसे points घटाने के बजाय आपको points देना)।

मान लें कि आपको वह address मिल गया है जो आपके player की life में से 1 subtract कर रहा है:

![Random Memory Address - pointer ढूँढना - Code Injection: मान लें कि आपको वह address मिल गया है जो आपके player की life में से 1 subtract कर रहा है](<../../images/image (203).png>)

**disassemble code** प्राप्त करने के लिए Show disassembler पर click करें।\
फिर Auto assemble window खोलने के लिए **CTRL+a** दबाएँ और _**Template --> Code Injection**_ select करें।

![Random Memory Address - pointer ढूँढना - Code Injection: फिर Auto assemble window खोलने के लिए CTRL+a दबाएँ और Template -- Code Injection select करें](<../../images/image (902).png>)

उस instruction का **address भरें जिसे आप modify करना चाहते हैं** (यह आमतौर पर अपने-आप भर जाता है):

![Random Memory Address - pointer ढूँढना - Code Injection: उस instruction का address भरें जिसे आप modify करना चाहते हैं (यह आमतौर पर अपने-आप भर जाता है)](<../../images/image (744).png>)

एक template generate किया जाएगा:

![Random Memory Address - pointer ढूँढना - Code Injection: एक template generate किया जाएगा](<../../images/image (944).png>)

अब अपना नया assembly code "**newmem**" section में insert करें और यदि आप original code को execute नहीं करना चाहते, तो उसे "**originalcode**" से remove कर दें**.** इस example में injected code 1 subtract करने के बजाय 2 points add करेगा:

![Random Memory Address - pointer ढूँढना - Code Injection: अब अपना नया assembly code " newmem " section में insert करें और यदि आप original code को execute नहीं करना चाहते, तो उसे " originalcode " से...](<../../images/image (521).png>)

**execute आदि पर click करें और आपका code program में inject हो जाना चाहिए, जिससे functionality का behaviour बदल जाएगा!**

## AOB signatures के साथ relocation-safe code injection

`game.exe+123456` पर hook करने वाली script ASLR या software update के बाद काम करना बंद कर सकती है। एक **Array of Bytes (AOB) signature** instruction के आसपास के machine code से उस instruction को ढूँढती है। Search को एक module तक सीमित करने के लिए `aobscanmodule` का उपयोग करें। Signature इतनी लंबी रखें कि केवल एक match मिले। Relocation bytes, addresses और ऐसे अन्य bytes के लिए wildcard का उपयोग करें जो बदल सकते हैं। जिस पूरी instruction को restore करना है, उस पर wildcard का उपयोग न करें।<sup>[[4]](#references)</sup>

Memory View में instruction select करें और **Tools → Auto Assemble → Template → AOB Injection** का उपयोग करें। Generate हुआ `[DISABLE]` block महत्वपूर्ण है। इसे overwrite किए गए प्रत्येक byte को restore करना और allocation को free करना आवश्यक है।<sup>[[4]](#references)</sup>

<details>
<summary>Minimal x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

स्क्रिप्ट enable करने से पहले इन बिंदुओं को verify करें:

1. AOB केवल **एक** address लौटाता है। यदि यह अधिक लौटाता है, तो दोनों ओर stable instructions जोड़ें।
2. Jump पूरी instructions को replace करता है। किसी instruction को कभी split न करें।
3. Allocated cave generated jump से reachable है। x64 पर far allocation के लिए 14-byte jump की आवश्यकता हो सकती है।
4. Injected code उन registers, flags और stack alignment को preserve करता है जिनकी original function अपेक्षा करती है।
5. Disable block exact original bytes को restore करता है। Table save करने से पहले enable और disable को कई बार test करें।

## Reliable pointer workflow

एक run में मिला pointer केवल एक candidate है। कई fresh executions में pointer maps बनाएं और उन सभी के विरुद्ध rescan करें। Captures के बीच target को restart करें, ताकि ASLR और heap allocations बदलें। ऐसे paths को प्राथमिकता दें जिनका base कोई module या अन्य stable symbol हो। उन paths को reject करें जो केवल एक save, level या object instance के साथ काम करते हैं।

**The pointer must end with specific offsets** filter और इसका deviation option तब उपयोगी paths को बनाए रख सकता है जब builds के बीच कोई nearby field move हो। 7.5 release में यह deviation control भी जोड़ा गया था। यह एक filter है, pointer chain के stable होने का proof नहीं।<sup>[[1]](#references)</sup>

जब कोई structure pointer scanning के लिए बहुत अधिक बार move हो, तो उस instruction को hook करें जो उसे access करती है। Live object pointer को किसी register से allocated symbol में capture करें। Entity lists और managed objects के लिए यह अक्सर अधिक reliable होता है।

## Values scan करने के बजाय code tracing

जब value सीधे modify हो रही हो, तो **Find out what writes to this address** का उपयोग करें। जब आपको owning object की आवश्यकता हो या write copied data के माध्यम से होती हो, तो **Find out what accesses this address** का उपयोग करें। Target में केवल एक action trigger करें। फिर hit count और register state की तुलना करें।

**Ultimap 2** supported Intel CPUs पर Intel Processor Trace का उपयोग करता है। यह हर instruction को step करने की तुलना में कम interruption के साथ executed control flow record करता है। उस code के लिए filter करें जो interesting action के दौरान execute हुआ था और उस code को हटा दें जो idle capture के दौरान भी execute हुआ था। Intel PT कोई stealth feature नहीं है। Target tracing, timing changes या स्वयं Cheat Engine का पता लगा सकता है।<sup>[[1]](#references)</sup>

Cheat Engine 7.5 ने Windows द्वारा प्रदान किया गया Intel PT interface भी जोड़ा। पुराने DBVM-backed Ultimap mode और Intel PT mode की hardware तथा OS requirements अलग-अलग हैं। यह न मानें कि DBVM-capable CPU Intel PT को support करता है।<sup>[[1]](#references)</sup>

## Debugger और breakpoint selection

जो debugger काम करता हो, उसमें सबसे कम invasive विकल्प चुनें:

- **Windows debugger** सरल है, लेकिन normal debug events बनाता है। Anti-debugging checks इसका पता लगा सकते हैं।
- **VEH debugger** vectored exception handler के माध्यम से breakpoints handle करता है। यह कुछ basic debugger checks से बचता है, लेकिन invisible नहीं है।
- **Hardware breakpoints** instruction bytes को patch नहीं करते, लेकिन x86/x64 में debug-register slots की संख्या बहुत कम होती है।
- **Software breakpoints** एक byte को `INT3` से replace करते हैं। इनका पता लगाना आसान है और ये integrity checks के साथ conflict कर सकते हैं।
- **DBVM debugger** कुछ operations को guest OS के नीचे ले जाता है। इसके पास कहीं अधिक privilege होता है और misconfigured होने पर यह host को crash कर सकता है।

Cheat Engine 7.5 exception handler और `INT3` पर आधारित one-byte jump का उपयोग कर सकता है, जब normal relative jump के लिए पर्याप्त जगह न हो। इसे software breakpoint की तरह समझें। Exception flow verify करें और यह न मानें कि यह anti-tamper checks को bypass करता है।<sup>[[1]](#references)</sup>

DBVM एक hypervisor है, general invisibility switch नहीं। इसका उपयोग केवल disposable lab में करें। इसके control interface को untrusted code के सामने expose न करें। Kernel anti-cheat और endpoint products driver, hypervisor state या modified memory का अभी भी पता लगा सकते हैं।

## Managed runtimes और recent 7.6/7.7 features

Mono, IL2CPP, .NET और Java targets के लिए, जब उपलब्ध हो, blind scans के बजाय runtime metadata को प्राथमिकता दें। **Mono → Activate mono features** या संबंधित runtime information window खोलें। पहले class, field या method locate करें। इसके बाद managed method के JIT-compiled होने पर native disassembly का उपयोग करें।

7.6 line में executable-memory-only signatures के लिए `AOBSCANEX`, एक `gdbserver` debugger interface, Java metadata inspection, तेज़ IL2CPP enumeration और ऐसा pointer-scan option जो ARM memory tagging द्वारा उपयोग किए जाने वाले upper pointer byte को ignore करता है, जोड़े गए। 7.7 line में native Linux builds, `HOOK`/`UNHOOK`, `aobscanfunction`, बेहतर generic Mono method lookup, improved PDB structure support और basic Unreal Engine structure dissection जोड़े गए।<sup>[[3]](#references)</sup>

ये additions एक उपयोगी workflow enable करते हैं:

1. Metadata से managed method या static field resolve करें।
2. उस method के लिए produced native code को trace या disassemble करें।
3. Stable executable signature locate करने के लिए `AOBSCANEX` या `aobscanfunction` का उपयोग करें।
4. Reversible hook generate करें। Original instructions रखें और disable path validate करें।
5. हर target update के बाद signature को फिर से check करें। Successful match यह guarantee नहीं करता कि surrounding logic का अर्थ अभी भी वही है।

## `ceserver` के साथ Remote targets

`ceserver` Cheat Engine GUI को process enumeration, memory access और debugging उपलब्ध कराता है। Official builds Linux और Android को cover करते हैं। Target पर matching architecture run करें और **Network** tab के माध्यम से connect करें। Android पर default port को forward करने से इसे network पर expose करने से बचा जा सकता है:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
तृतीय-पक्ष `frida-ceserver` bridge iOS targets के लिए Cheat Engine-compatible interface प्रदान कर सकता है। यह official `ceserver` नहीं है और इसके supported operations अलग हो सकते हैं।<sup>[[2]](#references)</sup>

मान लें कि protocol debugger-level access प्रदान करता है। इसे loopback से bind करें या SSH/ADB tunnel के पीछे रखें। TCP 52736 को कभी भी किसी untrusted network के सामने expose न करें। Session समाप्त होने पर server को stop कर दें।

## संचालन संबंधी सुरक्षा

केवल उसी software से attach करें जिसके आप स्वामी हैं या जिसका परीक्षण करने के लिए अधिकृत हैं। Online game या production endpoint के साथ Cheat Engine न चलाएँ। Memory writes, injected code, drivers और DBVM target को crash या corrupt कर सकते हैं।<sup>[[3]](#references)</sup>

Builds को official site से download करें या published source compile करें। Security products अक्सर memory editors, debuggers और उनके drivers को hack tools के रूप में classify करते हैं। Host protection को globally disable न करें। Dedicated VM या lab host का उपयोग करें और उसे चलाने से पहले artifact verify करें।<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5 release notes](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [remote targets के लिए frida-ceserver bridge](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine official release news](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
