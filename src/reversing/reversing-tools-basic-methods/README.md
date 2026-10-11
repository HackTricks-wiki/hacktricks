# रिवर्सिंग टूल्स और बुनियादी तरीके

{{#include ../../banners/hacktricks-training.md}}

## ImGui आधारित रिवर्सिंग टूल्स

सॉफ़्टवेयर:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

ऑनलाइन:

- wasm (binary) से wat (स्पष्ट टेक्स्ट) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
- wat से wasm में **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें
- आप decompilation के लिए [web-wasmdec](https://wwwg.github.io/web-wasmdec/) भी आज़मा सकते हैं।

सॉफ़्टवेयर:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक decompiler है, जो **कई फ़ॉर्मैट को decompile करके उनकी जाँच करता है**, जिनमें **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe) शामिल हैं। Decompile करने के बाद, किसी assembly को Visual Studio project (.csproj) के रूप में सेव किया जा सकता है।

इसका फ़ायदा यह है कि अगर किसी खोए हुए source code को पुराने assembly से बहाल करना हो, तो इससे समय बच सकता है। इसके अलावा, dotPeek decompiled code में आसानी से नेविगेट करने की सुविधा देता है, जिससे यह **Xamarin algorithm analysis** के लिए एक बेहतरीन टूल बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक add-in model और आपकी ज़रूरतों के अनुसार टूल को ढालने वाली API के साथ, .NET Reflector समय बचाता है और development को सरल बनाता है। आइए, इस टूल की reverse engineering सेवाओं पर नज़र डालें:

- यह दिखाता है कि किसी library या component में data का प्रवाह कैसे होता है
- .NET languages और frameworks के implementation और उपयोग की जानकारी देता है
- इस्तेमाल किए जा रहे APIs और technologies से अधिक लाभ लेने के लिए undocumented और unexposed functionality खोजता है।
- dependencies और अलग-अलग assemblies ढूँढ़ता है
- आपके code, third-party components और libraries में errors की सटीक जगह का पता लगाता है।
- आपके द्वारा इस्तेमाल किए जा रहे सभी .NET code के source को debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) और [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): इसे किसी भी OS पर इस्तेमाल किया जा सकता है (आप इसे सीधे VSCode से install कर सकते हैं; git download करने की ज़रूरत नहीं है। **Extensions** पर क्लिक करें और **ILSpy खोजें**)।\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसके सक्रिय रूप से maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) का उपयोग कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** चुनें।)

### DNSpy Logging

**DNSpy से किसी फ़ाइल में कुछ जानकारी log करवाने** के लिए, आप यह snippet इस्तेमाल कर सकते हैं:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy का उपयोग करके code debug करने के लिए आपको:

सबसे पहले, **debugging** से संबंधित **Assembly attributes** बदलें:

![DNSpy Logging - DNSpy Debugging: सबसे पहले, debugging से संबंधित Assembly attributes बदलें](<../../images/image (973).png>)

इससे:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

को:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

और **compile** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: और compile पर क्लिक करें](<../../images/image (314) (1).png>)

फिर _**File >> Save module...**_ के ज़रिए नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: फिर File Save module के ज़रिए नई फ़ाइल सेव करें](<../../images/image (602).png>)

यह ज़रूरी है, क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** में कोड पर कई **optimisations** लागू होंगे और ऐसा हो सकता है कि debugging के दौरान **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, अगर आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस तरह **restart** कर सकते हैं:

```
iisreset /noforce
```

फिर debugging शुरू करने के लिए सभी खुली हुई files बंद करें और **Debug Tab** में **Attach to Process...** चुनें:

![DNSpy Logging - DNSpy Debugging: फिर debugging शुरू करने के लिए सभी खुली हुई files बंद करें और Debug Tab में Attach to Process चुनें](<../../images/image (318).png>)

फिर **w3wp.exe** चुनकर **IIS server** से attach करें और **attach** पर click करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर click करें](<../../images/image (113).png>)

अब जबकि हम process को debug कर रहे हैं, इसे रोकने और सभी modules load करने का समय है। पहले _Debug >> Break All_ पर click करें, फिर _**Debug >> Windows >> Modules**_ पर click करें:

![DNSpy Logging - DNSpy Debugging: अब जबकि हम process को debug कर रहे हैं, इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर click करें, फिर Debug Windows Modules पर click करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जबकि हम process को debug कर रहे हैं, इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर click करें, फिर Debug Windows Modules पर click करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर click करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर click करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर click करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right click करें और Sort Assemblies पर click करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की debugging

### IDA का उपयोग

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe में और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe में)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - IDA का उपयोग: " Suspend on library load/unload " चुनें](<../../images/image (868).png>)

- execution के **parameters** configure करें और **DLL का path** तथा जिस function को call करना है, उसे डालें:

![Debugging DLLs - IDA का उपयोग: execution के parameters configure करें और DLL का path तथा जिस function को call करना है, उसे डालें](<../../images/image (704).png>)

फिर, debugging शुरू करने पर **हर DLL load होने पर execution रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL load करेगा, तब execution रुक जाएगा।

यह तरीका module-load events पर रुकता है, लेकिन loaded DLL के entry point तक पहुँचना नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe में और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe में)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा जिस function को call करना है, उसे set करें। उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**। debugger हर dll main पर रुकेगा और किसी बिंदु पर **आपकी dll के Entry पर रुकेगा**। वहाँ से, बस उन points को खोजें जहाँ breakpoint लगाना है।

ध्यान दें कि win64dbg में किसी भी कारण से execution रुकने पर, **win64dbg window के सबसे ऊपर** देखकर आप जान सकते हैं कि **आप किस code में हैं**:

![IDA का उपयोग - x64dbg/x32dbg का उपयोग: ध्यान दें कि win64dbg में किसी भी कारण से execution रुकने पर, win64dbg window के सबसे ऊपर देखकर आप जान सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि execution उस DLL के अंदर रुका है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) running game की memory में महत्वपूर्ण values कहाँ save हैं, यह खोजने और उन्हें बदलने के लिए एक उपयोगी program है। अधिक जानकारी यहाँ:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालाँकि, इसे reverse-engineering से जुड़ी किसी भी चीज़ के लिए इस्तेमाल किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner से shellcode की debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** allocate करता है, उसका **memory address** print करता है और execution को pause करता है।\
IDA या x64dbg जैसे debugger को attach करें, print किए गए address पर breakpoint set करें और shellcode debug करने के लिए execution resume करें।

releases github page में compiled releases वाली zips मौजूद हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप नीचे दिए गए link पर Blobrunner का थोड़ा modified version पा सकते हैं। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएँ, code copy और paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it से shellcode की debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) BlobRunner जैसा है। यह shellcode allocate करता है और एक infinite loop में प्रवेश करता है। debugger attach करें, **2–5 seconds** के लिए resume करें, उस loop के अंदर pause करें और फिर उस अगले call तक step करें जो execution को allocated shellcode में transfer करता है।

![jmp2it के infinite loop में debugger रुका हुआ, allocated shellcode के call से ठीक पहले](<../../images/image (509).png>)

आप [releases page में jmp2it का compiled version](https://github.com/adamkramer/jmp2it/releases/) download कर सकते हैं।

### Cutter का उपयोग करके shellcode की debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode emulate कर सकते हैं और इसे dynamically inspect कर सकते हैं।

ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" विकल्प देता है। मेरे मामले में, shellcode को file के रूप में खोलने पर उसने इसे सही ढंग से decompile किया, लेकिन shellcode के रूप में खोलने पर ऐसा नहीं हुआ:

![Cutter में वही bytes file और shellcode के रूप में खोलने पर analysis के अलग-अलग नतीजे](<../../images/image (562).png>)

जिस जगह से emulation शुरू करनी है, वहाँ bp set करें। ऐसा लगता है कि Cutter अपने-आप वहीं से emulation शुरू कर देगा:

![Cutter emulation शुरू करने से पहले इच्छित shellcode entry पर breakpoint set करना](<../../images/image (589).png>)

![Cutter emulator चुने हुए shellcode breakpoint पर रुका हुआ](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump में देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### shellcode को deobfuscate करना और execute हुए functions प्राप्त करना

आप [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़मा सकते हैं।\
यह आपको बताएगा कि shellcode किन **functions** का उपयोग कर रहा है और क्या shellcode memory में खुद को **decode** कर रहा है।

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg में एक graphical launcher भी है, जहाँ आप अपने इच्छित विकल्प चुनकर shellcode execute कर सकते हैं

![shellcode emulation और tracing विकल्प चुनने के लिए scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** विकल्प, shellcode के memory में dynamically बदलने पर, अंतिम shellcode का dump बनाएगा (decoded shellcode डाउनलोड करने के लिए उपयोगी)। **start offset** किसी विशिष्ट offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** विकल्प scDbg terminal का उपयोग करके shellcode debug करने के लिए उपयोगी है (हालाँकि इस काम के लिए मुझे पहले बताए गए विकल्प बेहतर लगते हैं, क्योंकि उनसे आप Ida या x64dbg का उपयोग कर सकेंगे)।

### CyberChef का उपयोग करके Disassemble करना

अपनी shellcode फ़ाइल को input के रूप में upload करें और उसे decompile करने के लिए यह recipe इस्तेमाल करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` जैसे सरल expressions को ऐसे formulas के पीछे छिपाता है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाते हैं। महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** में ही सही होती हैं, इसलिए carry और overflow मायने रखते हैं:

```c
(x ^ y) + 2 * (x & y) == x + y
```

अगर आप इस तरह की expression को generic algebra tooling से simplify करते हैं, तो bit-width semantics को नज़रअंदाज़ करने के कारण आसानी से गलत नतीजा मिल सकता है।<sup>[[1]](#references)</sup>

### व्यावहारिक workflow

1. Lift किए गए code/IR/decompiler output से **मूल bit-width** बनाए रखें (`8/16/32/64` bits)।
2. इसे simplify करने की कोशिश करने से पहले expression को **वर्गीकृत** करें:
   - **Linear**: bitwise atoms के weighted sums
   - **Semilinear**: linear expression के साथ constant masks, जैसे `x & 0xFF`
   - **Polynomial**: इसमें products हों
   - **Mixed**: products और bitwise logic आपस में मिले हों, अक्सर repeated subexpressions के साथ
3. हर candidate rewrite को random testing या SMT proof से **verify** करें। अगर equivalence prove नहीं की जा सकती, तो अनुमान लगाने के बजाय मूल expression को ही रखें।

### संकीर्ण execution slice से flattened control flow को bypass करें

पूरा control-flow graph recover करना अक्सर ज़रूरी नहीं होता। Control-flow flattening, opaque predicates, बड़े dispatchers या MBA-heavy code के मामले में, encrypted blobs और output buffers से उन सबसे छोटी routines तक references का अनुसरण करें जो उन्हें transform करती हैं। फिर केवल उस data-flow slice को reproduce करें या उसे स्वतंत्र रूप से execute करें; अगर relevant state को सीधे initialize किया जा सकता है, तो dispatcher आवश्यक solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक व्यावहारिक workflow:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations और cross-references की सूची बनाएँ। `.rodata` से candidate tables dump करते समय उनका byte order और element width बनाए रखें।
2. उस आखिरी routine की पहचान करें जो plaintext या output buffer में लिखती है। उसके inputs, referenced tables, imported calls और आवश्यक global state दर्ज करें।
3. केवल उन्हीं operations को fixed-width Python model में lift करें। अगर slice अब भी बहुत अधिक state पर निर्भर है, तो पूरे program को emulate करने के बजाय routine को Unicorn, QEMU या debugger के तहत invoke करें और अप्रासंगिक imports को hook करें।
4. Validate करें कि extractor सच में दिए गए binary से अपना output निकालता है: silent fallbacks हटाएँ, उसमें embedded answers खोजें, और बदले हुए strings, keys, identifiers, layouts और obfuscation seeds वाले unseen builds पर इसे चलाएँ।

पहले चरण में काम आने वाली commands:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### disguised constants के रूप में छिपे MBA expressions का पता लगाएँ

दिखने में input पर निर्भर byte expression, input को पूरी तरह रद्द कर सकता है। इसकी tables निकालने के बाद, expression को पूरे 8-bit domain पर evaluate करें; singleton output set साबित करता है कि वह byte constant है—इसके लिए आसपास की state machine को recover करने की ज़रूरत नहीं होती।<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

अंतिम mask बनाए रखें, क्योंकि मूल जोड़ में byte-width wraparound होता है। बड़े domain के लिए, SMT solver से पूछें कि क्या समान-width वाले दो symbolic inputs के लिए `f(x1) != f(x2)` satisfiable है: `unsat` invariance साबित करता है, जबकि `sat` एक counterexample देता है और इसका अर्थ है कि input को हटाया नहीं जा सकता।<sup>[[7]](#references)</sup>

#### Environment-bound decoding पहचानें

Anti-analysis checks के लिए branch करना या crash होना ज़रूरी नहीं है। कोई decoder sensor result को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से जारी रह सकता है, और emulator में विश्वसनीय दिखने वाला लेकिन गलत plaintext दे सकता है। इसलिए, केवल दिखाई देने वाली failure branches को patch करना पर्याप्त नहीं है; environment probes से decoder state तक data dependencies trace करें, authentic device और emulator पर उसी slice की तुलना करें, और जाँचें कि हर sensor result को force करने से अंतिम buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक व्यावहारिक MBA simplifier है। यह expression को classify करता है और सब पर एक ही generic rewrite pass लागू करने के बजाय उसे specialized pipelines से गुज़ारता है।<sup>[[2]](#references)</sup>

त्वरित उपयोग:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

उपयोगी मामले:

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature निकालता है, और pattern matching, ANF conversion तथा coefficient interpolation जैसे कई recovery methods को आज़माता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर बनाया जाता है, ताकि masked regions सही रहें।
- **Polynomial/Mixed MBA**: products को cores में विभाजित किया जाता है और outer relation को simplify करने से पहले repeated subexpressions को temporaries में रखा जा सकता है।

एक mixed identity का उदाहरण, जिसे recover करने की कोशिश करना अक्सर उपयोगी होता है:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

इसे घटाकर यह किया जा सकता है:

```c
x * y
```

### Reversing नोट्स

- CoBRA को **lifted IR expressions** या decompiler output पर चलाना बेहतर है, जब आपने सटीक computation को अलग कर लिया हो।
- अगर expression masked arithmetic या narrow registers से आया है, तो `--bitwidth` स्पष्ट रूप से इस्तेमाल करें।
- अगर आपको अधिक मज़बूत proof step चाहिए, तो यहाँ दिए गए स्थानीय Z3 नोट्स देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है। यह तब उपयोगी है, जब आप बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करना चाहते हैं।
- Unsupported carry-sensitive mixed-domain residuals को इस संकेत के रूप में लें कि मूल expression को बनाए रखें और carry path पर मैन्युअल रूप से विचार करें।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-आधारित instruction sequences से बदलता है और control flow को बदलने के लिए signal/exception handling का उपयोग करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

समर्थित binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) परिणाम को deobfuscate कर सकता है। इसकी कई dependencies हैं।

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

और [keystone इंस्टॉल करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF खेल रहे हैं, तो flag ढूँढ़ने के लिए यह workaround** बहुत काम आ सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** ढूँढ़ने के लिए, functions में `::main` खोजें, जैसे:

![Ghidra में function names में double-colon main खोजकर Rust entry point ढूँढ़ना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह समझना आसान है कि यही दिलचस्प main function है।\
जिन **functions** को call किया जा रहा है, उनके **नाम** पता होने पर, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर खोजें।

### ELF firmware से Rust strings वापस पाना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। `rustc` का एक आम layout यह है: **`.data.rel.ro`** के अंदर एक **pointer/length tuple**, जो **`.rodata`** में रखे असली string blob की ओर इंगित करता है:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

इसका मतलब है कि `strings` या Ghidra का डिफ़ॉल्ट विश्लेषण पास-पास की strings को मिला सकता है या cross-references को पूरी तरह से छोड़ सकता है।<sup>[[3]](#references)</sup>

त्वरित workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक बार में एक word के हिसाब से enumerate करें।
3. **`.rodata`** address range के भीतर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. Sanity filters लागू करें (उदाहरण के लिए, **4** से **100** bytes तक की lengths रखें)।
6. `0x00` मिलने तक scan करने के बजाय, **`.rodata`** से ठीक `length` bytes पढ़ें।

न्यूनतम extractor logic:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि प्राप्त Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers और auth-related logic** उजागर करते हैं।

अगर Ghidra इन strings को नहीं पहचानता, तो एक custom script/plugin चलाएँ, जो यही heuristic लागू करे और संदर्भित `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools, इस विचार को अन्य **word sizes, endianness और section layouts** के लिए अपनाने हेतु अच्छे संदर्भ हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

अगर आपको Delphi binary को reverse करना है, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने की सलाह दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin debugging शुरू होने पर binary को execute करेगा और function names को dynamically resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ, और real code की शुरुआत में एक breakpoint hit होगा।

अगर आप graphical application में कोई button दबाते हैं, तो debugger उस button से invoke हुए function पर रुक सकता है।

## Golang

अगर आपको Golang binary को reverse करना है, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने की सलाह दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

इससे functions के names resolve हो जाएँगे।

## Compiled Python

इस पेज पर आप जान सकते हैं कि ELF/EXE में compiled Python binary से python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

अगर आपको GBA game की **binary** मिलती है, तो उसे **emulate** और **debug** करने के लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version डाउनलोड करें_) - इसमें interface वाला debugger है
- [**mgba** ](https://mgba.io)- इसमें CLI debugger है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** पर जाकर आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाएँ।

![Game Boy Advance के button mappings दिखाता no$gba controls configuration](<../../images/image (581).png>)

दबाए जाने पर, हर **key की एक value होती है**, जिससे उसकी पहचान की जा सकती है:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

तो, इस तरह के प्रोग्राम में दिलचस्प बात यह होगी कि **प्रोग्राम यूज़र इनपुट को कैसे हैंडल करता है**। एड्रेस **0x4000130** पर आपको आम तौर पर मिलने वाला फ़ंक्शन **KEYINPUT** मिलेगा।

![0x4000130 एड्रेस पर KEYINPUT का संदर्भ दिखाता Ghidra में GBA बाइनरी का दृश्य](<../../images/image (447).png>)

पिछली इमेज में आप देख सकते हैं कि फ़ंक्शन को **FUN_080015a8** से कॉल किया गया है (एड्रेस: _0x080015fa_ और _0x080017ac_)।

उस फ़ंक्शन में, कुछ init ऑपरेशन्स के बाद (जिनका कोई महत्व नहीं है):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

इसमें यह कोड मिला है:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

आख़िरी if यह जाँच रहा है कि **`uVar4`** पिछली Keys में है और मौजूदा key नहीं है—इसे बटन छोड़ना भी कहते हैं (मौजूदा key **`uVar1`** में स्टोर होती है)।

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

पिछले कोड में आप देख सकते हैं कि हम **uVar1** (जहाँ **दबाए गए बटन का मान** होता है) की तुलना कुछ मानों से कर रहे हैं:

- सबसे पहले, इसकी तुलना **मान 4** (**SELECT** बटन) से की जाती है: इस चुनौती में यह बटन स्क्रीन साफ़ करता है।
- फिर, इसकी तुलना **8** (**START** बटन) से की जाती है; इस चुनौती में, यह पथ जाँचता है कि दर्ज किया गया कोड मान्य है या नहीं।
  - इस स्थिति में, var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि मान समान हो, तो कुछ कोड निष्पादित होता है।
- अन्य सभी स्थितियों में, एक काउंटर (`DAT_030000d4`) जाँचा और बढ़ाया जाता है।\
  जब तक काउंटर 8 से कम होता है, दबाई गई कुंजियों के मान `DAT_030000d8` में जोड़े जाते हैं।

इसलिए, इस चुनौती में, बटनों के मान जानने के बाद आपको **8 से कम लंबाई वाला ऐसा संयोजन दबाना था, जिसके मानों का जोड़ 0xf3 हो।**

**इस ट्यूटोरियल का संदर्भ:** [आर्काइव किया गया Nostalgia चुनौती writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## पाठ्यक्रम

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA के साथ MBA obfuscation को सरल बनाना](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings को decode करना - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing ट्यूटोरियल (आर्काइव किया गया)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-सहायता प्राप्त Reverse Engineering को विफल करना, या कम-से-कम कोशिश करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
