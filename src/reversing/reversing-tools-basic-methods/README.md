# Reversing Tools और Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui आधारित Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Online:

- wasm (binary) से wat (साफ़ टेक्स्ट) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
- wat से wasm में **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें
- Decompilation के लिए आप [web-wasmdec](https://wwwg.github.io/web-wasmdec/) भी आज़मा सकते हैं।

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualized payloads और custom VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक decompiler है, जो **कई formats को decompile और examine करता है**, जिनमें **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe) शामिल हैं। Decompile करने के बाद, किसी assembly को Visual Studio project (.csproj) के रूप में सेव किया जा सकता है।

इसका फ़ायदा यह है कि अगर किसी legacy assembly से खोए हुए source code को restore करना हो, तो इससे समय बच सकता है। इसके अलावा, dotPeek decompiled code में आसान navigation देता है, जिससे यह **Xamarin algorithm analysis** के लिए बेहतरीन tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक add-in model और ऐसा API, जो tool को आपकी सटीक ज़रूरतों के अनुसार ढालता है, के साथ .NET reflector समय बचाता है और development को आसान बनाता है। आइए, इस tool द्वारा दी जाने वाली reverse engineering सेवाओं को देखें:

- यह बताता है कि किसी library या component में data का flow कैसे होता है
- .NET languages और frameworks के implementation और उपयोग के बारे में जानकारी देता है
- उपयोग किए गए APIs और technologies से अधिक लाभ पाने के लिए undocumented और unexposed functionality ढूँढ़ता है।
- Dependencies और अलग-अलग assemblies ढूँढ़ता है
- आपके code, third-party components और libraries में errors की सटीक जगह का पता लगाता है।
- आपके उपयोग में आने वाले सभी .NET code के source को debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS पर इस्तेमाल कर सकते हैं (इसे सीधे VSCode से install किया जा सकता है; git download करने की ज़रूरत नहीं। **Extensions** पर क्लिक करें और **ILSpy खोजें**)।\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसका सक्रिय रूप से maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), इस्तेमाल कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** करें।)

### DNSpy Logging

**DNSpy से किसी file में कुछ जानकारी log करवाने** के लिए, आप इस snippet का उपयोग कर सकते हैं:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy का उपयोग करके code debug करने के लिए आपको:

सबसे पहले, **debugging** से संबंधित **Assembly attributes** बदलने होंगे:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

फिर _**File >> Save module...**_ के ज़रिए नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

यह ज़रूरी है, क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर कोड में कई **optimisations** लागू होंगी और हो सकता है कि debugging के दौरान कोई **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, अगर आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस तरह **restart** कर सकते हैं:

```
iisreset /noforce
```

फिर, debugging शुरू करने के लिए आपको खोली गई सभी files बंद करनी चाहिए और **Debug Tab** में **Attach to Process...** चुनना चाहिए:

![DNSpy Logging - DNSpy Debugging: फिर, debugging शुरू करने के लिए खोली गई सभी files बंद करें और Debug Tab में Attach to Process चुनें](<../../images/image (318).png>)

फिर **w3wp.exe** चुनकर **IIS server** से attach करें और **attach** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर क्लिक करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो उसे रोककर सभी modules load करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें, फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो उसे रोककर सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें, फिर Debug Windows Modules पर क्लिक करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो उसे रोककर सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें, फिर Debug Windows Modules पर क्लिक करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर क्लिक करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर क्लिक करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right-click करें और **Sort Assemblies** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right-click करें और Sort Assemblies पर क्लिक करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की debugging

### IDA का उपयोग

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - IDA का उपयोग: "Suspend on library load/unload" चुनें](<../../images/image (868).png>)

- execution के **parameters** configure करें और उसमें **DLL का path** तथा वह function डालें जिसे आप call करना चाहते हैं:

![Debugging DLLs - IDA का उपयोग: execution के parameters configure करें और उसमें DLL का path तथा वह function डालें जिसे आप call करना चाहते हैं](<../../images/image (704).png>)

फिर, debugging शुरू करने पर **हर DLL load होने पर execution रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL load करेगा, तो execution रुक जाएगा।

यह तरीका module-load events पर रुकता है, लेकिन loaded DLL के entry point तक पहुंचना नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और DLL का path तथा वह function सेट करें जिसे आप call करना चाहते हैं। उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**। debugger हर dll main पर रुकेगा; किसी बिंदु पर यह **आपकी DLL के Entry पर रुकेगा**। वहां से, बस उन points को खोजें जहां आप breakpoint रखना चाहते हैं।

ध्यान दें कि win64dbg में किसी भी कारण से execution रुकने पर, आप **win64dbg window के ऊपर** देखकर जान सकते हैं कि **आप किस code में हैं**:

![Using IDA - x64dbg/x32dbg का उपयोग: ध्यान दें कि win64dbg में किसी भी कारण से execution रुकने पर, win64dbg window के ऊपर देखकर आप जान सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि execution उस DLL के अंदर रुका है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) running game की memory में महत्वपूर्ण values कहां save हैं, यह खोजने और उन्हें बदलने के लिए उपयोगी program है। अधिक जानकारी यहां:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) का front-end/reverse engineering tool है, जो games पर केंद्रित है। हालांकि, इसका उपयोग reverse-engineering से संबंधित किसी भी काम के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner से shellcode की debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** allocate करता है, उसका **memory address** print करता है और execution रोक देता है।\
IDA या x64dbg जैसे debugger को attach करें, print किए गए address पर breakpoint सेट करें और shellcode debug करने के लिए execution resume करें।

releases github page में compiled releases वाली zips हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप नीचे दिए गए link पर Blobrunner का थोड़ा modified version पा सकते हैं। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएं, code copy और paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it से shellcode की debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) BlobRunner जैसा ही है। यह shellcode allocate करके infinite loop में चला जाता है। debugger attach करें, **2–5 seconds** तक resume करें, उस loop के अंदर pause करें और फिर उस call तक step करें जो execution को allocated shellcode में transfer करता है।

![jmp2it के infinite loop में debugger रुका हुआ है, allocated shellcode को call करने से ठीक पहले](<../../images/image (509).png>)

आप [releases page में jmp2it का compiled version](https://github.com/adamkramer/jmp2it/releases/) download कर सकते हैं।

### Cutter से shellcode की debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode emulate कर सकते हैं और उसे dynamically inspect कर सकते हैं।

ध्यान दें कि Cutter में "Open File" और "Open Shellcode" विकल्प हैं। मेरे मामले में, shellcode को file के रूप में खोलने पर यह सही decompile हुआ, लेकिन shellcode के रूप में खोलने पर नहीं:

![Cutter में समान bytes को file या shellcode के रूप में खोलने पर अलग-अलग analysis results दिखते हैं](<../../images/image (562).png>)

जहां आप emulation शुरू करना चाहते हैं, वहां bp सेट करें। ऐसा लगता है कि Cutter वहां से अपने आप emulation शुरू कर देगा:

![Cutter emulation शुरू करने से पहले चुने गए shellcode entry पर breakpoint सेट करना](<../../images/image (589).png>)

![Cutter emulator चुने गए shellcode breakpoint पर रुका हुआ है](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump में देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### shellcode को deobfuscate करना और executed functions प्राप्त करना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़माना चाहिए।\
यह आपको बताएगा कि shellcode कौन-से **functions** इस्तेमाल कर रहा है और क्या shellcode memory में खुद को **decode** कर रहा है।

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg में एक graphical launcher भी है, जहाँ आप अपनी इच्छित options चुनकर shellcode execute कर सकते हैं

![shellcode emulation और tracing options चुनने के लिए scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** option, shellcode को तब dump करेगा जब memory में shellcode को dynamically बदला गया हो (decoded shellcode download करने के लिए उपयोगी)। **start offset** किसी विशेष offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** option, scDbg terminal का उपयोग करके shellcode debug करने के लिए उपयोगी है (हालाँकि, मुझे लगता है कि इस काम के लिए पहले बताए गए options बेहतर हैं, क्योंकि उनसे आप Ida या x64dbg का उपयोग कर पाएँगे)।

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए यह recipe इस्तेमाल करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation का deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` जैसे सरल expressions को ऐसे formulas के पीछे छिपाता है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाते हैं। अहम बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के तहत सही होती हैं, इसलिए carries और overflows मायने रखते हैं:

```c
(x ^ y) + 2 * (x & y) == x + y
```

यदि आप इस तरह की expression को generic algebra tooling से simplify करते हैं, तो आपको आसानी से गलत नतीजा मिल सकता है, क्योंकि bit-width semantics को नज़रअंदाज़ किया गया था।<sup>[[1]](#references)</sup>

### व्यावहारिक कार्यप्रवाह

1. Lift किए गए code/IR/decompiler output से **मूल bit-width** (`8/16/32/64` bits) बनाए रखें।
2. Simplify करने की कोशिश करने से पहले **expression का वर्गीकरण** करें:
   - **Linear**: bitwise atoms के weighted sums
   - **Semilinear**: linear expression के साथ constant masks, जैसे `x & 0xFF`
   - **Polynomial**: products मौजूद हों
   - **Mixed**: products और bitwise logic आपस में interleaved हों, अक्सर repeated subexpressions के साथ
3. हर candidate rewrite को random testing या SMT proof से **verify** करें। यदि equivalence साबित नहीं हो सकती, तो अनुमान लगाने के बजाय मूल expression बनाए रखें।

### Narrow execution slice से flattened control flow को bypass करें

पूरा control-flow graph recover करना अक्सर ज़रूरी नहीं होता। Control-flow flattening, opaque predicates, बड़े dispatchers या MBA-heavy code में, encrypted blobs और output buffers से उन सबसे छोटी routines तक references का अनुसरण करें जो उन्हें transform करती हैं। फिर केवल उस data-flow slice को reproduce करें, या उसे स्वतंत्र रूप से execute करें; यदि relevant state को सीधे initialize किया जा सकता है, तो dispatcher आवश्यक solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक व्यावहारिक कार्यप्रवाह है:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations तथा cross-references की सूची बनाएँ। `.rodata` से candidate tables dump करते समय उनका byte order और element width बनाए रखें।
2. उस आख़िरी routine की पहचान करें जो plaintext या output buffer में लिखती है। उसके inputs, referenced tables, imported calls और आवश्यक global state दर्ज करें।
3. केवल उन्हीं operations को fixed-width Python model में lift करें। यदि slice अभी भी बहुत अधिक state पर निर्भर करती है, तो पूरे program को emulate करने के बजाय routine को Unicorn, QEMU या debugger के अंतर्गत invoke करें और अप्रासंगिक imports को hook करें।
4. सुनिश्चित करें कि extractor वास्तव में दिए गए binary से अपना output निकालता है: silent fallbacks हटाएँ, उसमें embedded answers खोजें, और बदली हुई strings, keys, identifiers, layouts तथा obfuscation seeds वाले unseen builds पर इसे चलाएँ।

पहले चरण में काम आने वाले commands हैं:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### छिपे हुए constants बने MBA expressions का पता लगाना

इनपुट पर निर्भर दिखने वाला byte expression अपना इनपुट पूरी तरह रद्द कर सकता है। इसकी tables निकालने के बाद, पूरे 8-bit domain पर expression का मूल्यांकन करें; यदि output set में केवल एक मान हो, तो यह साबित होता है कि वह byte constant है—इसके लिए आसपास की state machine को recover करने की आवश्यकता नहीं होती।<sup>[[7]](#references)</sup>

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

Anti-analysis checks के लिए branch करना या crash होना ज़रूरी नहीं है। Decoder किसी sensor result को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से आगे बढ़ सकता है और emulator में विश्वसनीय दिखने वाला, लेकिन गलत plaintext बना सकता है। इसलिए केवल दिखाई देने वाली failure branches को patch करना पर्याप्त नहीं है; environment probes से decoder state तक data dependencies trace करें, authentic device और emulator पर समान slice की तुलना करें, और जाँचें कि हर sensor result को force करने से final buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक व्यावहारिक MBA simplifier है। यह expression को classify करता है और हर चीज़ पर एक generic rewrite pass लागू करने के बजाय उसे specialized pipelines के ज़रिए process करता है।<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature निकालता है और pattern matching, ANF conversion तथा coefficient interpolation जैसी कई recovery methods को समानांतर चलाता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर बनाया जाता है, ताकि masked regions सही बने रहें।
- **Polynomial/Mixed MBA**: products को cores में विभाजित किया जाता है और outer relation को simplify करने से पहले repeated subexpressions को temporaries में रखा जा सकता है।

एक mixed identity का उदाहरण, जिसे अक्सर recover करने की कोशिश करना उपयोगी होता है:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

इसे घटाकर यह किया जा सकता है:

```c
x * y
```

### रिवर्सिंग नोट्स

- CoBRA को **lifted IR expressions** या decompiler output पर चलाना बेहतर है, जब आपने सटीक computation को अलग कर लिया हो।
- अगर expression masked arithmetic या narrow registers से आया है, तो स्पष्ट रूप से `--bitwidth` का उपयोग करें।
- अगर आपको अधिक मजबूत proof step चाहिए, तो यहाँ दिए गए स्थानीय Z3 नोट्स देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA, **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है। यह तब उपयोगी है, जब आप बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करना चाहते हैं।
- Unsupported carry-sensitive mixed-domain residuals को इस संकेत के रूप में लें कि मूल expression को बनाए रखें और carry path के बारे में स्वयं तर्क करें।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-आधारित instruction sequences से बदलता है और control flow को बदलने के लिए signal/exception handling का उपयोग करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

समर्थित binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) परिणाम को deobfuscate कर सकता है। इसकी कई dependencies हैं।

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

और [keystone install करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF** खेल रहे हैं, तो **flag खोजने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए, `::main` से functions खोजें, जैसे:

![Ghidra में function names में double-colon main खोजकर Rust entry point ढूँढ़ना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह स्पष्ट है कि यही दिलचस्प main function है।\
जिन **functions** को call किया जा रहा है, उनके **नाम** मिलने पर, उनके **inputs** और **outputs** जानने के लिए उन्हें **Internet** पर खोजें।

### ELF firmware से Rust strings पुनर्प्राप्त करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। `rustc` का एक आम layout है: **`.data.rel.ro`** के अंदर **pointer/length tuple**, जो **`.rodata`** में संग्रहीत वास्तविक string blob की ओर point करता है:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

इसका मतलब है कि `strings` या Ghidra का डिफ़ॉल्ट विश्लेषण पास-पास की strings को मिला सकता है या cross-references को पूरी तरह छोड़ सकता है।<sup>[[3]](#references)</sup>

त्वरित वर्कफ़्लो:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक-एक word करके enumerate करें।
3. `.rodata` address range के अंदर आने वाली किसी भी value को संभावित string pointer मानें।
4. अगले word को संभावित length मानें।
5. Sanity filters लागू करें (उदाहरण के लिए, 4 से 100 bytes के बीच की lengths रखें)।
6. `0x00` मिलने तक scan करने के बजाय `.rodata` से ठीक `length` bytes पढ़ें।

न्यूनतम extractor logic:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers और auth-related logic** उजागर करती हैं।

अगर Ghidra इन strings को नहीं खोज पाता, तो एक custom script/plugin चलाएँ, जो वही heuristic लागू करे और संदर्भित `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools इस विचार को अन्य **word sizes, endianness और section layouts** के अनुसार ढालने के लिए अच्छे संदर्भ हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) इस्तेमाल कर सकते हैं।

अगर आपको Delphi binary को reverse करना है, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) इस्तेमाल करने की सलाह दूँगा।

IDA में Python plugin लोड करने के लिए **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin binary को execute करेगा और debugging शुरू होते समय function names को dynamically resolve करेगा। Debugging शुरू करने के बाद Start button (हरा वाला या f9) फिर से दबाएँ; real code की शुरुआत में एक breakpoint hit होगा।

अगर आप graphical application में कोई button दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

सामान्य Go binaries के लिए, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime structures recover कर सकता है और IDA में function names बेहतर बना सकता है। इसका Python plugin **Alt+F7** से लोड करें।

### symbol table के बिना metadata recover करना

एक stripped Go executable को भी program counters को functions से map करने के लिए runtime metadata की ज़रूरत होती है। [GoReSym](https://github.com/mandiant/GoReSym), Go runtime से निकले code का उपयोग करके `pclntab` और `moduledata` जैसी structures खोजता और parse करता है। इससे conventional symbol table पर निर्भर हुए बिना function boundaries, names, source paths, types और build details recover किए जा सकते हैं।<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

एक obfuscator इन structures को usable छोड़ सकता है, जबकि recovered names को बदल देता है। उदाहरण के लिए, Garble identifiers और package paths को hash करता है और build, module तथा debug information हटा देता है।<sup>[[12]](#references)</sup> Obfuscated package token को उस package के functions में consistent रहना चाहिए। बार-बार आने वाले token के आधार पर functions को group करें, उसके callees, strings और APIs से एक package का अनुमान लगाएँ, फिर उस package label को पूरे group पर लागू करें।<sup>[[13]](#references)</sup>

### GoResolver से Garble names रिकवर करें

[GoResolver](https://github.com/volexity/GoResolver) runtime-symbol extraction को clean-reference generation और control-flow-graph (CFG) matching के साथ जोड़ता है। यह क्रम अपनाएँ:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler version पहचानें।** पहले `BuildInfo` और embedded version strings जाँचें। यदि obfuscator ने उन्हें हटा दिया है, तो bundled Go runtime के हिस्सों की तुलना versioned reference runtimes से करें। Volexity के tests में, runtime का लगभग `2%` हिस्सा major Go versions में अंतर करने के लिए पर्याप्त था। इसे empirical optimization मानें, universal threshold नहीं।<sup>[[13]](#references)</sup>
2. **Matching references बनाएँ।** पहचाने गए Go version, target architecture और संभावित libraries के लिए clean binaries generate करें। Toolchain का मिलान करने से compiler-generated CFG differences कम होते हैं।<sup>[[10]](#references)[[13]](#references)</sup>
3. **Functions की तुलना करें।** GoGrapher function CFGs का मिलान करता है और `0.0` से `1.0` तक normalized scores देता है। इसका basic-block matching, similar instructions की weighted comparison पर आधारित है। High-confidence matches randomized functions को clean implementation से map करते हैं। Weaker matches से भी package या module की पहचान हो सकती है।<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validate और import करें।** प्रस्तावित names की पुष्टि call relationships, constants, strings और side effects से करें, फिर IDA या Ghidra के GoResolver plugin से JSON report import करें।<sup>[[10]](#references)[[13]](#references)</sup>

Toolchain install करें और combined extractor तथा graph matcher चलाएँ:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

डिफ़ॉल्ट significant-match threshold `0.9` है। `--extract` और `--graph` switches से किसी भी चरण को अलग-अलग चलाया जा सकता है, जबकि डिफ़ॉल्ट रूप से दोनों चलते हैं, क्योंकि प्राप्त runtime metadata और CFG के साक्ष्य एक-दूसरे के पूरक हैं।<sup>[[10]](#references)</sup> CFG scores heuristic होते हैं: inlining, build flags, architecture और library-version के अंतर graph की बनावट बदल सकते हैं, इसलिए कम-confidence वाले नाम थोपने के बजाय unresolved functions को ऐसे ही रखें।<sup>[[13]](#references)</sup>

## संकलित Python

इस पेज पर जानें कि ELF/EXE Python compiled binary से Python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

अगर आपको किसी GBA game का **binary** मिलता है, तो उसे **emulate** और **debug** करने के लिए अलग-अलग tools इस्तेमाल कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version डाउनलोड करें_) - इसमें interface वाला debugger है
- [**mgba** ](https://mgba.io)- इसमें CLI debugger है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** पर जाकर देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाने हैं।

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

दबाने पर, हर **key की एक value होती है**, जिससे उसकी पहचान की जा सकती है:

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

तो, इस तरह के प्रोग्राम में दिलचस्प बात यह होगी कि **प्रोग्राम यूज़र इनपुट को कैसे संभालता है**। पते **0x4000130** पर आपको आमतौर पर मिलने वाला function मिलेगा: **KEYINPUT**।

![0x4000130 पते पर KEYINPUT का संदर्भ देने वाली GBA binary का Ghidra view](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि यह function **FUN_080015a8** से कॉल किया जाता है (पते: _0x080015fa_ और _0x080017ac_)।

उस function में, कुछ init operations के बाद (जो महत्वपूर्ण नहीं हैं):

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

यह कोड मिला है:

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

आखिरी if यह जाँच रहा है कि **`uVar4`** आखिरी Keys में है और मौजूदा key नहीं है। इसे बटन छोड़ना भी कहते हैं (मौजूदा key **`uVar1`** में stored है)।

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

पिछले code में आप देख सकते हैं कि हम **uVar1** (जहाँ **दबाए गए button की value** होती है) की तुलना कुछ values से कर रहे हैं:

- सबसे पहले, इसकी तुलना **value 4** (**SELECT** button) से की जाती है: challenge में यह button screen को साफ़ करता है।
- फिर इसकी तुलना **8** (**START** button) से की जाती है; इस challenge में, उस path पर यह जाँचा जाता है कि दर्ज किया गया code मान्य है या नहीं।
  - इस मामले में, var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute होता है।
- अन्य सभी मामलों में, एक counter (`DAT_030000d4`) की जाँच करके उसे increment किया जाता है।\
  जब तक counter 8 से कम रहता है, दबाई गई keys की values को `DAT_030000d8` में जोड़ा जाता है।

इसलिए, इस challenge में, buttons की values जानने के बाद, आपको **8 से कम लंबाई वाला ऐसा combination दबाना था जिसका कुल जोड़ 0xf3 हो।**

**इस tutorial का reference:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA के साथ MBA obfuscation को सरल बनाना](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings को decode करना - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-सहायता प्राप्त reverse engineering को विफल करना, या कम-से-कम कोशिश करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching पर आधारित Control Flow Graphs की तुलना करने का एक तरीका](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graph Similarity का उपयोग करके Golang binaries को स्वचालित रूप से deobfuscate करना](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
