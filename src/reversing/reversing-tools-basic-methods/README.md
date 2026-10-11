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

- wasm (binary) से wat (clear text) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
- wat से wasm में **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें
- Decompilation के लिए आप [web-wasmdec](https://wwwg.github.io/web-wasmdec/) भी आज़मा सकते हैं।

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक decompiler है, जो **libraries** (.dll), **Windows metadata files** (.winmd) और **executables** (.exe) समेत कई formats को **decompile और examine** करता है। Decompile करने के बाद, किसी assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

इसका फायदा यह है कि अगर किसी खोए हुए source code को legacy assembly से restore करना हो, तो इससे समय बच सकता है। इसके अलावा, dotPeek decompiled code में आसानी से navigation करने की सुविधा देता है, जिससे यह **Xamarin algorithm analysis** के लिए बेहतरीन tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक add-in model और आपकी ज़रूरतों के अनुसार tool को ढालने वाली API के साथ, .NET Reflector समय बचाता है और development को सरल बनाता है। आइए, इस tool द्वारा दी जाने वाली reverse engineering सेवाओं पर नज़र डालें:

- यह दिखाता है कि किसी library या component में data कैसे flow करता है
- .NET languages और frameworks के implementation और usage की जानकारी देता है
- इस्तेमाल किए गए APIs और technologies का अधिक लाभ लेने के लिए undocumented और unexposed functionality ढूँढ़ता है।
- Dependencies और अलग-अलग assemblies ढूँढ़ता है
- आपके code, third-party components और libraries में errors की सटीक जगह खोजता है।
- आपके द्वारा इस्तेमाल किए जाने वाले सभी .NET code के source में debugging करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) और [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS पर इस्तेमाल कर सकते हैं (इसे सीधे VSCode से install किया जा सकता है, git download करने की ज़रूरत नहीं। **Extensions** पर क्लिक करें और **ILSpy खोजें**)।\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसका सक्रिय रूप से maintained fork [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) इस्तेमाल कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** चुनें।)

### DNSpy Logging

**DNSpy से किसी file में जानकारी log करवाने** के लिए, आप यह snippet इस्तेमाल कर सकते हैं:

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

प्रति:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

और **compile** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

इसके बाद _**File >> Save module...**_ के ज़रिए नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

यह ज़रूरी है, क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर कोड में कई **optimisations** लागू होंगी और संभव है कि debugging के दौरान **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

इसके बाद, अगर आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस तरह **restart** कर सकते हैं:

```
iisreset /noforce
```

फिर, debugging शुरू करने के लिए सभी खुली हुई फ़ाइलें बंद करें और **Debug Tab** में **Attach to Process...** चुनें:

![DNSpy Logging - DNSpy Debugging: फिर, debugging शुरू करने के लिए सभी खुली हुई फ़ाइलें बंद करें और Debug Tab में Attach to Process चुनें](<../../images/image (318).png>)

इसके बाद **w3wp.exe** चुनकर **IIS server** से attach करें और **attach** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: IIS server से attach करने के लिए w3wp.exe चुनें और attach पर क्लिक करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो उसे रोककर सभी modules load करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें और फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो उसे रोककर सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो उसे रोककर सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर क्लिक करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर क्लिक करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right click करें और Sort Assemblies पर क्लिक करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs को debug करना

### IDA का उपयोग करना

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: "Suspend on library load/unload" चुनें](<../../images/image (868).png>)

- निष्पादन के **parameters** configure करते हुए **DLL का path** और जिस function को call करना है, उसे डालें:

![Debugging DLLs - Using IDA: निष्पादन के parameters configure करते हुए DLL का path और जिस function को call करना है, उसे डालें](<../../images/image (704).png>)

इसके बाद, debugging शुरू करने पर **हर DLL load होने पर निष्पादन रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL load करेगा, तब निष्पादन रुक जाएगा।

यह method module-load events पर रुकता है, लेकिन loaded DLL के entry point तक पहुँचना नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग करना

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** (_File --> Change Command Line_) और dll का path तथा जिस function को call करना है, उसे सेट करें। उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **निष्पादन शुरू करें**। debugger हर dll main पर रुकेगा और किसी बिंदु पर **आपकी dll के Entry पर रुकेगा**। वहाँ से उन जगहों को खोजें जहाँ आप breakpoint लगाना चाहते हैं।

ध्यान दें कि win64dbg में किसी भी कारण से निष्पादन रुकने पर, **win64dbg window के सबसे ऊपर** देखकर पता लगा सकते हैं कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि win64dbg में किसी भी कारण से निष्पादन रुकने पर, win64dbg window के सबसे ऊपर देखकर पता लगा सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि निष्पादन उस DLL के अंदर रुका है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो चल रहे game की memory में अहम values कहाँ save हैं, यह ढूँढने और उन्हें बदलने में मदद करता है। अधिक जानकारी:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालाँकि, इसका उपयोग reverse-engineering से जुड़े किसी भी काम के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner से shellcode debug करना

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** को allocate करता है, उसका **memory address** print करता है और execution pause करता है।\
IDA या x64dbg जैसे debugger से attach करें, print किए गए address पर breakpoint लगाएँ और shellcode debug करने के लिए execution फिर से शुरू करें।

releases github page में compiled releases वाली zip files हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप Blobrunner का थोड़ा modified version इस link पर पा सकते हैं। इसे compile करने के लिए **Visual Studio Code में C/C++ project बनाएँ, code copy-paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it से shellcode debug करना

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner जैसा ही है। यह shellcode को allocate करके infinite loop में चला जाता है। debugger से attach करें, **2–5 seconds** तक resume करें, उस loop के अंदर pause करें और फिर उस call तक step करें जो execution को allocated shellcode में भेजता है।

![jmp2it's infinite loop में, allocated shellcode के call से ठीक पहले रुका हुआ debugger](<../../images/image (509).png>)

[jmp2it को releases page से download कर सकते हैं](https://github.com/adamkramer/jmp2it/releases/)।

### Cutter से shellcode debug करना

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और उसे dynamically inspect कर सकते हैं।

ध्यान दें कि Cutter में "Open File" और "Open Shellcode" विकल्प हैं। मेरे मामले में, shellcode को file के रूप में खोलने पर यह सही decompile हुआ, लेकिन shellcode के रूप में खोलने पर नहीं:

![Cutter में वही bytes file और shellcode के रूप में खोलने पर analysis के अलग-अलग नतीजे](<../../images/image (562).png>)

अपनी पसंद की जगह से emulation शुरू करने के लिए, वहाँ bp सेट करें। ऐसा लगता है कि Cutter emulation उसी जगह से अपने आप शुरू कर देगा:

![Cutter emulation शुरू करने से पहले, इच्छित shellcode entry पर breakpoint सेट करना](<../../images/image (589).png>)

![Cutter emulator चुने गए shellcode breakpoint पर रुका हुआ](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump में देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### shellcode को deobfuscate करना और execute किए गए functions पता करना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़माना चाहिए।\
यह आपको बताएगा कि shellcode कौन-से **functions** इस्तेमाल कर रहा है और क्या वह memory में खुद को **decode** कर रहा है।

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg में एक graphical launcher भी है, जहाँ आप मनचाहे विकल्प चुनकर shellcode को execute कर सकते हैं।

![shellcode emulation और tracing विकल्प चुनने के लिए scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** विकल्प, shellcode को memory में dynamically बदलने पर उसके अंतिम रूप का dump बनाएगा (decoded shellcode डाउनलोड करने के लिए उपयोगी)। **start offset** का उपयोग shellcode को किसी विशिष्ट offset से शुरू करने के लिए किया जा सकता है। **Debug Shell** विकल्प, scDbg terminal का उपयोग करके shellcode को debug करने के लिए उपयोगी है (हालाँकि, इस काम के लिए मुझे पहले बताए गए विकल्प बेहतर लगते हैं, क्योंकि उनसे आप Ida या x64dbg का उपयोग कर पाएँगे)।

### CyberChef का उपयोग करके disassemble करना

अपनी shellcode फ़ाइल को input के रूप में upload करें और उसे decompile करने के लिए यह recipe इस्तेमाल करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation को deobfuscate करना

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` जैसे सरल expressions को ऐसे formulas के पीछे छिपाता है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाते हैं। महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के अंतर्गत सही होती हैं, इसलिए carries और overflows मायने रखते हैं:

```c
(x ^ y) + 2 * (x & y) == x + y
```

यदि आप इस तरह के expression को generic algebra tooling से simplify करते हैं, तो bit-width semantics को नज़रअंदाज़ करने के कारण आसानी से गलत परिणाम मिल सकता है।<sup>[[1]](#references)</sup>

### व्यावहारिक कार्यप्रवाह

1. Lift किए गए code/IR/decompiler output से **मूल bit-width** बनाए रखें (`8/16/32/64` bits)।
2. इसे simplify करने से पहले **expression का वर्गीकरण** करें:
   - **Linear**: bitwise atoms के weighted sums
   - **Semilinear**: linear expression के साथ `x & 0xFF` जैसे constant masks
   - **Polynomial**: products मौजूद हों
   - **Mixed**: products और bitwise logic एक-दूसरे में interleaved हों, अक्सर repeated subexpressions के साथ
3. हर candidate rewrite को random testing या SMT proof से **verify** करें। यदि equivalence साबित न हो सके, तो अनुमान लगाने के बजाय मूल expression बनाए रखें।

### Narrow execution slice के साथ flattened control flow को bypass करें

पूरा control-flow graph recover करना अक्सर अनावश्यक होता है। Control-flow flattening, opaque predicates, बड़े dispatchers या MBA-heavy code के मामले में, encrypted blobs और output buffers के references को उस सबसे छोटी routine तक follow करें जो उन्हें transform करती है। फिर केवल उस data-flow slice को reproduce करें या उसे स्वतंत्र रूप से execute करें; यदि संबंधित state सीधे initialize की जा सकती है, तो dispatcher आवश्यक solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक व्यावहारिक कार्यप्रवाह है:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations तथा cross-references की सूची बनाएँ। `.rodata` से candidate tables dump करते समय उनका byte order और element width बनाए रखें।
2. उस आखिरी routine की पहचान करें जो plaintext या output buffer में लिखती है। उसके inputs, referenced tables, imported calls और आवश्यक global state को दर्ज करें।
3. केवल उन operations को fixed-width Python model में lift करें। यदि slice अभी भी बहुत अधिक state पर निर्भर है, तो पूरे program को emulate करने के बजाय Unicorn, QEMU या debugger के तहत routine invoke करें और अप्रासंगिक imports को hook करें।
4. पुष्टि करें कि extractor वास्तव में दिए गए binary से अपना output निकालता है: silent fallbacks हटाएँ, embedded answers के लिए उसे search करें, और बदली हुई strings, keys, identifiers, layouts तथा obfuscation seeds वाले unseen builds पर चलाएँ।

पहली जाँच के लिए उपयोगी commands हैं:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### छिपे हुए constants वाले MBA expressions पहचानें

ऊपरी तौर पर input पर निर्भर दिखने वाला byte expression, अपने input को पूरी तरह रद्द कर सकता है। इसकी tables निकालने के बाद, expression का मूल्यांकन पूरे 8-bit domain पर करें; output set में केवल एक मान होना साबित करता है कि वह byte constant है—इसके लिए आसपास की state machine को recover करने की ज़रूरत नहीं होती।<sup>[[7]](#references)</sup>

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

#### environment-bound decoding पहचानें

Anti-analysis checks के लिए branch या crash करना ज़रूरी नहीं है। कोई decoder sensor result को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से आगे बढ़ सकता है और emulator में संभावित लेकिन गलत plaintext बना सकता है। इसलिए केवल दिखाई देने वाली failure branches को patch करना पर्याप्त नहीं है; environment probes से decoder state तक data dependencies trace करें, authentic device और emulator पर उसी slice की तुलना करें, और जाँचें कि हर sensor result को force करने से अंतिम buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक व्यावहारिक MBA simplifier है। यह expression को classify करता है और सब कुछ पर एक ही generic rewrite pass लागू करने के बजाय उसे specialized pipelines के ज़रिए process करता है।<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature निकालता है, और pattern matching, ANF conversion तथा coefficient interpolation जैसी कई recovery methods के बीच दौड़ लगाता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर बनाया जाता है, ताकि masked regions सही बने रहें।
- **Polynomial/Mixed MBA**: products को cores में विघटित किया जाता है और बाहरी relation को सरल बनाने से पहले repeated subexpressions को temporaries में उठाया जा सकता है।

एक mixed identity का उदाहरण जिसे अक्सर पुनः प्राप्त करने की कोशिश करना उपयोगी होता है:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

इसे संक्षिप्त करके इस रूप में लिखा जा सकता है:

```c
x * y
```

### Reversing notes

- CoBRA को **lifted IR expressions** या decompiler के output पर चलाना बेहतर है, जब आपने सटीक computation को अलग कर लिया हो।
- अगर expression masked arithmetic या narrow registers से आया है, तो `--bitwidth` स्पष्ट रूप से इस्तेमाल करें।
- अगर आपको अधिक मज़बूत proof step चाहिए, तो यहाँ दिए गए स्थानीय Z3 notes देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA, **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है। यह तब उपयोगी है जब आप बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करना चाहते हैं।
- Unsupported carry-sensitive mixed-domain residuals को इस संकेत के रूप में लें कि मूल expression को बनाए रखें और carry path पर manually विचार करें।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-based instruction sequences से बदलता है और control flow को बदलने के लिए signal/exception handling का इस्तेमाल करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

समर्थित binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) परिणाम को deobfuscate कर सकता है। इसकी कई dependencies हैं।

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

और [keystone install करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF खेल रहे हैं, तो flag ढूँढ़ने का यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** ढूँढ़ने के लिए, functions में `::main` खोजें, जैसे:

![Ghidra में function names में double-colon main खोजकर Rust entry point ढूँढ़ना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह पहचानना आसान है कि यही दिलचस्प main function है।\
कॉल किए जा रहे **functions** के **नाम** मिलने पर, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर खोजें।

### ELF firmware से Rust strings recover करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। `rustc` का एक आम layout **`.data.rel.ro`** के अंदर **pointer/length tuple** होता है, जो **`.rodata`** में रखे असली string blob की ओर इशारा करता है:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

इसका मतलब है कि `strings` या Ghidra का default analysis पास-पास की strings को merge कर सकता है या cross-references को पूरी तरह miss कर सकता है।<sup>[[3]](#references)</sup>

त्वरित workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक-एक word करके enumerate करें।
3. `.rodata` address range के अंदर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. Sanity filters लागू करें (उदाहरण के लिए, **4** से **100** bytes के बीच की lengths रखें)।
6. `0x00` मिलने तक scan करने के बजाय, `.rodata` से ठीक `length` bytes पढ़ें।

न्यूनतम extractor logic:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers और auth-related logic** उजागर करते हैं।

अगर Ghidra इन strings को नहीं ढूँढ़ पाता, तो ऐसा custom script/plugin चलाएँ जो वही heuristic लागू करे और संदर्भित `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools इस विचार को अन्य **word sizes, endianness और section layouts** के अनुसार ढालने के लिए अच्छे संदर्भ हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi से compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

अगर आपको किसी Delphi binary को reverse करना हो, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) इस्तेमाल करने की सलाह दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin debugging शुरू होने पर binary को execute करेगा और function names को dynamically resolve करेगा। Debugging शुरू करने के बाद Start button (हरा बटन या f9) फिर से दबाएँ; वास्तविक code की शुरुआत में एक breakpoint लगेगा।

अगर आप graphical application में कोई button दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

सामान्य Go binaries के लिए, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime structures को recover कर सकता है और IDA में function names को बेहतर बना सकता है। इसका Python plugin **Alt+F7** से लोड करें।

### symbol table के बिना metadata recover करना

एक stripped Go executable को भी program counters को functions से map करने के लिए runtime metadata की ज़रूरत होती है। [GoReSym](https://github.com/mandiant/GoReSym), Go runtime से लिए गए code का उपयोग करके `pclntab` और `moduledata` जैसी structures को ढूँढ़ता और parse करता है। इससे conventional symbol table पर निर्भर हुए बिना function boundaries, names, source paths, types और build details recover किए जा सकते हैं।<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

एक obfuscator recovered names को बदलते हुए भी उन structures को usable छोड़ सकता है। उदाहरण के लिए, Garble identifiers और package paths को hash करता है और build, module तथा debug information हटा देता है।<sup>[[12]](#references)</sup> Obfuscated package token को उस package के functions में एकसमान रहना चाहिए। बार-बार आने वाले token के आधार पर functions को group करें, उसके callees, strings और APIs से एक package का अनुमान लगाएँ, फिर उस package label को पूरे group पर लागू करें।<sup>[[13]](#references)</sup>

### GoResolver से Garble names recover करें

[GoResolver](https://github.com/volexity/GoResolver), runtime-symbol extraction को clean-reference generation और control-flow-graph (CFG) matching के साथ जोड़ता है। इस क्रम का उपयोग करें:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler version पहचानें।** पहले `BuildInfo` और embedded version strings देखें। अगर obfuscator ने इन्हें हटा दिया हो, तो bundled Go runtime के हिस्सों की तुलना versioned reference runtimes से करें। Volexity के tests में, Go के major versions में अंतर पहचानने के लिए runtime का लगभग `2%` हिस्सा पर्याप्त था। इसे एक empirical optimization मानें, सार्वभौमिक threshold नहीं।<sup>[[13]](#references)</sup>
2. **Matching references बनाएँ।** पहचाने गए Go version, target architecture और संभावित libraries के लिए clean binaries generate करें। Toolchain का मिलान करने से compiler-generated CFG differences कम होते हैं।<sup>[[10]](#references)[[13]](#references)</sup>
3. **Functions की तुलना करें।** GoGrapher function CFGs का मिलान करता है और `0.0` से `1.0` तक normalized scores देता है। इसका basic-block matching, मिलते-जुलते instructions की weighted comparison पर आधारित है। High-confidence matches, randomized functions को clean implementation से map करते हैं। कमज़ोर matches से भी package या module की पहचान हो सकती है।<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

डिफ़ॉल्ट significant-match threshold `0.9` है। `--extract` और `--graph` switches से किसी भी stage को अलग किया जा सकता है, जबकि डिफ़ॉल्ट रूप से दोनों चलते हैं, क्योंकि recovered runtime metadata और CFG evidence एक-दूसरे के पूरक हैं।<sup>[[10]](#references)</sup> CFG scores heuristic होते हैं: inlining, build flags, architecture और library-version के अंतर graph shape को बदल सकते हैं, इसलिए low-confidence names थोपने के बजाय unresolved functions को बनाए रखें।<sup>[[13]](#references)</sup>

## Compiled Python

इस page में आप जान सकते हैं कि ELF/EXE Python compiled binary से Python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

अगर आपको किसी GBA game का **binary** मिले, तो उसे **emulate** और **debug** करने के लिए आप अलग-अलग tools इस्तेमाल कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - इसमें interface वाला debugger शामिल है
- [**mgba** ](https://mgba.io)- इसमें CLI debugger शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** पर आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाएँ

![Game Boy Advance button mappings दिखाने वाला no$gba controls configuration](<../../images/image (581).png>)

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

तो, इस तरह के प्रोग्राम में दिलचस्प बात यह होगी कि **प्रोग्राम उपयोगकर्ता के इनपुट को कैसे संभालता है**। पते **0x4000130** पर आपको आम तौर पर मिलने वाला function: **KEYINPUT** मिलेगा।

![0x4000130 पते पर KEYINPUT का संदर्भ दिखाता GBA binary का Ghidra दृश्य](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि function को **FUN_080015a8** से call किया गया है (पते: _0x080015fa_ और _0x080017ac_)।

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

इसमें यह code मिला है:

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

आख़िरी if जाँच रहा है कि **`uVar4`** आख़िरी Keys में है और मौजूदा key नहीं है। इसका मतलब है कि button छोड़ा जा रहा है (मौजूदा key **`uVar1`** में stored है)।

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

पिछले code में आप देख सकते हैं कि हम **uVar1** (वह स्थान जहाँ **दबाए गए बटन का मान** है) की तुलना कुछ मानों से कर रहे हैं:

- पहले, इसकी तुलना **मान 4** (**SELECT** बटन) से की जाती है: इस challenge में यह बटन स्क्रीन साफ़ करता है।
- फिर, मान की तुलना **8** (**START** बटन) से की जाती है; इस challenge में, यह path जाँचता है कि दर्ज किया गया code मान्य है या नहीं।
  - इस स्थिति में, var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है। यदि मान समान हो, तो कुछ code निष्पादित होता है।
- अन्य सभी स्थितियों में, एक counter (`DAT_030000d4`) की जाँच की जाती है और उसे बढ़ाया जाता है।\
  जब तक counter 8 से कम है, दबाए गए बटनों के मान `DAT_030000d8` में जोड़े जाते हैं।

इसलिए, इस challenge में, बटनों के मान जानने के बाद, आपको **8 से कम लंबाई का ऐसा संयोजन दबाना था जिसके मानों का योग 0xf3 हो।**

**इस tutorial के लिए संदर्भ:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## पाठ्यक्रम

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA obfuscation को CoBRA से सरल बनाना](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings को decode करना - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-Assisted Reverse Engineering को विफल करना, या कम-से-कम कोशिश करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching पर आधारित Control Flow Graphs की तुलना का एक तरीका](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Control-Flow Graph Similarity का उपयोग करके Golang Binaries को स्वचालित रूप से Deobfuscate करना](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
