# Reversing Tools और Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- wasm (binary) से wat (clear text) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
- wat से wasm में **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें
- आप decompilation के लिए [web-wasmdec](https://wwwg.github.io/web-wasmdec/) भी आज़मा सकते हैं।

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक decompiler है जो **कई formats को decompile और examine करता है**, जिनमें **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe) शामिल हैं। Decompile किए जाने के बाद, किसी assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

इसका लाभ यह है कि यदि किसी खोए हुए source code को किसी legacy assembly से restore करने की आवश्यकता हो, तो यह कार्य समय बचा सकता है। इसके अलावा, dotPeek decompiled code में सुविधाजनक navigation प्रदान करता है, जिससे यह **Xamarin algorithm analysis** के लिए बेहतरीन tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक add-in model और आपकी सटीक आवश्यकताओं के अनुसार tool को विस्तारित करने वाली API के साथ, .NET reflector समय बचाता है और development को सरल बनाता है। आइए उन reverse engineering services पर नज़र डालें जो यह tool प्रदान करता है:

- यह जानकारी देता है कि किसी library या component में data कैसे flow करता है
- .NET languages और frameworks के implementation और usage की जानकारी देता है
- उपयोग किए जा रहे APIs और technologies से अधिक लाभ प्राप्त करने के लिए undocumented और unexposed functionality खोजता है।
- dependencies और अलग-अलग assemblies खोजता है
- आपके code, third-party components और libraries में errors का exact location खोजता है।
- आपके द्वारा उपयोग किए जाने वाले सभी .NET code के source में debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS में उपयोग कर सकते हैं (आप इसे सीधे VSCode से install कर सकते हैं, git download करने की आवश्यकता नहीं है। **Extensions** पर click करें और **search ILSpy** करें)।\
यदि आपको फिर से **decompile**, **modify** और **recompile** करना है, तो आप [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसके actively maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) का उपयोग कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** करें।)

### DNSpy Logging

**DNSpy से कुछ information को file में log** करने के लिए, आप इस snippet का उपयोग कर सकते हैं:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy का उपयोग करके code debug करने के लिए आपको:

सबसे पहले, **debugging** से संबंधित **Assembly attributes** बदलें:

![DNSpy Logging - DNSpy Debugging: सबसे पहले, debugging से संबंधित Assembly attributes बदलें](<../../images/image (973).png>)

से:
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

फिर _**File >> Save module...**_ के माध्यम से नई फ़ाइल save करें:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

यह आवश्यक है, क्योंकि यदि आप ऐसा नहीं करते हैं, तो **runtime** पर code में कई **optimisations** लागू हो जाएँगी और यह संभव है कि debugging के दौरान कोई **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, यदि आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस प्रकार **restart** कर सकते हैं:
```
iisreset /noforce
```
फिर, debugging शुरू करने के लिए आपको खुली हुई सभी files बंद करनी चाहिए और **Debug Tab** के अंदर **Attach to Process...** चुनना चाहिए:

![DNSpy Logging - DNSpy Debugging: फिर, debugging शुरू करने के लिए आपको खुली हुई सभी files बंद करनी चाहिए और Debug Tab के अंदर Attach to Process चुनना चाहिए](<../../images/image (318).png>)

फिर **IIS server** से attach करने के लिए **w3wp.exe** चुनें और **attach** पर click करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर click करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो उसे रोकने और सभी modules load करने का समय है। पहले _Debug >> Break All_ पर click करें और फिर _**Debug >> Windows >> Modules**_ पर click करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो उसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर click करें और फिर Debug Windows Modules पर click करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो उसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर click करें और फिर Debug Windows Modules पर click करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर click करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर click करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर click करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right click करें और Sort Assemblies पर click करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की debugging

### IDA का उपयोग

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Execution के **parameters** configure करें, जिसमें **DLL का path** और वह function डालें जिसे आप call करना चाहते हैं:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

फिर, जब आप debugging शुरू करेंगे, **हर DLL के load होने पर execution रुक जाएगा**; इसलिए, जब rundll32 आपकी DLL को load करेगा, तो execution रुक जाएगा।

यह method module-load events पर रुकती है, लेकिन loaded DLL के entry point तक पहुंचना नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा उस function को set करें जिसे आप call करना चाहते हैं, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**, debugger हर dll main पर रुकेगा; किसी point पर आप **अपनी dll के dll Entry पर रुकेंगे**। वहां से, उन points को खोजें जहां आप breakpoint लगाना चाहते हैं।

ध्यान दें कि जब win64dbg में किसी भी कारण से execution रुकता है, तो आप **win64dbg window के top पर** देख सकते हैं कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि जब win64dbg में किसी भी कारण से execution रुकता है, तो आप win64dbg window के top पर देख सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि execution उस DLL के अंदर रुक गया है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो यह पता लगाने में मदद करता है कि running game के memory के अंदर महत्वपूर्ण values कहां save की गई हैं और उन्हें बदलने में मदद करता है। अधिक जानकारी:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालांकि, इसका उपयोग reverse-engineering से संबंधित किसी भी काम के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner के साथ shellcode debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** allocate करता है, उसका **memory address** print करता है और execution को pause करता है।\
IDA या x64dbg जैसे debugger से attach करें, printed address पर breakpoint set करें और shellcode को debug करने के लिए execution resume करें।

releases github page में compiled releases वाली zips मौजूद हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप निम्न link में Blobrunner का थोड़ा modified version पा सकते हैं। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएं, code को copy और paste करें और उसे build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it के साथ shellcode debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) BlobRunner के समान है। यह shellcode allocate करता है और infinite loop में प्रवेश करता है। debugger से attach करें, **2–5 seconds** तक resume करें, उस loop के अंदर pause करें और allocated shellcode में execution transfer करने वाले अगले call तक step करें।

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

आप [jmp2it को releases page के अंदर download कर सकते हैं](https://github.com/adamkramer/jmp2it/releases/)।

### Cutter का उपयोग करके shellcode debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और उसका dynamically inspection कर सकते हैं।

ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" करने देता है। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने उसे सही ढंग से decompile किया; लेकिन जब मैंने उसे shellcode के रूप में खोला, तो ऐसा नहीं हुआ:

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

Emulation को अपनी इच्छित जगह से शुरू करने के लिए वहां bp set करें; ऐसा लगता है कि Cutter emulation को वहां से automatically शुरू कर देगा:

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

उदाहरण के लिए, आप hex dump के अंदर stack देख सकते हैं:

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### Shellcode को deobfuscate करना और executed functions प्राप्त करना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़माना चाहिए।\
यह आपको बताएगा कि shellcode **किन functions** का उपयोग कर रहा है और क्या shellcode memory में स्वयं को **decode** कर रहा है।
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg में एक graphical launcher भी है, जिसमें आप अपने इच्छित options चुनकर shellcode को execute कर सकते हैं।

![shellcode emulation और tracing options चुनने के लिए scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** option अंतिम shellcode को dump करेगा, यदि memory में shellcode को dynamically बदला गया हो (decoded shellcode को download करने के लिए उपयोगी)। **start offset** किसी specific offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** option scDbg terminal का उपयोग करके shellcode को debug करने के लिए उपयोगी है (हालांकि इस मामले में मुझे पहले बताए गए options बेहतर लगते हैं, क्योंकि आप Ida या x64dbg का उपयोग कर पाएंगे)।

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए निम्न recipe का उपयोग करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation `x + y` जैसे simple expressions को ऐसे formulas के पीछे छिपाता है, जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाते हैं। महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के अंतर्गत सही होती हैं, इसलिए carries और overflows मायने रखते हैं:
```c
(x ^ y) + 2 * (x & y) == x + y
```
यदि आप इस प्रकार के expression को generic algebra tooling से simplify करते हैं, तो आसानी से गलत result मिल सकता है क्योंकि bit-width semantics को अनदेखा कर दिया गया था।<sup>[[1]](#references)</sup>

### Practical workflow

1. Lifted code/IR/decompiler output (`8/16/32/64` bits) से **original bit-width** बनाए रखें।
2. इसे simplify करने का प्रयास करने से पहले **expression को classify** करें:
- **Linear**: bitwise atoms के weighted sums
- **Semilinear**: linear तथा constant masks जैसे `x & 0xFF`
- **Polynomial**: products दिखाई देते हैं
- **Mixed**: products और bitwise logic interleaved होते हैं, अक्सर repeated subexpressions के साथ
3. हर candidate rewrite को random testing या SMT proof से **verify** करें। यदि equivalence को prove नहीं किया जा सकता, तो अनुमान लगाने के बजाय original expression बनाए रखें।

### Bypass flattened control flow with a narrow execution slice

Complete control-flow graph को recover करना अक्सर आवश्यक नहीं होता। Control-flow flattening, opaque predicates, large dispatchers या MBA-heavy code के साथ, encrypted blobs और output buffers से references follow करके उस सबसे छोटी routine तक पहुँचें जो उन्हें transform करती है। फिर केवल उस data-flow slice को reproduce करें या उसे independently execute करें; यदि relevant state को सीधे initialize किया जा सकता है, तो dispatcher required solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक practical workflow इस प्रकार है:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations तथा cross-references की inventory बनाएं। `.rodata` से candidate tables को उनके byte order और element width को बनाए रखते हुए dump करें।
2. उस अंतिम routine की पहचान करें जो plaintext या output buffer में लिखती है। इसके inputs, referenced tables, imported calls और required global state को record करें।
3. केवल उन्हीं operations को fixed-width Python model में lift करें। यदि slice अभी भी बहुत अधिक state पर निर्भर है, तो पूरे program को emulate करने के बजाय Unicorn, QEMU या debugger के अंतर्गत routine invoke करें और irrelevant imports को hook करें।
4. Validate करें कि extractor वास्तव में supplied binary से अपना output derive करता है: silent fallbacks हटाएं, उसमें embedded answers के लिए search करें और बदले हुए strings, keys, identifiers, layouts तथा obfuscation seeds वाले unseen builds पर इसे run करें।

Useful first-pass commands हैं:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Disguised constants के रूप में MBA expressions का पता लगाएँ

दिखने में input-dependent byte expression अपने input को पूरी तरह cancel कर सकता है। इसकी tables निकालने के बाद, expression का मूल्यांकन पूरे 8-bit domain पर करें; singleton output set यह सिद्ध करता है कि वह byte constant है, इसके आसपास के state machine को recover किए बिना भी।<sup>[[7]](#references)</sup>
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
अंतिम mask बनाए रखें क्योंकि मूल addition में byte-width wraparound होता है। व्यापक domain के लिए, SMT solver से पूछें कि क्या दो समान-width वाले symbolic inputs के लिए `f(x1) != f(x2)` satisfiable है: `unsat` invariance सिद्ध करता है, जबकि `sat` counterexample देता है और इसका अर्थ है कि input को discard नहीं किया जा सकता।<sup>[[7]](#references)</sup>

#### environment-bound decoding को पहचानें

Anti-analysis checks का branch या crash करना आवश्यक नहीं है। कोई decoder sensor result को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से आगे बढ़ सकता है और emulator में plausible लेकिन गलत plaintext उत्पन्न कर सकता है। इसलिए, केवल दिखाई देने वाली failure branches को patch करना अपर्याप्त है; environment probes से decoder state तक data dependencies को trace करें, authentic device और emulator पर उसी slice की तुलना करें, और जाँचें कि प्रत्येक sensor result को force करने पर final buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक practical MBA simplifier है। यह expression को classify करता है और हर चीज़ पर एक generic rewrite pass लागू करने के बजाय उसे specialized pipelines के माध्यम से route करता है।<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature प्राप्त करता है, और pattern matching, ANF conversion तथा coefficient interpolation जैसी कई recovery methods को एक साथ आज़माता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction के साथ फिर से बनाया जाता है, ताकि masked regions सही रहें।
- **Polynomial/Mixed MBA**: products को cores में विभाजित किया जाता है और outer relation को simplify करने से पहले repeated subexpressions को temporaries में lift किया जा सकता है।

एक mixed identity का उदाहरण, जिसे recover करने का प्रयास आमतौर पर उपयोगी होता है:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
इसे संक्षिप्त करके यह बनाया जा सकता है:
```c
x * y
```
### Reversing notes

- exact computation को isolate करने के बाद **lifted IR expressions** या decompiler output पर CoBRA चलाना पसंद करें।
- जब expression masked arithmetic या narrow registers से आया हो, तो `--bitwidth` explicitly उपयोग करें।
- यदि आपको stronger proof step चाहिए, तो यहाँ दिए गए local Z3 notes देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA एक **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है, जो बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करने के लिए उपयोगी है।
- Unsupported carry-sensitive mixed-domain residuals को original expression को बनाए रखने और carry path के बारे में manually reason करने के signal के रूप में समझना चाहिए।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-based instruction sequences से replace करता है और control flow को बदलने के लिए signal/exception handling का उपयोग करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Supported binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) result को deobfuscate कर सकता है। इसके लिए कई dependencies हैं।
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
और [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

यदि आप **CTF खेल रहे हैं, तो flag खोजने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए functions में `::main` से search करें, जैसे:

![Ghidra में double-colon main के लिए function names search करके Rust entry point खोजना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह स्पष्ट है कि यही महत्वपूर्ण main function है।\
जिन **functions** को call किया जा रहा है, उनके **name** जानने के बाद, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर search करें।

### ELF firmware से Rust strings को recover करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। एक सामान्य `rustc` layout में **`.data.rel.ro`** के अंदर एक **pointer/length tuple** होता है, जो वास्तविक string blob की ओर point करता है और वह blob **`.rodata`** में stored होता है:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
इसका मतलब है कि `strings` या default Ghidra analysis आस-पास की strings को merge कर सकता है या cross-references को पूरी तरह miss कर सकता है।<sup>[[3]](#references)</sup>

त्वरित workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक-एक word करके enumerate करें।
3. `.rodata` address range के अंदर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. sanity filters लागू करें (उदाहरण के लिए, **4** और **100** bytes के बीच की lengths रखें)।
6. `0x00` तक scan करने के बजाय `.rodata` से ठीक `length` bytes पढ़ें।

न्यूनतम extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, और auth-related logic** प्रकट करती हैं।

यदि Ghidra उन strings को miss कर देता है, तो एक custom script/plugin चलाएँ, जो इसी heuristic को लागू करे और referenced `.rodata` offsets पर string data बनाए। Pen Test Partners के published `rust-strings` और `RustStrings.py` tools इस विचार को अन्य **word sizes, endianness, और section layouts** के लिए adapt करने के अच्छे references हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

यदि आपको किसी Delphi binary को reverse करना हो, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने का सुझाव दूँगा।

IDA में Python plugin load करने के लिए **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin binary को execute करेगा और debugging की शुरुआत में function names को dynamically resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ और real code की शुरुआत में एक breakpoint hit होगा।

यदि आप graphical application में कोई button दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

यदि आपको किसी Golang binary को reverse करना हो, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने का सुझाव दूँगा।

IDA में Python plugin load करने के लिए **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह functions के names को resolve करेगा।

## Compiled Python

इस page पर आप जान सकते हैं कि ELF/EXE Python compiled binary से Python code कैसे प्राप्त किया जाए:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

यदि आपको किसी GBA game की **binary** मिलती है, तो आप उसे **emulate** और **debug** करने के लिए अलग-अलग tools का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Interface वाला debugger
- [**mgba** ](https://mgba.io)- CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** के अंतर्गत आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाने हैं।

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

दबाए जाने पर, प्रत्येक **key has a value** होती है, जिससे उसकी पहचान की जा सकती है:
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
तो, इस प्रकार के program में दिलचस्प भाग यह होगा कि **program user input को कैसे handle करता है**। address **0x4000130** पर आपको आमतौर पर मिलने वाला function: **KEYINPUT** मिलेगा।

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि function को **FUN_080015a8** से call किया गया है (addresses: _0x080015fa_ और _0x080017ac_)।

उस function में, कुछ init operations के बाद (जिनका कोई महत्व नहीं है):
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
अंतिम **`if`** यह जाँच रहा है कि **`uVar4`** पिछली **Keys** में है और वर्तमान key नहीं है; इसे बटन छोड़ना भी कहा जाता है (वर्तमान key **`uVar1`** में संग्रहीत है)।
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
पिछले code में आप देख सकते हैं कि हम **uVar1** (वह स्थान जहाँ **दबाए गए button की value** होती है) की तुलना कुछ values से कर रहे हैं:

- सबसे पहले, इसकी तुलना **value 4** (**SELECT** button) से की जाती है: challenge में यह button screen को clear करता है
- फिर इसकी तुलना **8** (**START** button) से की जाती है; इस challenge में, यह path जाँचता है कि दर्ज किया गया code valid है या नहीं।
- इस मामले में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute किया जाता है।
- अन्य सभी मामलों में, एक counter (`DAT_030000d4`) को check और increment किया जाता है।\
जब तक counter 8 से कम रहता है, दबाई गई keys की values को `DAT_030000d8` में accumulate किया जाता है।

इसलिए, इस challenge में, buttons की values जानने के बाद आपको **8 से छोटी length वाला ऐसा combination press करना था जिसका resulting addition 0xf3 हो।**

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
- [7] [AI-Assisted Reverse Engineering को हराना, या कम-से-कम प्रयास करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
