# Reversing Tools और Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui आधारित Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

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

dotPeek एक decompiler है जो **कई formats को decompile और examine करता है**, जिनमें **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe) शामिल हैं। Decompile करने के बाद, किसी assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

इसका लाभ यह है कि यदि किसी lost source code को legacy assembly से restore करने की आवश्यकता हो, तो यह action समय बचा सकता है। इसके अतिरिक्त, dotPeek decompiled code में सुविधाजनक navigation प्रदान करता है, जिससे यह **Xamarin algorithm analysis** के लिए एक perfect tool बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक comprehensive add-in model और tool को आपकी exact needs के अनुसार विस्तारित करने वाली API के साथ, .NET reflector समय बचाता है और development को सरल बनाता है। आइए उन reverse engineering services पर नज़र डालते हैं जो यह tool प्रदान करता है:

- यह जानकारी देता है कि data किसी library या component में किस तरह flow करता है
- .NET languages और frameworks के implementation और usage की जानकारी देता है
- उपयोग किए गए APIs और technologies से अधिक लाभ प्राप्त करने के लिए undocumented और unexposed functionality खोजता है।
- Dependencies और अलग-अलग assemblies खोजता है
- आपके code, third-party components और libraries में errors का exact location पता करता है।
- आपके द्वारा उपयोग किए जाने वाले सभी .NET code के source में debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS में उपयोग कर सकते हैं (आप इसे सीधे VSCode से install कर सकते हैं, git download करने की आवश्यकता नहीं है। **Extensions** पर click करें और **search ILSpy** करें)।\
यदि आपको **decompile**, **modify** और फिर से **recompile** करना है, तो आप [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसके actively maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) का उपयोग कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** करें)।

### DNSpy Logging

**DNSpy से किसी file में कुछ information log कराने के लिए**, आप इस snippet का उपयोग कर सकते हैं:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy का उपयोग करके code debug करने के लिए आपको:

सबसे पहले, **Assembly attributes** से संबंधित **debugging** को बदलें:

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

![DNSpy Logging - DNSpy Debugging: compile पर क्लिक करें](<../../images/image (314) (1).png>)

फिर _**File >> Save module...**_ के माध्यम से नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: File Save module के माध्यम से नई फ़ाइल सेव करें](<../../images/image (602).png>)

यह आवश्यक है, क्योंकि यदि आप ऐसा नहीं करते हैं, तो **runtime** पर code में कई **optimisations** लागू किए जाएंगे और संभव है कि debugging के दौरान **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, यदि आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस प्रकार **restart** कर सकते हैं:
```
iisreset /noforce
```
फिर, debugging शुरू करने के लिए आपको खोली गई सभी files बंद करनी चाहिए और **Debug Tab** के अंदर **Attach to Process...** चुनना चाहिए:

![DNSpy Logging - DNSpy Debugging: फिर, debugging शुरू करने के लिए आपको खोली गई सभी files बंद करनी चाहिए और Debug Tab के अंदर Attach to Process चुनना चाहिए](<../../images/image (318).png>)

फिर **IIS server** से attach करने के लिए **w3wp.exe** चुनें और **attach** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर क्लिक करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो इसे रोकने और सभी modules load करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें और फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर क्लिक करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर क्लिक करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right click करें और Sort Assemblies पर क्लिक करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs को Debug करना

### IDA का उपयोग करना

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: " Suspend on library load/unload " चुनें](<../../images/image (868).png>)

- **parameters** configure करें और execution में **DLL का path** तथा वह function डालें जिसे आप call करना चाहते हैं:

![Debugging DLLs - Using IDA: execution के parameters configure करें और DLL का path तथा वह function डालें जिसे आप call करना चाहते हैं](<../../images/image (704).png>)

फिर, जब आप debugging शुरू करेंगे, **हर DLL load होने पर execution रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL load करेगा, तो execution रुक जाएगा।

यह method module-load events पर रुकता है, लेकिन loaded DLL के entry point तक पहुँचना नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग करना

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा वह function सेट करें जिसे आप call करना चाहते हैं, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**। debugger हर dll main पर रुकेगा और किसी बिंदु पर **आपकी dll के dll Entry पर रुक जाएगा**। वहाँ से, केवल उन points को खोजें जहाँ आप breakpoint लगाना चाहते हैं।

ध्यान दें कि win64dbg में किसी भी कारण से execution रुकने पर आप **win64dbg window के शीर्ष पर** देख सकते हैं कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि win64dbg में किसी भी कारण से execution रुकने पर आप win64dbg window के शीर्ष पर देख सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि execution उस DLL के अंदर रुक गया है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो यह पता लगाने में मदद करता है कि running game की memory में महत्वपूर्ण values कहाँ save हैं और उन्हें बदलने में मदद करता है। अधिक जानकारी:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालांकि, इसका उपयोग reverse-engineering से संबंधित किसी भी काम के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers का web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner के साथ shellcode को Debug करना

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** को allocate करता है, उसका **memory address** print करता है और execution को pause करता है।\
IDA या x64dbg जैसे debugger को attach करें, printed address पर breakpoint सेट करें और shellcode को debug करने के लिए execution resume करें।

releases github page में compiled releases वाली zips हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप निम्न link में Blobrunner का थोड़ा modified version पा सकते हैं। इसे compile करने के लिए बस **Visual Studio Code में एक C/C++ project बनाएं, code को copy और paste करें और उसे build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it के साथ shellcode को Debug करना

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) BlobRunner के समान है। यह shellcode को allocate करता है और एक infinite loop में प्रवेश करता है। debugger को attach करें, **2–5 seconds** तक resume करें, उस loop के अंदर pause करें और अगली call तक step करें, जो execution को allocated shellcode में transfer करती है।

![jmp2it के infinite loop में allocated shellcode को call करने से ठीक पहले paused debugger](<../../images/image (509).png>)

आप [jmp2it का compiled version releases page के अंदर](https://github.com/adamkramer/jmp2it/releases/) download कर सकते हैं।

### Cutter का उपयोग करके shellcode को Debug करना

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और इसे dynamically inspect कर सकते हैं।

ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" की अनुमति देता है। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने इसे सही ढंग से decompile किया, लेकिन जब मैंने इसे shellcode के रूप में खोला, तो ऐसा नहीं हुआ:

![समान bytes को file या shellcode के रूप में खोलने पर Cutter द्वारा दिखाए गए अलग-अलग analysis results](<../../images/image (562).png>)

Emulation को इच्छित स्थान से शुरू करने के लिए वहाँ bp सेट करें। ऐसा लगता है कि Cutter वहीं से emulation अपने-आप शुरू कर देगा:

![Cutter emulation शुरू करने से पहले इच्छित shellcode entry पर breakpoint सेट करना](<../../images/image (589).png>)

![चयनित shellcode breakpoint पर paused Cutter emulator](<../../images/image (387).png>)

उदाहरण के लिए, आप hex dump के अंदर stack देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### shellcode को Deobfuscate करना और executed functions प्राप्त करना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़माना चाहिए।\
यह आपको ऐसी जानकारी देगा कि shellcode **किन functions** का उपयोग कर रहा है और क्या shellcode memory में स्वयं को **decode** कर रहा है।
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

**Create Dump** option अंतिम shellcode को dump करेगा, यदि memory में shellcode में dynamically कोई बदलाव किया गया हो (decoded shellcode को download करने के लिए उपयोगी)। **start offset** किसी specific offset से shellcode शुरू करने में उपयोगी हो सकता है। **Debug Shell** option scDbg terminal का उपयोग करके shellcode को debug करने के लिए उपयोगी है (हालांकि इस काम के लिए मुझे पहले समझाए गए options में से कोई भी बेहतर लगता है, क्योंकि आप Ida या x64dbg का उपयोग कर पाएंगे)।

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए निम्न recipe का उपयोग करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाने वाले formulas के पीछे `x + y` जैसे simple expressions को छिपाता है। महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के अंतर्गत सही होती हैं, इसलिए carries और overflows मायने रखते हैं:
```c
(x ^ y) + 2 * (x & y) == x + y
```
यदि आप इस प्रकार के expression को generic algebra tooling से simplify करते हैं, तो आपको आसानी से गलत result मिल सकता है, क्योंकि bit-width semantics को नज़रअंदाज़ कर दिया गया था।<sup>[[1]](#references)</sup>

### Practical workflow

1. **Original bit-width बनाए रखें** lifted code/IR/decompiler output (`8/16/32/64` bits) से।
2. **Simplify करने से पहले expression को classify करें:**
- **Linear**: bitwise atoms के weighted sums
- **Semilinear**: constant masks जैसे `x & 0xFF` के साथ linear
- **Polynomial**: products मौजूद हों
- **Mixed**: products और bitwise logic interleaved हों, अक्सर repeated subexpressions के साथ
3. **हर candidate rewrite को** random testing या SMT proof से verify करें। यदि equivalence prove नहीं की जा सकती, तो अनुमान लगाने के बजाय original expression रखें।

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक practical MBA simplifier है। यह expression को classify करता है और हर चीज़ पर एक generic rewrite pass लागू करने के बजाय उसे specialized pipelines के माध्यम से process करता है।<sup>[[2]](#references)</sup>

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

एक mixed identity का उदाहरण, जिसे recover करने का प्रयास करना सामान्यतः उपयोगी होता है:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
इसे संक्षेप में इस प्रकार लिखा जा सकता है:
```c
x * y
```
### Reversing notes

- CoBRA को **lifted IR expressions** या decompiler output पर चलाना पसंद करें, जब आपने exact computation को isolate कर लिया हो।
- जब expression masked arithmetic या narrow registers से आया हो, तो `--bitwidth` का स्पष्ट रूप से उपयोग करें।
- यदि आपको अधिक मजबूत proof step की आवश्यकता हो, तो यहाँ दिए गए local Z3 notes देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA एक **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है, जो बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करने के लिए उपयोगी है।
- Unsupported carry-sensitive mixed-domain residuals को original expression बनाए रखने और carry path का manually reasoning करने के संकेत के रूप में समझें।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-based instruction sequences से replace करता है और control flow को बदलने के लिए signal/exception handling का उपयोग करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Supported binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) result को deobfuscate कर सकता है। इसकी कई dependencies हैं।
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
जिन **functions** को call किया जा रहा है, उनका **name** जानने के बाद, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर search करें।

### ELF firmware से Rust strings recover करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। एक सामान्य `rustc` layout में **`.data.rel.ro`** के अंदर एक **pointer/length tuple** होता है, जो वास्तविक string blob की ओर point करता है, जो **`.rodata`** में stored होता है:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
इसका अर्थ है कि `strings` या default Ghidra analysis आस-पास की strings को merge कर सकता है या cross-references को पूरी तरह miss कर सकता है।<sup>[[3]](#references)</sup>

त्वरित workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक-एक word करके enumerate करें।
3. `.rodata` address range के अंदर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. Sanity filters लागू करें (उदाहरण के लिए, **4** और **100** bytes के बीच की lengths रखें)।
6. `0x00` तक scan करने के बजाय `.rodata` से ठीक `length` bytes पढ़ें।

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, और auth-related logic** प्रकट करती हैं।

यदि Ghidra उन strings को miss कर देता है, तो एक custom script/plugin चलाएँ, जो उसी heuristic को लागू करे और referenced `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools इस विचार को अन्य **word sizes, endianness, और section layouts** के लिए अनुकूलित करने हेतु अच्छे references हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

यदि आपको किसी Delphi binary को reverse करना हो, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने की सलाह दूँगा।

IDA में Python plugin load करने के लिए **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin binary को execute करेगा और debugging की शुरुआत में function names को dynamically resolve करेगा। Debugging शुरू करने के बाद Start button (हरा वाला या f9) फिर से दबाएँ और real code की शुरुआत में breakpoint hit होगा।

यदि आप graphical application में कोई button दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

यदि आपको किसी Golang binary को reverse करना हो, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने की सलाह दूँगा।

IDA में Python plugin load करने के लिए **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह functions के names को resolve करेगा।

## Compiled Python

इस page पर आप जान सकते हैं कि ELF/EXE Python compiled binary से Python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

यदि आपको किसी GBA game की **binary** मिलती है, तो आप उसे **emulate** और **debug** करने के लिए विभिन्न tools का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Interface वाला debugger शामिल है
- [**mgba** ](https://mgba.io)- CLI debugger शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** के अंतर्गत आप Game Boy Advance के **buttons** दबाने का तरीका देख सकते हैं।

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

दबाए जाने पर, प्रत्येक **key की एक value होती है**, जिससे उसकी पहचान की जाती है:
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
इस तरह के program में, दिलचस्प हिस्सा यह होगा कि **program user input को कैसे handle करता है**। address **0x4000130** पर आपको आमतौर पर मिलने वाला function: **KEYINPUT** मिलेगा।

![0x4000130 address पर KEYINPUT को reference करने वाले GBA binary का Ghidra view](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि यह function **FUN_080015a8** (addresses: _0x080015fa_ और _0x080017ac_) से call किया गया है।

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
इसमें यह code मिला:
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
अंतिम `if` यह जाँच रहा है कि **`uVar4`** पिछले **Keys** में है और वर्तमान key नहीं है; इसे button को छोड़ना भी कहा जाता है (वर्तमान key **`uVar1`** में संग्रहीत है)।
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

- सबसे पहले, इसकी तुलना **value 4** (**SELECT** button) से की जाती है: challenge में यह button screen को clear करता है
- फिर इसकी तुलना **8** (**START** button) से की जाती है; इस challenge में यह path जाँचता है कि दर्ज किया गया code valid है या नहीं।
- इस स्थिति में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute किया जाता है।
- हर दूसरे मामले में, एक counter (`DAT_030000d4`) को check और increment किया जाता है।\
जब तक counter 8 से कम रहता है, दबाए गए keys की values को `DAT_030000d8` में accumulate किया जाता है।

इसलिए, इस challenge में buttons की values जानने के बाद, आपको **8 से छोटी length वाला ऐसा combination press करना था जिसका resulting addition 0xf3 हो।**

**इस tutorial का reference:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA obfuscation को CoBRA से सरल बनाना](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust strings को decode करना - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
