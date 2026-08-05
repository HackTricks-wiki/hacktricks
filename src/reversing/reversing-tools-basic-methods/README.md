# Reversing Tools और Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- wasm (binary) से wat (clear text) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
- wat से wasm में **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें
- decompile करने के लिए आप [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) का भी उपयोग कर सकते हैं

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक decompiler है जो **कई formats को decompile और examine करता है**, जिसमें **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe) शामिल हैं। Decompile करने के बाद, किसी assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

इसका लाभ यह है कि यदि किसी lost source code को किसी legacy assembly से restore करने की आवश्यकता हो, तो यह action समय बचा सकता है। इसके अलावा, dotPeek decompiled code में सुविधाजनक navigation प्रदान करता है, जिससे यह **Xamarin algorithm analysis** के लिए perfect tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक comprehensive add-in model और tool को आपकी exact needs के अनुसार extend करने वाली API के साथ, .NET reflector समय बचाता है और development को सरल बनाता है। आइए उन reverse engineering services पर एक नज़र डालें जो यह tool प्रदान करता है:

- यह जानकारी देता है कि data किसी library या component के माध्यम से कैसे flow करता है
- .NET languages और frameworks के implementation और usage की जानकारी देता है
- उपयोग की जा रही APIs और technologies से अधिक लाभ प्राप्त करने के लिए undocumented और unexposed functionality ढूंढता है।
- dependencies और अलग-अलग assemblies ढूंढता है
- आपके code, third-party components और libraries में errors का exact location ढूंढता है।
- आपके द्वारा उपयोग किए जा रहे सभी .NET code के source में debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS में उपयोग कर सकते हैं (आप इसे सीधे VSCode से install कर सकते हैं, git download करने की आवश्यकता नहीं है। **Extensions** पर click करें और **search ILSpy** करें)।\
यदि आपको फिर से **decompile**, **modify** और **recompile** करना है, तो आप [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसके actively maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) का उपयोग कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** करें)।

### DNSpy Logging

**DNSpy को किसी file में कुछ information log करने** के लिए आप इस snippet का उपयोग कर सकते हैं:
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

![DNSpy Logging - DNSpy Debugging: compile पर क्लिक करें](<../../images/image (314) (1).png>)

फिर _**File >> Save module...**_ के माध्यम से नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: फिर File Save module के माध्यम से नई फ़ाइल सेव करें](<../../images/image (602).png>)

यह आवश्यक है, क्योंकि यदि आप ऐसा नहीं करते हैं, तो **runtime** पर code में कई **optimisations** लागू हो जाएँगी और संभव है कि debugging के दौरान **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, यदि आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस प्रकार **restart** कर सकते हैं:
```
iisreset /noforce
```
फिर, debugging शुरू करने के लिए आपको खोली गई सभी files बंद करनी चाहिए और **Debug Tab** के अंदर **Attach to Process...** चुनना चाहिए:

![DNSpy Logging - DNSpy Debugging: फिर, debugging शुरू करने के लिए आपको खोली गई सभी files बंद करनी चाहिए और Debug Tab के अंदर Attach to Process चुनना चाहिए](<../../images/image (318).png>)

फिर **w3wp.exe** चुनकर **IIS server** से attach करें और **attach** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर क्लिक करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, इसे रोकने और सभी modules load करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें और फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर क्लिक करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर क्लिक करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right click करें और Sort Assemblies पर क्लिक करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की debugging

### IDA का उपयोग

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: " Suspend on library load/unload " चुनें](<../../images/image (868).png>)

- Execution के **parameters** configure करें, जिसमें **DLL का path** और वह function डालें जिसे आप call करना चाहते हैं:

![Debugging DLLs - Using IDA: Execution के parameters configure करें, जिसमें DLL का path और वह function डालें जिसे आप call करना चाहते हैं](<../../images/image (704).png>)

फिर, जब आप debugging शुरू करेंगे, **हर DLL के load होने पर execution रुक जाएगा**; इसलिए, जब rundll32 आपकी DLL load करेगा, execution रुक जाएगा।

लेकिन, load की गई DLL के code तक कैसे पहुंचें? इस method का उपयोग करके, मुझे नहीं पता कि यह कैसे किया जा सकता है।

### x64dbg/x32dbg का उपयोग

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा वह function set करें जिसे आप call करना चाहते हैं, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**; debugger प्रत्येक dll main पर रुक जाएगा और किसी बिंदु पर **आपकी dll के dll Entry पर रुकेंगे**। वहां से, केवल उन points को खोजें जहां आप breakpoint लगाना चाहते हैं।

ध्यान दें कि जब win64dbg में किसी भी कारण से execution रुकता है, तो आप **win64dbg window के शीर्ष पर** देखकर देख सकते हैं कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि जब win64dbg में किसी भी कारण से execution रुकता है, तो आप win64dbg window के शीर्ष पर देखकर देख सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

फिर, इसे देखकर आप जान सकते हैं कि execution उस dll में कब रुका जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो running game की memory में important values कहां save हैं, यह ढूंढने और उन्हें बदलने में मदद करता है। अधिक जानकारी यहां है:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) का एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालांकि, इसका उपयोग reverse-engineering से संबंधित किसी भी काम के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers का एक web front-end है। यह web service आपको छोटी executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner के साथ shellcode की debugging

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **shellcode** को memory के एक हिस्से में **allocate** करेगा, आपको वह **memory address बताएगा** जहां shellcode allocate किया गया है और **execution रोक देगा**।\
फिर, आपको process से **attach a debugger** (Ida या x64dbg) करना होगा, **बताए गए memory address पर breakpoint लगाना** होगा और **execution resume** करना होगा। इस तरह आप shellcode को debug कर पाएंगे।

Releases github page में compiled releases वाली zips हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप निम्न link में Blobrunner का थोड़ा modified version पा सकते हैं। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएं, code को copy और paste करें और उसे build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it के साथ shellcode की debugging

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) blobrunner के समान है। यह **shellcode** को memory के एक हिस्से में **allocate** करेगा और एक **अनंत loop** शुरू करेगा। इसके बाद आपको process से **debugger attach** करना होगा, **play start दबाएं, 2-5 secs प्रतीक्षा करें और stop दबाएं**, और आप स्वयं को **अनंत loop** के अंदर पाएंगे। अनंत loop की next instruction पर jump करें, क्योंकि वह shellcode को call करेगी; अंततः आप shellcode execute करते हुए पाए जाएंगे।

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it blobrunner के समान है। यह shellcode को memory के एक हिस्से में allocate करेगा और एक...](<../../images/image (509).png>)

आप [releases page में jmp2it का compiled version](https://github.com/adamkramer/jmp2it/releases/) download कर सकते हैं।

### Cutter का उपयोग करके shellcode की debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और उसका dynamically निरीक्षण कर सकते हैं।

ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" की अनुमति देता है। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने उसे सही ढंग से decompile किया; लेकिन जब मैंने उसे shellcode के रूप में खोला, तो ऐसा नहीं हुआ:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" की अनुमति देता है। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने...](<../../images/image (562).png>)

Emulation को अपनी इच्छित जगह से शुरू करने के लिए वहां bp set करें; ऐसा लगता है कि Cutter automatically वहीं से emulation शुरू कर देगा:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Emulation को अपनी इच्छित जगह से शुरू करने के लिए वहां bp set करें और ऐसा लगता है कि Cutter automatically वहीं से emulation शुरू कर देगा](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Emulation को अपनी इच्छित जगह से शुरू करने के लिए वहां bp set करें और ऐसा लगता है कि Cutter automatically वहीं से emulation शुरू कर देगा](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump के अंदर देख सकते हैं:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: उदाहरण के लिए, आप stack को hex dump के अंदर देख सकते हैं](<../../images/image (186).png>)

### shellcode को deobfuscate करना और executed functions प्राप्त करना

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
scDbg में एक graphical launcher भी है, जहाँ आप अपनी इच्छित options चुनकर shellcode execute कर सकते हैं

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg में एक graphical launcher भी है, जहाँ आप अपनी इच्छित options चुनकर shellcode...](<../../images/image (258).png>)

**Create Dump** option अंतिम shellcode को dump करेगा, यदि memory में shellcode में dynamically कोई बदलाव किया गया हो (decoded shellcode download करने के लिए उपयोगी)। **start offset** किसी specific offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** option scDbg terminal का उपयोग करके shellcode debug करने के लिए उपयोगी है (हालाँकि इस मामले में मुझे पहले समझाए गए options में से कोई भी बेहतर लगता है, क्योंकि आप Ida या x64dbg का उपयोग कर पाएँगे)।

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए निम्न recipe का उपयोग करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation `x + y` जैसे simple expressions को arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाने वाले formulas के पीछे छिपाता है। महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के अंतर्गत ही सही होती हैं, इसलिए carries और overflows मायने रखते हैं:
```c
(x ^ y) + 2 * (x & y) == x + y
```
यदि आप इस प्रकार के expression को generic algebra tooling से simplify करते हैं, तो आपको आसानी से गलत result मिल सकता है, क्योंकि bit-width semantics को अनदेखा कर दिया गया था।

### Practical workflow

1. **Original bit-width बनाए रखें** lifted code/IR/decompiler output (`8/16/32/64` bits) से।
2. **Expression को classify करें** इसे simplify करने का प्रयास करने से पहले:
- **Linear**: bitwise atoms के weighted sums
- **Semilinear**: constant masks जैसे `x & 0xFF` के साथ linear
- **Polynomial**: products दिखाई देते हैं
- **Mixed**: products और bitwise logic interleaved होते हैं, अक्सर repeated subexpressions के साथ
3. **हर candidate rewrite को verify करें** random testing या SMT proof से। यदि equivalence को prove नहीं किया जा सकता, तो अनुमान लगाने के बजाय original expression रखें।

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक practical MBA simplifier है। यह expression को classify करता है और हर चीज़ पर एक generic rewrite pass लागू करने के बजाय उसे specialized pipelines के माध्यम से process करता है।<sup>[[1]](#references)[[2]](#references)</sup>

Quick usage:
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

- **Linear MBA**: CoBRA Boolean inputs पर expression को evaluate करता है, एक signature derive करता है, और pattern matching, ANF conversion तथा coefficient interpolation जैसी कई recovery methods को parallel में आजमाता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction के साथ फिर से बनाया जाता है, ताकि masked regions सही बने रहें।
- **Polynomial/Mixed MBA**: products को cores में decompose किया जाता है और simplifying the outer relation से पहले repeated subexpressions को temporaries में lift किया जा सकता है।

एक mixed identity का उदाहरण, जिसे recover करने की कोशिश करना आमतौर पर उपयोगी होता है:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
इसे इस रूप में संक्षिप्त किया जा सकता है:
```c
x * y
```
### Reversing notes

- Exact computation को isolate करने के बाद CoBRA को **lifted IR expressions** या decompiler output पर चलाना बेहतर है।
- जब expression masked arithmetic या narrow registers से आया हो, तो `--bitwidth` को स्पष्ट रूप से इस्तेमाल करें।
- यदि आपको अधिक मजबूत proof step की आवश्यकता हो, तो यहां दिए गए local Z3 notes देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA एक **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है, जो बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करने में उपयोगी है।
- Unsupported carry-sensitive mixed-domain residuals को original expression को बनाए रखने और carry path पर manually reasoning करने के संकेत के रूप में समझना चाहिए।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator **`mov` के लिए सभी instructions को modify करता है** (हां, सच में काफी cool)। यह execution flows को बदलने के लिए interrupts का भी उपयोग करता है। यह कैसे काम करता है, इसकी अधिक जानकारी के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

यदि आप lucky हैं, तो [demovfuscator](https://github.com/kirschju/demovfuscator) binary को deofuscate कर देगा। इसकी कई dependencies हैं
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
और [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

यदि आप **CTF खेल रहे हैं, तो flag खोजने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए functions में `::main` से search करें, जैसा कि इसमें दिखाया गया है:

![Movfuscator - Rust: entry point खोजने के लिए functions में ::main से search करें, जैसा कि इसमें दिखाया गया है](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह स्पष्ट है कि यही महत्वपूर्ण main function है।\
जिन **functions** को call किया जा रहा है, उनके **नाम** से **Internet** पर search करें और उनके **inputs** तथा **outputs** के बारे में जानें।

### ELF firmware से Rust strings recover करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। एक सामान्य `rustc` layout में **`.data.rel.ro`** के अंदर एक **pointer/length tuple** होता है, जो **`.rodata`** में stored वास्तविक string blob की ओर point करता है:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
इसका मतलब है कि `strings` या default Ghidra analysis adjacent strings को merge कर सकता है या cross-references को पूरी तरह miss कर सकता है।

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
यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, और auth-related logic** प्रकट करते हैं।

यदि Ghidra उन strings को miss कर देता है, तो एक custom script/plugin चलाएँ, जो उसी heuristic को लागू करे और referenced `.rodata` offsets पर string data बनाए। Pen Test Partners के published `rust-strings` और `RustStrings.py` tools इस विचार को अन्य **word sizes, endianness, और section layouts** के लिए अनुकूलित करने हेतु अच्छे references हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

यदि आपको किसी Delphi binary को reverse करना हो, तो मैं आपको IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने का सुझाव दूँगा।

बस **ATL+f7** दबाएँ (IDA में python plugin import करें) और python plugin चुनें।

यह plugin binary को execute करेगा और debugging की शुरुआत में function names को dynamically resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ और real code की शुरुआत में एक breakpoint hit होगा।

यह इसलिए भी काफी उपयोगी है क्योंकि यदि आप graphic application में कोई button दबाते हैं, तो debugger उस button द्वारा execute किए गए function पर रुक जाएगा।

## Golang

यदि आपको किसी Golang binary को reverse करना हो, तो मैं आपको IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने का सुझाव दूँगा।

बस **ATL+f7** दबाएँ (IDA में python plugin import करें) और python plugin चुनें।

यह functions के names को resolve कर देगा।

## Compiled Python

इस page पर आप जान सकते हैं कि ELF/EXE python compiled binary से python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

यदि आपको किसी GBA game की **binary** मिलती है, तो आप इसे **emulate** और **debug** करने के लिए अलग-अलग tools का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Interface के साथ debugger शामिल है
- [**mgba** ](https://mgba.io)- CLI debugger शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** के अंतर्गत आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाने हैं।

![Game Boy Advance button mappings दिखाने वाला no$gba controls configuration](<../../images/image (581).png>)

दबाने पर, प्रत्येक **key has a value** होती है, जिससे उसकी पहचान की जा सकती है:
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
तो, इस तरह के program में दिलचस्प हिस्सा यह होगा कि **program user input के साथ कैसे व्यवहार करता है**। Address **0x4000130** पर आपको आमतौर पर मिलने वाला function: **KEYINPUT** मिलेगा।

![0x4000130 address पर KEYINPUT को reference करने वाले GBA binary का Ghidra view](<../../images/image (447).png>)

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
अंतिम **`if`** यह जांच रहा है कि **`uVar4`** पिछली **Keys** में है और current key नहीं है; इसे button छोड़ना भी कहा जाता है (current key **`uVar1`** में stored है)।
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
- फिर, इसकी तुलना **value 8** (**START** button) से की जाती है: challenge में यह जाँचता है कि flag प्राप्त करने के लिए code valid है या नहीं।
- इस मामले में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute किया जाता है।
- अन्य सभी मामलों में, कुछ cont (**`DAT_030000d4`**) को check किया जाता है। यह cont है क्योंकि code में प्रवेश करने के तुरंत बाद इसमें 1 जोड़ा जाता है।\
**य**दि यह 8 से कम है, तो **`DAT_030000d8`** में values **add** करने से संबंधित कुछ किया जाता है (मूल रूप से, जब तक cont 8 से कम है, तब तक दबाई गई keys की values इस variable में add की जाती हैं)।

इसलिए, इस challenge में, buttons की values जानने के बाद, आपको **8 से छोटी length वाला ऐसा combination press करना था जिसका resulting addition 0xf3 हो।**<sup>[[6]](#references)</sup>

**इस tutorial का Reference:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
