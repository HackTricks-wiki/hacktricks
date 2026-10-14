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

ऑनलाइन:

- wasm (binary) से wat (स्पष्ट टेक्स्ट) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
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

dotPeek एक decompiler है जो **कई formats को decompile और examine** करता है, जिनमें **libraries** (.dll), **Windows metadata files** (.winmd) और **executables** (.exe) शामिल हैं। Decompile करने के बाद, assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

इसका लाभ यह है कि अगर किसी पुराने assembly से खोए हुए source code को restore करना हो, तो इससे समय बच सकता है। इसके अलावा, dotPeek decompiled code में आसानी से navigation की सुविधा देता है, जिससे यह **Xamarin algorithm analysis** के लिए बेहतरीन tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक add-in model और ऐसी API के साथ, जो आपकी ज़रूरतों के अनुसार tool को बढ़ाती है, .NET Reflector समय बचाता है और development को आसान बनाता है। आइए, इस tool द्वारा दी जाने वाली reverse engineering services पर नज़र डालें:

- Library या component में data flow कैसे होता है, इसकी जानकारी देता है
- .NET languages और frameworks के implementation और उपयोग की जानकारी देता है
- इस्तेमाल किए गए APIs और technologies का अधिक लाभ उठाने के लिए undocumented और unexposed functionality ढूँढ़ता है।
- Dependencies और अलग-अलग assemblies ढूँढ़ता है
- आपके code, third-party components और libraries में errors की सटीक जगह का पता लगाता है।
- आपके द्वारा इस्तेमाल किए जाने वाले सभी .NET code के source को debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) और [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS पर इस्तेमाल कर सकते हैं (इसे सीधे VSCode से install कर सकते हैं; git download करने की ज़रूरत नहीं है। **Extensions** पर क्लिक करें और **ILSpy खोजें**)।\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसका सक्रिय रूप से maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) इस्तेमाल कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** चुनें।)

### REA के साथ execution-free managed inspection

**REA** assembly को load किए बिना PE/CLI metadata और CIL inspect कर सकता है। पहले artifact की पहचान करें, फिर members और घोषित native boundaries inspect करें; decompiler इस्तेमाल करने या program चलाने से पहले संदिग्ध calls की समीक्षा करते समय यह उपयोगी है।<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Version diffing के लिए, `compare_managed_members` metadata tokens को builds के बीच स्थिर मानने के बजाय raw CIL/signature identity और decoded-instruction fingerprints का उपयोग करता है। P/Invoke declaration इस बात का प्रमाण नहीं है कि native code चला; उस boundary की जाँच के लिए `verify_managed_native_boundaries` को matching native export या function Evidence की ज़रूरत होती है। परिणाम के साथ artifact digest, MVID और unresolved mappings रखें।<sup>[[17]](#references)</sup>

### DNSpy लॉगिंग

**DNSpy से किसी फ़ाइल में कुछ जानकारी लॉग करवाने** के लिए, आप यह snippet इस्तेमाल कर सकते हैं:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy डिबगिंग

DNSpy का उपयोग करके code डिबग करने के लिए आपको:

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

![DNSpy Logging - DNSpy Debugging: और compile पर क्लिक करें](<../../images/image (314) (1).png>)

फिर _**File >> Save module...**_ के ज़रिए नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: फिर File Save module के ज़रिए नई फ़ाइल सेव करें](<../../images/image (602).png>)

यह ज़रूरी है, क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर कोड में कई **optimisations** लागू हो जाएँगी और ऐसा हो सकता है कि debugging के दौरान कोई **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, अगर आपकी .NET application **IIS** द्वारा **run** की जा रही है, तो आप इसे इस तरह **restart** कर सकते हैं:

```
iisreset /noforce
```

फिर, debugging शुरू करने के लिए सभी खुली हुई फ़ाइलें बंद करें और **Debug Tab** में **Attach to Process...** चुनें:

![DNSpy Logging - DNSpy Debugging: फिर, debugging शुरू करने के लिए सभी खुली हुई फ़ाइलें बंद करें और Debug Tab में Attach to Process चुनें](<../../images/image (318).png>)

फिर **w3wp.exe** चुनकर **IIS server** से attach करें और **attach** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर क्लिक करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो इसे रोककर सभी modules लोड करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें और फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो इसे रोककर सभी modules लोड करने का समय है। पहले Debug Break All पर और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो इसे रोककर सभी modules लोड करने का समय है। पहले Debug Break All पर और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर क्लिक करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर क्लिक करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर राइट-क्लिक करें और **Sort Assemblies** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर राइट-क्लिक करें और Sort Assemblies पर क्लिक करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की debugging

### IDA का उपयोग करना

- **rundll32 लोड करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: "Suspend on library load/unload" चुनें](<../../images/image (868).png>)

- निष्पादन के **parameters** कॉन्फ़िगर करें: **DLL का path** और वह function दें जिसे आप call करना चाहते हैं:

![Debugging DLLs - Using IDA: निष्पादन के parameters कॉन्फ़िगर करें: DLL का path और वह function दें जिसे आप call करना चाहते हैं](<../../images/image (704).png>)

फिर, जब आप debugging शुरू करेंगे, तो **हर DLL लोड होने पर निष्पादन रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL लोड करेगा, तो निष्पादन रुक जाएगा।

यह तरीका module-load events पर रुकता है, लेकिन लोड की गई DLL के entry point तक पहुँचना, नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग करना

- **rundll32 लोड करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और DLL का path तथा वह function सेट करें जिसे आप call करना चाहते हैं। उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **निष्पादन शुरू करें**। debugger हर dll main पर रुकेगा और किसी बिंदु पर **आपकी DLL के Entry पर रुक जाएगा**। वहाँ से, बस उन जगहों को खोजें जहाँ आप breakpoint लगाना चाहते हैं।

ध्यान दें कि win64dbg में किसी भी कारण से निष्पादन रुकने पर, **win64dbg window के सबसे ऊपर** देखकर पता लगाया जा सकता है कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि win64dbg में किसी भी कारण से निष्पादन रुकने पर, win64dbg window के सबसे ऊपर देखकर पता लगाया जा सकता है कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि निष्पादन उस DLL के अंदर रुका है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) running game की memory में महत्वपूर्ण values कहाँ save की गई हैं, यह ढूँढ़ने और उन्हें बदलने के लिए उपयोगी program है। अधिक जानकारी:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालाँकि, इसका उपयोग reverse-engineering से जुड़ी किसी भी चीज़ के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## REA के साथ साक्ष्य-आधारित native जाँच

**REA** CLI और MCP के माध्यम से Hopper, Ghidra और IDA analysis उपलब्ध कराता है। इसके लिए Node.js 22.x (कम-से-कम 22.19), 24.x (कम-से-कम 24.11), या 26+ और npm चाहिए। पहले किसी मौजूदा native provider को configure करें; `rea providers --json` चलाकर जाँचें और जब एक से अधिक provider target को support करते हों, तो किसी एक provider को स्पष्ट रूप से चुनें। नीचे `0x1000` की जगह inventory से मिले किसी observed function name या address का उपयोग करें।<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

किसी feature string या symbol से शुरू करें, references और callers का अनुसरण करें, फिर `rea decompile` से चुने गए function dossier और pseudocode की जाँच करें। REA किसी failure के बाद चुपचाप provider बदलने के बजाय session को चुने गए provider से बाँधता है। दोहराए जा सकने वाले queries के लिए, `--snapshot PATH` केवल मेल खाने वाले artifact bytes, provider, settings, operation और parameters का पुनः उपयोग करता है; snapshot एक local cache है, सहेजा हुआ provider database नहीं। लौटाए गए Evidence और स्पष्ट unknowns को सुरक्षित रखें; अनुमानित paths या decompiler text को original source न मानें।<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron entry points से native add-ons तक जाने के लिए, देखें [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner से shellcode को debug करना

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** के लिए memory allocate करता है, उसका **memory address** प्रिंट करता है और execution रोक देता है।\
IDA या x64dbg जैसे debugger को attach करें, प्रिंट किए गए address पर breakpoint सेट करें और shellcode को debug करने के लिए execution फिर से शुरू करें।

releases github page में compiled releases वाली zip फ़ाइलें हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आपको नीचे दिए गए link में Blobrunner का थोड़ा modified version मिलेगा। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएँ, code को copy-paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it से shellcode को debug करना

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner जैसा है। यह shellcode के लिए memory allocate करता है और infinite loop में प्रवेश करता है। Debugger attach करें, **2–5 seconds** तक execution फिर से शुरू करें, उस loop के अंदर pause करें और फिर उस अगले call तक step करें जो execution को allocated shellcode में transfer करता है।

![Debugger, jmp2it के infinite loop में allocated shellcode को call करने से ठीक पहले paused है](<../../images/image (509).png>)

आप [releases page में jmp2it का compiled version डाउनलोड कर सकते हैं](https://github.com/adamkramer/jmp2it/releases/)।

### Cutter का उपयोग करके shellcode को debug करना

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और उसका dynamically निरीक्षण कर सकते हैं।

ध्यान दें कि Cutter में "Open File" और "Open Shellcode" विकल्प हैं। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने उसे सही ढंग से decompile किया; लेकिन जब मैंने उसे shellcode के रूप में खोला, तो ऐसा नहीं हुआ:

![Cutter में वही bytes file या shellcode के रूप में खोलने पर अलग analysis results दिख रहे हैं](<../../images/image (562).png>)

Emulation को अपनी इच्छित जगह से शुरू करने के लिए, वहाँ bp सेट करें और Cutter अपने-आप वहीं से emulation शुरू कर देगा:

![Cutter emulation शुरू करने से पहले इच्छित shellcode entry पर breakpoint सेट करना](<../../images/image (589).png>)

![Cutter emulator चुने गए shellcode breakpoint पर paused है](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump में देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### shellcode को deobfuscate करना और execute किए गए functions पाना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़माना चाहिए।\
यह आपको बताएगा कि shellcode किन **functions** का उपयोग कर रहा है और क्या shellcode memory में खुद को **decode** कर रहा है।

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg में एक graphical launcher भी है, जहाँ आप अपने इच्छित विकल्प चुनकर shellcode चला सकते हैं

![shellcode emulation और tracing विकल्प चुनने के लिए scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** विकल्प, shellcode को memory में dynamically बदलने पर, अंतिम shellcode का dump बनाता है (decoded shellcode डाउनलोड करने के लिए उपयोगी)। **start offset** किसी विशिष्ट offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** विकल्प, scDbg terminal का उपयोग करके shellcode debug करने के लिए उपयोगी है (हालाँकि, मुझे लगता है कि इस काम के लिए पहले बताए गए विकल्प बेहतर हैं, क्योंकि उनसे आप Ida या x64dbg का उपयोग कर पाएँगे)।

### CyberChef का उपयोग करके disassemble करना

अपनी shellcode file को input के रूप में upload करें और उसे decompile करने के लिए यह recipe इस्तेमाल करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` जैसे सरल expressions को ऐसे formulas के पीछे छिपाता है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाते हैं। अहम बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के अंतर्गत सही होती हैं, इसलिए carries और overflows मायने रखते हैं:

```c
(x ^ y) + 2 * (x & y) == x + y
```

यदि आप इस तरह के expression को generic algebra tooling से simplify करते हैं, तो bit-width semantics को नज़रअंदाज़ किए जाने के कारण आसानी से गलत result मिल सकता है।<sup>[[1]](#references)</sup>

### व्यावहारिक workflow

1. **मूल bit-width बनाए रखें** lifted code/IR/decompiler output (`8/16/32/64` bits) से।
2. **Simplify करने की कोशिश से पहले expression को classify करें**:
   - **Linear**: bitwise atoms के weighted sums
   - **Semilinear**: linear expression के साथ constant masks, जैसे `x & 0xFF`
   - **Polynomial**: products शामिल हों
   - **Mixed**: products और bitwise logic आपस में मिले हों, अक्सर repeated subexpressions के साथ
3. **हर संभावित rewrite को** random testing या SMT proof से verify करें। यदि equivalence साबित न हो सके, तो अंदाज़ा लगाने के बजाय मूल expression को ही रखें।

### Narrow execution slice के साथ flattened control flow को bypass करें

पूरा control-flow graph recover करना अक्सर ज़रूरी नहीं होता। Control-flow flattening, opaque predicates, बड़े dispatchers या MBA-heavy code के मामले में, encrypted blobs और output buffers के references का पीछा करते हुए उस सबसे छोटी routine तक पहुँचें जो उन्हें transform करती है। फिर केवल उस data-flow slice को reproduce करें या उसे स्वतंत्र रूप से execute करें; यदि संबंधित state सीधे initialize की जा सकती है, तो dispatcher आवश्यक solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक व्यावहारिक workflow है:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations, तथा cross-references की सूची बनाएँ। `.rodata` से candidate tables dump करें और उनका byte order तथा element width बनाए रखें।
2. उस आखिरी routine की पहचान करें जो plaintext या output buffer में लिखती है। उसके inputs, referenced tables, imported calls और आवश्यक global state दर्ज करें।
3. केवल उन्हीं operations को fixed-width Python model में lift करें। यदि slice अब भी बहुत अधिक state पर निर्भर हो, तो पूरे program को emulate करने के बजाय routine को Unicorn, QEMU या debugger में चलाएँ और अप्रासंगिक imports को hook करें।
4. Validate करें कि extractor वास्तव में दिए गए binary से अपना output निकालता है: silent fallbacks हटाएँ, उसमें embedded answers खोजें, और बदले हुए strings, keys, identifiers, layouts तथा obfuscation seeds वाले unseen builds पर इसे चलाएँ।

शुरुआती जाँच के लिए उपयोगी commands हैं:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### disguised constants के रूप में छिपे MBA expressions का पता लगाएँ

ऊपरी तौर पर input पर निर्भर दिखने वाला byte expression अपने input को पूरी तरह रद्द कर सकता है। इसकी tables निकालने के बाद, expression को पूरे 8-bit domain पर evaluate करें; singleton output set साबित करता है कि वह byte constant है—इसके लिए आसपास की state machine को recover करने की ज़रूरत नहीं है।<sup>[[7]](#references)</sup>

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

अंतिम mask बनाए रखें, क्योंकि मूल जोड़ में byte-width wraparound होता है। बड़े domain के लिए, SMT solver से पूछें कि क्या समान-width वाले दो symbolic inputs के लिए `f(x1) != f(x2)` satisfiable है: `unsat` invariance साबित करता है, जबकि `sat` counterexample देता है और इसका अर्थ है कि input को हटाया नहीं जा सकता।<sup>[[7]](#references)</sup>

#### Environment-bound decoding को पहचानें

Anti-analysis checks के लिए branch करना या crash होना ज़रूरी नहीं है। Decoder, sensor के नतीजे को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से चलता रह सकता है और emulator में विश्वसनीय लेकिन गलत plaintext दे सकता है। इसलिए, केवल दिखाई देने वाली failure branches को patch करना पर्याप्त नहीं है; environment probes से decoder state तक data dependencies trace करें, authentic device और emulator पर उसी slice की तुलना करें और जाँचें कि sensor के हर नतीजे को force करने से अंतिम buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक व्यावहारिक MBA simplifier है। यह expression को classify करके specialized pipelines से गुज़ारता है, बजाय इसके कि हर चीज़ पर एक ही generic rewrite pass लागू करे।<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, signature प्राप्त करता है, और pattern matching, ANF conversion तथा coefficient interpolation जैसे कई recovery methods को एक-दूसरे से प्रतिस्पर्धा करने देता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर बनाया जाता है, ताकि masked regions सही रहें।
- **Polynomial/Mixed MBA**: products को cores में विभाजित किया जाता है और outer relation को simplify करने से पहले repeated subexpressions को temporaries में रखा जा सकता है।

एक mixed identity का उदाहरण, जिसे पुनः प्राप्त करने का प्रयास करना अक्सर उपयोगी होता है:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

इसे इस रूप में संक्षिप्त किया जा सकता है:

```c
x * y
```

### Reversing से जुड़े नोट्स

- CoBRA को **lifted IR expressions** या decompiler के output पर चलाना बेहतर है, जब आपने सटीक computation को अलग कर लिया हो।
- अगर expression masked arithmetic या narrow registers से आया है, तो `--bitwidth` स्पष्ट रूप से इस्तेमाल करें।
- अगर आपको अधिक मजबूत proof step चाहिए, तो यहाँ दिए गए स्थानीय Z3 नोट्स देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA, **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है। यह तब उपयोगी है, जब आप बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करना चाहते हैं।
- Unsupported carry-sensitive mixed-domain residuals को इस संकेत के रूप में लें कि मूल expression को बनाए रखें और carry path का मैन्युअल रूप से विश्लेषण करें।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-आधारित instruction sequences से बदलता है और control flow में बदलाव करने के लिए signal/exception handling का उपयोग करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

समर्थित binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) परिणाम को deobfuscate कर सकता है। इसकी कई dependencies हैं।

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

और [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF** खेल रहे हैं, तो **flag खोजने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए, `::main` द्वारा functions खोजें, जैसे:

![Ghidra में function names में double-colon main खोजकर Rust entry point ढूँढ़ना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह पहचानना काफी आसान है कि यही दिलचस्प main function है।\
जिन **functions** को call किया जा रहा है, उनके **नाम** पता होने पर, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर खोजें।

### ELF firmware से Rust strings को रिकवर करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। `rustc` का एक आम layout यह है: **`.data.rel.ro`** के अंदर एक **pointer/length tuple**, जो **`.rodata`** में रखे असली string blob की ओर इंगित करता है:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

इसका मतलब है कि `strings` या Ghidra का डिफ़ॉल्ट विश्लेषण पास-पास की strings को मिला सकता है या cross-references को पूरी तरह छोड़ सकता है।<sup>[[3]](#references)</sup>

त्वरित workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक बार में एक word के हिसाब से enumerate करें।
3. `.rodata` address range के अंदर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. sanity filters लागू करें (उदाहरण के लिए, 4 और 100 bytes के बीच की lengths रखें)।
6. `0x00` तक scan करने के बजाय, `.rodata` से ठीक `length` bytes पढ़ें।

न्यूनतम extractor logic:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि पुनर्प्राप्त Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers और auth-related logic** उजागर करती हैं।

यदि Ghidra इन strings को नहीं पहचानता, तो एक custom script/plugin चलाएँ जो वही heuristic लागू करे और संदर्भित `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools, इस विचार को अन्य **word sizes, endianness और section layouts** के अनुसार ढालने के लिए अच्छे संदर्भ हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

यदि आपको Delphi binary reverse करनी हो, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने का सुझाव दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin debugging शुरू होने पर binary को execute करेगा और function names को dynamically resolve करेगा। Debugging शुरू करने के बाद Start button (हरा वाला या f9) फिर से दबाएँ; real code की शुरुआत में एक breakpoint लगेगा।

यदि आप graphical application में किसी button को दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

सामान्य Go binaries के लिए, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime structures पुनर्प्राप्त कर सकता है और IDA में function names को बेहतर बना सकता है। इसका Python plugin **Alt+F7** से लोड करें।

यदि आपको Golang binary reverse करनी हो, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने का सुझाव दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह functions के names को resolve करेगा।

### symbol table के बिना metadata पुनर्प्राप्त करें

Stripped Go executable को भी program counters को functions से map करने के लिए runtime metadata की आवश्यकता होती है। [GoReSym](https://github.com/mandiant/GoReSym), Go runtime से लिए गए code का उपयोग करके `pclntab` और `moduledata` जैसी structures को ढूँढ़ता और parse करता है। इससे conventional symbol table पर निर्भर हुए बिना function boundaries, names, source paths, types और build details पुनर्प्राप्त किए जा सकते हैं।<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

एक obfuscator इन संरचनाओं को उपयोग योग्य छोड़ते हुए, पुनर्प्राप्त नामों को बदल सकता है। उदाहरण के लिए, Garble identifiers और package paths को hash करता है तथा build, module और debug जानकारी हटा देता है।<sup>[[12]](#references)</sup> Obfuscated package token को उस package के सभी functions में एक जैसा रहना चाहिए। बार-बार आने वाले token के आधार पर functions को समूहों में बाँटें, किसी एक package का अनुमान उसके callees, strings और APIs से लगाएँ, फिर उस package का label पूरे समूह में लागू करें।<sup>[[13]](#references)</sup>

### GoResolver के साथ Garble के नाम पुनर्प्राप्त करें

[GoResolver](https://github.com/volexity/GoResolver), runtime-symbol extraction को clean-reference generation और control-flow-graph (CFG) matching के साथ जोड़ता है। यह क्रम अपनाएँ:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler version पहचानें।** पहले `BuildInfo` और embedded version strings देखें। यदि obfuscator ने उन्हें हटा दिया है, तो bundled Go runtime के हिस्सों की तुलना versioned reference runtimes से करें। Volexity के परीक्षणों में, runtime का लगभग `2%` हिस्सा major Go versions में अंतर पहचानने के लिए पर्याप्त था। इसे एक अनुभवजन्य optimization मानें, न कि सार्वभौमिक threshold।<sup>[[13]](#references)</sup>
2. **Matching references बनाएँ।** पहचाने गए Go version, target architecture और संभावित libraries के लिए clean binaries बनाएँ। Toolchain का मेल compiler द्वारा बनाए गए CFG अंतर को कम करता है।<sup>[[10]](#references)[[13]](#references)</sup>
3. **Functions की तुलना करें।** GoGrapher function CFGs का मिलान करता है और `0.0` से `1.0` तक के normalized scores देता है। इसका basic-block matching, मिलते-जुलते instructions की weighted comparison पर आधारित है। High-confidence matches randomized functions को clean implementation से जोड़ते हैं। कमज़ोर matches से भी package या module की पहचान हो सकती है।<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **सत्यापन करें और import करें।** प्रस्तावित नामों की पुष्टि call relationships, constants, strings और side effects से करें, फिर IDA या Ghidra के GoResolver plugin से JSON report import करें।<sup>[[10]](#references)[[13]](#references)</sup>

Toolchain install करें और संयुक्त extractor तथा graph matcher चलाएँ:<sup>[[10]](#references)</sup>

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

डिफ़ॉल्ट significant-match threshold `0.9` है। `--extract` और `--graph` switches किसी भी stage को अलग-अलग चला सकते हैं, जबकि डिफ़ॉल्ट रूप से दोनों चलते हैं, क्योंकि recovered runtime metadata और CFG evidence एक-दूसरे के पूरक हैं।<sup>[[10]](#references)</sup> CFG scores heuristic होते हैं: inlining, build flags, architecture और library-version के अंतर graph की shape बदल सकते हैं, इसलिए कम-confidence वाले names को थोपने के बजाय unresolved functions को बनाए रखें।<sup>[[13]](#references)</sup>

### Go string table को recover करना

Go binaries में linked packages के सभी string bytes एक contiguous table में रखे जाते हैं। Entries NUL-terminated नहीं होतीं, और runtime structures table का base या size नहीं बताते। हालांकि, compiler सभी operating systems और architectures पर पहले length के अनुसार और फिर alphabetically entries को क्रमबद्ध करता है। इसलिए, एक entry मिलने के बाद analyst पास की entries को scan कर सकता है और strings को code से जोड़ने के लिए data cross-references का उपयोग कर सकता है।<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) IDA Pro और Ghidra में इस workflow को automate करता है। पहले auto-analysis पूरा होने दें, क्योंकि plugin data-segment cross-references पर निर्भर करता है। इसका default anchor runtime string `entersyscall` है। इसके बाद यह दोनों दिशाओं में scan कर सकता है, recovered strings को database में define कर सकता है और strings से उन्हें reference करने वाले functions की JSON mapping export कर सकता है।<sup>[[14]](#references)</sup>

रिपोर्ट को referencing function के package के आधार पर filter करें, ताकि application या malware code को linked libraries के शोर से अलग किया जा सके। यह technique obfuscation से नष्ट किए गए literals को recover नहीं कर सकती, जैसे Garble का `-literals` transformation। फिर भी, यह उन runtime strings को व्यवस्थित कर सकती है जो unobfuscated रहती हैं।<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime types को recover करना

Go में garbage collection जैसी सुविधाओं द्वारा उपयोग की जाने वाली runtime type information शामिल होती है। जब build information हटा दी जाती है या disassembler इस metadata को parse नहीं करता, तो instructions मनमाने data addresses को load करते हुए दिखाई दे सकते हैं और target region untyped रह जाता है। Metadata recover करने से ये addresses पढ़ने योग्य type references में बदल जाते हैं और package की capabilities को समझना आसान हो जाता है।<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) symbols extract कर सकता है और runtime types को parse करके JSON report बना सकता है। मौजूदा CLI में `resolve` subcommand का उपयोग होता है:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` विकल्प type parsing सक्षम करता है। बरामद किए गए types को परिभाषित करने और analysis database में उनके references लागू करने के लिए, रिपोर्ट को GoResolver के IDA Pro या Ghidra plugin से import करें। इस सुविधा के साथ पेश किए गए report format में, `-y` छोड़ने पर RTTI address और recovered-types members null रहते हैं।<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver x86, AMD64, ARM और ARM64 के लिए PE, ELF और Mach-O samples को support करता है, इसलिए यही workflow Windows, Linux और macOS की Go binaries पर लागू होता है।<sup>[[10]](#references)</sup>

## Compiled Python

इस पेज पर आप जान सकते हैं कि ELF/EXE में compiled Python binary से Python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

अगर आपको किसी GBA game की **binary** मिलती है, तो उसे **emulate** और **debug** करने के लिए आप अलग-अलग tools का इस्तेमाल कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version डाउनलोड करें_) - इसमें interface वाला debugger शामिल है
- [**mgba** ](https://mgba.io)- इसमें CLI debugger शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** पर जाकर आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाएँ

![no$gba controls configuration में Game Boy Advance button mappings दिखाई गई हैं](<../../images/image (581).png>)

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

![0x4000130 पते पर KEYINPUT का संदर्भ देने वाले GBA binary का Ghidra दृश्य](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि यह function **FUN_080015a8** से कॉल किया गया है (पते: _0x080015fa_ और _0x080017ac_)।

उस function में, कुछ शुरुआती operations के बाद (जिनका कोई महत्व नहीं है):

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

आखिरी if यह जाँच रहा है कि **`uVar4`** पिछली Keys में है और मौजूदा key नहीं है। इसे बटन छोड़ना भी कहते हैं (मौजूदा key **`uVar1`** में stored है)।

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

पिछले code में आप देख सकते हैं कि हम **uVar1** (जहाँ **दबाए गए बटन की value** होती है) की तुलना कुछ values से कर रहे हैं:

- पहले, इसकी तुलना **value 4** (**SELECT** बटन) से की जाती है: challenge में यह बटन स्क्रीन साफ़ करता है।
- फिर इसकी तुलना **8** (**START** बटन) से की जाती है; इस challenge में, यह path जाँचता है कि दर्ज किया गया code valid है या नहीं।
  - इस स्थिति में, var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute होता है।
- अन्य सभी स्थितियों में, एक counter (`DAT_030000d4`) जाँचा और increment किया जाता है।\
  जब तक counter 8 से कम होता है, दबाए गए बटनों की values को `DAT_030000d8` में जोड़ा जाता है।

इसलिए, इस challenge में, बटनों की values जानने के बाद, आपको **8 से कम लंबाई का ऐसा combination दबाना था जिसका कुल योग 0xf3 हो।**

**इस tutorial का reference:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-सहायता प्राप्त reverse engineering को विफल करना, या कम-से-कम कोशिश करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching पर आधारित Control Flow Graphs की तुलना करने का एक तरीका](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binaries को अपने-आप deobfuscate करने के लिए Control-Flow Graph Similarity का उपयोग](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang Tooling के updates](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: कुछ भी Reverse Engineer करें](https://github.com/morluto/rea)
- [17] [REA managed-code analysis](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI और Evidence guide](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
