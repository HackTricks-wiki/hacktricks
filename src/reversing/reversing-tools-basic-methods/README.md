# Reversing Tools और बुनियादी तरीके

{{#include ../../banners/hacktricks-training.md}}

## ImGui पर आधारित reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg user-mode स्वचालन

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

ऑनलाइन:

- wasm (binary) से wat (साफ़ टेक्स्ट) में **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें
- wat से wasm में **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें
- decompilation के लिए आप [web-wasmdec](https://wwwg.github.io/web-wasmdec/) भी आज़मा सकते हैं।

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

dotPeek एक decompiler है, जो **कई formats को decompile और जाँचता है**, जिनमें **libraries** (.dll), **Windows metadata files** (.winmd) और **executables** (.exe) शामिल हैं। Decompile हो जाने के बाद, assembly को Visual Studio project (.csproj) के रूप में सहेजा जा सकता है।

इसका फ़ायदा यह है कि यदि किसी legacy assembly से खोए हुए source code को पुनर्स्थापित करना हो, तो इससे समय बच सकता है। इसके अलावा, dotPeek decompiled code में आसानी से नेविगेट करने की सुविधा देता है, जिससे यह **Xamarin algorithm analysis** के लिए बेहतरीन tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

व्यापक add-in model और आपकी सटीक ज़रूरतों के अनुसार tool को बेहतर बनाने वाली API के साथ, .NET Reflector समय बचाता है और development को सरल बनाता है। आइए, इस tool द्वारा दी जाने वाली reverse engineering सेवाओं पर नज़र डालें:

- यह दिखाता है कि किसी library या component में data का प्रवाह कैसे होता है
- .NET languages और frameworks के implementation और उपयोग की जानकारी देता है
- उपयोग किए गए APIs और technologies का अधिक लाभ उठाने के लिए undocumented और unexposed functionality ढूँढ़ता है।
- dependencies और अलग-अलग assemblies ढूँढ़ता है
- आपके code, third-party components और libraries में errors की सटीक जगह का पता लगाता है।
- आपके उपयोग में आने वाले सभी .NET code के source में debugging करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) और [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS पर इस्तेमाल कर सकते हैं (इसे सीधे VSCode से install कर सकते हैं; git download करने की ज़रूरत नहीं है। **Extensions** पर क्लिक करें और **ILSpy खोजें**).\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसका सक्रिय रूप से maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) इस्तेमाल कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** चुनें।)

### REA के साथ execution-free managed inspection

**REA** assembly को load किए बिना PE/CLI metadata और CIL की जाँच कर सकता है। Artifact की पहचान से शुरुआत करें, फिर members और घोषित native boundaries की जाँच करें; decompiler इस्तेमाल करने या program चलाने से पहले संदिग्ध calls की समीक्षा करते समय यह उपयोगी है।<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Version diffing के लिए, `compare_managed_members` metadata tokens को builds के बीच स्थिर मानने के बजाय raw CIL/signature identity और decoded-instruction fingerprints का उपयोग करता है। P/Invoke declaration इस बात का प्रमाण नहीं है कि native code चला; उस boundary को जाँचने के लिए `verify_managed_native_boundaries` को matching native export या function Evidence की ज़रूरत होती है। Artifact digest, MVID और unresolved mappings को result के साथ रखें।<sup>[[17]](#references)</sup>

### DNSpy Logging

**DNSpy से किसी फ़ाइल में कुछ जानकारी log कराने के लिए**, आप यह snippet इस्तेमाल कर सकते हैं:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy डिबगिंग

DNSpy का उपयोग करके code को डिबग करने के लिए आपको यह करना होगा:

सबसे पहले, **debugging** से संबंधित **Assembly attributes** बदलें:

![DNSpy Logging - DNSpy डिबगिंग: सबसे पहले, debugging से संबंधित Assembly attributes बदलें](<../../images/image (973).png>)

यहाँ से:

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

यह ज़रूरी है, क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर कोड में कई **optimisations** लागू होंगे और संभव है कि debugging के दौरान **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, अगर आपकी .NET application को **IIS** **run** कर रहा है, तो आप इसे **restart** कर सकते हैं:

```
iisreset /noforce
```

फिर debugging शुरू करने के लिए, खोली गई सभी files बंद करें और **Debug Tab** में **Attach to Process...** चुनें:

![DNSpy Logging - DNSpy Debugging: फिर debugging शुरू करने के लिए, खोली गई सभी files बंद करें और Debug Tab में Attach to Process चुनें](<../../images/image (318).png>)

फिर **IIS server** से attach करने के लिए **w3wp.exe** चुनें और **attach** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: फिर IIS server से attach करने के लिए w3wp.exe चुनें और attach पर क्लिक करें](<../../images/image (113).png>)

अब जब process debugging के तहत है, तो उसे रोककर सभी modules load करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें, फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: अब जब process debugging के तहत है, तो उसे रोककर सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब process debugging के तहत है, तो उसे रोककर सभी modules load करने का समय है। पहले Debug Break All पर क्लिक करें और फिर Debug Windows Modules पर क्लिक करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर क्लिक करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर क्लिक करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right-click करें और **Sort Assemblies** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right-click करें और Sort Assemblies पर क्लिक करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की debugging

### IDA का उपयोग करना

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: " Suspend on library load/unload " चुनें](<../../images/image (868).png>)

- Execution के **parameters** में **DLL का path** और उस function को configure करें जिसे आप call करना चाहते हैं:

![Debugging DLLs - Using IDA: Execution के parameters में DLL का path और उस function को configure करें जिसे आप call करना चाहते हैं](<../../images/image (704).png>)

फिर, debugging शुरू करने पर **हर DLL load होने पर execution रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL load करेगा, execution रुक जाएगा।

यह तरीका module-load events पर रुकता है, लेकिन loaded DLL के entry point तक पहुँचना, नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग करना

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा उस function को set करें जिसे आप call करना चाहते हैं, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**। debugger हर dll main पर रुकेगा और किसी बिंदु पर **आपकी dll के Entry पर रुकेगा**। वहाँ से, उन points को खोजें जहाँ आप breakpoint लगाना चाहते हैं।

ध्यान दें कि win64dbg में किसी भी वजह से execution रुकने पर, **win64dbg window के सबसे ऊपर** देखकर पता लगा सकते हैं कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि win64dbg में किसी भी वजह से execution रुकने पर, win64dbg window के सबसे ऊपर देखकर पता लगा सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि execution उस DLL के अंदर रुका है जिसे आप debug करना चाहते हैं।

## GUI ऐप्स / वीडियो गेम

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो यह पता लगाने में मदद करता है कि चल रहे game की memory में महत्वपूर्ण values कहाँ save हैं, और उन्हें बदलने में भी मदद करता है। अधिक जानकारी यहाँ:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालाँकि, इसका उपयोग reverse-engineering से जुड़ी किसी भी चीज़ के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## REA के साथ साक्ष्य-आधारित native जाँच

**REA**, CLI और MCP के माध्यम से Hopper, Ghidra और IDA analysis उपलब्ध कराता है। इसके लिए Node.js 22.x (कम-से-कम 22.19), 24.x (कम-से-कम 24.11), या 26+, और npm आवश्यक हैं। पहले कोई मौजूदा native provider configure करें; `rea providers --json` जाँचें और यदि एक से अधिक providers target को support करते हों, तो उनमें से किसी एक को स्पष्ट रूप से चुनें। नीचे `0x1000` की जगह inventory में दिखाई देने वाला function name या address इस्तेमाल करें।<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

किसी feature string या symbol से शुरू करें, references और callers का अनुसरण करें, फिर `rea decompile` से चुने गए function dossier और pseudocode की जाँच करें। REA किसी विफलता के बाद चुपचाप provider बदलने के बजाय session को चुने गए provider से जोड़ता है। बार-बार दोहराए जा सकने वाले queries के लिए, `--snapshot PATH` केवल मेल खाते artifact bytes, provider, settings, operation और parameters का पुनः उपयोग करता है; snapshot एक local cache है, सहेजा हुआ provider database नहीं। लौटाए गए Evidence और स्पष्ट रूप से अज्ञात बातों को सुरक्षित रखें; अनुमानित paths या decompiler text को original source न मानें।<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron entry points से native add-ons तक जाने वाले रास्तों के लिए, [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) देखें।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner से shellcode को debug करना

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** के लिए memory allocate करता है, उसका **memory address** दिखाता है और execution को रोक देता है।\
IDA या x64dbg जैसे debugger को attach करें, दिखाए गए address पर breakpoint सेट करें और shellcode को debug करने के लिए execution फिर से शुरू करें।

Releases github page पर compiled releases वाली zip files उपलब्ध हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आपको नीचे दिए गए link पर Blobrunner का थोड़ा modified version मिल सकता है। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएँ, code को copy-paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it से shellcode को debug करना

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner जैसा ही है। यह shellcode के लिए memory allocate करता है और infinite loop में चला जाता है। Debugger attach करें, **2–5 seconds** तक resume करें, उस loop के भीतर pause करें और फिर अगले call तक step करें, जो execution को allocated shellcode तक पहुँचाता है।

![jmp2it के infinite loop में, allocated shellcode को call करने से ठीक पहले रुका हुआ debugger](<../../images/image (509).png>)

आप [releases page से jmp2it का compiled version डाउनलोड कर सकते हैं](https://github.com/adamkramer/jmp2it/releases/)।

### Cutter से shellcode को debug करना

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और गतिशील रूप से उसका निरीक्षण कर सकते हैं।

ध्यान दें कि Cutter में "Open File" और "Open Shellcode" विकल्प हैं। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने उसे सही ढंग से decompile किया; लेकिन shellcode के रूप में खोलने पर ऐसा नहीं हुआ:

![एक ही bytes को file या shellcode के रूप में खोलने पर Cutter में अलग-अलग analysis results](<../../images/image (562).png>)

Emulation को अपनी इच्छित जगह से शुरू करने के लिए, वहाँ bp सेट करें; ऐसा लगता है कि Cutter अपने आप वहीं से emulation शुरू कर देगा:

![Cutter emulation शुरू करने से पहले इच्छित shellcode entry पर breakpoint सेट करना](<../../images/image (589).png>)

![Cutter emulator चुने गए shellcode breakpoint पर रुका हुआ](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump में देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### Shellcode को deobfuscate करना और executed functions पाना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) आज़माना चाहिए।\
यह आपको ऐसी बातें बताएगा, जैसे shellcode कौन-से **functions** का उपयोग कर रहा है और क्या shellcode memory में खुद को **decode** कर रहा है।

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

**Create Dump** option, shellcode को memory में dynamically बदलने पर अंतिम shellcode का dump बनाता है (decoded shellcode download करने के लिए उपयोगी)। **start offset** किसी खास offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** option, scDbg terminal का उपयोग करके shellcode को debug करने के लिए उपयोगी है (हालाँकि, मुझे इस काम के लिए पहले बताए गए options बेहतर लगते हैं, क्योंकि उनसे आप Ida या x64dbg का उपयोग कर सकते हैं)।

### CyberChef का उपयोग करके disassemble करना

अपनी shellcode file को input के रूप में upload करें और इसे disassemble करने के लिए यह recipe इस्तेमाल करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation को deobfuscate करना

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` जैसे सरल expressions को arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाने वाले formulas के पीछे छिपाता है। अहम बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के तहत सही होते हैं, इसलिए carries और overflows मायने रखते हैं:

```c
(x ^ y) + 2 * (x & y) == x + y
```

यदि आप इस तरह के expression को generic algebra tooling से simplify करते हैं, तो आपको आसानी से गलत परिणाम मिल सकता है, क्योंकि bit-width semantics को नज़रअंदाज़ किया गया था।<sup>[[1]](#references)</sup>

### व्यावहारिक कार्यप्रवाह

1. **मूल bit-width बनाए रखें**—lifted code/IR/decompiler output से (`8/16/32/64` bits)।
2. **Simplify करने से पहले expression को वर्गीकृत करें:**
   - **Linear**: bitwise atoms के weighted sums
   - **Semilinear**: linear के साथ constant masks, जैसे `x & 0xFF`
   - **Polynomial**: इसमें products हों
   - **Mixed**: products और bitwise logic आपस में मिले हों, अक्सर repeated subexpressions के साथ
3. **हर candidate rewrite को** random testing या SMT proof से verify करें। अगर equivalence prove नहीं हो सकती, तो अनुमान लगाने के बजाय मूल expression बनाए रखें।

### Narrow execution slice के साथ flattened control flow को bypass करें

पूरा control-flow graph recover करना अक्सर ज़रूरी नहीं होता। Control-flow flattening, opaque predicates, बड़े dispatchers या MBA-heavy code में, encrypted blobs और output buffers के references को उस सबसे छोटे routine तक follow करें जो उन्हें transform करता है। फिर केवल उसी data-flow slice को reproduce करें या उसे independently execute करें; अगर relevant state को सीधे initialize किया जा सकता है, तो dispatcher आवश्यक solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक व्यावहारिक कार्यप्रवाह है:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations, और cross-references की सूची बनाएँ। `.rodata` से candidate tables dump करते समय उनका byte order और element width बनाए रखें।
2. उस आखिरी routine की पहचान करें जो plaintext या output buffer लिखता है। उसके inputs, referenced tables, imported calls, और आवश्यक global state दर्ज करें।
3. केवल उन्हीं operations को fixed-width Python model में lift करें। अगर slice अब भी बहुत अधिक state पर निर्भर है, तो पूरे program को emulate करने के बजाय Unicorn, QEMU या debugger के तहत routine को invoke करें और अप्रासंगिक imports को hook करें।
4. Verify करें कि extractor वास्तव में अपना output दिए गए binary से derive करता है: silent fallbacks हटाएँ, उसमें embedded answers खोजें, और बदले हुए strings, keys, identifiers, layouts, तथा obfuscation seeds वाले unseen builds पर इसे चलाएँ।

पहले चरण के लिए उपयोगी commands हैं:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### छिपे हुए constants वाले MBA expressions का पता लगाएँ

इनपुट पर निर्भर दिखने वाला byte expression अपने इनपुट को पूरी तरह cancel कर सकता है। इसकी tables निकालने के बाद, expression को पूरे 8-bit domain पर evaluate करें; output का singleton set साबित करता है कि वह byte constant है—इसके लिए आसपास की state machine को recover करने की ज़रूरत नहीं है।<sup>[[7]](#references)</sup>

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

Anti-analysis checks के लिए branch लेना या crash होना ज़रूरी नहीं है। Decoder, sensor के नतीजे को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से चलता रह सकता है, और emulator में विश्वसनीय दिखने वाला लेकिन गलत plaintext बना सकता है। इसलिए केवल दिखाई देने वाली failure branches को patch करना पर्याप्त नहीं है; environment probes से decoder state तक data dependencies trace करें, authentic device और emulator पर उसी slice की तुलना करें, और जाँचें कि हर sensor result को force करने से अंतिम buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक व्यावहारिक MBA simplifier है। यह expression को classify करके उसे specialized pipelines में भेजता है, बजाय इसके कि हर चीज़ पर एक generic rewrite pass लागू करे।<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature निकालता है, और कई recovery methods—जैसे pattern matching, ANF conversion और coefficient interpolation—को एक साथ आज़माता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर बनाया जाता है, ताकि masked regions सही बने रहें।
- **Polynomial/Mixed MBA**: products को cores में विघटित किया जाता है और outer relation को सरल करने से पहले repeated subexpressions को temporaries में रखा जा सकता है।

एक mixed identity का उदाहरण, जिसे अक्सर वापस प्राप्त करने की कोशिश करना उपयोगी होता है:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

इसे घटाकर यह किया जा सकता है:

```c
x * y
```

### Reversing notes

- Exact computation अलग करने के बाद, CoBRA को **lifted IR expressions** या decompiler output पर चलाना बेहतर है।
- यदि expression masked arithmetic या narrow registers से आया है, तो `--bitwidth` स्पष्ट रूप से इस्तेमाल करें।
- यदि आपको अधिक मजबूत proof step चाहिए, तो यहाँ दिए गए स्थानीय Z3 notes देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA, **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है। यह बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करने के लिए उपयोगी है।
- Unsupported carry-sensitive mixed-domain residuals इस बात का संकेत हैं कि original expression को बनाए रखें और carry path का मैन्युअल रूप से विश्लेषण करें।

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-आधारित instruction sequences से बदलता है और control flow बदलने के लिए signal/exception handling का उपयोग करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

समर्थित binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) परिणाम को deobfuscate कर सकता है। इसकी कई dependencies हैं।

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

और [keystone इंस्टॉल करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF** खेल रहे हैं, तो **flag खोजने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए, functions में `::main` खोजें, जैसे:

![Ghidra में function names में double-colon main खोजकर Rust entry point ढूँढ़ना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह main function स्पष्ट रूप से दिलचस्प है।\
जिन **functions** को call किया जा रहा है, उनके **नाम** मिलने के बाद, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर खोजें।

### ELF firmware से Rust strings को पुनर्प्राप्त करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers के रूप में reference नहीं किया जाता। `rustc` का एक आम layout है: **`.data.rel.ro`** में **pointer/length tuple**, जो **`.rodata`** में रखे असली string blob की ओर point करता है:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

इसका मतलब है कि `strings` या Ghidra का डिफ़ॉल्ट analysis आस-पास की strings को मिला सकता है या cross-references को पूरी तरह छोड़ सकता है।<sup>[[3]](#references)</sup>

त्वरित workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक बार में एक word के हिसाब से enumerate करें।
3. **`.rodata`** की address range के अंदर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. Sanity filters लागू करें (उदाहरण के लिए, **4** से **100** bytes तक की lengths रखें)।
6. `0x00` तक scan करने के बजाय, **`.rodata`** से ठीक `length` bytes पढ़ें।

न्यूनतम extractor logic:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, और auth-related logic** उजागर करती हैं।

अगर Ghidra इन strings को नहीं पहचानता, तो ऐसा custom script/plugin चलाएँ जो यही heuristic लागू करे और संदर्भित `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools इस विचार को दूसरे **word sizes, endianness, और section layouts** के अनुसार ढालने के लिए अच्छे संदर्भ हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

अगर आपको Delphi binary reverse करनी है, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने का सुझाव दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin binary को execute करेगा और debugging शुरू होते ही function names को dynamically resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ; real code की शुरुआत में एक breakpoint hit होगा।

अगर आप graphical application में कोई button दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

सामान्य Go binaries के लिए, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime structures को recover कर सकता है और IDA में function names को बेहतर बना सकता है। इसका Python plugin **Alt+F7** से load करें।

अगर आपको Golang binary reverse करनी है, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने का सुझाव दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह functions के names resolve करेगा।

### symbol table के बिना metadata recover करना

Stripped Go executable को भी program counters को functions से map करने के लिए runtime metadata की ज़रूरत होती है। [GoReSym](https://github.com/mandiant/GoReSym), Go runtime से लिए गए code का उपयोग करके `pclntab` और `moduledata` जैसी structures को खोजता और parse करता है। इससे conventional symbol table पर निर्भर हुए बिना function boundaries, names, source paths, types और build details recover किए जा सकते हैं।<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

एक obfuscator इन structures को उपयोग करने योग्य छोड़ सकता है, जबकि उनसे प्राप्त names को बदल देता है। उदाहरण के लिए, Garble identifiers और package paths को hash करता है और build, module तथा debug information हटा देता है।<sup>[[12]](#references)</sup> Obfuscated package token को उस package के अलग-अलग functions में एक जैसा रहना चाहिए। बार-बार आने वाले token के आधार पर functions को group करें, उसके callees, strings और APIs से एक package का अनुमान लगाएँ, फिर उस package label को पूरे group पर लागू करें।<sup>[[13]](#references)</sup>

### GoResolver से Garble names recover करें

[GoResolver](https://github.com/volexity/GoResolver) runtime-symbol extraction को clean-reference generation और control-flow-graph (CFG) matching के साथ जोड़ता है। यह क्रम अपनाएँ:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler version पहचानें।** पहले `BuildInfo` और embedded version strings देखें। अगर obfuscator ने उन्हें हटा दिया हो, तो bundled Go runtime के हिस्सों की तुलना अलग-अलग versions के reference runtimes से करें। Volexity के tests में, Go के major versions में अंतर पहचानने के लिए runtime का लगभग `2%` हिस्सा पर्याप्त था। इसे एक अनुभवजन्य optimization मानें, सार्वभौमिक threshold नहीं।<sup>[[13]](#references)</sup>
2. **Matching references बनाएँ।** पहचाने गए Go version, target architecture और संभावित libraries के लिए clean binaries generate करें। Toolchain का मेल compiler द्वारा उत्पन्न CFG differences को कम करता है।<sup>[[10]](#references)[[13]](#references)</sup>
3. **Functions की तुलना करें।** GoGrapher function CFGs का मिलान करता है और `0.0` से `1.0` तक normalized scores देता है। इसका basic-block matching मिलते-जुलते instructions की weighted comparison पर आधारित है। High-confidence matches randomized functions को clean implementation से जोड़ते हैं। कमज़ोर matches भी package या module की पहचान कर सकते हैं।<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validate करके import करें।** Call relationships, constants, strings और side effects से सुझाए गए names की पुष्टि करें, फिर GoResolver plugin से IDA या Ghidra में JSON report import करें।<sup>[[10]](#references)[[13]](#references)</sup>

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

डिफ़ॉल्ट significant-match threshold `0.9` है। `--extract` और `--graph` switches किसी भी चरण को अलग से चला सकते हैं, जबकि डिफ़ॉल्ट रूप से दोनों चलते हैं, क्योंकि पुनर्प्राप्त runtime metadata और CFG साक्ष्य एक-दूसरे के पूरक हैं।<sup>[[10]](#references)</sup> CFG scores heuristic होते हैं: inlining, build flags, architecture और library-version के अंतर graph का स्वरूप बदल सकते हैं, इसलिए कम-विश्वसनीयता वाले नाम थोपने के बजाय अनसुलझे functions को बनाए रखें।<sup>[[13]](#references)</sup>

### Go string table पुनर्प्राप्त करना

Go binaries में linked package के सभी string bytes एक ही contiguous table में रखे जाते हैं। Entries NUL-terminated नहीं होतीं और runtime structures से table का base या size पता नहीं चलता। हालांकि, compiler सभी operating systems और architectures में entries को पहले लंबाई और फिर वर्णक्रम के आधार पर क्रमबद्ध करता है। इसलिए, एक entry मिलने के बाद analyst आस-पास की entries पर जा सकता है और strings को code से जोड़ने के लिए data cross-references का उपयोग कर सकता है।<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) IDA Pro और Ghidra में इस workflow को स्वचालित करता है। पहले auto-analysis पूरा होने दें, क्योंकि plugin data-segment cross-references पर निर्भर करता है। इसका डिफ़ॉल्ट anchor runtime string `entersyscall` है। इसके बाद यह किसी भी दिशा में scan कर सकता है, database में पुनर्प्राप्त strings को परिभाषित कर सकता है और strings को reference करने वाले functions की JSON mapping export कर सकता है।<sup>[[14]](#references)</sup>

referencing function के package के आधार पर report को filter करें, ताकि application या malware code को linked libraries के अतिरिक्त डेटा से अलग किया जा सके। यह technique obfuscation से नष्ट हुए literals को पुनर्प्राप्त नहीं कर सकती, जैसे Garble का `-literals` transformation। फिर भी यह उन runtime strings को व्यवस्थित कर सकती है जो obfuscated नहीं हैं।<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime types पुनर्प्राप्त करना

Go में garbage collection जैसी सुविधाओं द्वारा उपयोग की जाने वाली runtime type information शामिल होती है। जब build information हटा दी जाती है या disassembler इस metadata को parse नहीं करता, तो instructions किसी भी data address को load करते हुए दिखाई दे सकते हैं और target region untyped रह जाता है। Metadata पुनर्प्राप्त करने से वे addresses पढ़ने योग्य type references में बदल जाते हैं और package की क्षमताओं को समझना आसान हो जाता है।<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) symbols निकाल सकता है और runtime types को parse करके JSON report तैयार कर सकता है। मौजूदा CLI में `resolve` subcommand का उपयोग होता है:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` विकल्प type parsing सक्षम करता है। पुनर्प्राप्त types को परिभाषित करने और analysis database में उनके references लागू करने के लिए, रिपोर्ट को GoResolver के IDA Pro या Ghidra plugin से import करें। इस feature के साथ प्रस्तुत report format में, `-y` छोड़ने पर RTTI address और recovered-types members null रहते हैं।<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver x86, AMD64, ARM और ARM64 के लिए PE, ELF और Mach-O samples को support करता है, इसलिए यही workflow Windows, Linux और macOS की Go binaries पर लागू होता है।<sup>[[10]](#references)</sup>

## Compiled Python

इस page पर आप जान सकते हैं कि ELF/EXE Python compiled binary से Python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

अगर आपको GBA game का **binary** मिलता है, तो आप उसे **emulate** और **debug** करने के लिए अलग-अलग tools का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version डाउनलोड करें_) - इसमें interface वाला debugger है
- [**mgba** ](https://mgba.io)- इसमें CLI debugger है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** पर आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाने हैं।

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

दबाने पर, हर **key की एक value होती है** जिससे उसकी पहचान की जा सकती है:

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

तो, इस तरह के प्रोग्राम में दिलचस्प बात यह होगी कि **प्रोग्राम user input को कैसे संभालता है**। address **0x4000130** पर आपको आमतौर पर मिलने वाला function: **KEYINPUT** मिलेगा।

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि यह function **FUN_080015a8** से call किया जाता है (addresses: _0x080015fa_ और _0x080017ac_)।

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

इसमें यह कोड मिला:

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

आख़िरी if यह जाँच रहा है कि **`uVar4`** आख़िरी Keys में है और मौजूदा key नहीं है। इसे बटन छोड़ना भी कहते हैं (मौजूदा key **`uVar1`** में संग्रहीत है)।

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

- पहले, इसकी तुलना **value 4** (**SELECT** button) से की जाती है: इस challenge में यह button screen साफ़ करता है
- फिर इसकी तुलना **8** (**START** button) से की जाती है; इस challenge में, यह path जाँचता है कि दर्ज किया गया code valid है या नहीं।
  - इस मामले में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute होता है।
- बाकी सभी मामलों में, एक counter (`DAT_030000d4`) जाँचा और increment किया जाता है।\
  जब तक counter 8 से कम है, दबाई गई keys की values को `DAT_030000d8` में जोड़ा जाता है।

इसलिए, इस challenge में, buttons की values जानने के बाद आपको **8 से कम लंबाई वाला ऐसा combination दबाना था, जिसका कुल जोड़ 0xf3 हो।**

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
- [7] [AI-Assisted Reverse Engineering को विफल करना, या कम-से-कम कोशिश करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching पर आधारित Control Flow Graphs की तुलना का एक तरीका](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binaries को automatically deobfuscate करने के लिए Control-Flow Graph Similarity का उपयोग](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang Tooling के updates](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: कुछ भी Reverse Engineer करें](https://github.com/morluto/rea)
- [17] [REA managed-code analysis](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI और Evidence guide](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
