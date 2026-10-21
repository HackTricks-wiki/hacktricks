# Reversing Tools और बुनियादी तरीके

{{#include ../../banners/hacktricks-training.md}}

## ImGui आधारित Reversing tools

सॉफ़्टवेयर:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg user-mode automation

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows exception-driven control flow

{{#ref}}
../windows-exception-driven-control-flow.md
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

सॉफ़्टवेयर:

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

dotPeek एक decompiler है, जो **कई formats को decompile और जाँचता है**, जिनमें **libraries** (.dll), **Windows metadata files** (.winmd) और **executables** (.exe) शामिल हैं। Decompile करने के बाद, assembly को Visual Studio project (.csproj) के रूप में सहेजा जा सकता है।

इसका फ़ायदा यह है कि अगर किसी पुराने assembly से खोए हुए source code को बहाल करना हो, तो यह समय बचा सकता है। इसके अलावा, dotPeek decompiled code में आसानी से नेविगेट करने की सुविधा देता है, जिससे यह **Xamarin algorithm analysis** के लिए बेहतरीन tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक add-in model और ऐसी API के साथ, जो आपकी ज़रूरतों के मुताबिक tool को बढ़ाती है, .NET Reflector समय बचाता है और development को आसान बनाता है। आइए, इस tool द्वारा दी जाने वाली reverse engineering सेवाओं पर नज़र डालें:

- यह दिखाता है कि किसी library या component में data किस तरह flow करता है
- .NET languages और frameworks के implementation और उपयोग की जानकारी देता है
- इस्तेमाल किए गए APIs और technologies से अधिक लाभ पाने के लिए undocumented और unexposed functionality ढूँढ़ता है।
- dependencies और अलग-अलग assemblies ढूँढ़ता है
- आपके code, third-party components और libraries में errors की सटीक जगह पता लगाता है।
- आपके द्वारा उपयोग किए जाने वाले सभी .NET code के source में debugging करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) और [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS पर इस्तेमाल कर सकते हैं (इसे सीधे VSCode से install किया जा सकता है, git download करने की ज़रूरत नहीं है। **Extensions** पर क्लिक करें और **ILSpy खोजें**)।\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसका सक्रिय रूप से maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) इस्तेमाल कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method** चुनें)।

### REA के साथ execution-free managed inspection

**REA** assembly को load किए बिना PE/CLI metadata और CIL की जाँच कर सकता है। पहले artifact की पहचान करें, फिर उसके members और घोषित native boundaries की जाँच करें; decompiler इस्तेमाल करने या program चलाने से पहले संदिग्ध calls की समीक्षा करते समय यह उपयोगी है।<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

वर्ज़न diffing के लिए, `compare_managed_members` raw CIL/signature identity और decoded-instruction fingerprints का उपयोग करता है, न कि metadata tokens को अलग-अलग builds में स्थिर मानता है। P/Invoke declaration इस बात का प्रमाण नहीं है कि native code चला; इस सीमा की जाँच के लिए `verify_managed_native_boundaries` को मेल खाता native export या function का साक्ष्य चाहिए। परिणाम के साथ artifact digest, MVID और unresolved mappings रखें।<sup>[[17]](#references)</sup>

### DNSpy लॉगिंग

**DNSpy से किसी फ़ाइल में कुछ जानकारी लॉग करवाने के लिए**, आप यह snippet इस्तेमाल कर सकते हैं:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy का उपयोग करके code debug करने के लिए आपको:

सबसे पहले, **debugging** से संबंधित **Assembly attributes** बदलें:

![DNSpy Logging - DNSpy Debugging: सबसे पहले, debugging से संबंधित Assembly attributes बदलें](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

फिर _**File >> Save module...**_ के ज़रिए नई फ़ाइल सेव करें:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

यह ज़रूरी है, क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर कोड में कई **optimisations** लागू होंगी और संभव है कि debugging के दौरान कोई **break-point कभी hit न हो** या कुछ **variables मौजूद न हों**।

फिर, अगर आपकी .NET application **IIS** द्वारा **run** की जा रही है, तो आप इसे इस कमांड से **restart** कर सकते हैं:

```
iisreset /noforce
```

फिर, debugging शुरू करने के लिए आपको खोली गई सभी files बंद करनी चाहिए और **Debug Tab** में **Attach to Process...** चुनना चाहिए:

![DNSpy Logging - DNSpy Debugging: Debugging शुरू करने के लिए, खोली गई सभी files बंद करें और Debug Tab में Attach to Process चुनें](<../../images/image (318).png>)

फिर **w3wp.exe** चुनकर **IIS server** से attach करें और **attach** पर click करें:

![DNSpy Logging - DNSpy Debugging: IIS server से attach करने के लिए w3wp.exe चुनें और attach पर click करें](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो इसे रोकने और सभी modules load करने का समय है। पहले _Debug >> Break All_ पर click करें, फिर _**Debug >> Windows >> Modules**_ पर click करें:

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर click करें, फिर Debug Windows Modules पर click करें](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: अब जब हम process को debug कर रहे हैं, तो इसे रोकने और सभी modules load करने का समय है। पहले Debug Break All पर click करें, फिर Debug Windows Modules पर click करें](<../../images/image (834).png>)

**Modules** में किसी भी module पर click करें और **Open All Modules** चुनें:

![DNSpy Logging - DNSpy Debugging: Modules में किसी भी module पर click करें और Open All Modules चुनें](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर click करें:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer में किसी भी module पर right click करें और Sort Assemblies पर click करें](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLs की Debugging

### IDA का उपयोग

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger चुनें
- "**Suspend on library load/unload**" चुनें

![Debugging DLLs - Using IDA: " Suspend on library load/unload " चुनें](<../../images/image (868).png>)

- Execution के **parameters** configure करें और **DLL का path** तथा उस function का नाम डालें जिसे आप call करना चाहते हैं:

![Debugging DLLs - Using IDA: Execution के parameters configure करें और DLL का path तथा उस function का नाम डालें जिसे आप call करना चाहते हैं](<../../images/image (704).png>)

फिर, जब आप debugging शुरू करेंगे, **हर DLL load होने पर execution रुक जाएगा**। इसलिए, जब rundll32 आपकी DLL load करेगा, तो execution रुक जाएगा।

यह तरीका module-load events पर रुकता है, लेकिन loaded DLL के entry point तक पहुँचना नीचे दिए गए x64dbg workflow की तुलना में कम सीधा है।

### x64dbg/x32dbg का उपयोग

- **rundll32 load करें** (64bits के लिए C:\Windows\System32\rundll32.exe और 32 bits के लिए C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा उस function का नाम डालें जिसे आप call करना चाहते हैं, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**। Debugger हर dll main पर रुकेगा; किसी बिंदु पर आप **अपनी dll के Entry पर रुकेंगे**। वहाँ से, बस उन points को खोजें जहाँ आप breakpoint लगाना चाहते हैं।

ध्यान दें कि जब execution किसी भी कारण से win64dbg में रुकता है, तो **win64dbg window के ऊपर** देखकर आप जान सकते हैं कि **आप किस code में हैं**:

![Using IDA - Using x64dbg/x32dbg: ध्यान दें कि जब execution किसी भी कारण से win64dbg में रुकता है, तो win64dbg window के ऊपर देखकर आप जान सकते हैं कि आप किस code में हैं](<../../images/image (842).png>)

यह indicator पुष्टि करता है कि execution उस DLL के अंदर रुका है जिसे आप debug करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है, जो यह पता लगाने में मदद करता है कि चल रहे game की memory में महत्वपूर्ण values कहाँ save हैं, और उन्हें बदलने में भी मदद करता है। अधिक जानकारी यहाँ:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर केंद्रित है। हालाँकि, इसका उपयोग reverse-engineering से जुड़ी किसी भी चीज़ के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## REA के साथ साक्ष्य-आधारित native investigation

**REA**, CLI और MCP के माध्यम से Hopper, Ghidra और IDA analysis उपलब्ध कराता है। इसके लिए Node.js 22.x (कम-से-कम 22.19), 24.x (कम-से-कम 24.11), या 26+, और npm आवश्यक हैं। पहले किसी मौजूदा native provider को configure करें; `rea providers --json` चलाकर जाँचें और यदि एक से अधिक provider target को support करते हों, तो किसी एक को स्पष्ट रूप से चुनें। नीचे `0x1000` की जगह inventory में दिखा कोई function name या address इस्तेमाल करें।<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

किसी feature string या symbol से शुरू करें, references और callers का अनुसरण करें, फिर चुने गए function dossier और `rea decompile` से pseudocode का निरीक्षण करें। REA session को चुने गए provider से जोड़ता है, न कि विफलता के बाद चुपचाप उसे बदल देता है। दोहराए जा सकने वाले queries के लिए, `--snapshot PATH` केवल मेल खाते artifact bytes, provider, settings, operation और parameters को दोबारा इस्तेमाल करता है; snapshot एक local cache है, सहेजा हुआ provider database नहीं। लौटाए गए Evidence और स्पष्ट unknowns को सुरक्षित रखें; अनुमानित paths या decompiler के text को मूल source न मानें।<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron entry points से native add-ons तक जाने के लिए, देखें [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## स्थानीय TCP bridge के साथ scripted IDA और Ghidra विश्लेषण

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) **पहले से खुले** IDA database या Ghidra CodeBrowser program के अंदर चलता है और अलग script को उस analysis database को query और modify करने देता है। IDA के Python CLI से `ID_Server.py` चलाएँ (`import ID_Server`), या Ghidra के Script Manager से `Ghidra_Server.py` चलाएँ। IDA `127.0.0.1` पर port `5073` से bind होता है और उसके बाद के ports को scan करता है। मौजूदा Ghidra script port `5093` से शुरू होती है और `5102` तक दस ports आज़माती है; इसका Java socket केवल loopback पर नहीं, बल्कि wildcard address पर bind होता है। connect करने से पहले उस instance द्वारा दिखाए गए port की जाँच करें। Headless analyzer के विपरीत, यह bridge उस program पर काम करता है जो उस GUI instance में अभी खुला है।<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

हर connection पर **एक newline-terminated command** भेजें और newline-terminated response पढ़ें। परिणाम आम तौर पर JSON होता है। उदाहरण के लिए, किसी input path से संबंधित imported API मिलने के बाद, `IMPORTXREF` उसके call sites ढूँढ़ता है; फिर `DECOMP_XREF` चुने गए address के callers को batch-decompile करता है। `FUNC` किसी function का निरीक्षण करता है, जबकि `PCODE` decompiler का intermediate representation लौटाता है। Active database का address इस्तेमाल करें, किसी अलग तरह से rebased binary से कॉपी किया गया address नहीं। नीचे दिए गए उदाहरण में IDA का default port इस्तेमाल हुआ है; Ghidra के लिए उसकी script द्वारा दिखाया गया port इस्तेमाल करें।<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

उसी channel से **analysis database में बदलाव** भी किया जा सकता है: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` और `PATCH` नाम, types, structure definitions, function boundaries या stored bytes बदलते हैं। `PATCH` database में edit है, **live process में patch किए जाने का प्रमाण नहीं**। इनमें से कोई भी listener authentication के बारे में documentation नहीं देता। IDA केवल loopback पर उपलब्ध है, लेकिन Ghidra network interfaces के ज़रिए पहुँच योग्य हो सकता है; Ghidra listener का उपयोग करते समय उसकी access सीमित रखें। `QUIT` दोनों में से किसी भी listener को रोकता है, और IDA `ida_bridge_stop()` भी उपलब्ध कराता है।<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner से shellcode को debug करना

[**BlobRunner**](https://github.com/OALabs/BlobRunner) **shellcode** को allocate करता है, उसका **memory address** print करता है और execution रोक देता है।\
IDA या x64dbg जैसे debugger को attach करें, print किए गए address पर breakpoint लगाएँ और shellcode को debug करने के लिए execution फिर से शुरू करें।

releases github page में compiled releases वाली zip files हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आपको नीचे दिए गए link में Blobrunner का थोड़ा modified version मिलेगा। इसे compile करने के लिए बस **Visual Studio Code में C/C++ project बनाएँ, code copy-paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it से shellcode को debug करना

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner जैसा ही है। यह shellcode को allocate करके infinite loop में चला जाता है। Debugger attach करें, **2–5 seconds** तक execution resume करें, उस loop के अंदर pause करें और फिर उस अगले call तक step करें जो allocated shellcode को execution सौंपता है।

![jmp2it के infinite loop में debugger रुका हुआ है, allocated shellcode के call से ठीक पहले](<../../images/image (509).png>)

आप [releases page में jmp2it का compiled version डाउनलोड कर सकते हैं](https://github.com/adamkramer/jmp2it/releases/)।

### Cutter का उपयोग करके shellcode को debug करना

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और उसका dynamically निरीक्षण कर सकते हैं।

ध्यान दें कि Cutter में "Open File" और "Open Shellcode" विकल्प हैं। मेरे मामले में, जब मैंने shellcode को file के रूप में खोला, तो उसने उसे सही ढंग से decompile किया; लेकिन shellcode के रूप में खोलने पर ऐसा नहीं हुआ:

![एक ही bytes को file या shellcode के रूप में खोलने पर Cutter अलग-अलग analysis results दिखा रहा है](<../../images/image (562).png>)

जिस जगह से emulation शुरू करनी है, वहाँ bp सेट करें। ऐसा लगता है कि Cutter अपने आप वहीं से emulation शुरू कर देगा:

![Cutter emulation शुरू करने से पहले इच्छित shellcode entry पर breakpoint सेट करना](<../../images/image (589).png>)

![Cutter emulator चुने हुए shellcode breakpoint पर रुका हुआ है](<../../images/image (387).png>)

उदाहरण के लिए, आप stack को hex dump में देख सकते हैं:

![Cutter के hex dump में emulated shellcode stack देखना](<../../images/image (186).png>)

### shellcode को deobfuscate करना और execute किए गए functions प्राप्त करना

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

scDbg में एक graphical launcher भी है, जहाँ आप अपनी पसंद के options चुनकर shellcode execute कर सकते हैं

![shellcode emulation और tracing options चुनने के लिए scDbg graphical launcher](<../../images/image (258).png>)

**Create Dump** option, shellcode को memory में dynamically बदलने पर अंतिम shellcode का dump बनाएगा (decoded shellcode डाउनलोड करने के लिए उपयोगी)। **start offset** किसी खास offset से shellcode शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** option, scDbg terminal का उपयोग करके shellcode debug करने के लिए उपयोगी है (हालाँकि, मुझे इस काम के लिए पहले बताए गए options में से कोई भी बेहतर लगता है, क्योंकि आप Ida या x64dbg का उपयोग कर पाएँगे)।

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए यह recipe इस्तेमाल करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation का deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` जैसे सरल expressions को ऐसे formulas के पीछे छिपाता है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को मिलाते हैं। अहम बात यह है कि ये identities आम तौर पर केवल **fixed-width modular arithmetic** के तहत ही सही होती हैं, इसलिए carries और overflows मायने रखते हैं:

```c
(x ^ y) + 2 * (x & y) == x + y
```

यदि आप इस तरह की expression को generic algebra tooling से simplify करते हैं, तो bit-width semantics को अनदेखा करने के कारण आसानी से गलत result मिल सकता है।<sup>[[1]](#references)</sup>

### व्यावहारिक workflow

1. Lifted code/IR/decompiler output से **original bit-width** (`8/16/32/64` bits) बनाए रखें।
2. इसे simplify करने की कोशिश करने से पहले **expression को classify** करें:
   - **Linear**: bitwise atoms के weighted sums
   - **Semilinear**: linear के साथ constant masks, जैसे `x & 0xFF`
   - **Polynomial**: products मौजूद हों
   - **Mixed**: products और bitwise logic आपस में interleaved हों, अक्सर repeated subexpressions के साथ
3. हर candidate rewrite को random testing या SMT proof से **verify** करें। यदि equivalence साबित न हो सके, तो अनुमान लगाने के बजाय original expression बनाए रखें।

### narrow execution slice से flattened control flow को bypass करें

अक्सर complete control-flow graph recover करना ज़रूरी नहीं होता। Control-flow flattening, opaque predicates, बड़े dispatchers या MBA-heavy code के मामले में, encrypted blobs और output buffers से references को उस सबसे छोटी routine तक follow करें जो उन्हें transform करती है। फिर केवल उस data-flow slice को reproduce करें या उसे independently execute करें; यदि relevant state को सीधे initialize किया जा सकता है, तो dispatcher required solution का हिस्सा नहीं है।<sup>[[7]](#references)</sup>

एक व्यावहारिक workflow यह है:<sup>[[7]](#references)</sup>

1. Executable और data sections, relocations तथा cross-references की inventory बनाएं। `.rodata` से candidate tables dump करते समय उनका byte order और element width बनाए रखें।
2. उस आखिरी routine को identify करें जो plaintext या output buffer लिखती है। उसके inputs, referenced tables, imported calls और आवश्यक global state को record करें।
3. केवल उन्हीं operations को fixed-width Python model में lift करें। यदि slice अब भी बहुत अधिक state पर निर्भर है, तो पूरे program को emulate करने के बजाय routine को Unicorn, QEMU या debugger के अंतर्गत invoke करें और अप्रासंगिक imports को hook करें।
4. Validate करें कि extractor वास्तव में अपना output दिए गए binary से derive करता है: silent fallbacks हटाएं, embedded answers के लिए binary search करें और बदले हुए strings, keys, identifiers, layouts तथा obfuscation seeds वाले unseen builds पर इसे run करें।

पहले चरण के लिए उपयोगी commands हैं:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### छिपे हुए constants वाले MBA expressions का पता लगाएँ

ऊपरी तौर पर input पर निर्भर दिखने वाला byte expression, अपना input पूरी तरह रद्द कर सकता है। इसकी tables निकालने के बाद, पूरे 8-bit domain पर expression का मूल्यांकन करें; output set में केवल एक मान होना साबित करता है कि वह byte constant है—इसके लिए आसपास की state machine को पुनर्प्राप्त करने की ज़रूरत नहीं है।<sup>[[7]](#references)</sup>

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

अंतिम mask बनाए रखें, क्योंकि मूल जोड़ में byte-width wraparound होता है। बड़े domain के लिए, SMT solver से पूछें कि क्या समान-width वाले दो symbolic inputs के लिए `f(x1) != f(x2)` satisfiable है: `unsat` invariance साबित करता है, जबकि `sat` counterexample देता है और इसका मतलब है कि input को हटाया नहीं जा सकता।<sup>[[7]](#references)</sup>

#### Environment-bound decoding को पहचानें

Anti-analysis checks के लिए branch लेना या crash होना ज़रूरी नहीं है। Decoder किसी sensor result को key bit, opaque-predicate constant या flattened-dispatcher state में मिला सकता है, सामान्य रूप से चलता रह सकता है और emulator में विश्वसनीय दिखने वाला, लेकिन गलत plaintext दे सकता है। इसलिए केवल दिखने वाली failure branches को patch करना पर्याप्त नहीं है; environment probes से decoder state तक data dependencies trace करें, authentic device और emulator पर उसी slice की तुलना करें और जाँचें कि प्रत्येक sensor result को ज़बरन बदलने से अंतिम buffer कैसे बदलता है।<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक व्यावहारिक MBA simplifier है। यह expression को classify करता है और हर चीज़ पर एक ही generic rewrite pass लागू करने के बजाय उसे specialized pipelines से गुज़ारता है।<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature निकालता है, और pattern matching, ANF conversion तथा coefficient interpolation जैसी कई recovery methods को साथ-साथ चलाता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से दोबारा बनाया जाता है, ताकि masked regions सही रहें।
- **Polynomial/Mixed MBA**: products को cores में विभाजित किया जाता है और outer relation को simplify करने से पहले repeated subexpressions को temporaries में बदला जा सकता है।

एक mixed identity का उदाहरण, जिसे recover करने की कोशिश अक्सर उपयोगी होती है:

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
- अगर आपको अधिक मजबूत proof step चाहिए, तो यहाँ दिए गए local Z3 notes देखें:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA, **LLVM pass plugin** (`libCobraPass.so`) के रूप में भी उपलब्ध है। यह तब उपयोगी है, जब आप बाद के analysis passes से पहले MBA-heavy LLVM IR को normalize करना चाहें।
- Unsupported carry-sensitive mixed-domain residuals इस बात का संकेत हैं कि मूल expression को बनाए रखें और carry path का manually विश्लेषण करें।

## Recovering XOR-state control-flow flattening

OLLVM-style flattener, dispatcher पर XOR से state को reconstruct करने के लिए, मौजूदा basic-block state को दो 64-bit registers में रख सकता है। हर original block अगले state के लिए यह pair लिखता है और dispatcher पर वापस jump करता है। Conditional block, CPU flags के आधार पर pair के एक हिस्से को बदलने के लिए `CMOVcc` का इस्तेमाल कर सकता है, इसलिए केवल दिखाई देने वाले branch instructions को follow करने पर दोनों successors छूट जाते हैं। Indirect-jump dispatcher से अलग, इस रूप में हर जगह direct back-edges हो सकते हैं।<sup>[[19]](#references)[[20]](#references)</sup>

Graph को recover करने के लिए, dispatcher comparison tree और दोनों state registers पहचानें, हर compared XOR state को उसके target block से map करें, फिर हर original block में register pair को लिखने वाले reaching writes को trace करें। Conditional writes के लिए, flag-setting instruction और `CMOVcc` के दोनों outcomes शामिल करें। हर block के dispatcher exit को उसके resolved direct successor या conditional branch से बदलें; binary को patch किए बिना dispatcher फिर unreachable हो जाता है। यह full-CFG approach है; अगर केवल एक decoder मायने रखता है, तो ऊपर दिया गया [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice) तेज़ हो सकता है।<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), Binary Ninja में इस रूप को automate करता है। `plugins/DispatchThis` को Binary Ninja user plugin directory में copy करके restart करें। प्रभावित function पर, **Function Settings** खोलें और `OLLVM_XOR_64` चुनें; अगर analysis शुरू न हो, तो **Analysis → Reanalyze All Functions** इस्तेमाल करें। यह mode file bytes के बजाय MLIL control-flow edges को rewrite करता है और इसे Z3 या indirect-jump resolver की ज़रूरत नहीं होती। इसे Binary Ninja 5.3.9757+ पर आज़माया गया है; यह हर block के dead state writes को नहीं हटाता, इसलिए उन्हें शेष live transitions न समझें।<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह obfuscator program operations को `mov`-आधारित instruction sequences से बदलता है और control flow बदलने के लिए signal/exception handling का इस्तेमाल करता है। विवरण के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Supported binaries के लिए, [demovfuscator](https://github.com/kirschju/demovfuscator) नतीजे को deobfuscate कर सकता है। इसकी कई dependencies हैं।

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

और [keystone इंस्टॉल करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF खेल रहे हैं, तो flag खोजने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए, `::main` से functions खोजें, जैसे:

![Ghidra में function names में double-colon main खोजकर Rust entry point ढूँढना](<../../images/image (1080).png>)

इस मामले में binary का नाम authenticator था, इसलिए यह स्पष्ट है कि यही दिलचस्प main function है।\
कॉल किए जा रहे **functions** के **नाम** मिलने पर, उनके **inputs** और **outputs** के बारे में जानने के लिए उन्हें **Internet** पर खोजें।

### ELF firmware से Rust strings वापस प्राप्त करना

**Rust ELF** binaries में, कई static strings को C-style NUL-terminated pointers से संदर्भित नहीं किया जाता। `rustc` का एक आम layout है **`.data.rel.ro`** के भीतर **pointer/length tuple**, जो **`.rodata`** में मौजूद वास्तविक string blob की ओर इंगित करता है:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

इसका मतलब है कि `strings` या Ghidra का डिफ़ॉल्ट विश्लेषण पास-पास की strings को मिला सकता है या क्रॉस-रेफरेंस पूरी तरह से चूक सकता है।<sup>[[3]](#references)</sup>

त्वरित कार्यप्रवाह:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक बार में एक word के हिसाब से enumerate करें।
3. `.rodata` address range के अंदर आने वाली किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. sanity filters लागू करें (उदाहरण के लिए, **4** से **100** bytes के बीच की lengths रखें)।
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

यह firmware reversing में विशेष रूप से उपयोगी है, क्योंकि प्राप्त Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers और auth-related logic** उजागर करती हैं।

अगर Ghidra उन strings को नहीं पहचानता, तो ऐसा custom script/plugin चलाएँ जो वही heuristic लागू करे और संदर्भित `.rodata` offsets पर string data बनाए। Pen Test Partners के प्रकाशित `rust-strings` और `RustStrings.py` tools इस विचार को अन्य **word sizes, endianness और section layouts** के अनुसार ढालने के लिए अच्छे संदर्भ हैं।<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं।

अगर आपको Delphi binary को reverse करना है, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने का सुझाव दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह plugin debugging शुरू होने पर binary को execute करेगा और function names को dynamically resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ; real code की शुरुआत में एक breakpoint hit होगा।

अगर आप graphical application में कोई button दबाते हैं, तो debugger उस button द्वारा invoke किए गए function पर रुक सकता है।

## Golang

सामान्य Go binaries के लिए, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) runtime structures recover कर सकता है और IDA में function names बेहतर कर सकता है। इसका Python plugin **Alt+F7** दबाकर लोड करें।

अगर आपको Golang binary को reverse करना है, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने का सुझाव दूँगा।

Python plugin लोड करने के लिए IDA में **Alt+F7** दबाएँ, फिर plugin file चुनें।

यह functions के names resolve करेगा।

### symbol table के बिना metadata recover करना

Stripped Go executable को भी program counters को functions से map करने के लिए runtime metadata की ज़रूरत होती है। [GoReSym](https://github.com/mandiant/GoReSym), Go runtime से लिए गए code का उपयोग करके `pclntab` और `moduledata` जैसी structures ढूँढ़ता और parse करता है। इससे conventional symbol table पर निर्भर हुए बिना function boundaries, names, source paths, types और build details recover किए जा सकते हैं।<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

एक obfuscator इन structures को उपयोग करने योग्य छोड़ सकता है, जबकि recovered names को बदल देता है। उदाहरण के लिए, Garble identifiers और package paths को hash करता है और build, module तथा debug information हटा देता है।<sup>[[12]](#references)</sup> Obfuscated package token, उस package के functions में एक जैसा रहना चाहिए। दोहराए जाने वाले token के आधार पर functions को समूहों में बाँटें, callees, strings और APIs से एक package का अनुमान लगाएँ, फिर उस package label को पूरे समूह में लागू करें।<sup>[[13]](#references)</sup>

### GoResolver से Garble names पुनः प्राप्त करें

[GoResolver](https://github.com/volexity/GoResolver) runtime-symbol extraction को clean-reference generation और control-flow-graph (CFG) matching के साथ जोड़ता है। यह क्रम अपनाएँ:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler version पहचानें।** पहले `BuildInfo` और embedded version strings देखें। अगर obfuscator ने इन्हें हटा दिया हो, तो bundled Go runtime के हिस्सों की तुलना versioned reference runtimes से करें। Volexity के परीक्षणों में, runtime का लगभग `2%` हिस्सा major Go versions में अंतर पहचानने के लिए पर्याप्त था। इसे एक अनुभवजन्य optimization मानें, सार्वभौमिक threshold नहीं।<sup>[[13]](#references)</sup>
2. **Matching references बनाएँ।** पहचाने गए Go version, target architecture और संभावित libraries के लिए clean binaries बनाएँ। Toolchain का मेल compiler-generated CFG differences को कम करता है।<sup>[[10]](#references)[[13]](#references)</sup>
3. **Functions की तुलना करें।** GoGrapher function CFGs का मिलान करता है और `0.0` से `1.0` तक के normalized scores देता है। इसका basic-block matching, समान instructions की weighted comparison पर आधारित है। High-confidence matches randomized functions को clean implementation से map करते हैं। कमज़ोर matches फिर भी package या module की पहचान कर सकते हैं।<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **पुष्टि करें और import करें।** प्रस्तावित names की पुष्टि call relationships, constants, strings और side effects से करें, फिर IDA या Ghidra के GoResolver plugin से JSON report import करें।<sup>[[10]](#references)[[13]](#references)</sup>

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

डिफ़ॉल्ट significant-match threshold `0.9` है। `--extract` और `--graph` switches किसी भी stage को अलग से चलाते हैं, जबकि डिफ़ॉल्ट रूप से दोनों चलते हैं, क्योंकि recovered runtime metadata और CFG evidence एक-दूसरे के पूरक होते हैं।<sup>[[10]](#references)</sup> CFG scores heuristic होते हैं: inlining, build flags, architecture और library-version के अंतर graph की संरचना बदल सकते हैं, इसलिए कम-confidence वाले नाम थोपने के बजाय unresolved functions को बनाए रखें।<sup>[[13]](#references)</sup>

### Go string table को रिकवर करना

Go binaries हर linked package के string bytes को एक contiguous table में रखते हैं। Entries NUL-terminated नहीं होतीं और runtime structures table का base या size नहीं बताते। हालांकि, compiler अलग-अलग operating systems और architectures में entries को पहले length के अनुसार और फिर alphabetically क्रमबद्ध करता है। इसलिए, एक entry मिलने के बाद analyst आस-पास की entries को देख सकता है और data cross-references की मदद से strings को code से जोड़ सकता है।<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) इस workflow को IDA Pro और Ghidra में automate करता है। पहले auto-analysis पूरा होने दें, क्योंकि plugin data-segment cross-references पर निर्भर करता है। इसका default anchor runtime string `entersyscall` है। इसके बाद यह दोनों दिशाओं में scan कर सकता है, database में recovered strings को define कर सकता है और strings को referencing functions से जोड़ने वाली JSON mapping export कर सकता है।<sup>[[14]](#references)</sup>

Referencing function के package के आधार पर report को filter करें, ताकि application या malware code को linked libraries के अनावश्यक data से अलग किया जा सके। यह technique obfuscation से नष्ट किए गए literals को recover नहीं कर सकती, जैसे Garble का `-literals` transformation। फिर भी, यह उन runtime strings को व्यवस्थित कर सकती है जो unobfuscated बने रहते हैं।<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime types को रिकवर करना

Go में garbage collection जैसी सुविधाओं के लिए इस्तेमाल होने वाली runtime type information शामिल होती है। जब build information हटा दी जाती है या disassembler इस metadata को parse नहीं करता, तो instructions मनमाने data addresses load करते हुए दिखाई दे सकते हैं और target region untyped रह जाता है। Metadata को recover करने से ये addresses पढ़ने योग्य type references में बदल जाते हैं और package की क्षमताओं को समझना आसान हो जाता है।<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) symbols extract कर सकता है और runtime types को parse करके JSON report बना सकता है। मौजूदा CLI में `resolve` subcommand का इस्तेमाल होता है:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` विकल्प type parsing सक्षम करता है। बरामद किए गए types को परिभाषित करने और analysis database में उनके references लागू करने के लिए, GoResolver के IDA Pro या Ghidra plugin से report import करें। इस feature के साथ पेश किए गए report format में, `-y` को छोड़ने पर RTTI address और recovered-types members null रहते हैं।<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver x86, AMD64, ARM और ARM64 के लिए PE, ELF और Mach-O samples सपोर्ट करता है, इसलिए यही workflow Windows, Linux और macOS के Go binaries पर लागू होता है।<sup>[[10]](#references)</sup>

## Compiled Python

इस page में आप जान सकते हैं कि ELF/EXE Python compiled binary से Python code कैसे प्राप्त करें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

अगर आपको GBA game का **binary** मिलता है, तो आप उसे **emulate** और **debug** करने के लिए अलग-अलग tools का इस्तेमाल कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug version डाउनलोड करें_) - इसमें interface वाला debugger है
- [**mgba** ](https://mgba.io)- इसमें CLI debugger है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** पर आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे दबाने हैं

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

दबाने पर, हर **key की एक value होती है** जिससे उसकी पहचान होती है:

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

तो, इस तरह के प्रोग्राम में दिलचस्प बात यह होगी कि **प्रोग्राम user input को कैसे संभालता है**। address **0x4000130** पर आपको आम तौर पर मिलने वाला function: **KEYINPUT** मिलेगा।

![GBA binary का Ghidra view, जो address 0x4000130 पर KEYINPUT को संदर्भित करता है](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि यह function **FUN_080015a8** से call किया जाता है (addresses: _0x080015fa_ और _0x080017ac_)।

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

अंतिम if यह जाँच रहा है कि **`uVar4`** पिछले Keys में है और मौजूदा key नहीं है। इसे बटन छोड़ना भी कहते हैं (मौजूदा key **`uVar1`** में संग्रहीत है)।

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

- पहले, इसकी तुलना **value 4** (**SELECT** button) से की जाती है: challenge में यह button screen साफ़ करता है।
- फिर इसकी तुलना **8** (**START** button) से की जाती है; इस challenge में, यह path जाँचता है कि दर्ज किया गया code valid है या नहीं।
  - इस स्थिति में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि value समान हो, तो कुछ code execute होता है।
- हर दूसरे मामले में, एक counter (`DAT_030000d4`) को जाँचा और increment किया जाता है।\
  जब तक counter 8 से कम है, दबाए गए keys की values को `DAT_030000d8` में जोड़ा जाता है।

इसलिए, इस challenge में, buttons की values जानने के बाद, आपको **8 से कम लंबाई वाला ऐसा combination दबाना था जिसका कुल योग 0xf3 हो।**

**इस tutorial का संदर्भ:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [7] [AI-सहायता प्राप्त Reverse Engineering को विफल करना, या कम-से-कम कोशिश करना](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching पर आधारित Control Flow Graphs की तुलना करने का एक तरीका](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binaries को automatically deobfuscate करने के लिए Control-Flow Graph Similarity का उपयोग](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang Tooling के अपडेट](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: कुछ भी Reverse Engineer करें](https://github.com/morluto/rea)
- [17] [REA managed-code analysis](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI और Evidence guide](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening workflow](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day Intrusion, Java Loader, Web Shell, और AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge server implementation](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge server implementation](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) wildcard address से bind होता है](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
