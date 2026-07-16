# रिवर्सिंग टूल्स और बेसिक मेथड्स

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक decompiler है जो **decompiles and examines multiple formats**, including **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe). एक बार decompile होने पर, assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

यहाँ फायदा यह है कि अगर lost source code को legacy assembly से restore करना हो, तो यह action time बचा सकता है। आगे, dotPeek decompiled code में आसान navigation देता है, जिससे यह **Xamarin algorithm analysis.** के लिए perfect tools में से एक बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक comprehensive add-in model और API के साथ जो tool को आपकी exact needs के अनुसार extend करती है, .NET reflector time बचाता है और development को सरल बनाता है। आइए देखें कि reverse engineering services की इतनी सारी सुविधाएँ यह tool क्या देती है:

- यह दिखाता है कि data library या component के through कैसे flow करता है
- .NET languages और frameworks के implementation और usage पर insight देता है
- undocumented और unexposed functionality ढूँढता है ताकि APIs और technologies से और अधिक निकाला जा सके
- dependencies और अलग-अलग assemblies ढूँढता है
- आपके code, third-party components, और libraries में errors की exact location track करता है।
- आप जिन सभी .NET code के साथ काम करते हैं, उनके source में debug करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS में इस्तेमाल कर सकते हैं (आप इसे सीधे VSCode से install कर सकते हैं, git download करने की जरूरत नहीं). **Extensions** पर click करें और **ILSpy search** करें।\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना है, तो आप [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसका actively maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) use कर सकते हैं। (**Right Click -> Modify Method** से function के अंदर कुछ बदल सकते हैं).

### DNSpy Logging

**DNSpy log कुछ information को file में** करने के लिए, आप यह snippet use कर सकते हैं:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy का उपयोग करके code को debug करने के लिए आपको:

सबसे पहले, **debugging** से संबंधित **Assembly attributes** बदलने होंगे:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
के लिए:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
और **compile** पर क्लिक करें:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

फिर नए file को _**File >> Save module...**_ के जरिए save करें:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

यह आवश्यक है क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर code में कई **optimisations** लागू हो जाएंगे और यह संभव है कि debugging के दौरान कोई **break-point कभी hit न हो** या कुछ **variables मौजूद ही न हों**।

फिर, अगर आपकी .NET application **IIS** द्वारा **run** की जा रही है, तो आप इसे इस तरह **restart** कर सकते हैं:
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules](<../../images/image (834).png>)

Click any module on **Modules** and select **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Right click any module in **Assembly Explorer** and click **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.

{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg में एक graphical launcher भी होता है, जहाँ आप अपनी इच्छित options चुनकर shellcode execute कर सकते हैं

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

**Create Dump** option, shellcode में memory के भीतर dynamically कोई change होने पर final shellcode को dump करेगा (decoded shellcode download करने के लिए useful). **start offset** shellcode को किसी specific offset से start करने के लिए useful हो सकता है. **Debug Shell** option, scDbg terminal का उपयोग करके shellcode debug करने के लिए useful है (हालाँकि इस काम के लिए ऊपर बताए गए किसी भी option को मैं बेहतर मानता हूँ, क्योंकि आप Ida या x64dbg use कर पाएँगे).

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए following recipe का उपयोग करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, simple expressions जैसे `x + y` को ऐसे formulas के पीछे छिपाती है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को mix करती हैं. महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** के तहत ही सही होती हैं, इसलिए carries और overflows matter करते हैं:
```c
(x ^ y) + 2 * (x & y) == x + y
```
यदि आप इस तरह के expression को generic algebra tooling से simplify करते हैं, तो आप आसानी से गलत result पा सकते हैं क्योंकि bit-width semantics को ignore कर दिया गया था।

### Practical workflow

1. **Keep the original bit-width** lifted code/IR/decompiler output से (`8/16/32/64` bits)।
2. **Expression को classify करें** simplify करने से पहले:
- **Linear**: bitwise atoms के weighted sums
- **Semilinear**: linear plus constant masks जैसे `x & 0xFF`
- **Polynomial**: products दिखाई देते हैं
- **Mixed**: products और bitwise logic interleaved होते हैं, अक्सर repeated subexpressions के साथ
3. **हर candidate rewrite को verify करें** random testing या SMT proof से। अगर equivalence prove नहीं हो सकती, तो guessing करने के बजाय original expression को रखें।

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक practical MBA simplifier है। यह expression को classify करता है और एक generic rewrite pass सब पर लागू करने के बजाय specialized pipelines से route करता है।

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

- **Linear MBA**: CoBRA Boolean inputs पर expression का मूल्यांकन करता है, एक signature निकालता है, और pattern matching, ANF conversion, और coefficient interpolation जैसी कई recovery methods को एक साथ चलाता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर से बनाया जाता है ताकि masked regions सही रहें।
- **Polynomial/Mixed MBA**: products को cores में decomposed किया जाता है और outer relation को simplify करने से पहले repeated subexpressions को temporaries में lift किया जा सकता है।

एक mixed identity का उदाहरण जिसे recover करने की कोशिश करना अक्सर worthwhile होता है:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
यह इस तरह संक्षेपित किया जा सकता है:
```c
x * y
```
### Reversing notes

- Prefer running CoBRA on **lifted IR expressions** or decompiler output after you isolated the exact computation.
- Use `--bitwidth` explicitly when the expression came from masked arithmetic or narrow registers.
- If you need a stronger proof step, check the local Z3 notes here:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA also ships as an **LLVM pass plugin** (`libCobraPass.so`), which is useful when you want to normalize MBA-heavy LLVM IR before later analysis passes.
- Unsupported carry-sensitive mixed-domain residuals should be treated as a signal to keep the original expression and reason about the carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **सभी instructions को `mov` के लिए modify करता है**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

To find the **entry point** search the functions by `::main` like in:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

### Recovering Rust strings from ELF firmware

In **Rust ELF** binaries, many static strings are not referenced as C-style NUL-terminated pointers. A common `rustc` layout is a **pointer/length tuple** inside **`.data.rel.ro`** pointing into the real string blob stored in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
इसका मतलब है कि `strings` या डिफ़ॉल्ट Ghidra analysis आस-पास की strings को merge कर सकता है या cross-references को पूरी तरह miss कर सकता है।

Quick workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** का virtual address और size प्राप्त करें।
2. **`.data.rel.ro`** को एक-एक word करके enumerate करें।
3. `.rodata` address range के अंदर किसी भी value को candidate string pointer मानें।
4. अगले word को candidate length मानें।
5. sanity filters लागू करें (उदाहरण के लिए, lengths को **4** और **100** bytes के बीच रखें)।
6. `0x00` तक scan करने के बजाय `.rodata` से exactly `length` bytes पढ़ें।

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
यह खास तौर पर firmware reversing में उपयोगी है क्योंकि recovered Rust strings अक्सर **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, and auth-related logic** को reveal करती हैं।

अगर Ghidra उन strings को miss कर दे, तो एक custom script/plugin चलाएँ जो वही heuristic apply करे और referenced `.rodata` offsets पर string data बनाए। Pen Test Partners के published `rust-strings` और `RustStrings.py` tools इस idea को अन्य **word sizes, endianness, and section layouts** के लिए adapt करने के अच्छे reference हैं।

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं

अगर आपको किसी Delphi binary को reverse करना हो, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) उपयोग करने की सलाह दूँगा

बस **ATL+f7** (IDA में python plugin import) दबाएँ और python plugin select करें।

यह plugin debugging की शुरुआत में binary को execute करेगा और function names को dynamically resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ और real code की शुरुआत में एक breakpoint hit होगा।

यह भी बहुत interesting है क्योंकि अगर आप graphic application में कोई button press करते हैं, तो debugger उस function में stop हो जाएगा जो उस bottom द्वारा execute किया गया है।

## Golang

अगर आपको किसी Golang binary को reverse करना हो, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) उपयोग करने की सलाह दूँगा

बस **ATL+f7** (IDA में python plugin import) दबाएँ और python plugin select करें।

यह functions के names resolve कर देगा।

## Compiled Python

इस page पर आप देख सकते हैं कि ELF/EXE python compiled binary से python code कैसे निकालें:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

अगर आपके पास किसी GBA game का **binary** है, तो आप उसे **emulate** और **debug** करने के लिए अलग-अलग tools का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - interface वाला debugger शामिल है
- [**mgba** ](https://mgba.io)- CLI debugger शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** में आप देख सकते हैं कि Game Boy Advance **buttons** कैसे press करने हैं

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

जब इसे press किया जाता है, तो हर **key has a value** जिससे उसे identify किया जाता है:
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
तो, इस तरह के program में, दिलचस्प हिस्सा होगा **program user input को कैसे treat करता है**। **0x4000130** address पर आपको आमतौर पर मिलने वाला function मिलेगा: **KEYINPUT**।

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि function को **FUN_080015a8** से call किया गया है (addresses: _0x080015fa_ and _0x080017ac_)।

उस function में, कुछ init operations के बाद (जिनका कोई importance नहीं है):
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
यह कोड मिला:
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
अंतिम if यह जांच रहा है कि **`uVar4`** **last Keys** में है और यह current key नहीं है, जिसे button छोड़ना भी कहा जाता है (current key **`uVar1`** में stored है)।
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
In the previous code you can see that we are comparing **uVar1** (वह स्थान जहाँ **दबाए गए button का value** है) with some values:

- First, it's compared with the **value 4** (**SELECT** button): In the challenge this button clears the screen
- Then, it's comparing it with the **value 8** (**START** button): In the challenge this checks is the code is valid to get the flag.
- In this case the var **`DAT_030000d8`** is compared with 0xf3 and if the value is the same some code is executed.
- In any other cases, some cont (**`DAT_030000d4`**) is checked. It's a cont because it's adding 1 right after entering in the code.\
**I**f less than 8 something that involves **adding** values to **`DAT_030000d8`** is done (basically it's adding the values of the keys pressed in this variable as long as the cont is less than 8).

So, in this challenge, knowing the values of the buttons, you needed to **press a combination with a length smaller than 8 that the resulting addition is 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
