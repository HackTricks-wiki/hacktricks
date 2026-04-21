# Reversing Tools & Basic Methods

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

dotPeek एक decompiler है जो **कई formats को decompile** और examine करता है, जिसमें **libraries** (.dll), **Windows metadata file**s (.winmd), और **executables** (.exe) शामिल हैं। एक बार decompile हो जाने पर, assembly को Visual Studio project (.csproj) के रूप में save किया जा सकता है।

यहाँ फायदा यह है कि अगर lost source code को legacy assembly से restore करना हो, तो यह समय बचा सकता है। इसके अलावा, dotPeek decompiled code में आसान navigation देता है, जिससे यह **Xamarin algorithm analysis** के लिए एक बेहतरीन tool बन जाता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक comprehensive add-in model और API के साथ जो tool को आपकी exact जरूरतों के अनुसार extend करती है, .NET reflector समय बचाता है और development को सरल बनाता है। आइए इस tool द्वारा दी जाने वाली reverse engineering services की बहुतायत पर नज़र डालें:

- यह दिखाता है कि data library या component के through कैसे flow करता है
- यह .NET languages और frameworks के implementation और usage की insight देता है
- undocumented और unexposed functionality ढूँढता है ताकि इस्तेमाल की गई APIs और technologies से और अधिक हासिल किया जा सके.
- dependencies और अलग-अलग assemblies ढूँढता है
- आपके code, third-party components, और libraries में errors की exact location track करता है.
- जिन .NET code के साथ आप काम करते हैं, उनके source में debug करता है.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS में रख सकते हैं (आप इसे सीधे VSCode से install कर सकते हैं, git download करने की जरूरत नहीं है। **Extensions** पर क्लिक करें और **ILSpy** search करें).\
अगर आपको **decompile**, **modify** और फिर से **recompile** करना हो, तो आप [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या उसका actively maintained fork, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) इस्तेमाल कर सकते हैं। (किसी function के अंदर कुछ बदलने के लिए **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy को किसी file में कुछ information log** कराने के लिए, आप यह snippet उपयोग कर सकते हैं:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

कोड को DNSpy का उपयोग करके debug करने के लिए आपको:

पहले, **debugging** से संबंधित **Assembly attributes** बदलने होंगे:

![](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
और **compile** पर क्लिक करें:

![](<../../images/image (314) (1).png>)

फिर नए फ़ाइल को _**File >> Save module...**_ के माध्यम से सेव करें:

![](<../../images/image (602).png>)

यह ज़रूरी है क्योंकि अगर आप ऐसा नहीं करते हैं, तो **runtime** पर कोड पर कई **optimisations** लागू हो जाएँगी और संभव है कि debugging के दौरान कोई **break-point कभी hit न हो** या कुछ **variables मौजूद ही न हों**।

फिर, अगर आपका .NET application **IIS** द्वारा **run** किया जा रहा है, तो आप इसे इस तरह **restart** कर सकते हैं:
```
iisreset /noforce
```
Then, debugging शुरू करने के लिए आपको सभी खुले हुए files बंद करने चाहिए और **Debug Tab** के अंदर **Attach to Process...** चुनना चाहिए:

![](<../../images/image (318).png>)

फिर **IIS server** से attach करने के लिए **w3wp.exe** चुनें और **attach** पर click करें:

![](<../../images/image (113).png>)

अब जब हम process को debug कर रहे हैं, तो उसे stop करने और सभी modules load करने का समय है। पहले _Debug >> Break All_ पर click करें और फिर _**Debug >> Windows >> Modules**_ पर click करें:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

**Modules** में किसी भी module पर click करें और **Open All Modules** चुनें:

![](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी module पर right click करें और **Sort Assemblies** पर click करें:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Execution के **parameters** को configure करें, DLL का **path** और जिस function को आप call करना चाहते हैं उसे डालकर:

![](<../../images/image (704).png>)

फिर, जब आप debugging start करेंगे तो **execution हर बार किसी DLL के load होने पर stop हो जाएगी**, फिर जब rundll32 आपकी DLL load करेगा तो execution stop हो जाएगी।

लेकिन, आप loaded DLL के code तक कैसे पहुँच सकते हैं? इस method से, मुझे नहीं पता कैसे।

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line बदलें** ( _File --> Change Command Line_ ) और dll का path तथा जिस function को आप call करना चाहते हैं उसे set करें, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ बदलें और "**DLL Entry**" चुनें।
- फिर **execution start** करें, debugger हर dll main पर stop करेगा, किसी point पर आप **अपनी dll के dll Entry** में stop करेंगे। वहाँ से, बस उन points को search करें जहाँ आप breakpoint लगाना चाहते हैं।

ध्यान दें कि जब execution किसी भी reason से win64dbg में stop हो जाती है, तो आप **win64dbg window के top** को देखकर **जान सकते हैं कि आप किस code में हैं**:

![](<../../images/image (842).png>)

फिर, इसे देखकर पता करें कि execution आपकी debug करने वाली dll में stop हुई है।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी program है जिससे पता लगाया जा सकता है कि चल रहे game के memory के अंदर important values कहाँ save हैं और उन्हें बदला जा सकता है। अधिक जानकारी के लिए:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) के लिए एक front-end/reverse engineering tool है, जो games पर focused है। हालांकि, इसे reverse-engineering से जुड़ी किसी भी चीज़ के लिए इस्तेमाल किया जा सकता है

[**Decompiler Explorer**](https://dogbolt.org/) कई decompilers के लिए एक web front-end है। यह web service आपको छोटे executables पर अलग-अलग decompilers के output की तुलना करने देती है।

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **shellcode** को memory के एक space के अंदर **allocate** करेगा, आपको वह **memory address** **indicate** करेगा जहाँ shellcode allocate हुआ था और execution को **stop** करेगा।\
फिर, आपको process से **attach a debugger** (Ida or x64dbg) करना होगा और indicated memory address पर **breakpoint** लगाना होगा और execution **resume** करनी होगी। इस तरह आप shellcode को debug करेंगे।

Releases github page में compiled releases वाली zips होती हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप निम्न link में Blobrunner का थोड़ा modified version पा सकते हैं। इसे compile करने के लिए बस **Visual Studio Code में एक C/C++ project create करें, code copy-paste करें और build करें**।


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) blobrunner के बहुत similar है। यह **shellcode** को memory के एक space के अंदर **allocate** करेगा, और एक **eternal loop** शुरू करेगा। फिर आपको process से **debugger attach** करना होगा, **play start wait 2-5 secs and press stop** करना होगा और आप **eternal loop** के अंदर होंगे। eternal loop की next instruction पर jump करें, क्योंकि वह shellcode की call होगी, और अंत में आप shellcode execute करते हुए पाएँगे।

![](<../../images/image (509).png>)

आप [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/) पर compiled version डाउनलोड कर सकते हैं।

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode को emulate कर सकते हैं और उसे dynamically inspect कर सकते हैं।

ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" करने देता है। मेरे मामले में जब मैंने shellcode को file के रूप में खोला तो उसने उसे सही से decompile किया, लेकिन जब मैंने उसे shellcode के रूप में खोला तो उसने नहीं:

![](<../../images/image (562).png>)

जहाँ आप emulation शुरू करना चाहते हैं, वहाँ bp set करें और apparently cutter वहाँ से automatically emulation start करेगा:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

आप उदाहरण के लिए stack को hex dump के अंदर देख सकते हैं:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) try करना चाहिए।\
यह आपको ऐसी चीज़ें बताएगा जैसे **shellcode कौन-सी functions use कर रहा है** और क्या shellcode memory में खुद को **decoding** कर रहा है।
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg में एक graphical launcher भी है जहाँ आप अपनी ज़रूरत के options चुनकर shellcode execute कर सकते हैं

![](<../../images/image (258).png>)

**Create Dump** option अंतिम shellcode को dump कर देगा अगर shellcode में memory के अंदर dynamically कोई change किया गया हो (decoded shellcode download करने के लिए useful)। **start offset** shellcode को किसी specific offset से start करने के लिए useful हो सकता है। **Debug Shell** option scDbg terminal का उपयोग करके shellcode debug करने के लिए useful है (हालाँकि इस काम के लिए मुझे ऊपर बताए गए कोई भी option बेहतर लगते हैं, क्योंकि आप Ida या x64dbg use कर पाएँगे)।

### CyberChef का उपयोग करके Disassembling

अपनी shellcode file को input के रूप में upload करें और इसे decompile करने के लिए following recipe का उपयोग करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation simple expressions जैसे `x + y` को ऐसे formulas के पीछे छुपाती है जो arithmetic (`+`, `-`, `*`) और bitwise operators (`&`, `|`, `^`, `~`, shifts) को mix करते हैं। महत्वपूर्ण बात यह है कि ये identities आमतौर पर केवल **fixed-width modular arithmetic** में ही सही होती हैं, इसलिए carries और overflows matter करते हैं:
```c
(x ^ y) + 2 * (x & y) == x + y
```
यदि आप इस तरह के expression को generic algebra tooling से simplify करते हैं, तो आपको आसानी से गलत result मिल सकता है क्योंकि bit-width semantics को ignore किया गया था।

### Practical workflow

1. **Original bit-width बनाए रखें** lifted code/IR/decompiler output (`8/16/32/64` bits) से।
2. **Expression को classify करें** उसे simplify करने से पहले:
- **Linear**: bitwise atoms के weighted sums
- **Semilinear**: linear plus constant masks जैसे `x & 0xFF`
- **Polynomial**: products दिखाई देते हैं
- **Mixed**: products और bitwise logic interleaved होते हैं, अक्सर repeated subexpressions के साथ
3. **हर candidate rewrite को verify करें** random testing या SMT proof के साथ। अगर equivalence prove नहीं हो सकती, तो guess करने के बजाय original expression को रखें।

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis और protected-binary reversing के लिए एक practical MBA simplifier है। यह expression को classify करता है और उसे specialized pipelines से route करता है, बजाय इसके कि एक generic rewrite pass सब पर लागू करे।

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

- **Linear MBA**: CoBRA Boolean इनपुट्स पर expression का मूल्यांकन करता है, एक signature निकालता है, और pattern matching, ANF conversion, और coefficient interpolation जैसी कई recovery methods को parallel में चलाता है।
- **Semilinear MBA**: constant-masked atoms को bit-partitioned reconstruction से फिर से बनाया जाता है ताकि masked regions सही रहें।
- **Polynomial/Mixed MBA**: products को cores में decomposed किया जाता है और repeated subexpressions को outer relation को simplify करने से पहले temporaries में lifted किया जा सकता है।

एक mixed identity का उदाहरण जिसे आम तौर पर recover करने की कोशिश करना worth होता है:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
यह इस पर संक्षेपित हो सकता है:
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

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
और [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

अगर आप **CTF** खेल रहे हैं, तो flag ढूँढने के लिए यह workaround बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point** खोजने के लिए functions को `::main` से search करें, जैसे:

![](<../../images/image (1080).png>)

इस case में binary का नाम authenticator था, इसलिए यह साफ़ है कि यही interesting main function है।\
जिन **functions** को call किया जा रहा है, उनके **name** जानकर उन्हें **Internet** पर search करें ताकि उनके **inputs** और **outputs** के बारे में जान सकें।

## **Delphi**

Delphi compiled binaries के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) इस्तेमाल कर सकते हैं

अगर आपको किसी Delphi binary को reverse करना हो, तो मैं IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) इस्तेमाल करने की सलाह दूँगा

बस **ATL+f7** दबाएँ (IDA में python plugin import करने के लिए) और python plugin select करें।

यह plugin binary को execute करेगा और debugging की शुरुआत में dynamically function names resolve करेगा। Debugging शुरू करने के बाद फिर से Start button (हरा वाला या f9) दबाएँ और breakpoint real code की शुरुआत में hit होगा।

यह भी बहुत दिलचस्प है क्योंकि अगर आप graphic application में कोई button press करते हैं, तो debugger उस bottom द्वारा executed function पर रुक जाएगा।

## Golang

अगर आपको Golang binary reverse करनी हो, तो मैं IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) इस्तेमाल करने की सलाह दूँगा

बस **ATL+f7** दबाएँ (IDA में python plugin import करने के लिए) और python plugin select करें।

यह functions के names resolve करेगा।

## Compiled Python

इस page में आप यह जान सकते हैं कि किसी ELF/EXE python compiled binary से python code कैसे निकाला जाए:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

अगर आपके पास किसी GBA game का **binary** हो, तो आप उसे **emulate** और **debug** करने के लिए अलग-अलग tools इस्तेमाल कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - debugger with interface शामिल है
- [**mgba** ](https://mgba.io) - CLI debugger शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_** ** के अंदर आप देख सकते हैं कि Game Boy Advance के **buttons** कैसे press करने हैं

![](<../../images/image (581).png>)

जब press किया जाता है, तो हर **key** की पहचान के लिए एक value होती है:
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
तो, इस तरह के program में, interesting part होगा **program user input को कैसे treat करता है**। address **0x4000130** में आपको commonly found function: **KEYINPUT** मिलेगा।

![](<../../images/image (447).png>)

पिछली image में आप देख सकते हैं कि function को **FUN_080015a8** से call किया गया है (addresses: _0x080015fa_ और _0x080017ac_)।

उस function में, कुछ init operations के बाद (without any importance):
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
इस code को पाया गया है:
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
अंतिम `if` जाँच रहा है कि **`uVar4`** **last Keys** में है और वर्तमान key नहीं है, इसे button छोड़ना भी कहते हैं (current key **`uVar1`** में stored है)।
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
पिछले code में आप देख सकते हैं कि हम **uVar1** (वह स्थान जहां **pressed button का value** होता है) की कुछ values से तुलना कर रहे हैं:

- सबसे पहले, इसकी तुलना **value 4** (**SELECT** button) से की जाती है: challenge में यह button screen को clear करता है
- फिर, इसकी तुलना **value 8** (**START** button) से की जाती है: challenge में यह code valid है या नहीं, ताकि flag मिले, यह जांचता है।
- इस case में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और अगर value same होती है तो कुछ code execute होता है।
- किसी भी other case में, कुछ cont (**`DAT_030000d4`**) check किया जाता है। यह cont इसलिए है क्योंकि code में enter करने के right after 1 add होता है।\
**I**f 8 से कम हो, तो कुछ ऐसा किया जाता है जिसमें **`DAT_030000d8`** में values **add** की जाती हैं (basically, यह इस variable में pressed keys की values add करता है, जब तक cont 8 से कम है)।

So, इस challenge में, buttons की values जानते हुए, आपको **8 से छोटी length वाली एक combination press करनी थी, ताकि resulting addition 0xf3 हो।**

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

{{#include ../../banners/hacktricks-training.md}}
