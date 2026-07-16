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

dotPeek is a decompiler that **decompiles and examines multiple formats**, including **libraries** (.dll), **Windows metadata file**s (.winmd), and **executables** (.exe). Once decompiled, an assembly can be saved as a Visual Studio project (.csproj).

The merit here is that if a lost source code requires restoration from a legacy assembly, this action can save time. Further, dotPeek provides handy navigation throughout the decompiled code, making it one of the perfect tools for **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

With a comprehensive add-in model and an API that extends the tool to suit your exact needs, .NET reflector saves time and simplifies development. Let's take a look at the plethora of reverse engineering services this tool provides:

- Provides an insight into how the data flows through a library or component
- Provides insight into the implementation and usage of .NET languages and frameworks
- Finds undocumented and unexposed functionality to get more out of the APIs and technologies used.
- Finds dependencies and different assemblies
- Tracks down the exact location of errors in your code, third-party components, and libraries.
- Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): You can have it in any OS (you can install it directly from VSCode, no need to download the git. Click on **Extensions** and **search ILSpy**).\
If you need to **decompile**, **modify** and **recompile** again you can use [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) or an actively maintained fork of it, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** to change something inside a function).

### DNSpy Logging

In order to make **DNSpy log some information in a file**, you could use this snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Щоб налагоджувати код за допомогою DNSpy, вам потрібно:

Спочатку змінити **Assembly attributes**, пов’язані з **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
До:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
І клацніть на **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Це необхідно, тому що якщо ви цього не зробите, під час **runtime** до коду буде застосовано кілька **optimisations**, і може статися так, що під час debugging **break-point** ніколи не буде досягнуто або деякі **variables** не існують.

Потім, якщо вашу .NET application **run** через **IIS**, ви можете **restart** її за допомогою:
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

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
scDbg також має графічний launcher, де ви можете вибрати потрібні опції та виконати shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Опція **Create Dump** збере final shellcode, якщо до shellcode динамічно в пам’яті буде внесено будь-які зміни (корисно для завантаження decoded shellcode). Опція **start offset** може бути корисною, щоб запускати shellcode з певного offset. Опція **Debug Shell** корисна для debug shellcode за допомогою термінала scDbg (однак, на мій погляд, для цього краще підходять будь-які з описаних вище опцій, оскільки ви зможете використовувати Ida або x64dbg).

### Disassembling using CyberChef

Завантажте ваш shellcode file як input і використайте такий recipe, щоб decompile його: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation приховує прості вирази, такі як `x + y`, за формулами, що змішують arithmetic (`+`, `-`, `*`) і bitwise оператори (`&`, `|`, `^`, `~`, shifts). Важлива частина полягає в тому, що ці identities зазвичай правильні лише за **fixed-width modular arithmetic**, тому carries і overflows мають значення:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Якщо спростити такий тип виразу за допомогою generic algebra tooling, можна легко отримати хибний результат, бо semantics bit-width було проігноровано.

### Практичний workflow

1. **Зберігайте original bit-width** з lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Класифікуйте expression** перед спробою його спростити:
- **Linear**: weighted sums of bitwise atoms
- **Semilinear**: linear plus constant masks such as `x & 0xFF`
- **Polynomial**: products appear
- **Mixed**: products and bitwise logic are interleaved, often with repeated subexpressions
3. **Перевіряйте кожен candidate rewrite** за допомогою random testing або SMT proof. If the equivalence cannot be proven, keep the original expression instead of guessing.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is a practical MBA simplifier for malware analysis and protected-binary reversing. It classifies the expression and routes it through specialized pipelines instead of applying one generic rewrite pass to everything.

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
Корисні випадки:

- **Linear MBA**: CoBRA оцінює вираз на Boolean input, виводить signature і запускає кілька methods відновлення, таких як pattern matching, ANF conversion і coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms перебудовуються за допомогою bit-partitioned reconstruction, щоб masked regions залишалися correct.
- **Polynomial/Mixed MBA**: products розкладаються на cores, а repeated subexpressions можуть бути lifted into temporaries before simplifying the outer relation.

Приклад mixed identity, яку зазвичай варто спробувати recover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Це може звестися до:
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
Це означає, що `strings` або стандартний аналіз Ghidra можуть об’єднувати суміжні strings або повністю пропускати cross-references.

Швидкий workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Отримайте віртуальну адресу та розмір **`.rodata`**.
2. Перебирайте **`.data.rel.ro`** по одному слову за раз.
3. Розглядайте будь-яке значення всередині діапазону адрес `.rodata` як кандидат на вказівник на рядок.
4. Розглядайте наступне слово як кандидат на довжину.
5. Застосовуйте фільтри здорового глузду (наприклад, залишайте довжини між **4** і **100** байт).
6. Читайте рівно `length` байтів з `.rodata` замість сканування до `0x00`.

Мінімальна логіка екстрактора:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Це особливо корисно під час reversing firmware, тому що відновлені Rust strings часто розкривають **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, and auth-related logic**.

Якщо Ghidra пропускає ці strings, запустіть custom script/plugin, який застосовує ту саму heuristic і створює string data на відповідних `.rodata` offsets. Опубліковані інструменти `rust-strings` і `RustStrings.py` від Pen Test Partners — хороші приклади для адаптації ідеї до інших **word sizes, endianness, and section layouts**.

## **Delphi**

Для Delphi compiled binaries ви можете використовувати [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Якщо вам потрібно reverse Delphi binary, я б порадив використовувати IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Просто натисніть **ATL+f7** (import python plugin in IDA) і виберіть python plugin.

Цей plugin виконає binary і динамічно розв'яже function names на початку debugging. Після старту debugging знову натисніть кнопку Start (зелену або f9), і breakpoint спрацює на початку real code.

Це також дуже цікаво, тому що якщо ви натиснете кнопку в graphic application, debugger зупиниться у function, яка виконується цією кнопкою.

## Golang

Якщо вам потрібно reverse Golang binary, я б порадив використовувати IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Просто натисніть **ATL+f7** (import python plugin in IDA) і виберіть python plugin.

Це розв'яже names функцій.

## Compiled Python

На цій сторінці ви можете знайти, як отримати python code з ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Якщо у вас є **binary** гри для GBA, ви можете використовувати різні інструменти, щоб **emulate** і **debug** її:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Містить debugger з interface
- [**mgba** ](https://mgba.io)- Містить CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

У [**no$gba**](https://problemkaputt.de/gba.htm), у _**Options --> Emulation Setup --> Controls**_** ** ви можете побачити, як натискати **buttons** Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Коли кнопку натиснуто, кожен **key має value**, щоб його ідентифікувати:
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
Отже, у такому типі програми цікава частина — це **те, як програма обробляє введення користувача**. За адресою **0x4000130** ви знайдете поширену функцію: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

На попередньому зображенні ви можете побачити, що функція викликається з **FUN_080015a8** (адреси: _0x080015fa_ та _0x080017ac_).

У цій функції, після деяких операцій ініціалізації (без жодного значення):
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
Знайдено цей код:
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
Останній if перевіряє, що **`uVar4`** знаходиться в **last Keys** і не є поточним key, також це називається відпусканням кнопки (current key зберігається в **`uVar1`**).
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
У попередньому code ви можете побачити, що ми порівнюємо **uVar1** (місце, де знаходиться **value of the pressed button**) з деякими значеннями:

- Спочатку його порівнюють зі **значенням 4** (**SELECT** button): У challenge ця button очищає screen
- Потім його порівнюють зі **значенням 8** (**START** button): У challenge це перевіряє, чи code є valid, щоб отримати flag.
- У цьому випадку var **`DAT_030000d8`** порівнюється з 0xf3, і якщо value те саме, виконується some code.
- В усіх інших cases перевіряється some cont (`DAT_030000d4`). Це cont, тому що воно додає 1 одразу після входу в code.\
**Я**кщо менше ніж 8, виконується щось, що involves **додавання** values до **`DAT_030000d8`** (basically, до this variable додаються values of the keys pressed, поки cont менший за 8).

Отже, у цьому challenge, знаючи values of the buttons, вам потрібно було **натиснути combination з length менше 8, щоб resulting addition була 0xf3.**

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
