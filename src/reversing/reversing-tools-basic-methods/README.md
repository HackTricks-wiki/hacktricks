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

dotPeek — це decompiler, який **декомпілює та аналізує кілька форматів**, зокрема **libraries** (.dll), **Windows metadata file**s (.winmd) та **executables** (.exe). Після декомпіляції assembly можна зберегти як Visual Studio project (.csproj).

Перевага тут у тому, що якщо втрачений source code потрібно відновити зі старого assembly, це може заощадити час. Крім того, dotPeek забезпечує зручну навігацію по декомпільованому коду, що робить його одним із ідеальних інструментів для **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

З комплексною моделлю add-in і API, який розширює tool відповідно до ваших точних потреб, .NET reflector заощаджує час і спрощує development. Давайте подивимося на безліч reverse engineering services, які надає цей tool:

- Надає розуміння того, як data flows through a library or component
- Надає розуміння implementation and usage of .NET languages and frameworks
- Знаходить undocumented and unexposed functionality, щоб отримати більше від APIs і technologies used.
- Знаходить dependencies і різні assemblies
- Відстежує точне місце errors у вашому code, third-party components, and libraries.
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

Щоб налагоджувати код за допомогою DNSpy, потрібно:

Спочатку змінити **Assembly attributes**, пов’язані з **debugging**:

![](<../../images/image (973).png>)

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
І натисніть **compile**:

![](<../../images/image (314) (1).png>)

Потім збережіть новий файл через _**File >> Save module...**_:

![](<../../images/image (602).png>)

Це необхідно, тому що якщо ви цього не зробите, під час **runtime** до коду буде застосовано кілька **optimisations**, і може статися так, що під час debugging **break-point never hit** або деякі **variables don't exist**.

Потім, якщо вашу .NET application **run** by **IIS**, ви можете **restart** її за допомогою:
```
iisreset /noforce
```
Тоді, щоб почати налагодження, ви повинні закрити всі відкриті файли і у **Debug Tab** вибрати **Attach to Process...**:

![](<../../images/image (318).png>)

Потім виберіть **w3wp.exe**, щоб приєднатися до **IIS server**, і натисніть **attach**:

![](<../../images/image (113).png>)

Тепер, коли ми налагоджуємо процес, час зупинити його і завантажити всі модулі. Спочатку натисніть _Debug >> Break All_, а потім натисніть на _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Натисніть будь-який модуль у **Modules** і виберіть **Open All Modules**:

![](<../../images/image (922).png>)

Клацніть правою кнопкою миші будь-який модуль у **Assembly Explorer** і натисніть **Sort Assemblies**:

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

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![](<../../images/image (704).png>)

Тоді, коли ви почнете налагодження, **виконання зупинятиметься під час завантаження кожної DLL**, а коли rundll32 завантажить вашу DLL, виконання буде зупинено.

Але як отримати доступ до коду DLL, яку було завантажено? За допомогою цього методу я не знаю як.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Зверніть увагу, що коли виконання зупинене з будь-якої причини у win64dbg, ви можете побачити, **в якому коді ви перебуваєте**, подивившись у **верхню частину вікна win64dbg**:

![](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) — це корисна програма, щоб знаходити, де важливі значення зберігаються в пам’яті запущеної гри, і змінювати їх. Більше інформації в:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) — це front-end/reverse engineering tool для GNU Project Debugger (GDB), орієнтований на ігри. Однак його можна використовувати для будь-чого, що пов’язано з reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) — це web front-end до кількох decompilers. Цей веб-сервіс дає змогу порівнювати результат різних decompilers для невеликих executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) буде **виділяти** **shellcode** в області пам’яті, **показуватиме** вам **memory address**, де було виділено shellcode, і **зупинятиме** виконання.\
Потім вам потрібно **attach a debugger** (Ida або x64dbg) до процесу і поставити **breakpoint у вказаній memory address**, а потім **resume** виконання. Таким чином ви будете налагоджувати shellcode.

Сторінка releases на github містить zip-архіви з compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Ви можете знайти трохи модифіковану версію Blobrunner за наступним посиланням. Щоб скомпілювати її, просто **створіть C/C++ project у Visual Studio Code, скопіюйте і вставте код та зберіть його**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) дуже схожий на blobrunner. Він буде **виділяти** **shellcode** в області пам’яті та запускати **eternal loop**. Потім вам потрібно **attach the debugger** до процесу, **play start wait 2-5 secs and press stop**, і ви опинитеся всередині **eternal loop**. Перейдіть до наступної інструкції eternal loop, оскільки це буде call до shellcode, і зрештою ви побачите, як виконується shellcode.

![](<../../images/image (509).png>)

Ви можете завантажити compiled version [jmp2it на сторінці releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) — це GUI для radare. Використовуючи cutter, ви можете емулявати shellcode і динамічно його досліджувати.

Зверніть увагу, що Cutter дозволяє **Open File** і **Open Shellcode**. У моєму випадку, коли я відкрив shellcode як файл, він правильно decompiled його, але коли я відкрив його як shellcode — ні:

![](<../../images/image (562).png>)

Щоб почати емуляцію в потрібному місці, встановіть там bp, і, схоже, cutter автоматично запустить емуляцію звідти:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Ви можете побачити stack, наприклад, у hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Спробуйте [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Він покаже вам такі речі, як **які functions** використовує shellcode і чи **decoding** він сам себе в memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg також має графічний launcher, де ви можете вибрати потрібні опції та виконати shellcode

![](<../../images/image (258).png>)

Опція **Create Dump** збере кінцевий shellcode, якщо в shellcode під час виконання в пам’яті динамічно внесено будь-які зміни (корисно для завантаження decoded shellcode). Опція **start offset** може бути корисною, щоб запустити shellcode з певного зсуву. Опція **Debug Shell** корисна для debugging shellcode за допомогою термінала scDbg (однак для цього я вважаю кращими будь-які з опцій, пояснених раніше, оскільки ви зможете використовувати Ida або x64dbg).

### Disassembling using CyberChef

Завантажте ваш shellcode-файл як input і використайте такий recipe для decompile його: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation приховує прості expressions, такі як `x + y`, за формулами, що змішують arithmetic (`+`, `-`, `*`) і bitwise operators (`&`, `|`, `^`, `~`, shifts). Важлива частина полягає в тому, що ці identities зазвичай коректні лише за **fixed-width modular arithmetic**, тому carries і overflows мають значення:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Якщо спростити такий тип виразу за допомогою generic algebra tooling, можна легко отримати неправильний результат, бо bit-width semantics були проігноровані.

### Practical workflow

1. **Keep the original bit-width** з lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Classify the expression** before trying to simplify it:
- **Linear**: weighted sums of bitwise atoms
- **Semilinear**: linear plus constant masks such as `x & 0xFF`
- **Polynomial**: products appear
- **Mixed**: products and bitwise logic are interleaved, often with repeated subexpressions
3. **Verify every candidate rewrite** with random testing or an SMT proof. If the equivalence cannot be proven, keep the original expression instead of guessing.

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

- **Linear MBA**: CoBRA оцінює вираз на Boolean inputs, виводить signature і запускає кілька методів відновлення, таких як pattern matching, ANF conversion і coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms перебудовуються за допомогою bit-partitioned reconstruction, щоб masked regions залишалися correct.
- **Polynomial/Mixed MBA**: products декомпозуються на cores, а повторювані subexpressions можна підняти в temporaries перед simplifing outer relation.

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

![](<../../images/image (1080).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

## **Delphi**

For Delphi compiled binaries you can use [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

If you have to reverse a Delphi binary I would suggest you to use the IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This plugin will execute the binary and resolve function names dynamically at the start of the debugging. After starting the debugging press again the Start button (the green one or f9) and a breakpoint will hit in the beginning of the real code.

It is also very interesting because if you press a button in the graphic application the debugger will stop in the function executed by that bottom.

## Golang

If you have to reverse a Golang binary I would suggest you to use the IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This will resolve the names of the functions.

## Compiled Python

In this page you can find how to get the python code from an ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

If you get the **binary** of a GBA game you can use different tools to **emulate** and **debug** it:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contains a debugger with interface
- [**mgba** ](https://mgba.io)- Contains a CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** you can see how to press the Game Boy Advance **buttons**

![](<../../images/image (581).png>)

When pressed, each **key has a value** to identify it:
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
Отже, у цьому типі програми цікавою частиною буде **те, як програма обробляє введення користувача**. За адресою **0x4000130** ви знайдете часто трапляючуся функцію: **KEYINPUT**.

![](<../../images/image (447).png>)

На попередньому зображенні ви можете побачити, що функцію викликають з **FUN_080015a8** (адреси: _0x080015fa_ та _0x080017ac_).

У цій функції, після деяких init operations (без жодного значення):
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
Останній `if` перевіряє, чи **`uVar4`** є в **last Keys** і не є поточним ключем; це також називається відпусканням кнопки (поточний ключ зберігається в **`uVar1`**).
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
У попередньому code ви можете побачити, що ми порівнюємо **uVar1** (місце, де знаходиться **value of the pressed button**) з деякими values:

- Спочатку його порівнюють із **value 4** (**SELECT** button): У challenge ця button очищає screen
- Потім його порівнюють із **value 8** (**START** button): У challenge це перевіряє, чи code є valid, щоб отримати flag.
- У цьому case var **`DAT_030000d8`** порівнюється з 0xf3, і якщо value та сама, виконується some code.
- В any other cases перевіряється some cont (`DAT_030000d4`). Це cont, тому що після входу в code до нього одразу додається 1.\
**Я**кщо менше ніж 8, виконується some thing, що involves **adding** values до **`DAT_030000d8`** (basically it додає values натиснутих keys у цю variable, поки cont менший за 8).

So, у цьому challenge, знаючи values buttons, потрібно було **press a combination with a length smaller than 8 that the resulting addition is 0xf3.**

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
