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

dotPeek to decompiler, który **decompiles and examines multiple formats**, w tym **libraries** (.dll), **Windows metadata file**s (.winmd) oraz **executables** (.exe). Po dekompilacji assembly można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony source code wymaga odzyskania z legacy assembly, ta operacja może zaoszczędzić czas. Dodatkowo dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, co czyni go jednym z idealnych narzędzi do **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi add-in i API, które rozszerza narzędzie tak, aby odpowiadało dokładnie Twoim potrzebom, .NET reflector oszczędza czas i upraszcza development. Przyjrzyjmy się wielu usługom reverse engineering, które oferuje to narzędzie:

- Zapewnia wgląd w to, jak data flows through a library or component
- Zapewnia wgląd w implementację i usage języków oraz frameworków .NET
- Znajduje undocumented and unexposed functionality, aby wycisnąć więcej z używanych APIs i technologies.
- Znajduje dependencies i różne assemblies
- Namierza dokładną lokalizację błędów w Twoim kodzie, komponentach third-party i bibliotekach.
- Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz mieć go na dowolnym OS (możesz zainstalować go bezpośrednio z VSCode, bez potrzeby pobierania z gita. Kliknij **Extensions** i wyszukaj **ILSpy**).\
Jeśli musisz **decompile**, **modify** i **recompile** ponownie, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) albo aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method**), aby zmienić coś wewnątrz function).

### DNSpy Logging

Aby sprawić, by **DNSpy log some information in a file**, możesz użyć tego snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugowanie w DNSpy

Aby debugować kod przy użyciu DNSpy musisz:

Najpierw zmień **atrybuty Assembly** związane z **debugowaniem**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

Z:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Do:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
I kliknij **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik przez _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, w czasie **runtime** zostanie zastosowanych kilka **optimisations** do kodu i możliwe, że podczas debugowania **break-point** nigdy nie zostanie trafiony albo niektóre **variables** nie będą istniały.

Następnie, jeśli twoja aplikacja .NET jest **run** przez **IIS**, możesz ją **restart** za pomocą:
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
scDbg ma również graficzny launcher, w którym możesz wybrać żądane opcje i wykonać shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Opcja **Create Dump** zrzuci końcowy shellcode, jeśli jakakolwiek zmiana zostanie dynamicznie wprowadzona do shellcode w pamięci (przydatne do pobrania zdekodowanego shellcode). **start offset** może być użyteczny do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** jest przydatna do debugowania shellcode za pomocą terminala scDbg (jednak uważam, że każda z wcześniej wyjaśnionych opcji jest do tego lepsza, ponieważ będziesz mógł użyć Ida lub x64dbg).

### Disassembling using CyberChef

Prześlij plik shellcode jako input i użyj następującego recipe, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Obfuscation **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia takie jak `x + y` za pomocą formuł, które mieszają operatory arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko przy **modular arithmetic o stałej szerokości**, więc przeniesienia i przepełnienia mają znaczenie:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo dostać błędny wynik, ponieważ semantyka szerokości bitowej została zignorowana.

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyniku dekompilatora (`8/16/32/64` bity).
2. **Sklasyfikuj wyrażenie** przed próbą uproszczenia:
- **Linear**: ważone sumy atomów bitowych
- **Semilinear**: linear plus stałe maski, takie jak `x & 0xFF`
- **Polynomial**: pojawiają się iloczyny
- **Mixed**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą kandydującą regułę przepisywania** za pomocą losowych testów lub dowodu SMT. Jeśli równoważności nie da się udowodnić, zachowaj oryginalne wyrażenie zamiast zgadywać.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is a praktyczny upraszczacz MBA do analizy malware i reverse engineering protected-binary. Klasyfikuje wyrażenie i kieruje je przez specjalistyczne pipeline'y zamiast stosować jeden ogólny pass przepisywania do wszystkiego.

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
Przydatne przypadki:

- **Linear MBA**: CoBRA ocenia wyrażenie na wejściach Boolean, wyprowadza sygnaturę i równolegle uruchamia kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja do ANF oraz interpolacja współczynników.
- **Semilinear MBA**: atomy maskowane stałą są odbudowywane za pomocą rekonstrukcji bit-partitioned, aby maskowane regiony pozostały poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na cores, a powtarzające się podwyrażenia mogą być przeniesione do temporary przed uproszczeniem zewnętrznej relacji.

Przykład mixed identity, który często warto spróbować odzyskać:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
To może się skondensować do:
```c
x * y
```
### Notatki o reversing

- Preferuj uruchamianie CoBRA na **lifted IR expressions** lub output dekompilatora, po wyizolowaniu dokładnego obliczenia.
- Używaj `--bitwidth` jawnie, gdy expression pochodziło z masked arithmetic albo narrow registers.
- Jeśli potrzebujesz mocniejszego kroku proof, sprawdź lokalne notatki Z3 tutaj:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest też dostępny jako **LLVM pass plugin** (`libCobraPass.so`), co jest przydatne, gdy chcesz znormalizować MBA-heavy LLVM IR przed późniejszymi analysis passes.
- Unsupported carry-sensitive mixed-domain residuals powinny być traktowane jako sygnał, żeby zachować oryginalny expression i analizować carry path ręcznie.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator **modyfikuje wszystkie instrukcje na `mov`**(tak, serio, fajne). Używa też interruptions do zmiany execution flow. Więcej informacji o tym, jak to działa:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Jeśli masz szczęście, [demovfuscator](https://github.com/kirschju/demovfuscator) zdeobfuskatuje binary. Ma kilka zależności
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
Oznacza to, że `strings` lub domyślna analiza Ghidra może łączyć sąsiadujące łańcuchy albo całkowicie pomijać cross-references.

Szybki workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pobierz adres wirtualny i rozmiar **`.rodata`**.
2. Enumeruj **`.data.rel.ro`** po jednym słowie naraz.
3. Traktuj każdą wartość w zakresie adresów `.rodata` jako kandydat na wskaźnik do stringa.
4. Traktuj następne słowo jako kandydat na długość.
5. Zastosuj filtry rozsądku (na przykład, zachowuj długości między **4** a **100** bajtów).
6. Odczytaj dokładnie `length` bajtów z `.rodata` zamiast skanować aż do `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Jest to szczególnie przydatne przy reversing firmware, ponieważ odzyskane ciągi Rust często ujawniają **HTTP routes, nazwy RPC, komunikaty logów, assertions, nazwy plików, klucze config, handlery komend oraz logikę związaną z auth**.

Jeśli Ghidra nie wykryje tych ciągów, uruchom własny script/plugin, który zastosuje tę samą heurystykę i utworzy string data w odwołanych offsetach `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners są dobrym punktem odniesienia do dostosowania tego pomysłu do innych **word sizes, endianness i section layouts**.

## **Delphi**

Dla binarek skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reverse Delphi binary, sugeruję użyć pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Wystarczy nacisnąć **ATL+f7** (import python plugin w IDA) i wybrać python plugin.

Ten plugin uruchomi binary i dynamicznie rozwiąże nazwy funkcji na początku debuggingu. Po rozpoczęciu debuggingu naciśnij ponownie przycisk Start (zielony lub f9), a breakpoint zatrzyma się na początku rzeczywistego code.

Jest to też bardzo interesujące, ponieważ jeśli naciśniesz przycisk w aplikacji graficznej, debugger zatrzyma się w funkcji wykonywanej przez ten przycisk.

## Golang

Jeśli musisz przeprowadzić reverse Golang binary, sugeruję użyć pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Wystarczy nacisnąć **ATL+f7** (import python plugin w IDA) i wybrać python plugin.

To rozwiąże nazwy funkcji.

## Compiled Python

Na tej stronie znajdziesz, jak odzyskać python code z binarnego ELF/EXE skompilowanego przez python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Jeśli masz **binary** gry GBA, możesz użyć różnych narzędzi do **emulacji** i **debuggingu**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz zobaczyć, jak naciskać przyciski Game Boy Advance **buttons**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Po naciśnięciu każdy **key ma wartość** do identyfikacji:
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
Więc w tego typu programie interesująca część będzie polegać na tym, **jak program traktuje dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz powszechnie występującą funkcję: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Na poprzednim obrazie widać, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po kilku operacjach inicjalizacyjnych (bez większego znaczenia):
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
Znalazł ten kod:
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
Ostatni `if` sprawdza, czy **`uVar4`** znajduje się w **ostatnich Keys** i nie jest obecnym key, czyli puszczenie przycisku (obecny key jest przechowywany w **`uVar1`**).
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
W poprzednim kodzie możesz zobaczyć, że porównujemy **uVar1** (miejsce, w którym znajduje się **wartość wciśniętego przycisku**) z pewnymi wartościami:

- Najpierw jest porównywane z **wartością 4** (**SELECT** button): W challenge ten przycisk czyści ekran
- Następnie jest porównywane z **wartością 8** (**START** button): W challenge to sprawdza, czy kod jest poprawny, aby dostać flagę.
- W tym przypadku var **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartość jest taka sama, wykonywany jest pewien kod.
- W każdym innym przypadku sprawdzany jest pewien cont (**`DAT_030000d4`**). To jest cont, ponieważ dodaje się 1 zaraz po wejściu w kod.\
**I**f jest mniejsze niż 8, wykonywane jest coś, co polega na **dodawaniu** wartości do **`DAT_030000d8`** (zasadniczo dodaje się wartości naciśniętych klawiszy do tej zmiennej, dopóki cont jest mniejszy niż 8).

Tak więc w tym challenge, znając wartości przycisków, trzeba było **wcisnąć kombinację o długości mniejszej niż 8, której wynikowa suma daje 0xf3.**

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
