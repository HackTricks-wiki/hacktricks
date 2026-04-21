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

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji assembly można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego rozwiązania jest to, że jeśli utracony kod źródłowy wymaga odtworzenia z legacy assembly, ta operacja może zaoszczędzić czas. Dodatkowo dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, co czyni go jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które rozszerza narzędzie tak, aby odpowiadało Twoim dokładnym potrzebom, .NET reflector oszczędza czas i upraszcza development. Spójrzmy na bogactwo usług reverse engineering, które to narzędzie oferuje:

- Zapewnia wgląd w to, jak dane przepływają przez bibliotekę lub komponent
- Zapewnia wgląd w implementację i użycie języków oraz frameworków .NET
- Znajduje nieudokumentowaną i nieujawnioną funkcjonalność, aby wyciągnąć więcej z używanych API i technologii.
- Znajduje zależności i różne assembly
- Namierza dokładną lokalizację błędów w Twoim kodzie, komponentach firm trzecich i bibliotekach.
- Debuguje źródło całego kodu .NET, z którym pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz mieć go na każdym OS (możesz zainstalować go bezpośrednio z VSCode, nie trzeba pobierać git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli musisz **dekompilować**, **modyfikować** i **ponownie kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) albo aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** żeby zmienić coś wewnątrz funkcji).

### DNSpy Logging

Aby sprawić, by **DNSpy zapisywał pewne informacje do pliku**, możesz użyć tego snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugowanie DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Najpierw zmień **Assembly attributes** związane z **debugging**:

![](<../../images/image (973).png>)

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

![](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik przez _**File >> Save module...**_:

![](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, w czasie **runtime** do kodu zostanie zastosowanych kilka **optimisations** i może się zdarzyć, że podczas debugowania **break-point is never hit** albo niektóre **variables don't exist**.

Następnie, jeśli twoja aplikacja .NET jest **run** przez **IIS**, możesz ją **restart** za pomocą:
```
iisreset /noforce
```
Then, aby rozpocząć debugowanie, powinieneś zamknąć wszystkie otwarte pliki i w zakładce **Debug Tab** wybrać **Attach to Process...**:

![](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do **IIS server** i kliknij **attach**:

![](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, czas go zatrzymać i załadować wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie kliknij _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i kliknij **Sort Assemblies**:

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

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![](<../../images/image (842).png>)

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

![](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![](<../../images/image (186).png>)

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
scDbg ma również graficzny launcher, w którym możesz wybrać opcje, których chcesz użyć, i wykonać shellcode

![](<../../images/image (258).png>)

Opcja **Create Dump** zrzuci finalny shellcode, jeśli jakakolwiek zmiana zostanie dynamicznie wprowadzona do shellcode w pamięci (przydatne do pobrania zdekodowanego shellcode). **start offset** może być przydatny do uruchomienia shellcode od konkretnego offsetu. Opcja **Debug Shell** jest przydatna do debugowania shellcode z użyciem terminala scDbg (jednak uważam, że do tego lepsze są wcześniejsze opcje, ponieważ będziesz mógł użyć Ida lub x64dbg).

### Disassembling using CyberChef

Prześlij swój plik shellcode jako input i użyj poniższego recipe, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł, które mieszają operatory arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważna część polega na tym, że te tożsamości są zwykle poprawne tylko w przypadku **arytmetyki modularnej o stałej szerokości**, więc znaczenie mają przeniesienia i przepełnienia:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Jeśli uprościsz tego typu wyrażenie za pomocą ogólnych narzędzi algebraicznych, możesz łatwo dostać błędny wynik, ponieważ semantyka szerokości bitów została zignorowana.

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitów** z wyświetlonego kodu/IR/wyniku dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą uproszczenia:
- **Linear**: ważone sumy atomów bitowych
- **Semilinear**: linear plus stałe maski, takie jak `x & 0xFF`
- **Polynomial**: pojawiają się iloczyny
- **Mixed**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą kandydacką transformację** za pomocą losowego testowania albo dowodu SMT. Jeśli równoważność nie może zostać udowodniona, zachowaj oryginalne wyrażenie zamiast zgadywać.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) is a practical MBA simplifier for malware analysis and protected-binary reversing. It klasyfikuje wyrażenie i kieruje je przez wyspecjalizowane pipeline'y zamiast stosować jeden ogólny pass rewrite do wszystkiego.

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

- **Linear MBA**: CoBRA ocenia wyrażenie na wejściach Boolean, wyprowadza sygnaturę i uruchamia kilka metod odzyskiwania równolegle, takich jak pattern matching, ANF conversion oraz coefficient interpolation.
- **Semilinear MBA**: atoms z maską stałą są odbudowywane za pomocą bit-partitioned reconstruction, tak aby maskowane regiony pozostały poprawne.
- **Polynomial/Mixed MBA**: products są rozkładane na cores, a powtarzające się subexpressions mogą być podniesione do temporaries przed uproszczeniem zewnętrznej relacji.

Przykład mixed identity, którą zwykle warto spróbować odzyskać:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
To może się sprowadzić do:
```c
x * y
```
### Reversing notes

- Preferuj uruchamianie CoBRA na **lifted IR expressions** albo output dekompilera po odizolowaniu dokładnego obliczenia.
- Używaj `--bitwidth` jawnie, gdy expression pochodzi z masked arithmetic albo narrow registers.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, sprawdź lokalne notatki o Z3 tutaj:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest też dostępny jako **LLVM pass plugin** (`libCobraPass.so`), co jest przydatne, gdy chcesz znormalizować LLVM IR z dużą ilością MBA przed późniejszymi analysis passes.
- Niewspierane carry-sensitive mixed-domain residuals powinny być traktowane jako sygnał, by zachować oryginalne expression i ręcznie przeanalizować path przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator **modyfikuje wszystkie instrukcje na `mov`**(tak, naprawdę fajne). Używa też interruptions do zmiany execution flows. Więcej informacji o tym, jak to działa:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Jeśli masz szczęście, [demovfuscator](https://github.com/kirschju/demovfuscator) zdeofuscate binary. Ma kilka dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście do znalezienia flagi** może być bardzo użyteczne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje po `::main`, jak w:

![](<../../images/image (1080).png>)

W tym przypadku binarka nazywała się authenticator, więc dość oczywiste jest, że to jest interesująca funkcja main.\
Mając **nazwę** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **wejścia** i **wyjścia**.

## **Delphi**

Dla binarek skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz odwracać binarkę Delphi, sugerowałbym użycie wtyczki do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Po prostu naciśnij **ATL+f7** (import python plugin in IDA) i wybierz wtyczkę python.

Ta wtyczka uruchomi binarkę i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9) i breakpoint zatrzyma się na początku właściwego kodu.

To również jest bardzo interesujące, ponieważ jeśli naciśniesz przycisk w aplikacji graficznej, debugger zatrzyma się w funkcji wykonanej przez ten przycisk.

## Golang

Jeśli musisz odwracać binarkę Golang, sugerowałbym użycie wtyczki do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Po prostu naciśnij **ATL+f7** (import python plugin in IDA) i wybierz wtyczkę python.

To rozwiąże nazwy funkcji.

## Compiled Python

Na tej stronie możesz znaleźć, jak odzyskać kod python z binarki ELF/EXE skompilowanej z python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Jeśli dostaniesz **binarkę** gry GBA, możesz użyć różnych narzędzi do jej **emulacji** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - wtyczka Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - wtyczka Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz zobaczyć, jak naciskać przyciski Game Boy Advance **buttons**

![](<../../images/image (581).png>)

Po naciśnięciu każdy **klawisz ma wartość** służącą do identyfikacji go:
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
Więc w tego typu programie interesującą częścią będzie **to, jak program traktuje dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![](<../../images/image (447).png>)

Na poprzednim obrazie widać, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po pewnych operacjach inicjalizacyjnych (bez większego znaczenia):
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
Znaleziono ten kod:
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
Ostatni `if` sprawdza, czy **`uVar4`** znajduje się w **last Keys** i nie jest bieżącym klawiszem, co oznacza też puszczenie przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).
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
W poprzednim kodzie widać, że porównujemy **uVar1** (miejsce, w którym znajduje się **wartość naciśniętego przycisku**) z pewnymi wartościami:

- Najpierw jest porównywane z **wartością 4** (**SELECT** button): W challenge ten przycisk czyści ekran
- Następnie jest porównywane z **wartością 8** (**START** button): W challenge to sprawdza, czy kod jest poprawny, aby dostać flagę.
- W tym przypadku var **`DAT_030000d8`** jest porównywany z 0xf3 i jeśli wartość jest taka sama, wykonywany jest jakiś kod.
- W każdym innym przypadku sprawdzany jest jakiś cont (**`DAT_030000d4`**). To jest cont, ponieważ dodaje 1 zaraz po wejściu do kodu.\
**J**eśli jest mniejsze niż 8, wykonywane jest coś, co polega na **dodawaniu** wartości do **`DAT_030000d8`** (w zasadzie dodaje wartości wciśniętych klawiszy do tej zmiennej, dopóki cont jest mniejsze niż 8).

Tak więc w tym challenge, znając wartości przycisków, trzeba było **nacisnąć kombinację o długości mniejszej niż 8, której wynikowa suma wynosi 0xf3.**

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
