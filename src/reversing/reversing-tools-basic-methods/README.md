# Narzędzia do Reversing i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do Reversing oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **zdekompilować** wasm (binary) do wat (czytelny tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **skompilować** wat do wasm
- możesz także spróbować użyć [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/), aby zdekompilować

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji assembly można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony kod źródłowy wymaga odtworzenia z legacy assembly, działanie to może zaoszczędzić czas. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, co czyni go jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki kompleksowemu modelowi add-inów i API, które rozszerza narzędzie, aby dopasować je do dokładnych potrzeb, .NET reflector oszczędza czas i upraszcza development. Przyjrzyjmy się szerokiemu zakresowi usług reverse engineering, które zapewnia to narzędzie:

- Zapewnia wgląd w przepływ danych przez bibliotekę lub komponent
- Zapewnia wgląd w implementację i użycie języków oraz frameworków .NET
- Znajduje nieudokumentowane i nieudostępnione funkcje, aby lepiej wykorzystać używane API i technologie.
- Znajduje zależności i różne assembly
- Wskazuje dokładną lokalizację błędów w kodzie, komponentach firm trzecich i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz używać go w dowolnym systemie operacyjnym (możesz zainstalować go bezpośrednio z VSCode, bez potrzeby pobierania git. Kliknij **Extensions** i **search ILSpy**).\
Jeśli potrzebujesz **zdekompilować**, **zmodyfikować** i ponownie **skompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### DNSpy Logging

Aby **DNSpy zapisywał niektóre informacje w pliku**, możesz użyć tego fragmentu:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugowanie DNSpy

Aby debugować kod za pomocą DNSpy, należy:

Najpierw zmienić **atrybuty Assembly** związane z **debugowaniem**:

![Logowanie DNSpy - Debugowanie DNSpy: Najpierw zmień atrybuty Assembly związane z debugowaniem](<../../images/image (973).png>)

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

Następnie zapisz nowy plik za pomocą _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **runtime** do kodu zostanie zastosowanych kilka **optymalizacji** i możliwe będzie, że podczas debugowania **break-point nigdy nie zostanie osiągnięty** lub niektóre **zmienne nie będą istnieć**.

Następnie, jeśli Twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:
```
iisreset /noforce
```
Następnie, aby rozpocząć debugging, należy zamknąć wszystkie otwarte pliki, a wewnątrz **Debug Tab** wybrać **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugging, należy zamknąć wszystkie otwarte pliki, a wewnątrz Debug Tab wybrać Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby podłączyć się do IIS server, i kliknij attach](<../../images/image (113).png>)

Teraz, gdy debugging procesu jest aktywny, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie kliknij _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugging procesu jest aktywny, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij Debug Break All, a następnie kliknij Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugging procesu jest aktywny, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij Debug Break All, a następnie kliknij Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i wybierz **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i wybierz Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parameters** wykonania, podając **path to the DLL** oraz funkcję, którą chcesz wywołać:

![Debugging DLLs - Using IDA: Skonfiguruj parameters wykonania, podając path to the DLL oraz funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Następnie, gdy rozpoczniesz debugging, **execution will be stopped when each DLL is loaded**, a gdy rundll32 załaduje Twoją DLL, execution zostanie zatrzymane.

Jak jednak uzyskać dostęp do kodu załadowanej DLL? Nie wiem, jak to zrobić przy użyciu tej metody.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) i ustaw ścieżkę do dll oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **start the execution**. Debugger zatrzyma się przy każdym dll main; w pewnym momencie **stop in the dll Entry of your dll**. Następnie wyszukaj punkty, w których chcesz ustawić breakpoint.

Zauważ, że gdy execution zostanie zatrzymane z dowolnego powodu w win64dbg, możesz zobaczyć, **in which code you are**, w górnej części okna win64dbg:

![Using IDA - Using x64dbg/x32dbg: Zauważ, że gdy execution zostanie zatrzymane z dowolnego powodu w win64dbg, możesz zobaczyć, in which code you are, w górnej części okna win64dbg](<../../images/image (842).png>)

Dzięki temu możesz zobaczyć, kiedy execution zostało zatrzymane w dll, którą chcesz debugować.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania miejsc, w których ważne wartości są zapisywane w pamięci uruchomionej gry, oraz do ich zmieniania. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to front-end/reverse engineering tool dla GNU Project Debugger (GDB), koncentrujący się na grach. Może jednak być używany do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end dla wielu decompilerów. Ten web service pozwala porównywać wyniki różnych decompilerów dla małych plików wykonywalnych.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **allocate** **shellcode** w obszarze pamięci, **indicate** **memory address**, pod którym shellcode został zaalokowany, i **stop** execution.\
Następnie należy **attach a debugger** (Ida lub x64dbg) do procesu, ustawić **breakpoint the indicated memory address** i **resume** execution. W ten sposób będziesz debugować shellcode.

Strona github z releases zawiera pliki zip ze skompilowanymi releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod następującym linkiem. Aby ją skompilować, po prostu **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)jest bardzo podobny do blobrunner. **allocate** **shellcode** w obszarze pamięci i uruchamia **eternal loop**. Następnie należy **attach the debugger** do procesu, **play start wait 2-5 secs and press stop**, a znajdziesz się wewnątrz **eternal loop**. Przejdź do następnej instrukcji eternal loop, ponieważ będzie to call do shellcode, a ostatecznie znajdziesz się podczas wykonywania shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it jest bardzo podobny do blobrunner. Allocate shellcode w obszarze pamięci i uruchamia...](<../../images/image (509).png>)

Możesz pobrać skompilowaną wersję [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Przy użyciu Cutter możesz emulować shellcode i analizować go dynamicznie.

Zauważ, że Cutter pozwala wybrać „Open File” oraz „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode już nie:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Zauważ, że Cutter pozwala wybrać „Open File” oraz „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku...](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp; wygląda na to, że Cutter automatycznie rozpocznie w tym miejscu emulację:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp; wygląda na to, że Cutter automatycznie...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp; wygląda na to, że Cutter automatycznie...](<../../images/image (387).png>)

Możesz na przykład zobaczyć stack wewnątrz hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Możesz na przykład zobaczyć stack wewnątrz hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Powinieneś wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Poinformuje Cię między innymi, **which functions** są używane przez shellcode oraz czy shellcode **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg posiada również graficzny launcher, w którym można wybrać żądane opcje i wykonać shellcode

![Debugowanie shellcode przy użyciu Cutter - Deobfuscation shellcode i uzyskiwanie wykonywanych funkcji: scDbg posiada również graficzny launcher, w którym można wybrać żądane opcje i...](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli shellcode został dynamicznie zmieniony w pamięci (przydatne do pobrania zdekodowanego shellcode). Opcja **start offset** może być przydatna do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** służy do debugowania shellcode przy użyciu terminala scDbg (jednak uważam, że dowolna z opisanych wcześniej opcji jest do tego lepsza, ponieważ będzie można użyć Ida lub x64dbg).

### Disassembling przy użyciu CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj następującej receptury, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuscation MBA

Obfuscation **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za formułami łączącymi operatory arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko w ramach **modularnej arytmetyki o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ zignorowano semantykę szerokości bitowej.

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyniku dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
- **Liniowe**: ważone sumy atomów bitowych
- **Semiliniowe**: wyrażenia liniowe oraz stałe maski, takie jak `x & 0xFF`
- **Wielomianowe**: występują iloczyny
- **Mieszane**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną zamianę** za pomocą testów losowych lub dowodu SMT. Jeśli równoważności nie można udowodnić, zachowaj oryginalne wyrażenie zamiast zgadywać.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA na potrzeby analizy malware i reversing chronionych plików binarnych. Klasyfikuje wyrażenie i przekazuje je do wyspecjalizowanych pipeline'ów zamiast stosować jeden ogólny etap przepisywania do wszystkiego.<sup>[[1]](#references)[[2]](#references)</sup>

Szybkie użycie:
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

- **Linear MBA**: CoBRA ocenia wyrażenie na wejściach Boolean, wyprowadza sygnaturę i równolegle uruchamia kilka metod odzyskiwania, takich jak pattern matching, konwersja ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy zamaskowane stałą są odbudowywane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane obszary pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia można przenieść do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład mieszanej tożsamości, którą często warto spróbować odzyskać:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Można to sprowadzić do:
```c
x * y
```
### Notatki dotyczące reverse engineeringu

- Preferuj uruchamianie CoBRA na **podniesionych wyrażeniach IR** lub na wyjściu dekompilatora po wyizolowaniu dokładnego obliczenia.
- Używaj jawnie `--bitwidth`, gdy wyrażenie pochodzi z arytmetyki maskowanej lub rejestrów o mniejszej szerokości.
- Jeśli potrzebujesz silniejszego kroku dowodowego, sprawdź lokalne notatki dotyczące Z3 tutaj:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępny jako **plugin pass dla LLVM** (`libCobraPass.so`), co jest przydatne, gdy chcesz znormalizować obfitujący w MBA kod LLVM IR przed wykonaniem kolejnych passów analitycznych.
- Nieobsługiwane, wrażliwe na przeniesienie pozostałości mieszanych domen należy traktować jako sygnał, aby zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator **modyfikuje wszystkie instrukcje dla `mov`** (tak, naprawdę fajne). Wykorzystuje również przerwania do zmiany przepływów wykonywania. Więcej informacji o tym, jak działa:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Jeśli masz szczęście, [demovfuscator](https://github.com/kirschju/demovfuscator) zdeobfuskacja binarkę. Ma kilka zależności
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli bierzesz udział w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **entry point**, wyszukaj funkcje po `::main`, tak jak na przykładzie:

![Movfuscator - Rust: Aby znaleźć entry point, wyszukaj funkcje po ::main, tak jak na przykładzie](<../../images/image (1080).png>)

W tym przypadku binary nosił nazwę authenticator, więc jest dość oczywiste, że jest to interesująca funkcja main.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby dowiedzieć się więcej o ich **inputach** i **outputach**.

### Odzyskiwanie stringów Rust z firmware ELF

W binary **Rust ELF** wiele statycznych stringów nie jest wskazywanych przez wskaźniki zakończone NUL-em w stylu C. Typowy układ `rustc` to **krotka wskaźnik/długość** wewnątrz **`.data.rel.ro`**, wskazująca na rzeczywisty blob stringów przechowywany w **`.rodata`**:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Oznacza to, że `strings` lub domyślna analiza Ghidra może łączyć sąsiadujące stringi albo całkowicie pomijać odwołania krzyżowe.

Szybki workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pobierz adres wirtualny i rozmiar **`.rodata`**.
2. Wyliczaj zawartość **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako potencjalny wskaźnik do stringa.
4. Traktuj następne słowo jako potencjalną długość.
5. Zastosuj filtry poprawności (na przykład zachowuj długości od **4** do **100** bajtów).
6. Odczytaj dokładnie `length` bajtów z `.rodata`, zamiast skanować do `0x00`.

Minimalna logika extractora:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Jest to szczególnie przydatne podczas reverse engineeringu firmware, ponieważ odzyskane stringi Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracyjne, handlery poleceń oraz logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykryje tych stringów, uruchom własny skrypt/plugin, który zastosuje tę samą heurystykę i utworzy dane stringów pod wskazanymi offsetami w `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` autorstwa Pen Test Partners są dobrymi przykładami do dostosowania tego podejścia do innych **rozmiarów słów, endianowości oraz układów sekcji**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

W przypadku skompilowanych binariów Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reverse engineering binarnego pliku Delphi, sugeruję użyć pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Po prostu naciśnij **ATL+f7** (import python pluginu w IDA) i wybierz plugin pythonowy.

Ten plugin uruchomi binary i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a breakpoint zostanie trafiony na początku właściwego kodu.

Jest to również bardzo interesujące, ponieważ po naciśnięciu przycisku w aplikacji graficznej debugger zatrzyma się w funkcji wykonanej przez ten przycisk.

## Golang

Jeśli musisz przeprowadzić reverse engineering binarnego pliku Golang, sugeruję użyć pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Po prostu naciśnij **ATL+f7** (import python pluginu w IDA) i wybierz plugin pythonowy.

Spowoduje to rozwiązanie nazw funkcji.

## Compiled Python

Na tej stronie znajdziesz informacje, jak uzyskać kod pythonowy ze skompilowanego binarnego pliku ELF/EXE zawierającego Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Jeśli zdobędziesz **binary** gry GBA, możesz użyć różnych narzędzi do jej **emulacji** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz zobaczyć, jak naciskać **przyciski** Game Boy Advance

![konfiguracja sterowania no$gba pokazująca mapowanie przycisków Game Boy Advance](<../../images/image (581).png>)

Po naciśnięciu każdy **klawisz ma wartość**, która pozwala go zidentyfikować:
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
W tego rodzaju programie interesujące będzie **to, jak program przetwarza dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidry pliku binarnego GBA odwołującego się do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

Na poprzednim obrazie możesz zobaczyć, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po kilku operacjach inicjalizacyjnych (bez znaczenia):
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
Ostatni `if` sprawdza, czy **`uVar4`** znajduje się w **ostatnich Keys** i nie jest bieżącym klawiszem — oznacza to puszczenie przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).
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
W poprzednim kodzie widać, że porównujemy **uVar1** (miejsce, w którym znajduje się **value of the pressed button**) z pewnymi wartościami:

- Najpierw jest porównywana z **value 4** (przycisk **SELECT**): w challenge ten przycisk czyści ekran
- Następnie jest porównywana z **value 8** (przycisk **START**): w challenge sprawdza, czy kod jest poprawny, aby uzyskać flagę.
- W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartość jest taka sama, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany jest pewien cont (**`DAT_030000d4`**). Jest to cont, ponieważ zaraz po wejściu w kod jest zwiększany o 1.\
**J**eśli jest mniejszy niż 8, wykonywana jest operacja obejmująca **adding** wartości do **`DAT_030000d8`** (zasadniczo wartości wciśniętych klawiszy są dodawane do tej zmiennej, dopóki cont jest mniejszy niż 8).

W tym challenge, znając wartości przycisków, należało **wcisnąć kombinację o długości mniejszej niż 8, której wynikowa suma wynosi 0xf3.**<sup>[[6]](#references)</sup>

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Referencje

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
