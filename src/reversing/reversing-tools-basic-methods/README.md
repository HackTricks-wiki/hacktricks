# Narzędzia do Reversing i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do Reversing oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** wasm (binary) do wat (clear text)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** wat do wasm
- Możesz także wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/) do dekompilacji.

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji assembly można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony kod źródłowy wymaga odtworzenia z legacy assembly, działanie to może zaoszczędzić czas. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, co czyni go jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki kompleksowemu modelowi add-inów i API, które rozszerza narzędzie zgodnie z Twoimi dokładnymi potrzebami, .NET Reflector oszczędza czas i upraszcza development. Przyjrzyjmy się szerokiemu zakresowi usług reverse engineering zapewnianych przez to narzędzie:

- Zapewnia wgląd w sposób przepływu danych przez bibliotekę lub komponent
- Zapewnia wgląd w implementację i użycie języków oraz frameworków .NET
- Znajduje nieudokumentowane i nieujawnione funkcje, aby umożliwić lepsze wykorzystanie używanych API i technologii.
- Znajduje zależności i różne assembly
- Śledzi dokładną lokalizację błędów w Twoim kodzie, komponentach firm trzecich i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego kodu .NET, z którym pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz mieć go w dowolnym systemie operacyjnym (możesz zainstalować go bezpośrednio z VSCode, bez konieczności pobierania repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli potrzebujesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Logowanie DNSpy

Aby **DNSpy zapisywał określone informacje w pliku**, możesz użyć tego fragmentu:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugowanie DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Najpierw zmienić atrybuty **Assembly** związane z **debugowaniem**:

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

![DNSpy Logging - DNSpy Debugging: I kliknij compile](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik za pomocą _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Następnie zapisz nowy plik za pomocą File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, w **runtime** do kodu zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **break-point nigdy nie zostanie osiągnięty** lub niektóre **zmienne nie będą istnieć**.

Następnie, jeśli Twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:
```
iisreset /noforce
```
Następnie, aby rozpocząć debugowanie, należy zamknąć wszystkie otwarte pliki, a w **Debug Tab** wybrać **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, należy zamknąć wszystkie otwarte pliki, a w Debug Tab wybrać Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby podłączyć się do IIS server, i kliknij attach](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie kliknij _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij Debug Break All, a następnie kliknij Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij Debug Break All, a następnie kliknij Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i kliknij **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i kliknij Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugowanie DLLs - Using IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parameters** wykonania, podając **path to the DLL** oraz funkcję, którą chcesz wywołać:

![Debugowanie DLLs - Using IDA: Skonfiguruj parameters wykonania, podając path to the DLL oraz funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Następnie, po rozpoczęciu debugowania, **execution will be stopped when each DLL is loaded**, a gdy rundll32 załaduje Twoją DLL, wykonanie zostanie zatrzymane.

Ta metoda zatrzymuje wykonanie podczas zdarzeń ładowania modułów, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym poniżej workflow z x64dbg.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) i ustaw ścieżkę do dll oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **start the execution**; debugger zatrzyma się przy każdym dll main i w pewnym momencie **stop in the dll Entry of your dll**. Następnie wyszukaj punkty, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, **in which code you are**, patrząc na **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Zauważ, że gdy wykonanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, in which code you are, patrząc na top of the win64dbg window](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania miejsc, w których ważne wartości są zapisywane w pamięci uruchomionej gry, oraz ich zmieniania. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to front-end/reverse engineering tool dla GNU Project Debugger (GDB), skoncentrowany na grach. Może jednak być używany do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end dla wielu decompilerów. Ten web service pozwala porównywać wyniki różnych decompilerów dla małych plików wykonywalnych.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **memory address** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Strona github z wydaniami zawiera pliki zip ze skompilowanymi wydaniami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 seconds**, zatrzymaj je wewnątrz tej pętli i przejdź do następnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger wstrzymany w nieskończonej pętli jmp2it bezpośrednio przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/) można pobrać.

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI programu radare. Za pomocą Cutter możesz emulować shellcode i analizować go dynamicznie.

Pamiętaj, że Cutter umożliwia użycie opcji "Open File" i "Open Shellcode". W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode już nie:

![Cutter pokazujący różne wyniki analizy po otwarciu tych samych bajtów jako pliku lub jako shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp; najwyraźniej Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter wstrzymany na wybranym breakpointcie shellcode](<../../images/image (387).png>)

Możesz na przykład wyświetlić stack wewnątrz hex dump:

![Wyświetlanie emulowanego stack shellcode w hex dumpie Cutter](<../../images/image (186).png>)

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
scDbg oferuje również graficzny launcher, w którym można wybrać żądane opcje i wykonać shellcode

![Graficzny launcher scDbg do wybierania opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zrzuci końcowy shellcode, jeśli w pamięci dynamicznie dokonano w nim jakichkolwiek zmian (przydatne do pobrania zdekodowanego shellcode). Opcja **start offset** może być przydatna do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** służy do debugowania shellcode za pomocą terminala scDbg (uważam jednak, że dowolna z opisanych wcześniej opcji będzie lepsza w tym przypadku, ponieważ można będzie użyć Ida lub x64dbg).

### Disassembling using CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj następującej receptury, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desobfuskacja MBA obfuscation

Obfuscation **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za formułami łączącymi operacje arytmetyczne (`+`, `-`, `*`) i operatory bitowe (`&`, `|`, `^`, `~`, shifts). Ważne jest to, że te tożsamości są zwykle poprawne wyłącznie w warunkach **fixed-width modular arithmetic**, dlatego przeniesienia i przepełnienia mają znaczenie:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ semantyka szerokości bitowej została pominięta.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z lifted code/IR/dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
- **Liniowe**: ważone sumy atomów bitowych
- **Semiliniowe**: wyrażenia liniowe plus stałe maski, takie jak `x & 0xFF`
- **Wielomianowe**: występują iloczyny
- **Mieszane**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną zamianę** za pomocą testów losowych lub dowodu SMT. Jeśli równoważności nie można udowodnić, zachowaj oryginalne wyrażenie zamiast zgadywać.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczny upraszczacz MBA do analizy malware oraz reversing chronionych binariów. Klasyfikuje wyrażenie i kieruje je przez wyspecjalizowane pipeline'y, zamiast stosować jedno ogólne przejście przekształceń do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA ocenia wyrażenie na wejściach Boolean, wyprowadza sygnaturę i równolegle uruchamia kilka metod odzyskiwania, takich jak pattern matching, konwersja ANF oraz interpolacja współczynników.
- **Semilinear MBA**: stałe maskowane atomy są odbudowywane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane regiony pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia można przenieść do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład mieszanej tożsamości, którą zwykle warto spróbować odzyskać:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Można to uprościć do:
```c
x * y
```
### Notatki dotyczące reversingu

- Prefer uruchamianie CoBRA na **lifted IR expressions** lub wynikach dekompilatora po wyizolowaniu dokładnego obliczenia.
- Używaj jawnie `--bitwidth`, gdy wyrażenie pochodzi z operacji maskowanych lub rejestrów o wąskiej szerokości.
- Jeśli potrzebujesz silniejszego kroku dowodowego, sprawdź lokalne notatki dotyczące Z3 tutaj:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostarczany jako **LLVM pass plugin** (`libCobraPass.so`), co jest przydatne, gdy chcesz znormalizować LLVM IR zawierający dużo MBA przed wykonaniem kolejnych passów analitycznych.
- Nieobsługiwane, zależne od przeniesienia residuals z mieszanych domen należy traktować jako sygnał, aby zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Szczegóły:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych binary, [demovfuscator](https://github.com/kirschju/demovfuscator) może zdeobfuskować wynik. Ma kilka zależności.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli bierzesz udział w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje za pomocą `::main`, jak na przykładzie:

![Znajdowanie punktu wejścia Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających main oddzielone podwójnym dwukropkiem](<../../images/image (1080).png>)

W tym przypadku plik binarny nosił nazwę authenticator, więc jest dość oczywiste, że to właśnie ta interesująca funkcja main.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby dowiedzieć się więcej o ich **danych wejściowych** i **wyjściowych**.

### Odzyskiwanie stringów Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych stringów nie jest wskazywanych przez wskaźniki zakończone NUL-em w stylu C. Typowy układ `rustc` zawiera **krotkę wskaźnik/długość** wewnątrz **`.data.rel.ro`**, wskazującą na rzeczywisty blok stringów przechowywany w **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Oznacza to, że `strings` lub domyślna analiza Ghidra może łączyć sąsiadujące ciągi znaków albo całkowicie pomijać odwołania krzyżowe.<sup>[[3]](#references)</sup>

Szybki workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Pobierz adres wirtualny i rozmiar **`.rodata`**.
2. Wyliczaj zawartość **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako kandydata na wskaźnik do ciągu znaków.
4. Traktuj następne słowo jako kandydata na długość.
5. Zastosuj filtry poprawności (na przykład zachowuj długości od **4** do **100** bajtów).
6. Odczytaj dokładnie `length` bajtów z `.rodata` zamiast skanować do `0x00`.

Minimalna logika ekstraktora:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Jest to szczególnie przydatne podczas reversing firmware, ponieważ odzyskane stringi Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, handlery poleceń oraz logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykryje tych stringów, uruchom customowy skrypt/plugin, który zastosuje tę samą heurystykę i utworzy dane stringów pod wskazanymi offsetami `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` firmy Pen Test Partners są dobrymi materiałami referencyjnymi do dostosowania tego pomysłu do innych **rozmiarów słów, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binariów skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz wykonać reversing binarium Delphi, sugeruję użycie pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Ten plugin wykona binarium i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a breakpoint zostanie trafiony na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywoływanej przez ten przycisk.

## Golang

Jeśli musisz wykonać reversing binarium Golang, sugeruję użycie pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Spowoduje to rozwiązanie nazw funkcji.

## Skompilowany Python

Na tej stronie znajdziesz informacje, jak uzyskać kod Python z binarium ELF/EXE skompilowanego w Pythonie:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli zdobędziesz **binarium** gry GBA, możesz użyć różnych narzędzi do jej **emulacji** i **debugowania**:

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
Zatem w tego rodzaju programie interesującą częścią będzie **sposób, w jaki program przetwarza dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidra pliku binarnego GBA odwołującego się do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

Na poprzednim obrazie widać, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po wykonaniu kilku operacji inicjalizacyjnych (niemających znaczenia):
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
Znaleziono następujący kod:
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
Ostatni if sprawdza, czy **`uVar4`** znajduje się w **last Keys** i nie jest bieżącym klawiszem; jest to również nazywane puszczeniem przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).
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
W poprzednim kodzie widać, że porównujemy **uVar1** (miejsce, w którym znajduje się **value wciśniętego przycisku**) z określonymi wartościami:

- Najpierw jest ono porównywane z **value 4** (przycisk **SELECT**): w tym challenge ten przycisk czyści ekran
- Następnie value jest porównywane z **8** (przycisk **START**); w tym challenge ta ścieżka sprawdza, czy wprowadzony kod jest prawidłowy.
- W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli value jest taka sama, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany i zwiększany jest licznik (`DAT_030000d4`).\
Dopóki licznik jest mniejszy niż 8, values wciśniętych klawiszy są sumowane w `DAT_030000d8`.

A zatem w tym challenge, znając values przycisków, należało **wcisnąć kombinację o długości mniejszej niż 8, której wynikowa suma wynosi 0xf3.**

**Reference do tego tutorialu:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Upraszczanie MBA obfuscation za pomocą CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repozytorium Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Dekodowanie strings w Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversingu GBA (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
