# Narzędzia do reverse engineeringu i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do reverse engineeringu oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** z wasm (binary) do wat (zwykły tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** z wat do wasm
- Możesz również wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/) do dekompilacji.

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Buforowany bytecode Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji assembly można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony kod źródłowy wymaga odtworzenia z legacy assembly, działanie to może zaoszczędzić czas. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z doskonałych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki kompleksowemu modelowi add-inów i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza development. Przyjrzyjmy się szerokiemu zakresowi usług reverse engineeringu zapewnianych przez to narzędzie:

- Zapewnia wgląd w sposób przepływu danych przez bibliotekę lub komponent
- Zapewnia wgląd w implementację i użycie języków oraz frameworków .NET
- Znajduje nieudokumentowaną i nieujawnioną funkcjonalność, aby lepiej wykorzystać używane API i technologie.
- Znajduje zależności i różne assembly
- Śledzi dokładną lokalizację błędów w kodzie, komponentach third-party i bibliotekach.
- Debuguje kod źródłowy całego kodu .NET, z którym pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz używać go w dowolnym systemie operacyjnym (możesz zainstalować go bezpośrednio z VSCode, bez potrzeby pobierania git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli potrzebujesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Logowanie DNSpy

Aby **DNSpy zapisywał niektóre informacje w pliku**, możesz użyć tego snippetu:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Aby debugować kod za pomocą DNSpy, należy:

Najpierw zmienić **Assembly attributes** związane z **debuggingiem**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
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

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **runtime** do kodu zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **breakpoint nigdy nie zostanie osiągnięty** lub niektóre **zmienne nie będą istnieć**.

Następnie, jeśli aplikacja .NET jest **uruchomiona** przez **IIS**, możesz ją **zrestartować** za pomocą:
```
iisreset /noforce
```
Następnie, aby rozpocząć debugowanie, należy zamknąć wszystkie otwarte pliki, a w zakładce **Debug Tab** wybrać **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, należy zamknąć wszystkie otwarte pliki, a w zakładce Debug Tab wybrać Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby dołączyć do IIS server, i kliknij attach](<../../images/image (113).png>)

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

![Debugging DLLs - Using IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parameters** wykonania, podając **path to the DLL** oraz funkcję, którą chcesz wywołać:

![Debugging DLLs - Using IDA: Skonfiguruj parameters wykonania, podając path to the DLL oraz funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Następnie, gdy rozpoczniesz debugowanie, **execution will be stopped when each DLL is loaded**, a gdy rundll32 załaduje Twoją DLL, wykonanie zostanie zatrzymane.

Ta metoda zatrzymuje wykonanie podczas zdarzeń ładowania modułów, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym poniżej workflow x64dbg.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) i ustaw ścieżkę do dll oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **start the execution**. Debugger zatrzyma się przy każdym dll main; w pewnym momencie **stop in the dll Entry of your dll**. Następnie wyszukaj punkty, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz zobaczyć, **in which code you are**, patrząc na **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Zauważ, że gdy wykonanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz zobaczyć, in which code you are, patrząc na top of the win64dbg window](<../../images/image (842).png>)

Ten wskaźnik potwierdza, kiedy wykonanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania miejsc, w których ważne wartości są zapisywane w pamięci uruchomionej gry, oraz do ich zmieniania. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to front-end i reverse engineering tool dla GNU Project Debugger (GDB), skoncentrowany na grach. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to web front-end dla wielu decompilerów. Ta usługa webowa pozwala porównywać wyniki różnych decompilerów dla małych plików wykonywalnych.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **memory address** i wstrzymuje wykonanie.\
Dołącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Strona github z wydaniami zawiera archiwa zip ze skompilowanymi wydaniami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Lekko zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Dołącz debugger, wznów wykonanie na **2–5 seconds**, wstrzymaj je wewnątrz tej pętli i przejdź do następnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI narzędzia radare. Za pomocą Cutter możesz emulować shellcode i analizować go dynamicznie.

Pamiętaj, że Cutter pozwala wybrać opcję "Open File" oraz "Open Shellcode". W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode już nie:

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp; najwyraźniej Cutter automatycznie rozpocznie emulację od tego miejsca:

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

Możesz na przykład wyświetlić stack wewnątrz hex dump:

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Spróbuj użyć [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Narzędzie poinformuje Cię między innymi, **which functions** są używane przez shellcode oraz czy shellcode **decoding** się w pamięci.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ma również graficzny launcher, w którym można wybrać żądane opcje i wykonać shellcode

![Graficzny launcher scDbg do wyboru opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zrzuci końcowy shellcode, jeśli w pamięci zostaną dynamicznie wprowadzone jakiekolwiek zmiany w shellcode (przydatne do pobrania zdekodowanego shellcode). **start offset** może być przydatny do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** umożliwia debugowanie shellcode za pomocą terminala scDbg (jednak uważam, że dowolna z wcześniej opisanych opcji jest do tego lepsza, ponieważ będzie można użyć Ida lub x64dbg).

### Disassembling using CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj następującej receptury, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Obfuscation **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za formułami łączącymi operatory arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko w ramach **modular arithmetic o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać nieprawidłowy wynik, ponieważ zignorowano semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z kodu/IR/dekompilatora po liftingu (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
- **Liniowe**: ważone sumy atomów bitowych
- **Semiliniowe**: wyrażenia liniowe oraz stałe maski, takie jak `x & 0xFF`
- **Wielomianowe**: występują iloczyny
- **Mieszane**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną transformację** za pomocą testów losowych lub dowodu SMT. Jeśli nie można dowieść równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omiń spłaszczony przepływ sterowania za pomocą wąskiego wycinka wykonania

Odtworzenie kompletnego grafu przepływu sterowania jest często niepotrzebne. W przypadku flatteningu przepływu sterowania, opaque predicates, dużych dispatcherów lub kodu obciążonego MBA podążaj za referencjami od zaszyfrowanych blobów i buforów wyjściowych do najmniejszej procedury, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych lub wykonaj go niezależnie; dispatcher nie jest częścią wymaganego rozwiązania, jeśli odpowiedni stan można zainicjalizować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow wygląda następująco:<sup>[[7]](#references)</sup>

1. Sporządź inwentarz sekcji wykonywalnych i danych, relokacji oraz odwołań krzyżowych. Zrzuć potencjalne tablice z `.rodata`, zachowując ich kolejność bajtów i szerokość elementów.
2. Zidentyfikuj ostatnią procedurę, która zapisuje plaintext lub bufor wyjściowy. Zapisz jej dane wejściowe, referencjonowane tablice, wywołania importowane oraz wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Python o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt dużej ilości stanu, wywołaj procedurę za pomocą Unicorn, QEMU lub debuggera i przechwytuj nieistotne importy zamiast emulować cały program.
4. Zweryfikuj, czy extractor rzeczywiście wyprowadza dane wyjściowe z dostarczonego pliku binarnego: usuń ciche fallbacki, przeszukaj go pod kątem osadzonych odpowiedzi i uruchom go na nieznanych buildach ze zmienionymi stringami, kluczami, identyfikatorami, layoutami oraz seedami obfuskacji.

Przydatne polecenia do pierwszego przejścia to:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Wykrywanie wyrażeń MBA zamaskowanych jako stałe

Pozornie zależne od danych wejściowych wyrażenie bajtowe może całkowicie eliminować swój argument. Po wyodrębnieniu jego tablic oblicz wyrażenie dla pełnej 8-bitowej dziedziny; jednoelementowy zbiór wyników dowodzi, że ten bajt jest stały, bez konieczności odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>
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
Zachowaj końcową maskę, ponieważ oryginalne dodawanie ma zawijanie w zakresie szerokości bajtu. Dla szerszej domeny zapytaj solver SMT, czy `f(x1) != f(x2)` jest spełnialne dla dwóch symbolicznych danych wejściowych o tej samej szerokości: `unsat` dowodzi niezmienniczości, natomiast `sat` dostarcza kontrprzykładu i oznacza, że danych wejściowych nie można odrzucić.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole anti-analysis nie muszą wykonywać skoku ani powodować awarii. Decoder może połączyć wynik odczytu z sensora z bitem klucza, stałą opaque predicate lub stanem flattened-dispatchera, kontynuować normalne działanie i wygenerować wiarygodny, lecz fałszywy plaintext w emulatorze. Dlatego samo patchowanie widocznych gałęzi awarii jest niewystarczające; prześledź zależności danych od sond środowiskowych do stanu decodera, porównaj ten sam wycinek na autentycznym urządzeniu i w emulatorze oraz sprawdź, jak wymuszenie każdego wyniku sensora zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczny upraszczacz MBA do analizy malware i reverse engineeringu chronionych plików binarnych. Klasyfikuje wyrażenie i kieruje je przez wyspecjalizowane potoki, zamiast stosować jedno ogólne przejście przepisujące do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wyrażenie dla Boolean inputs, wyprowadza sygnaturę i uruchamia równolegle kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy zamaskowane stałą są odbudowywane za pomocą rekonstrukcji z podziałem na części bitowe, dzięki czemu zamaskowane obszary pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia mogą zostać przeniesione do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład mieszanej tożsamości, którą często warto spróbować odzyskać:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Można to sprowadzić do:
```c
x * y
```
### Notatki dotyczące reversingu

- Prefer running CoBRA on **lifted IR expressions** or decompiler output after you isolated the exact computation.
- Use `--bitwidth` explicitly when the expression came from masked arithmetic or narrow registers.
- If you need a stronger proof step, check the local Z3 notes here:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA also ships as an **LLVM pass plugin** (`libCobraPass.so`), which is useful when you want to normalize MBA-heavy LLVM IR before later analysis passes.
- Unsupported carry-sensitive mixed-domain residuals should be treated as a signal to keep the original expression and reason about the carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator replaces program operations with `mov`-based instruction sequences and uses signal/exception handling to alter control flow. For details:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

For supported binaries, [demovfuscator](https://github.com/kirschju/demovfuscator) can deobfuscate the result. It has several dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Oraz [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **entry point**, wyszukaj funkcje za pomocą `::main`, jak w przykładzie:

![Znajdowanie entry point języka Rust w Ghidra przez wyszukiwanie nazw funkcji zawierających double-colon main](<../../images/image (1080).png>)

W tym przypadku binary nazywał się authenticator, więc jest dość oczywiste, że jest to interesująca funkcja main.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby dowiedzieć się więcej o ich **danych wejściowych** i **danych wyjściowych**.

### Odzyskiwanie stringów Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych stringów nie jest wskazywanych przez wskaźniki zakończone znakiem NUL w stylu C. Typowy układ `rustc` to **krotka wskaźnik/długość** wewnątrz **`.data.rel.ro`**, wskazująca na rzeczywisty blob stringów przechowywany w **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Oznacza to, że `strings` lub domyślna analiza Ghidra może łączyć sąsiadujące stringi albo całkowicie pomijać referencje krzyżowe.<sup>[[3]](#references)</sup>

Szybki workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Uzyskaj adres wirtualny i rozmiar **`.rodata`**.
2. Wyliczaj **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako potencjalny wskaźnik do stringa.
4. Traktuj następne słowo jako potencjalną długość.
5. Zastosuj filtry poprawności (na przykład zachowaj długości od **4** do **100** bajtów).
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

Jeśli Ghidra nie wykrywa tych stringów, uruchom customowy skrypt/plugin, który zastosuje tę samą heurystykę i utworzy dane stringów pod wskazanymi offsetami `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners są dobrymi przykładami do dostosowania tego pomysłu do innych **rozmiarów słów, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binariów skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz wykonać reverse engineering binarium Delphi, sugeruję użycie pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Ten plugin wykona binarium i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a breakpoint zostanie trafiony na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

Jeśli musisz wykonać reverse engineering binarium Golang, sugeruję użycie pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Spowoduje to rozwiązanie nazw funkcji.

## Skompilowany Python

Na tej stronie znajdziesz informacje o tym, jak uzyskać kod python z binarium ELF/EXE skompilowanego w Pythonie:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli masz **binarium** gry GBA, możesz użyć różnych narzędzi do jej **emulacji** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz zobaczyć, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja sterowania no$gba pokazująca mapowanie przycisków Game Boy Advance](<../../images/image (581).png>)

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

![Widok Ghidry pliku binarnego GBA odwołującego się do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

Na poprzednim obrazie możesz zobaczyć, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

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
Ostatnia instrukcja if sprawdza, czy **`uVar4`** znajduje się w **ostatnich Keys** i nie jest bieżącym klawiszem — jest to również nazywane puszczeniem przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).
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
W poprzednim kodzie widać, że porównujemy **uVar1** (miejsce, w którym znajduje się **wartość wciśniętego przycisku**) z pewnymi wartościami:

- Najpierw jest porównywana z **wartością 4** (przycisk **SELECT**): w tym challenge'u ten przycisk czyści ekran
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym challenge'u ta ścieżka sprawdza, czy wprowadzony kod jest poprawny.
- W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli wartości są takie same, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany i zwiększany jest licznik (`DAT_030000d4`).\
Dopóki licznik jest mniejszy niż 8, wartości wciśniętych przycisków są sumowane w `DAT_030000d8`.

Zatem w tym challenge'u, znając wartości przycisków, trzeba było **wcisnąć kombinację o długości mniejszej niż 8, której suma wynosi 0xf3.**

**Źródło do tego tutoriala:** [zarchiwizowany writeup challenge'u Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacja binarna)

## References

- [1] [Upraszczanie obfuskacji MBA za pomocą CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repozytorium Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Dekodowanie stringów Rusta - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - stringi Rusta](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reverse engineeringu GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie reverse engineeringu wspomaganego przez AI, a przynajmniej próby jego pokonania](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
