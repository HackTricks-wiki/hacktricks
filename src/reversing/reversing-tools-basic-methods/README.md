# Narzędzia do analizy wstecznej i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do analizy wstecznej oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugowanie jądra Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** wasm (plik binarny) do wat (czytelnego tekstu)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** wat do wasm
- Możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/) do dekompilacji.

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Buforowany bytecode Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) i **pliki wykonywalne** (.exe). Po dekompilacji zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego rozwiązania jest oszczędność czasu, gdy trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które można dostosować do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza tworzenie oprogramowania. Przyjrzyjmy się szerokiemu zakresowi usług inżynierii wstecznej, które oferuje to narzędzie:

- Pokazuje przepływ danych przez bibliotekę lub komponent
- Pokazuje implementację i sposób użycia języków oraz frameworków .NET
- Wyszukuje nieudokumentowane i nieudostępnione funkcje, aby umożliwić lepsze wykorzystanie używanych interfejsów API i technologii.
- Wyszukuje zależności i różne zestawy
- Ustala dokładną lokalizację błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz używać jej w dowolnym systemie operacyjnym (możesz zainstalować ją bezpośrednio z VSCode, nie trzeba pobierać git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie rozwijanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Logowanie DNSpy

Aby **DNSpy zapisywał pewne informacje w pliku**, możesz użyć tego fragmentu kodu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Aby debugować kod za pomocą DNSpy, należy:

Najpierw zmienić **Assembly attributes** związane z **debugging**:

![DNSpy Logging - DNSpy Debugging: Najpierw zmień Assembly attributes związane z debugging](<../../images/image (973).png>)

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

Następnie zapisz nowy plik, wybierając _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **runtime** do kodu zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **breakpoint nigdy nie zostanie trafiony** lub niektóre **zmienne nie będą istnieć**.

Następnie, jeśli Twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i na karcie **Debug** wybierz **Attach to Process...**:

![DNSpy Logging - Debugowanie w DNSpy: Aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i na karcie Debug wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **serwera IIS**, i kliknij **attach**:

![DNSpy Logging - Debugowanie w DNSpy: Wybierz w3wp.exe, aby podłączyć się do serwera IIS, i kliknij attach](<../../images/image (113).png>)

Skoro debugujemy już proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie _**Debug >> Windows >> Modules**_:

![DNSpy Logging - Debugowanie w DNSpy: Skoro debugujemy już proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - Debugowanie w DNSpy: Skoro debugujemy już proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - Debugowanie w DNSpy: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i wybierz **Sort Assemblies**:

![DNSpy Logging - Debugowanie w DNSpy: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i wybierz Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Używanie IDA

- **Załaduj rundll32** (64-bitowy plik znajduje się w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugowanie DLL - Używanie IDA: Wybierz „Suspend on library load/unload”](<../../images/image (868).png>)

- Skonfiguruj **parametry** uruchomienia, podając **ścieżkę do DLL** i funkcję, którą chcesz wywołać:

![Debugowanie DLL - Używanie IDA: Skonfiguruj parametry uruchomienia, podając ścieżkę do DLL i funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **uruchomienie zostanie zatrzymane po załadowaniu każdej DLL**. Gdy rundll32 załaduje Twoją DLL, wykonanie zostanie zatrzymane.

Ta metoda zatrzymuje wykonanie przy zdarzeniach ładowania modułów, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym niżej sposobie z x64dbg.

### Używanie x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy plik znajduje się w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień wiersz poleceń** (_File --> Change Command Line_) i podaj ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Wybierz _Options --> Settings_ i zaznacz "**DLL Entry**".
- Następnie **uruchom program**. Debugger zatrzyma się przy funkcji main każdej DLL; w pewnym momencie **zatrzymasz się w punkcie wejścia swojej DLL**. Następnie znajdź miejsca, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonanie zostanie z dowolnego powodu zatrzymane w win64dbg, **u góry okna win64dbg** możesz sprawdzić, **w którym kodzie jesteś**:

![Używanie IDA - Używanie x64dbg/x32dbg: Gdy wykonanie zostanie z dowolnego powodu zatrzymane w win64dbg, u góry okna win64dbg możesz sprawdzić, w którym kodzie jesteś](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania ważnych wartości zapisanych w pamięci uruchomionej gry i ich zmieniania. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie typu front-end do GNU Project Debugger (GDB), przeznaczone do inżynierii wstecznej, głównie gier. Można go jednak używać do dowolnych zadań związanych z inżynierią wsteczną.

[**Decompiler Explorer**](https://dogbolt.org/) to internetowy front-end udostępniający wiele dekompilatorów. Ta usługa internetowa umożliwia porównanie wyników różnych dekompilatorów dla małych plików wykonywalnych.

## ARM i MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres w pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie wydań GitHub znajdują się archiwa ZIP ze skompilowanymi wersjami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie go zbuduj**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 sekund**, zatrzymaj je wewnątrz tej pętli i przejdź do kolejnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger zatrzymany w nieskończonej pętli jmp2it, tuż przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI programu radare. Za pomocą Cutter możesz emulować shellcode i analizować jego działanie.

Pamiętaj, że Cutter umożliwia wybranie opcji „Open File” lub „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu jako shellcode już nie:

![Cutter pokazuje różne wyniki analizy tych samych bajtów otwartych jako plik lub jako shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp. Wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter zatrzymany na wybranym breakpoincie shellcode](<../../images/image (387).png>)

Stos możesz na przykład zobaczyć w zrzucie szesnastkowym:

![Wyświetlanie stosu emulowanego shellcode w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Usuwanie obfuskacji shellcode i pozyskiwanie wywoływanych funkcji

Warto wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Narzędzie pokaże między innymi, **których funkcji** używa shellcode oraz czy **dekoduje się** w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ma również graficzny launcher, w którym można wybrać żądane opcje i uruchomić shellcode

![Graficzny launcher scDbg do wyboru opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zrzuci końcowy shellcode, jeśli w pamięci zostaną w nim wprowadzone jakiekolwiek zmiany (przydatne do pobrania zdekodowanego shellcode). Opcja **start offset** może się przydać do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** umożliwia debugowanie shellcode za pomocą terminala scDbg (do tego celu lepiej jednak sprawdza się dowolna z wcześniej opisanych opcji, ponieważ można wtedy użyć Ida lub x64dbg).

### Deasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższego przepisu, aby go zdeasemblować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacja MBA

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących operacje arytmetyczne (`+`, `-`, `*`) i operatory bitowe (`&`, `|`, `^`, `~`, przesunięcia). Istotne jest to, że te tożsamości są zwykle poprawne tylko w ramach **arytmetyki modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, łatwo uzyskasz błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyjścia dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenia liniowe z dodatkowymi maskami stałych, takimi jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i operacje bitowe są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Weryfikuj każdą proponowaną zamianę** za pomocą losowych testów lub dowodu SMT. Jeśli nie da się udowodnić równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omijanie spłaszczonego przepływu sterowania za pomocą wąskiego wycinka wykonania

Odzyskanie pełnego grafu przepływu sterowania często nie jest konieczne. W przypadku control-flow flattening, opaque predicates, dużych dispatcherów lub kodu pełnego operacji MBA śledź odwołania od zaszyfrowanych bloków danych i buforów wyjściowych do najmniejszej rutyny, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych albo wykonaj go niezależnie; dispatcher nie jest niezbędny do rozwiązania, jeśli odpowiedni stan można zainicjować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow:<sup>[[7]](#references)</sup>

1. Zbierz informacje o sekcjach wykonywalnych i danych, relokacjach oraz odwołaniach krzyżowych. Zrzuć potencjalne tablice z `.rodata`, zachowując ich kolejność bajtów i szerokość elementów.
2. Zidentyfikuj ostatnią rutynę zapisującą tekst jawny lub bufor wyjściowy. Zapisz jej dane wejściowe, używane tablice, wywoływane funkcje importowane i wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Pythona o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt dużej ilości stanu, wywołaj rutynę w Unicornie, QEMU lub debuggerze i podłącz hooki do nieistotnych funkcji importowanych, zamiast emulować cały program.
4. Zweryfikuj, czy extractor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche mechanizmy awaryjne, sprawdź, czy plik nie zawiera osadzonych odpowiedzi, i uruchom extractor na nieznanych wcześniej buildach ze zmienionymi ciągami znaków, kluczami, identyfikatorami, układami i ziarnami obfuskacji.

Przydatne polecenia do wstępnej analizy:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywanie wyrażeń MBA maskujących stałe

Pozornie zależne od wejścia wyrażenie bajtowe może całkowicie eliminować wpływ wejścia. Po wyodrębnieniu tablic oblicz wyrażenie dla całej 8-bitowej dziedziny; jednoelementowy zbiór wyników dowodzi, że bajt jest stały, bez konieczności odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie powoduje zawijanie przy szerokości bajtu. W szerszej dziedzinie zapytaj solver SMT, czy dla dwóch symbolicznych wejść o tej samej szerokości spełnialne jest `f(x1) != f(x2)`: `unsat` dowodzi niezmienności, a `sat` dostarcza kontrprzykład i oznacza, że wejścia nie można odrzucić.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole anti-analysis nie muszą powodować skoku ani awarii. Dekoder może włączyć wynik czujnika do bitu klucza, stałej opaque predicate lub stanu flattened-dispatchera, działać dalej i wygenerować wiarygodny, ale fałszywy tekst jawny w emulatorze. Dlatego samo załatanie widocznych gałęzi błędów nie wystarczy; śledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam wycinek na autentycznym urządzeniu i w emulatorze oraz sprawdź, jak wymuszenie każdego wyniku czujnika zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA, przeznaczone do analizy malware i reverse engineeringu chronionych binariów. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków, zamiast stosować jeden ogólny przebieg przepisywania do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wyrażenie dla wejść boolowskich, wyznacza sygnaturę i równolegle uruchamia kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja do ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy maskowane stałą są odtwarzane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane obszary pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia można przenieść do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład mieszanej tożsamości, którą często warto spróbować odzyskać:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Można to zredukować do:

```c
x * y
```

### Notatki dotyczące reverse engineeringu

- Preferuj uruchamianie CoBRA na **wyrażeniach IR po liftingu** lub wyniku dekompilatora, gdy wyizolujesz już dokładne obliczenie.
- Używaj jawnie `--bitwidth`, gdy wyrażenie pochodzi z operacji maskowanych lub rejestrów o mniejszej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, zajrzyj do lokalnych notatek o Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępny jako **plugin pass LLVM** (`libCobraPass.so`), co jest przydatne, gdy chcesz znormalizować IR LLVM zawierający dużo MBA przed uruchomieniem późniejszych passów analizy.
- Nieobsługiwane reszty mieszanych domen zależne od przeniesienia należy traktować jako sygnał, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Szczegóły:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych binariów [demovfuscator](https://github.com/kirschju/demovfuscator) może zdeobfuskować wynik. Ma kilka zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Oraz [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje zawierające `::main`, jak na przykładzie:

![Znajdowanie punktu wejścia Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nazywał się authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **dane wejściowe** i **wyjściowe**.

### Odzyskiwanie ciągów znaków Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone znakiem NUL w stylu C. Typowy układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągu znaków przechowywany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidra mogą scalać sąsiadujące ciągi znaków albo całkowicie pomijać odwołania krzyżowe.<sup>[[3]](#references)</sup>

Szybki przepływ pracy:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar sekcji **`.rodata`**.
2. Enumeruj **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako kandydat na wskaźnik do ciągu znaków.
4. Traktuj następne słowo jako kandydat na długość.
5. Zastosuj filtry poprawności (na przykład zachowaj długości od **4** do **100** bajtów).
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

Jest to szczególnie przydatne przy reversing firmware, ponieważ odzyskane ciągi znaków Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, handlery poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykryje tych ciągów, uruchom własny skrypt/plugin, który zastosuje tę samą heurystykę i utworzy dane typu string pod wskazanymi offsetami `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners są dobrymi przykładami pokazującymi, jak dostosować ten pomysł do innych **rozmiarów słowa, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binariów skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reversing binarium Delphi, sugeruję użycie pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Ten plugin uruchomi binarium i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a na początku właściwego kodu zadziała breakpoint.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

W przypadku zwykłych binariów Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury runtime i poprawić nazwy funkcji w IDA. Załaduj jego plugin Python za pomocą **Alt+F7**.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet oczyszczony z symboli plik wykonywalny Go nadal potrzebuje metadanych runtime, aby mapować liczniki programu na funkcje. [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i analizuje struktury takie jak `pclntab` i `moduledata`, korzystając z kodu pochodzącego z runtime Go. Pozwala to odzyskać granice funkcji, nazwy, ścieżki źródłowe, typy i szczegóły kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator może pozostawić te struktury użyteczne, zastępując odzyskane nazwy. Na przykład Garble hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o kompilacji, module i debugowaniu.<sup>[[12]](#references)</sup> Obfuskowany token pakietu musi pozostać taki sam w funkcjach z tego pakietu. Grupuj funkcje według powtarzającego się tokenu, wywnioskuj nazwę jednego pakietu na podstawie jego funkcji wywoływanych, ciągów i API, a następnie przypisz tę nazwę całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli runtime’u z generowaniem czystych plików referencyjnych i dopasowywaniem grafów przepływu sterowania (CFG). Zastosuj następującą kolejność:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuscator je usunął, porównaj fragmenty dołączonego runtime’u Go z referencyjnymi runtime’ami dla poszczególnych wersji. W testach Volexity około `2%` runtime’u wystarczyło, by rozróżnić główne wersje Go. Traktuj to jako optymalizację potwierdzoną empirycznie, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj dopasowane pliki referencyjne.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, architektury docelowej i prawdopodobnych bibliotek. Dopasowanie toolchaina ogranicza różnice w CFG generowanym przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje CFG funkcji i zwraca znormalizowane wyniki w zakresie od `0.0` do `1.0`. Dopasowanie bloków podstawowych opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności mapują losowo nazwane funkcje na ich czyste implementacje. Słabsze dopasowania mogą nadal wskazać pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy, sprawdzając relacje wywołań, stałe, ciągi i skutki uboczne, a następnie zaimportuj raport JSON za pomocą pluginu GoResolver dla IDA lub Ghidry.<sup>[[10]](#references)[[13]](#references)</sup>

Zainstaluj toolchain i uruchom połączony ekstraktor oraz dopasowywacz grafów:<sup>[[10]](#references)</sup>

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

Domyślny próg istotnego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają wyodrębnić każdy z etapów, a domyślnie uruchamiane są oba, ponieważ odzyskane metadane środowiska uruchomieniowego i informacje z CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG są heurystyczne: inlining, flagi kompilacji, architektura i różnice między wersjami bibliotek mogą zmieniać strukturę grafu, dlatego pozostaw nierozpoznane funkcje zamiast przypisywać im nazwy przy niskim poziomie pewności.<sup>[[13]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje, jak uzyskać kod Python z pliku binarnego ELF/EXE skompilowanego z użyciem Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli zdobędziesz **plik binarny** gry na GBA, możesz użyć różnych narzędzi, aby ją **emulować** i **debugować**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz sprawdzić, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja sterowania no$gba pokazująca przypisanie przycisków Game Boy Advance](<../../images/image (581).png>)

Każdy naciśnięty **klawisz ma wartość**, która pozwala go zidentyfikować:

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

W tego rodzaju programie interesujące będzie **to, jak program obsługuje dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidry pliku binarnego GBA odwołującego się do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

Na poprzednim obrazie widać, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po kilku operacjach inicjalizacyjnych (które nie mają znaczenia):

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

Znaleziono taki kod:

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

Ostatni if sprawdza, czy **`uVar4`** znajduje się w **ostatnich Keys** i nie jest bieżącym klawiszem, czyli czy przycisk został puszczony (bieżący klawisz jest przechowywany w **`uVar1`**).

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

- Najpierw jest porównywana z **wartością 4** (przycisk **SELECT**): w tym wyzwaniu ten przycisk czyści ekran
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony code jest prawidłowy.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartości są takie same, wykonywany jest pewien kod.
- W każdym innym przypadku sprawdzany i zwiększany jest licznik (`DAT_030000d4`).\
  Dopóki licznik jest mniejszy niż 8, wartości wciśniętych przycisków są sumowane w `DAT_030000d8`.

W tym wyzwaniu, znając wartości przycisków, trzeba było **wcisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło do tego tutoriala:** [zarchiwizowany opis rozwiązania wyzwania Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacja plików binarnych)

## References

- [1] [Upraszczanie obfuskacji MBA za pomocą CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repozytorium CoBRA firmy Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodowanie ciągów znaków Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - ciągi znaków Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversingu GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Udaremnianie reverse engineeringu wspomaganego przez AI, a przynajmniej próby jego udaremnienia](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania na podstawie dopasowywania bloków podstawowych](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: wykorzystanie podobieństwa grafów przepływu sterowania do automatycznej deobfuskacji plików binarnych Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
