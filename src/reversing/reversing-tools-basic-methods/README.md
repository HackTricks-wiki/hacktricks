# Narzędzia do reverse engineeringu i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do reverse engineeringu oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugowanie jądra Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** wasm (binarne) do wat (czytelny tekst)
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

Zaletą tego narzędzia jest to, że może zaoszczędzić czas, jeśli trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu. Ponadto dotPeek ułatwia nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do dokładnych potrzeb, .NET Reflector oszczędza czas i upraszcza tworzenie oprogramowania. Przyjrzyjmy się licznym możliwościom reverse engineeringu, jakie oferuje to narzędzie:

- Pokazuje przepływ danych przez bibliotekę lub komponent
- Pokazuje implementację i sposób użycia języków oraz frameworków .NET
- Wyszukuje nieudokumentowane i nieudostępnione funkcje, aby umożliwić pełniejsze wykorzystanie używanych API i technologii.
- Wyszukuje zależności i różne zestawy
- Znajduje dokładne miejsce wystąpienia błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz używać jej na dowolnym systemie operacyjnym (możesz zainstalować ją bezpośrednio z VSCode, nie musisz pobierać repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub jego aktywnie rozwijanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Logowanie w DNSpy

Aby **DNSpy zapisywał wybrane informacje do pliku**, możesz użyć tego fragmentu kodu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie w DNSpy

Aby debugować kod za pomocą DNSpy, należy:

Najpierw zmienić **atrybuty Assembly** związane z **debugowaniem**:

![DNSpy Logging - Debugowanie w DNSpy: Najpierw zmień atrybuty Assembly związane z debugowaniem](<../../images/image (973).png>)

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

I kliknij **kompiluj**:

![DNSpy Logging - DNSpy Debugging: I kliknij kompiluj](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik, wybierając _**Plik >> Zapisz moduł...**_:

![DNSpy Logging - DNSpy Debugging: Następnie zapisz nowy plik, wybierając Plik Zapisz moduł](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **runtime** do kodu zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **punkt przerwania nigdy nie zostanie osiągnięty** albo **niektóre zmienne nie będą istnieć**.

Następnie, jeśli Twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i na karcie **Debug** wybierz **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i na karcie Debug wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **serwera IIS**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby podłączyć się do serwera IIS, i kliknij attach](<../../images/image (113).png>)

Skoro debugujemy już proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Skoro debugujemy już proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Skoro debugujemy już proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i wybierz **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i wybierz Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL-ów

### Z użyciem IDA

- **Załaduj rundll32** (64-bitowy znajduje się w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugowanie DLL-ów - Z użyciem IDA: Wybierz „Suspend on library load/unload”](<../../images/image (868).png>)

- Skonfiguruj **parametry** wykonania, podając **ścieżkę do DLL-a** i funkcję, którą chcesz wywołać:

![Debugowanie DLL-ów - Z użyciem IDA: Skonfiguruj parametry wykonania, podając ścieżkę do DLL-a i funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **wykonanie zostanie zatrzymane po załadowaniu każdej DLL**. Gdy rundll32 załaduje Twój DLL, wykonanie zostanie zatrzymane.

Ta metoda zatrzymuje wykonanie przy zdarzeniach ładowania modułów, ale dotarcie do punktu wejścia załadowanego DLL-a jest mniej bezpośrednie niż w opisanym niżej sposobie z x64dbg.

### Z użyciem x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy znajduje się w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień wiersz polecenia** ( _File --> Change Command Line_ ) i podaj ścieżkę do DLL-a oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień ustawienie _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **uruchom wykonanie**. Debugger zatrzyma się przy każdym dll main; w pewnym momencie **zatrzymasz się w punkcie wejścia swojego DLL-a**. Następnie wyszukaj miejsca, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonanie zostanie z jakiegokolwiek powodu zatrzymane w win64dbg, **u góry okna win64dbg** możesz sprawdzić, **w którym kodzie jesteś**:

![Z użyciem IDA - Z użyciem x64dbg/x32dbg: Zauważ, że gdy wykonanie zostanie z jakiegokolwiek powodu zatrzymane w win64dbg, u góry okna win64dbg możesz sprawdzić, w którym kodzie jesteś](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonanie zostało zatrzymane wewnątrz DLL-a, który chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do wyszukiwania ważnych wartości zapisanych w pamięci działającej gry i zmieniania ich. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie typu front-end do GNU Project Debugger (GDB) i reverse engineeringu, przeznaczone głównie do gier. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end do wielu dekompilatorów. Ta usługa internetowa umożliwia porównanie wyników różnych dekompilatorów dla małych plików wykonywalnych.

## ARM i MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres w pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie wydań GitHub znajdują się archiwa ZIP ze skompilowanymi wersjami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie go zbuduj**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie jak BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 sekund**, zatrzymaj je wewnątrz tej pętli i przejdź do następnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger zatrzymany w nieskończonej pętli jmp2it, tuż przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Cutter umożliwia emulację shellcode i jego dynamiczną analizę.

Pamiętaj, że Cutter umożliwia użycie opcji „Open File” i „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode — nie:

![Cutter pokazuje różne wyniki analizy tych samych bajtów otwartych jako plik lub jako shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp — Cutter najwyraźniej automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter zatrzymany na wybranym breakpoincie shellcode](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie stosu emulowanego shellcode w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Usuwanie obfuskacji shellcode i ustalanie wywoływanych funkcji

Warto wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Poinformuje Cię między innymi, **jakich funkcji** używa shellcode oraz czy **dekoduje** się on w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg oferuje również graficzny launcher, w którym możesz wybrać żądane opcje i uruchomić shellcode

![Graficzny launcher scDbg do wyboru opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli jego zawartość zostanie zmieniona dynamicznie w pamięci (przydatne do pobrania zdekodowanego shellcode). **start offset** może się przydać, jeśli chcesz rozpocząć wykonywanie shellcode od określonego offsetu. Opcja **Debug Shell** pozwala debugować shellcode w terminalu scDbg (jednak moim zdaniem lepiej sprawdzi się w tym celu jedna z wcześniej opisanych opcji, ponieważ będziesz móc użyć Ida lub x64dbg).

### Deasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższego przepisu, aby go zdeasemblować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących operacje arytmetyczne (`+`, `-`, `*`) i operatory bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyjścia dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenia liniowe z dodanymi stałymi maskami, takimi jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną transformację** za pomocą testów losowych lub dowodu SMT. Jeśli nie da się udowodnić równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omijanie spłaszczonego przepływu sterowania za pomocą wąskiego wycinka wykonania

Odzyskanie pełnego grafu przepływu sterowania często nie jest konieczne. W przypadku spłaszczania przepływu sterowania, nieprzezroczystych predykatów, dużych dyspozytorów lub kodu obciążonego MBA śledź odwołania od zaszyfrowanych blobów i buforów wyjściowych do najmniejszej rutyny, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych albo uruchom go niezależnie; dyspozytor nie jest potrzebny, jeśli odpowiedni stan można zainicjalizować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow:<sup>[[7]](#references)</sup>

1. Zinwentaryzuj sekcje kodu wykonywalnego i danych, relokacje oraz odwołania krzyżowe. Zrzuć kandydatów na tabele z `.rodata`, zachowując kolejność bajtów i szerokość elementów.
2. Zidentyfikuj ostatnią rutynę zapisującą tekst jawny lub bufor wyjściowy. Zanotuj jej dane wejściowe, referencjonowane tabele, wywołania importowane i wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Python o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt dużej ilości stanu, wywołaj rutynę w Unicorn, QEMU lub debuggerze i hookuj nieistotne importy zamiast emulować cały program.
4. Sprawdź, czy ekstraktor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche fallbacki, wyszukaj w nim osadzone odpowiedzi i uruchom go na nieznanych kompilacjach ze zmienionymi ciągami, kluczami, identyfikatorami, układami i seedami obfuskacji.

Przydatne polecenia do wstępnej analizy:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywanie wyrażeń MBA ukrywających stałe

Pozornie zależne od wejścia wyrażenie bajtowe może całkowicie eliminować wpływ wejścia. Po wyodrębnieniu jego tabel oblicz wartość wyrażenia dla całej 8-bitowej dziedziny; jednoelementowy zbiór wyników dowodzi, że bajt jest stały, bez konieczności odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ w oryginalnym dodawaniu występuje zawijanie wartości przy szerokości bajtu. Dla szerszej domeny zapytaj solver SMT, czy dla dwóch symbolicznych wejść o tej samej szerokości spełnialne jest `f(x1) != f(x2)`: `unsat` dowodzi niezmienności, a `sat` dostarcza kontrprzykład i oznacza, że nie można odrzucić wejścia.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole anti-analysis nie muszą powodować skoku ani awarii. Dekoder może domieszać wynik odczytu z sensora do bitu klucza, stałej opaque predicate lub stanu flattened dispatcher, działać dalej i wygenerować wiarygodny, ale fałszywy tekst jawny w emulatorze. Dlatego samo patchowanie widocznych gałęzi błędu nie wystarczy; śledź zależności danych od sond środowiskowych do stanu dekodera, porównuj ten sam wycinek na autentycznym urządzeniu i w emulatorze oraz sprawdzaj, jak wymuszenie każdego wyniku odczytu z sensora zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA, przydatne w analizie malware i reverse engineeringu zabezpieczonych plików binarnych. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków przetwarzania, zamiast stosować do wszystkiego jeden ogólny przebieg przepisywania.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wyrażenie dla wejść boolowskich, wyznacza sygnaturę i uruchamia równolegle kilka metod odzyskiwania, takich jak pattern matching, konwersja ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy maskowane stałą są odtwarzane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu maskowane obszary pozostają poprawne.
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

- Uruchamiaj CoBRA na **wyrażeniach lifted IR** lub wyniku dekompilatora po wyodrębnieniu dokładnego obliczenia.
- Używaj jawnie `--bitwidth`, jeśli wyrażenie pochodzi z arytmetyki maskowanej lub rejestrów o małej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, zajrzyj do lokalnych notatek o Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępny jako **plugin LLVM pass** (`libCobraPass.so`), przydatny do normalizacji IR LLVM obciążonego MBA przed późniejszymi passami analizy.
- Nieobsługiwane reszty mieszanych domen zależne od przeniesienia należy traktować jako sygnał, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Szczegóły:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych plików binarnych narzędzie [demovfuscator](https://github.com/kirschju/demovfuscator) może cofnąć obfuscation. Ma kilka zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli bierzesz udział w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje po `::main`, tak jak tutaj:

![Znajdowanie punktu wejścia programu Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nazywał się authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Znając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **dane wejściowe** i **wyniki**.

### Odzyskiwanie ciągów znaków Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone znakiem NUL w stylu C. Często spotykany układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągu znaków zapisany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidry mogą scalać sąsiadujące ciągi znaków albo całkowicie pomijać odwołania krzyżowe.<sup>[[3]](#references)</sup>

Szybki workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar sekcji **`.rodata`**.
2. Przejdź przez **`.data.rel.ro`** słowo maszynowe po słowie maszynowym.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako kandydata na wskaźnik do ciągu znaków.
4. Traktuj następne słowo maszynowe jako kandydata na długość.
5. Zastosuj filtry poprawności (na przykład zachowaj długości od **4** do **100** bajtów).
6. Odczytaj dokładnie `length` bajtów z `.rodata`, zamiast skanować do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Jest to szczególnie przydatne podczas reversing firmware, ponieważ odzyskane ciągi znaków Rust często ujawniają **ścieżki HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, procedury obsługi poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykrywa tych ciągów, uruchom niestandardowy skrypt/wtyczkę, która stosuje tę samą heurystykę i tworzy dane typu string pod wskazanymi offsetami `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners są dobrym punktem odniesienia przy dostosowywaniu tego podejścia do innych **rozmiarów słów, endianowości i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binariów skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reverse engineering binarium Delphi, polecam użyć wtyczki do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować wtyczkę Python, a następnie wybierz plik wtyczki.

Wtyczka uruchomi binarium i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a punkt przerwania zostanie osiągnięty na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

Jeśli musisz przeprowadzić reverse engineering binarium Golang, polecam użyć wtyczki do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować wtyczkę Python, a następnie wybierz plik wtyczki.

Spowoduje to rozwiązanie nazw funkcji.

## Skompilowany Python

Na tej stronie znajdziesz informacje, jak uzyskać kod Python z binarium ELF/EXE skompilowanego z Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli masz **binarium** gry na GBA, możesz użyć różnych narzędzi do jej **emulowania** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - wtyczka do Ghidry
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - wtyczka do Ghidry

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz sprawdzić, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja sterowania no$gba pokazująca przypisania przycisków Game Boy Advance](<../../images/image (581).png>)

Każdy naciśnięty **klawisz ma wartość**, która go identyfikuje:

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

W takim programie interesujące będzie **to, jak program przetwarza dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidry przedstawiający odwołanie binarium GBA do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

Na poprzednim obrazie widać, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

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

Ostatni warunek if sprawdza, czy **`uVar4`** znajduje się wśród **ostatnich klawiszy** i nie jest bieżącym klawiszem, czyli czy przycisk został puszczony (bieżący klawisz jest przechowywany w **`uVar1`**).

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

- Najpierw jest porównywany z **wartością 4** (przycisk **SELECT**): w tym wyzwaniu ten przycisk czyści ekran.
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony kod jest prawidłowy.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3. Jeśli wartości są takie same, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany i zwiększany jest licznik (`DAT_030000d4`).\
  Gdy licznik jest mniejszy niż 8, wartości naciśniętych przycisków są sumowane w `DAT_030000d8`.

Zatem w tym wyzwaniu, znając wartości przycisków, należało **nacisnąć kombinację krótszą niż 8 przycisków, której suma wyniesie 0xf3.**

**Źródło do tego poradnika:** [archiwalny opis rozwiązania wyzwania Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacja plików binarnych)

## References

- [1] [Upraszczanie obfuskacji MBA za pomocą CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repozytorium Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Dekodowanie ciągów znaków w Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - ciągi znaków w Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - poradnik reversing dla GBA (archiwalny)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie wspomaganego przez AI reverse engineeringu, a przynajmniej próby jego pokonania](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
