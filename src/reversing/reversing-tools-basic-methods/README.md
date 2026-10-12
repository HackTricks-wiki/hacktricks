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

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** wasm (plik binarny) do wat (czytelnego tekstu)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** wat do wasm
- Do dekompilacji możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Buforowany bytecode Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Zwirtualizowane payloady i niestandardowe VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego narzędzia jest to, że jeśli trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu, może to zaoszczędzić czas. Ponadto dotPeek ułatwia nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza programowanie. Przyjrzyjmy się licznym możliwościom reverse engineeringu oferowanym przez to narzędzie:

- Pokazuje, jak dane przepływają przez bibliotekę lub komponent
- Pokazuje implementację i zastosowanie języków oraz frameworków .NET
- Wykrywa nieudokumentowane i nieudostępnione funkcje, aby lepiej wykorzystać używane interfejsy API i technologie.
- Wykrywa zależności i różne zestawy
- Pozwala dokładnie ustalić miejsce występowania błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Można jej używać w dowolnym systemie operacyjnym (można ją zainstalować bezpośrednio z VSCode, bez pobierania git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie rozwijanego forka tego narzędzia — [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Logowanie w DNSpy

Aby **DNSpy zapisywał informacje w pliku**, możesz użyć tego fragmentu kodu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie w DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Najpierw zmienić **Assembly attributes** związane z **debugowaniem**:

![Rejestrowanie w DNSpy — debugowanie w DNSpy: najpierw zmień Assembly attributes związane z debugowaniem](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik za pomocą _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **uruchamiania** kod zostanie poddany różnym **optymalizacjom** i może się zdarzyć, że podczas debugowania **breakpoint nigdy nie zostanie osiągnięty** albo niektóre **zmienne nie będą istnieć**.

Następnie, jeśli Twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w **Debug Tab** wybierz **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w Debug Tab wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Wybierz w3wp.exe, aby dołączyć do IIS server, i kliknij attach](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i wybierz **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i wybierz Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL-i

### Używanie IDA

- **Załaduj rundll32** (64-bitowy w C:\Windows\System32\rundll32.exe i 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugowanie DLL-i - Używanie IDA: Wybierz „Suspend on library load/unload”](<../../images/image (868).png>)

- Skonfiguruj **parametry** uruchomienia, podając **ścieżkę do DLL** i funkcję, którą chcesz wywołać:

![Debugowanie DLL-i - Używanie IDA: Skonfiguruj parametry uruchomienia, podając ścieżkę do DLL i funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **wykonywanie zostanie zatrzymane przy załadowaniu każdej DLL**. Gdy rundll32 załaduje Twoją DLL, wykonywanie również zostanie zatrzymane.

Ta metoda zatrzymuje wykonywanie przy zdarzeniach ładowania modułów, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym poniżej sposobie z x64dbg.

### Używanie x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy w C:\Windows\System32\rundll32.exe i 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień wiersz poleceń** (_File --> Change Command Line_) i podaj ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **uruchom wykonywanie**. Debugger zatrzyma się przy każdej funkcji dll main; w pewnym momencie **zatrzyma się w punkcie wejścia Twojej DLL**. Następnie znajdź miejsca, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonywanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, **w jakim kodzie się znajdujesz**, patrząc na **górną część okna win64dbg**:

![Używanie IDA - Używanie x64dbg/x32dbg: Gdy wykonywanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, w jakim kodzie się znajdujesz, patrząc na górną część okna win64dbg](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonywanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do wyszukiwania ważnych wartości zapisanych w pamięci uruchomionej gry i zmieniania ich. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie typu front-end do reverse engineeringu dla GNU Project Debugger (GDB), przeznaczone głównie do gier. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end dla wielu dekompilatorów. Ta usługa internetowa pozwala porównywać wyniki różnych dekompilatorów dla małych plików wykonywalnych.

## ARM i MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres w pamięci** i wstrzymuje wykonywanie.\
Dołącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonywanie, aby debugować shellcode.

Strona z wydaniami GitHub zawiera archiwa ZIP ze skompilowanymi wersjami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie zbuduj projekt**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Dołącz debugger, wznów wykonywanie na **2–5 sekund**, zatrzymaj je wewnątrz tej pętli i przejdź do następnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger zatrzymany w nieskończonej pętli jmp2it, tuż przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony z wydaniami](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to graficzny interfejs radare. Cutter umożliwia emulowanie shellcode i jego dynamiczną analizę.

Cutter pozwala wybrać „Open File” lub „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode już nie:

![Cutter pokazuje różne wyniki analizy po otwarciu tych samych bajtów jako pliku lub shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp. Wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter zatrzymany na wybranym breakpoincie shellcode](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie stosu emulowanego shellcode w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Usuwanie obfuskacji shellcode i identyfikowanie wywoływanych funkcji

Warto wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokaże między innymi, **których funkcji** używa shellcode i czy **dekoduje się** w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ma również graficzny launcher, w którym możesz wybrać żądane opcje i uruchomić shellcode

![Graficzny launcher scDbg do wybierania opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli w pamięci zostaną wprowadzone jakiekolwiek dynamiczne zmiany (przydatne do pobrania zdekodowanego shellcode). **Start offset** może się przydać do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** pozwala debugować shellcode za pomocą terminala scDbg (jednak uważam, że lepiej sprawdzą się w tym celu omówione wcześniej opcje, ponieważ umożliwiają użycie Ida lub x64dbg).

### Deasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższej receptury, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Usuwanie obfuskacji MBA

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących operatory arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyjścia dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenie liniowe plus stałe maski, takie jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną transformację** za pomocą losowych testów lub dowodu SMT. Jeśli nie da się udowodnić równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omiń spłaszczony przepływ sterowania, analizując wąski wycinek wykonania

Odtworzenie kompletnego grafu przepływu sterowania często nie jest konieczne. W przypadku control-flow flattening, opaque predicates, dużych dispatcherów lub kodu intensywnie wykorzystującego MBA prześledź odwołania od zaszyfrowanych blobów i buforów wyjściowych do najmniejszej procedury, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych albo uruchom go niezależnie; dispatcher nie jest częścią wymaganego rozwiązania, jeśli odpowiedni stan można zainicjować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow:<sup>[[7]](#references)</sup>

1. Sporządź wykaz sekcji wykonywalnych i danych, relokacji oraz odwołań krzyżowych. Zrzucaj kandydackie tablice z `.rodata`, zachowując ich kolejność bajtów i szerokość elementów.
2. Znajdź ostatnią procedurę, która zapisuje tekst jawny lub bufor wyjściowy. Zapisz jej dane wejściowe, używane tablice, wywołania importowanych funkcji oraz wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Python o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt dużej ilości stanu, wywołaj procedurę w Unicorn, QEMU lub debuggerze i przechwytuj nieistotne importy zamiast emulować cały program.
4. Sprawdź, czy ekstraktor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche wartości zapasowe, wyszukaj osadzone odpowiedzi i uruchom go na nieznanych kompilacjach ze zmienionymi ciągami znaków, kluczami, identyfikatorami, układami i ziarnami obfuskacji.

Przydatne polecenia do wstępnej analizy:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywaj wyrażenia MBA ukrywające stałe

Pozornie zależne od wejścia wyrażenie bajtowe może całkowicie eliminować swoje wejście. Po wyodrębnieniu tablic oblicz wartość wyrażenia dla całej 8-bitowej domeny; jednoelementowy zbiór wyników dowodzi, że bajt jest stały, bez konieczności odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie zawija się do szerokości bajtu. Dla szerszej domeny zapytaj solver SMT, czy dla dwóch wejść symbolicznych o tej samej szerokości spełnialne jest `f(x1) != f(x2)`: `unsat` dowodzi niezmienności, a `sat` dostarcza kontrprzykład i oznacza, że nie można odrzucić wejścia.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole anti-analysis nie muszą powodować skoku ani awarii. Dekoder może połączyć wynik odczytu sensora z bitem klucza, stałą opaque predicate lub stanem flattened-dispatchera, działać dalej i wygenerować wiarygodny, lecz fałszywy tekst jawny w emulatorze. Dlatego samo patchowanie widocznych gałęzi błędu nie wystarczy; śledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam wycinek na autentycznym urządzeniu i w emulatorze oraz sprawdź, jak wymuszenie każdego wyniku sensora zmienia bufor końcowy.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA, przeznaczone do analizy malware i reverse engineeringu chronionych binariów. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków zamiast stosować jeden ogólny przebieg przekształceń do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wyrażenie dla wejść boolowskich, wyprowadza sygnaturę i uruchamia równolegle kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy z maskami stałych są odtwarzane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane obszary pozostają poprawne.
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

- Preferuj uruchamianie CoBRA na **wyrażeniach IR po liftingu** lub na wynikach dekompilacji, gdy wyizolujesz już dokładne obliczenie.
- Używaj jawnie `--bitwidth`, jeśli wyrażenie pochodzi z arytmetyki z maskowaniem lub z rejestrów o węższej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, sprawdź lokalne notatki dotyczące Z3 tutaj:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępne jako **plugin LLVM pass** (`libCobraPass.so`), przydatny do normalizowania IR LLVM z dużą ilością MBA przed późniejszymi etapami analizy.
- Nieobsługiwane reszty mieszanych dziedzin, wrażliwe na przeniesienia, należy traktować jako sygnał, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Więcej informacji:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych plików binarnych narzędzie [demovfuscator](https://github.com/kirschju/demovfuscator) może usunąć obfuscation. Wymaga kilku zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Oraz [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **entry point**, wyszukaj funkcje po `::main`, jak na przykładzie:

![Znajdowanie entry point w Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nazywał się authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Znając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **dane wejściowe** i **wyjściowe**.

### Odzyskiwanie ciągów znaków Rust z firmware’u ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone znakiem NUL, jak w C. Częsty układ generowany przez `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągów znaków zapisany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidry mogą łączyć sąsiadujące ciągi znaków albo całkowicie pomijać odwołania.<sup>[[3]](#references)</sup>

Szybki proces:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar sekcji **`.rodata`**.
2. Przejdź przez **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako potencjalny wskaźnik do ciągu znaków.
4. Traktuj następne słowo jako potencjalną długość.
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

Jest to szczególnie przydatne przy reversing firmware, ponieważ odzyskane ciągi znaków Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty dziennika, asercje, nazwy plików, klucze konfiguracji, handlery poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykryje tych ciągów, uruchom własny skrypt/plugin, który zastosuje tę samą heurystykę i utworzy dane typu string pod wskazanymi offsetami w `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners to dobre przykłady do dostosowania tego pomysłu do innych **rozmiarów słowa, endianowości i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku skompilowanych plików binarnych Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reverse engineering pliku binarnego Delphi, polecam użyć pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Plugin uruchomi plik binarny i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony przycisk lub f9), a breakpoint zatrzyma wykonanie na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

W przypadku standardowych plików binarnych Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury runtime i poprawić nazwy funkcji w IDA. Załaduj jego plugin Python, naciskając **Alt+F7**.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet stripped plik wykonywalny Go potrzebuje metadanych runtime, aby mapować liczniki programu na funkcje. Narzędzie [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i parsuje struktury, takie jak `pclntab` i `moduledata`, wykorzystując kod oparty na runtime Go. Pozwala to odzyskać granice funkcji, nazwy, ścieżki źródłowe, typy i informacje o kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuskator może pozostawić te struktury użyteczne, zastępując odzyskane nazwy. Na przykład Garble hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o buildzie, module i debugowaniu.<sup>[[12]](#references)</sup> Token obfuskowanego pakietu musi być spójny w funkcjach pochodzących z tego pakietu. Grupuj funkcje według powtarzającego się tokenu, wywnioskuj nazwę jednego pakietu na podstawie jego funkcji wywoływanych, ciągów znaków i API, a następnie przypisz tę nazwę całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli runtime z generowaniem czystych referencji i dopasowywaniem grafów przepływu sterowania (CFG). Wykonaj kolejno następujące kroki:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuskator je usunął, porównaj fragmenty dołączonego Go runtime z runtime’ami referencyjnymi dla poszczególnych wersji. W testach Volexity około `2%` runtime’u wystarczyło do rozróżnienia głównych wersji Go. Potraktuj to jako empiryczną optymalizację, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj pasujące referencje.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, architektury docelowej i prawdopodobnych bibliotek. Dopasowanie toolchainu ogranicza różnice CFG generowane przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje grafy CFG funkcji i generuje znormalizowane wyniki od `0.0` do `1.0`. Dopasowywanie podstawowych bloków opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności pozwalają powiązać funkcje o losowych nazwach z czystą implementacją. Słabsze dopasowania nadal mogą wskazać pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy na podstawie relacji wywołań, stałych, ciągów znaków i efektów ubocznych, a następnie zaimportuj raport JSON za pomocą pluginu GoResolver dla IDA lub Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Zainstaluj toolchain i uruchom połączony ekstraktor oraz matcher grafów:<sup>[[10]](#references)</sup>

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

Domyślny próg istotnego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają wyodrębnić każdy z tych etapów, natomiast domyślnie uruchamiane są oba, ponieważ odzyskane metadane runtime i dane CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG są heurystyczne: inlining, flagi kompilacji, architektura i różnice między wersjami bibliotek mogą zmieniać kształt grafu, dlatego pozostawiaj nierozpoznane funkcje bez nazw, zamiast przypisywać im nazwy przy niskim poziomie pewności.<sup>[[13]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje o tym, jak odzyskać kod Pythona z pliku binarnego ELF/EXE skompilowanego z użyciem Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli zdobędziesz **plik binarny** gry na GBA, możesz użyć różnych narzędzi do jej **emulacji** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz sprawdzić, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja przycisków no$gba pokazująca mapowanie przycisków Game Boy Advance](<../../images/image (581).png>)

Po naciśnięciu każdy **klawisz ma wartość**, która go identyfikuje:

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

W tego rodzaju programie interesujące będzie więc **to, jak program obsługuje dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidry przedstawiający odwołanie pliku binarnego GBA do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

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

Ostatni if sprawdza, czy **`uVar4`** znajduje się w **last Keys** i nie jest bieżącym klawiszem, czyli czy przycisk został zwolniony (bieżący klawisz jest przechowywany w **`uVar1`**).

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

- Najpierw jest porównywana z **wartością 4** (przycisk **SELECT**): w tym wyzwaniu ten przycisk czyści ekran.
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony kod jest poprawny.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartości są takie same, wykonywany jest kod.
- W każdym innym przypadku sprawdzany i zwiększany jest licznik (`DAT_030000d4`).\
  Dopóki licznik jest mniejszy niż 8, wartości naciśniętych przycisków są sumowane w `DAT_030000d8`.

Zatem w tym wyzwaniu, znając wartości przypisane przyciskom, trzeba było **nacisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło tego tutorialu:** [zarchiwizowany opis rozwiązania wyzwania Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacja binarna)

## References

- [1] [Upraszczanie obfuskacji MBA za pomocą CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repozytorium CoBRA Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodowanie ciągów znaków w Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - ciągi znaków w Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reverse engineering GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie reverse engineeringu wspomaganego przez AI, a przynajmniej próby](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania oparte na dopasowywaniu podstawowych bloków](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: automatyczna deobfuskacja binariów Golang z wykorzystaniem podobieństwa grafów przepływu sterowania](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
