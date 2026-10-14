# Narzędzia do reverse engineeringu i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do reverse engineeringu oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatyzacja WinDbg w trybie użytkownika

{{#ref}}
windbg-automation.md
{{#endref}}

## Debugowanie jądra Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** Wasm (binarny) do Wat (czytelny tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** Wat do Wasm
- Do dekompilacji możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode z cache Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Zwirtualizowane payloady i niestandardowe maszyny wirtualne

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) i **pliki wykonywalne** (.exe). Po dekompilacji zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego rozwiązania jest możliwość zaoszczędzenia czasu, gdy trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza proces tworzenia oprogramowania. Przyjrzyjmy się licznym możliwościom reverse engineeringu oferowanym przez to narzędzie:

- Umożliwia sprawdzenie, jak dane przepływają przez bibliotekę lub komponent
- Umożliwia wgląd w implementację i sposób użycia języków oraz frameworków .NET
- Wyszukuje nieudokumentowane i nieudostępnione funkcje, aby lepiej wykorzystać używane API i technologie.
- Wyszukuje zależności i różne zestawy
- Wskazuje dokładne miejsce występowania błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Można jej używać w dowolnym systemie operacyjnym (można ją zainstalować bezpośrednio z VSCode, bez pobierania repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub jego aktywnie rozwijanej forki, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Inspekcja kodu zarządzanego bez wykonywania go za pomocą REA

**REA** umożliwia inspekcję metadanych PE/CLI i CIL bez ładowania zestawu. Zacznij od ustalenia tożsamości artefaktu, a następnie sprawdź elementy składowe i zadeklarowane granice kodu natywnego; jest to przydatne podczas analizy podejrzanych wywołań przed użyciem dekompilatora lub uruchomieniem programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Do porównywania różnic między wersjami `compare_managed_members` używa surowej tożsamości CIL/podpisu i fingerprintów zdekodowanych instrukcji, zamiast traktować tokeny metadanych jako stabilne między kompilacjami. Deklaracja P/Invoke nie jest dowodem na wykonanie kodu natywnego; `verify_managed_native_boundaries` wymaga pasującego eksportu natywnego lub dowodu dotyczącego funkcji, aby sprawdzić tę granicę. Zachowaj digest artefaktu, MVID i nierozwiązane mapowania razem z wynikiem.<sup>[[17]](#references)</sup>

### DNSpy Logging

Aby **DNSpy zapisywał pewne informacje do pliku**, możesz użyć tego fragmentu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie w DNSpy

Aby debugować kod za pomocą DNSpy, należy:

Najpierw zmienić **atrybuty zestawu** związane z **debugowaniem**:

![Rejestrowanie DNSpy — debugowanie w DNSpy: najpierw zmień atrybuty zestawu związane z debugowaniem](<../../images/image (973).png>)

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

Następnie zapisz nowy plik przez _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Następnie zapisz nowy plik przez File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ w przeciwnym razie podczas **runtime** w kodzie zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **breakpoint nie zostanie trafiony** lub **niektóre zmienne nie będą istnieć**.

Jeśli aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w **Debug Tab** wybierz **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w Debug Tab wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby dołączyć do IIS server, i kliknij attach](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, zatrzymaj go i załaduj wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, zatrzymaj go i załaduj wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, zatrzymaj go i załaduj wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i wybierz **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i wybierz Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Używanie IDA

- **Załaduj rundll32** (64-bitowy plik znajduje się w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parameters** wykonania, podając **path to the DLL** oraz funkcję, którą chcesz wywołać:

![Debugging DLLs - Using IDA: Skonfiguruj parameters wykonania, podając path to the DLL oraz funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **wykonanie zostanie zatrzymane przy każdym załadowaniu DLL**. Gdy rundll32 załaduje Twoją DLL, wykonanie zostanie zatrzymane.

Ta metoda zatrzymuje wykonanie przy zdarzeniach ładowania modułu, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w przypadku opisanego poniżej workflow x64dbg.

### Używanie x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy plik znajduje się w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień Command Line** (_File --> Change Command Line_) i podaj ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Wybierz _Options --> Settings_, a następnie "**DLL Entry**".
- Następnie **uruchom wykonanie**. Debugger zatrzyma się przy każdej funkcji dll main; w pewnym momencie **zatrzymasz się w punkcie wejścia swojej DLL**. Stamtąd znajdź miejsca, w których chcesz ustawić breakpoint.

Zwróć uwagę, że gdy wykonanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, **w jakim kodzie jesteś**, patrząc na **górną część okna win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Zwróć uwagę, że gdy wykonanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, w jakim kodzie jesteś, patrząc na górną część okna win64dbg](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania wartości zapisanych w pamięci uruchomionej gry i zmieniania ich. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie front-end/reverse engineering dla GNU Project Debugger (GDB), przeznaczone głównie do gier. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end dla wielu dekompilatorów. Ta usługa internetowa pozwala porównywać wyniki różnych dekompilatorów dla małych plików wykonywalnych.

## Analiza plików natywnych oparta na dowodach z użyciem REA

**REA** udostępnia analizę z Hopper, Ghidra i IDA za pośrednictwem CLI i MCP. Wymaga Node.js 22.x (co najmniej 22.19), 24.x (co najmniej 24.11) lub 26+, a także npm. Najpierw skonfiguruj istniejącego natywnego providera; sprawdź `rea providers --json` i jawnie wybierz providera, jeśli więcej niż jeden obsługuje dany cel. Zamiast `0x1000` poniżej użyj zaobserwowanej nazwy funkcji lub adresu z inwentarza.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Zacznij od ciągu funkcji lub symbolu, podążaj za referencjami i wywołującymi, a następnie sprawdź dossier wybranej funkcji i pseudokod za pomocą `rea decompile`. REA wiąże sesję z wybranym providerem, zamiast po cichu zastępować go po błędzie. Aby uzyskać powtarzalne wyniki zapytań, `--snapshot PATH` ponownie wykorzystuje wyłącznie zgodne bajty artefaktu, providera, ustawienia, operację i parametry; snapshot to lokalna pamięć podręczna, a nie zapisana baza danych providera. Zachowaj zwrócone Evidence i jawnie wskazane niewiadome, zamiast traktować wywnioskowane ścieżki lub tekst dekompilatora jak oryginalny kod źródłowy.<sup>[[16]](#references)[[18]](#references)</sup>

Informacje o punktach wejścia JavaScript/Electron prowadzących do natywnych dodatków znajdziesz w [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie wydań na GitHubie znajdują się archiwa ZIP ze skompilowanymi wersjami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, po prostu **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie go zbuduj**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i przechodzi do nieskończonej pętli. Podłącz debugger, wznów wykonanie na **2–5 sekund**, wstrzymaj je wewnątrz tej pętli i przejdź do kolejnego wywołania przekazującego wykonanie do zaalokowanego shellcode.

![Debugger wstrzymany w nieskończonej pętli jmp2it, bezpośrednio przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Za pomocą Cutter możesz emulować shellcode i analizować go dynamicznie.

Pamiętaj, że Cutter umożliwia wybranie opcji „Open File” lub „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode — nie:

![Cutter pokazujący różne wyniki analizy tych samych bajtów otwartych jako plik lub shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp — wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter wstrzymany na wybranym breakpoincie shellcode](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie stosu emulowanego shellcode w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Usuwanie obfuskacji shellcode i identyfikowanie wywoływanych funkcji

Warto wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokaże między innymi, **których funkcji** używa shellcode i czy **dekoduje** się on w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg oferuje również graficzny launcher, w którym możesz wybrać potrzebne opcje i wykonać shellcode

![Graficzny launcher scDbg do wyboru opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli w pamięci zostaną wprowadzone jakiekolwiek dynamiczne zmiany w shellcode (przydatne do pobrania zdekodowanego shellcode). **start offset** może się przydać do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** służy do debugowania shellcode za pomocą terminala scDbg (jednak uważam, że lepiej sprawdzi się w tym celu dowolna z wcześniej omówionych opcji, ponieważ umożliwia użycie Ida lub x64dbg).

### Dezasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższego przepisu, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacja obfuskacji MBA

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących operacje arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego mają znaczenie przeniesienia i przepełnienia:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyjścia dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie**, zanim spróbujesz je uprościć:
   - **Liniowe**: ważone sumy atomów bitowych
   - **Semiliniowe**: wyrażenie liniowe plus stałe maski, takie jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i logika bitowa są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każde proponowane przekształcenie** za pomocą testów losowych lub dowodu SMT. Jeśli nie da się udowodnić równoważności, pozostaw oryginalne wyrażenie zamiast zgadywać.

### Omiń spłaszczony przepływ sterowania za pomocą wąskiego wycinka wykonania

Odtworzenie całego grafu przepływu sterowania często nie jest konieczne. W przypadku control-flow flattening, nieprzezroczystych predykatów, dużych dispatcherów lub kodu pełnego MBA śledź odwołania od zaszyfrowanych bloków i buforów wyjściowych do najmniejszej funkcji, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych lub wykonaj go niezależnie; dispatcher nie jest potrzebny, jeśli wymagany stan można zainicjować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow:<sup>[[7]](#references)</sup>

1. Zrób inwentaryzację sekcji wykonywalnych i danych, relokacji oraz odwołań krzyżowych. Zrzucaj kandydatów na tablice z `.rodata`, zachowując kolejność bajtów i szerokość elementów.
2. Znajdź ostatnią funkcję zapisującą tekst jawny lub bufor wyjściowy. Zapisz jej argumenty, używane tablice, wywołania importowane oraz wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Pythona o stałej szerokości. Jeśli wycinek nadal zależy od zbyt dużej ilości stanu, wywołaj funkcję w Unicorn, QEMU lub debuggerze i przechwytuj nieistotne importy zamiast emulować cały program.
4. Sprawdź, czy ekstraktor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche mechanizmy awaryjne, wyszukaj w nim osadzone odpowiedzi i uruchom go na nieznanych wcześniej kompilacjach ze zmienionymi ciągami, kluczami, identyfikatorami, układami i ziarnami obfuskacji.

Przydatne polecenia do wstępnej analizy:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywanie wyrażeń MBA ukrywających stałe

Wyrażenie bajtowe, które pozornie zależy od danych wejściowych, może całkowicie eliminować wpływ tych danych. Po wyodrębnieniu tablic oblicz wartość wyrażenia dla całej 8-bitowej dziedziny; jednoelementowy zbiór wyników dowodzi, że ten bajt jest stały — bez odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie powoduje zawijanie do szerokości bajtu. Dla szerszej dziedziny zapytaj solver SMT, czy dla dwóch symbolicznych danych wejściowych o tej samej szerokości spełnialne jest `f(x1) != f(x2)`: `unsat` dowodzi niezmienności, a `sat` wskazuje kontrprzykład i oznacza, że nie można pominąć danych wejściowych.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole anti-analysis nie muszą powodować skoku ani awarii. Dekoder może włączyć wynik czujnika do bitu klucza, stałej opaque predicate lub stanu spłaszczonego dispatchera, działać dalej normalnie i wygenerować wiarygodny, ale fałszywy tekst jawny w emulatorze. Dlatego samo poprawienie widocznych gałęzi błędów nie wystarczy; śledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam wycinek na autentycznym urządzeniu i w emulatorze oraz sprawdź, jak wymuszenie każdego wyniku czujnika zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA na potrzeby analizy malware i reverse engineeringu zabezpieczonych binariów. Klasyfikuje wyrażenie i kieruje je przez wyspecjalizowane potoki zamiast stosować jeden ogólny przebieg przepisujący do wszystkiego.<sup>[[2]](#references)</sup>

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
- **Semilinear MBA**: atomy z maskami stałymi są odtwarzane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane obszary pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia można przenieść do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład tożsamości mieszanej, którą często warto spróbować odzyskać:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Można to sprowadzić do:

```c
x * y
```

### Notatki dotyczące reverse engineeringu

- Uruchamiaj CoBRA najlepiej na **wyrażeniach IR po liftingu** lub na wyjściu dekompilatora, gdy wyizolujesz już dokładne obliczenie.
- Używaj jawnie `--bitwidth`, gdy wyrażenie pochodzi z operacji maskowanych lub rejestrów o wąskiej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, sprawdź lokalne notatki dotyczące Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest też dostępny jako **plugin LLVM pass** (`libCobraPass.so`), co przydaje się, gdy chcesz znormalizować IR LLVM zawierające dużo MBA przed późniejszymi passami analizy.
- Nieobsługiwane reszty mieszanych dziedzin wrażliwe na przeniesienia należy traktować jako sygnał, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesień.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuskator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Szczegóły:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych plików binarnych narzędzie [demovfuscator](https://github.com/kirschju/demovfuscator) może zdeobfuskować wynik. Wymaga kilku zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [zainstaluj Keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, ten sposób na znalezienie flagi** może być bardzo przydatny: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje zawierające `::main`, jak na przykładzie:

![Znajdowanie punktu wejścia programu Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nazywał się authenticator, więc dość oczywiste jest, że to interesująca nas funkcja main.\
Znając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **wejścia** i **wyjścia**.

### Odzyskiwanie ciągów znaków Rust z firmware’u ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone znakiem NUL, jak w C. Typowy układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągu znaków przechowywany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidry mogą łączyć sąsiadujące ciągi znaków albo całkowicie pomijać odwołania.<sup>[[3]](#references)</sup>

Szybki przebieg pracy:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar sekcji **`.rodata`**.
2. Przejdź przez **`.data.rel.ro`** słowo maszynowe po słowie maszynowym.
3. Potraktuj każdą wartość z zakresu adresów `.rodata` jako kandydata na wskaźnik do ciągu znaków.
4. Potraktuj następne słowo jako kandydat na długość.
5. Zastosuj filtry sanity (na przykład zachowaj długości od **4** do **100** bajtów).
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

Jest to szczególnie przydatne podczas reversingu firmware, ponieważ odzyskane ciągi znaków Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, procedury obsługi poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykryje tych ciągów, uruchom niestandardowy skrypt/wtyczkę, która zastosuje tę samą heurystykę i utworzy dane tekstowe pod wskazanymi przesunięciami w `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` autorstwa Pen Test Partners to dobre punkty odniesienia przy dostosowywaniu tego rozwiązania do innych **szerokości słowa, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku skompilowanych plików binarnych Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Do reversingu pliku binarnego Delphi polecam wtyczkę IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować wtyczkę Python, a następnie wybierz plik wtyczki.

Ta wtyczka uruchomi plik binarny i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a punkt przerwania zostanie osiągnięty na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

W przypadku zwykłych plików binarnych Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury runtime i poprawić nazwy funkcji w IDA. Załaduj jego wtyczkę Python za pomocą **Alt+F7**.

Do reversingu pliku binarnego Golang polecam wtyczkę IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować wtyczkę Python, a następnie wybierz plik wtyczki.

Spowoduje to rozpoznanie nazw funkcji.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet pozbawiony symboli plik wykonywalny Go nadal potrzebuje metadanych runtime, aby mapować liczniki programu na funkcje. [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i analizuje struktury takie jak `pclntab` i `moduledata`, korzystając z kodu wywodzącego się z runtime Go. Pozwala to odzyskać granice funkcji, nazwy, ścieżki źródłowe, typy i szczegóły kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator może pozostawić te struktury użyteczne, zastępując odzyskane nazwy. Na przykład Garble hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o kompilacji, modułach i debugowaniu.<sup>[[12]](#references)</sup> Token obfuskowanego pakietu musi pozostać taki sam dla funkcji z tego pakietu. Pogrupuj funkcje według powtarzającego się tokenu, wywnioskuj nazwę jednego pakietu na podstawie jego funkcji wywoływanych, ciągów znaków i API, a następnie przypisz tę etykietę pakietu całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli runtime z generowaniem czystych referencji i dopasowywaniem grafów przepływu sterowania (CFG). Wykonaj kolejno następujące kroki:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuscator je usunął, porównaj fragmenty dołączonego Go runtime z referencyjnymi wersjami runtime. W testach Volexity około `2%` runtime wystarczyło do rozróżnienia głównych wersji Go. Traktuj to jako optymalizację potwierdzoną empirycznie, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj dopasowane referencje.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, docelowej architektury i prawdopodobnych bibliotek. Dopasowanie łańcucha narzędzi ogranicza różnice w CFG generowanym przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje grafy CFG funkcji i generuje znormalizowane wyniki od `0.0` do `1.0`. Dopasowywanie podstawowych bloków opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności przyporządkowują losowo nazwane funkcje do ich czystych implementacji. Słabsze dopasowania nadal mogą wskazać pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy na podstawie relacji wywołań, stałych, ciągów znaków i skutków ubocznych, a następnie zaimportuj raport JSON za pomocą wtyczki GoResolver dla IDA lub Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Zainstaluj łańcuch narzędzi i uruchom połączony ekstraktor oraz narzędzie do dopasowywania grafów:<sup>[[10]](#references)</sup>

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

Domyślny próg istotnego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają wyodrębnić każdy z etapów, natomiast domyślnie uruchamiane są oba, ponieważ odzyskane metadane runtime i dane z CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG mają charakter heurystyczny: inlining, flagi kompilacji, architektura i różnice wersji bibliotek mogą zmieniać kształt grafu, dlatego nierozpoznane funkcje należy zachować, zamiast przypisywać im nazwy z niskim poziomem pewności.<sup>[[13]](#references)</sup>

### Odzyskiwanie tablicy ciągów Go

Binarne pliki Go umieszczają bajty ciągów ze wszystkich dołączonych pakietów w jednej, ciągłej tablicy. Wpisy nie są zakończone znakiem NUL, a struktury runtime nie udostępniają początku ani rozmiaru tablicy. Kompilator porządkuje jednak wpisy najpierw według długości, a następnie alfabetycznie, niezależnie od systemu operacyjnego i architektury. Po znalezieniu jednego wpisu analityk może więc przejść do sąsiednich wpisów i użyć odwołań do danych, aby powiązać ciągi z kodem.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatyzuje ten proces w IDA Pro i Ghidra. Najpierw poczekaj na zakończenie auto-analysis, ponieważ plugin korzysta z odwołań do segmentów danych. Domyślnym punktem odniesienia jest ciąg runtime `entersyscall`. Następnie narzędzie może skanować w obu kierunkach, zdefiniować odzyskane ciągi w bazie danych i wyeksportować mapowanie ciągów na odwołujące się do nich funkcje w formacie JSON.<sup>[[14]](#references)</sup>

Przefiltruj raport według pakietu funkcji odwołującej się do ciągu, aby oddzielić kod aplikacji lub malware od szumu pochodzącego z dołączonych bibliotek. Ta technika nie odzyska literałów zniszczonych przez obfuskację, taką jak transformacja `-literals` w Garble. Nadal może jednak uporządkować ciągi runtime, które nie zostały poddane obfuskacji.<sup>[[14]](#references)[[15]](#references)</sup>

### Odzyskiwanie typów runtime Go

Go osadza informacje o typach runtime wykorzystywane przez takie funkcje jak garbage collection. Gdy informacje o kompilacji zostały usunięte albo deasembler nie analizuje tych metadanych, instrukcje mogą wyglądać tak, jakby ładowały dowolne adresy danych, a obszar docelowy pozostaje bez przypisanego typu. Odzyskanie metadanych zamienia te adresy w czytelne odwołania do typów i ułatwia zrozumienie możliwości pakietów.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) może wyodrębniać symbole i analizować typy runtime, tworząc raport JSON. Obecny CLI używa podkomendy `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcja `-y`/`--types` włącza parsowanie typów. Zaimportuj raport za pomocą pluginu GoResolver do IDA Pro lub Ghidra, aby zdefiniować odzyskane typy i zastosować ich odwołania w bazie danych analizy. W formacie raportu wprowadzonym wraz z tą funkcją pominięcie `-y` powoduje, że pola RTTI address i recovered-types mają wartość null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver obsługuje próbki PE, ELF i Mach-O dla architektur x86, AMD64, ARM i ARM64, więc ten sam proces można zastosować do plików binarnych Go z Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje o tym, jak uzyskać kod Pythona ze skompilowanego pliku binarnego Pythona ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli masz **plik binarny** gry na GBA, możesz użyć różnych narzędzi, aby ją **emulować** i **debugować**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz sprawdzić, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja sterowania no$gba pokazująca przypisania przycisków Game Boy Advance](<../../images/image (581).png>)

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

Zatem w tego rodzaju programie interesujące będzie **to, jak program obsługuje dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidra pliku binarnego GBA odwołującego się do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

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

Ostatni if sprawdza, czy **`uVar4`** znajduje się wśród ostatnich klawiszy i nie jest bieżącym klawiszem — oznacza to zwolnienie przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).

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
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony kod jest prawidłowy.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartości są takie same, wykonywany jest pewien kod.
- W każdym innym przypadku sprawdzany jest licznik (`DAT_030000d4`) i zwiększany.\
  Gdy licznik jest mniejszy niż 8, wartości wciśniętych przycisków są sumowane w `DAT_030000d8`.

W tym wyzwaniu, znając wartości przycisków, trzeba było **wcisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło do tego samouczka:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Dekodowanie ciągów Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - samouczek reversing GBA (archiwalny)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie reverse engineering wspomaganego przez AI, a przynajmniej próby](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania oparte na dopasowywaniu bloków podstawowych](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repozytorium Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: użycie podobieństwa grafów przepływu sterowania do automatycznej deobfuskacji plików binarnych Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repozytorium Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aktualizacje narzędzi Volexity dla Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: inżynieria wsteczna wszystkiego](https://github.com/morluto/rea)
- [17] [Analiza kodu zarządzanego w REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Przewodnik po CLI i dowodach REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
