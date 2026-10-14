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

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **zdekompilować** wasm (format binarny) do wat (czytelny tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **skompilować** wat do wasm
- Możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/) do dekompilacji.

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Buforowany bytecode Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Wirtualizowane payloady i niestandardowe maszyny wirtualne

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) i **pliki wykonywalne** (.exe). Po dekompilacji zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego narzędzia jest to, że gdy trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu, może ono zaoszczędzić czas. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza tworzenie oprogramowania. Przyjrzyjmy się szerokiemu zakresowi usług reverse engineeringu, które oferuje to narzędzie:

- Pokazuje, jak dane przepływają przez bibliotekę lub komponent
- Umożliwia wgląd w implementację i użycie języków oraz frameworków .NET
- Wykrywa nieudokumentowane i nieujawnione funkcje, pozwalając lepiej wykorzystać używane API i technologie.
- Znajduje zależności i różne zestawy
- Wskazuje dokładną lokalizację błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy dla Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz używać jej w dowolnym systemie operacyjnym (możesz zainstalować ją bezpośrednio z VSCode; nie trzeba pobierać repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz ponownie **zdekompilować**, **zmodyfikować** i **skompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Inspekcja kodu zarządzanego bez wykonywania za pomocą REA

**REA** umożliwia inspekcję metadanych PE/CLI i CIL bez ładowania zestawu. Zacznij od ustalenia tożsamości artefaktu, a następnie sprawdź elementy członkowskie i zadeklarowane granice kodu natywnego. Jest to przydatne podczas analizy podejrzanych wywołań przed użyciem dekompilatora lub uruchomieniem programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Przy porównywaniu różnic między wersjami `compare_managed_members` używa surowej tożsamości CIL/sygnatur i fingerprintów zdekodowanych instrukcji, zamiast traktować tokeny metadanych jako niezmienne między kompilacjami. Deklaracja P/Invoke nie dowodzi, że uruchomiono kod natywny; `verify_managed_native_boundaries` wymaga pasującego eksportu natywnego lub Evidence funkcji, aby zweryfikować tę granicę. Zachowaj digest artefaktu, MVID i nierozwiązane mapowania wraz z wynikiem.<sup>[[17]](#references)</sup>

### DNSpy Logging

Aby **DNSpy zapisywał pewne informacje do pliku**, możesz użyć tego fragmentu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Najpierw zmienić **atrybuty zestawu** związane z **debugowaniem**:

![DNSpy Logging - Debugowanie DNSpy: Najpierw zmień atrybuty zestawu związane z debugowaniem](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Kliknij kompiluj](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik, wybierając _**Plik >> Zapisz moduł...**_:

![DNSpy Logging - DNSpy Debugging: Następnie zapisz nowy plik, wybierając Plik Zapisz moduł](<../../images/image (602).png>)

Jest to konieczne, ponieważ w przeciwnym razie podczas **runtime** kod zostanie poddany różnym **optymalizacjom** i może się zdarzyć, że podczas debugowania **punkt przerwania nigdy nie zostanie osiągnięty** albo **niektóre zmienne nie będą istnieć**.

Następnie, jeśli Twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i na **Debug Tab** wybierz **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i na Debug Tab wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby podłączyć się do IIS server, i kliknij attach](<../../images/image (113).png>)

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

## Debugowanie DLL

### Korzystanie z IDA

- **Załaduj rundll32** (64-bitową wersję znajdziesz w C:\Windows\System32\rundll32.exe, a 32-bitową w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parameters** wykonania, podając **path to the DLL** i funkcję, którą chcesz wywołać:

![Debugging DLLs - Using IDA: Skonfiguruj parameters wykonania, podając path to the DLL i funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **wykonywanie zostanie zatrzymane po załadowaniu każdej DLL**. Gdy rundll32 załaduje Twoją DLL, wykonywanie również zostanie zatrzymane.

Ta metoda zatrzymuje wykonywanie przy zdarzeniach ładowania modułu, ale osiągnięcie punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym poniżej przebiegu w x64dbg.

### Korzystanie z x64dbg/x32dbg

- **Załaduj rundll32** (64-bitową wersję znajdziesz w C:\Windows\System32\rundll32.exe, a 32-bitową w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień Command Line** ( _File --> Change Command Line_ ) i ustaw ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **uruchom wykonywanie**. Debugger zatrzyma się przy każdej funkcji main DLL. W pewnym momencie **zatrzymasz się w punkcie wejścia swojej DLL**. Następnie znajdź miejsca, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonywanie zostanie zatrzymane z dowolnego powodu w win64dbg, informację **w jakim kodzie się znajdujesz** można znaleźć **u góry okna win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Zauważ, że gdy wykonywanie zostanie zatrzymane z dowolnego powodu w win64dbg, informację, w jakim kodzie się znajdujesz, można znaleźć u góry okna win64dbg](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonywanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do wyszukiwania ważnych wartości zapisanych w pamięci uruchomionej gry i ich zmieniania. Więcej informacji:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie typu front-end/reverse engineering dla GNU Project Debugger (GDB), przeznaczone głównie do gier. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end dla wielu dekompilatorów. Ta usługa internetowa pozwala porównywać wyniki różnych dekompilatorów dla małych plików wykonywalnych.

## Dochodzenie natywne oparte na dowodach z REA

**REA** udostępnia analizy z Hopper, Ghidra i IDA za pośrednictwem CLI i MCP. Wymaga Node.js 22.x (co najmniej 22.19), 24.x (co najmniej 24.11) lub 26+, a także npm. Najpierw skonfiguruj istniejącego natywnego providera; sprawdź `rea providers --json`, a jeśli więcej niż jeden provider obsługuje dany cel, wybierz go jawnie. Zamiast `0x1000` poniżej użyj zaobserwowanej nazwy funkcji lub adresu z inwentarza.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Zacznij od ciągu funkcji lub symbolu, podążaj za odwołaniami i wywołującymi, a następnie sprawdź dossier wybranej funkcji i pseudokod za pomocą `rea decompile`. REA wiąże sesję z wybranym providerem, zamiast po cichu zastępować go po wystąpieniu błędu. Aby uzyskać powtarzalne wyniki zapytań, `--snapshot PATH` ponownie wykorzystuje wyłącznie zgodne bajty artefaktu, provider, ustawienia, operację i parametry; snapshot to lokalna pamięć podręczna, a nie zapisana baza danych providera. Zachowaj zwrócone Evidence i jawnie wskazane niewiadome, zamiast traktować wywnioskowane ścieżki lub tekst dekompilatora jako oryginalny kod źródłowy.<sup>[[16]](#references)[[18]](#references)</sup>

Informacje o punktach wejścia JavaScript/Electron prowadzących do natywnych dodatków znajdziesz w [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie wydań GitHub znajdują się pliki ZIP z skompilowanymi wydaniami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie go zbuduj**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 sekund**, wstrzymaj je wewnątrz tej pętli i przejdź do następnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger wstrzymany w nieskończonej pętli jmp2it tuż przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI programu radare. Za pomocą Cutter możesz emulować shellcode i analizować go dynamicznie.

Zwróć uwagę, że Cutter pozwala wybrać „Open File” oraz „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode — nie:

![Cutter pokazuje różne wyniki analizy po otwarciu tych samych bajtów jako pliku lub shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp — wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter wstrzymany na wybranym breakpoincie shellcode](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie emulowanego stosu shellcode w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Deobfuskacja shellcode i znajdowanie wykonywanych funkcji

Warto wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokaże między innymi, **których funkcji** używa shellcode oraz czy **dekoduje** się w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg udostępnia również graficzny launcher, w którym możesz wybrać żądane opcje i uruchomić shellcode

![Graficzny launcher scDbg do wybierania opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli podczas działania w pamięci zostaną w nim wprowadzone jakiekolwiek zmiany (przydatne do pobrania zdekodowanego shellcode). **start offset** może się przydać do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** umożliwia debugowanie shellcode za pomocą terminala scDbg (jednak uważam, że lepiej sprawdzi się w tym celu dowolna z wcześniej opisanych opcji, ponieważ można wtedy użyć Ida lub x64dbg).

### Deasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższego przepisu, aby go zdeasemblować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Usuwanie obfuskacji MBA

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących operatory arytmetyczne (`+`, `-`, `*`) i bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zazwyczaj poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz takie wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/wyjścia IR/dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie**, zanim spróbujesz je uprościć:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenia liniowe z dodatkowymi stałymi maskami, takimi jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i operacje bitowe są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Weryfikuj każdą proponowaną transformację** za pomocą losowych testów lub dowodu SMT. Jeśli nie można dowieść równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omiń spłaszczony przepływ sterowania, analizując wąski wycinek wykonania

Odtworzenie pełnego grafu przepływu sterowania często nie jest konieczne. W przypadku control-flow flattening, nieprzezroczystych predykatów, dużych dispatcherów lub kodu intensywnie wykorzystującego MBA śledź odwołania od zaszyfrowanych blobów i buforów wyjściowych do najmniejszej funkcji, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych albo wykonaj go niezależnie; dispatcher nie jest częścią wymaganego rozwiązania, jeśli odpowiedni stan można zainicjalizować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow:<sup>[[7]](#references)</sup>

1. Zrób spis sekcji wykonywalnych i danych, relokacji oraz odwołań krzyżowych. Zrzutuj kandydackie tablice z `.rodata`, zachowując kolejność bajtów i szerokość elementów.
2. Znajdź ostatnią funkcję, która zapisuje jawny tekst lub bufor wyjściowy. Zapisz jej dane wejściowe, referencje do tablic, wywołania importowanych funkcji i wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Python o stałej szerokości. Jeśli wycinek nadal zależy od zbyt dużej ilości stanu, wywołaj funkcję w Unicorn, QEMU lub debuggerze i podczep się pod nieistotne importy, zamiast emulować cały program.
4. Sprawdź, czy extractor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche fallbacki, wyszukaj w nim osadzone odpowiedzi i uruchom go na nieznanych wcześniej buildach ze zmienionymi ciągami znaków, kluczami, identyfikatorami, układami i seedami obfuskacji.

Przydatne polecenia do wstępnej analizy:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywanie wyrażeń MBA będących zamaskowanymi stałymi

Pozornie zależne od wejścia wyrażenie bajtowe może całkowicie eliminować wpływ wejścia. Po wyodrębnieniu jego tablic oblicz wartość wyrażenia dla całej 8-bitowej przestrzeni; jednoelementowy zbiór wyników dowodzi, że ten bajt jest stały, bez konieczności odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie powoduje zawijanie wartości do szerokości bajtu. Dla szerszej domeny zapytaj solver SMT, czy `f(x1) != f(x2)` jest spełnialne dla dwóch symbolicznych wejść o tej samej szerokości: `unsat` dowodzi niezmienności, a `sat` dostarcza kontrprzykład i oznacza, że nie można odrzucić wejścia.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole antyanalityczne nie muszą powodować skoku ani awarii. Dekoder może zmieszać wynik odczytu sensora z bitem klucza, stałą opaque predicate lub stanem spłaszczonego dyspozytora, działać dalej normalnie i wygenerować wiarygodny, ale fałszywy tekst jawny w emulatorze. Dlatego samo patchowanie widocznych gałęzi błędu nie wystarczy; śledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam fragment na autentycznym urządzeniu i w emulatorze, a także sprawdź, jak wymuszenie każdego wyniku sensora zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA, przeznaczone do analizy malware i inżynierii wstecznej chronionych plików binarnych. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków zamiast stosować jeden ogólny przebieg przepisywania do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wartość wyrażenia dla wejść boolowskich, wyznacza sygnaturę i uruchamia równolegle kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja do ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy maskowane stałą są odtwarzane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane obszary pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia można przenieść do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład mieszanej tożsamości, której odzyskanie często warto spróbować:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Można to uprościć do:

```c
x * y
```

### Notatki dotyczące reversing

- Preferuj uruchamianie CoBRA na **wyrażeniach IR po liftingu** lub wyniku dekompilatora po wyizolowaniu dokładnego obliczenia.
- Używaj jawnie `--bitwidth`, jeśli wyrażenie pochodzi z arytmetyki z maskowaniem lub z rejestrów o wąskiej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, zapoznaj się z lokalnymi notatkami o Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępny jako **wtyczka passa LLVM** (`libCobraPass.so`), przydatna do normalizowania LLVM IR zawierającego dużo MBA przed późniejszymi passami analizy.
- Nieobsługiwane reszty mieszanych domen zależne od przeniesienia należy traktować jako sygnał, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Szczegóły:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych plików binarnych narzędzie [demovfuscator](https://github.com/kirschju/demovfuscator) może usunąć obfuskację. Wymaga kilku zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje zawierające `::main`, jak na przykładzie:

![Znajdowanie punktu wejścia w Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nazywał się authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **dane wejściowe** i **wyjściowe**.

### Odzyskiwanie ciągów znaków Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone NUL-em w stylu C. Często spotykany układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągów znaków przechowywany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidry może łączyć sąsiadujące ciągi znaków albo całkowicie pomijać odwołania krzyżowe.<sup>[[3]](#references)</sup>

Szybki workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar sekcji **`.rodata`**.
2. Enumeruj **`.data.rel.ro`** słowo po słowie.
3. Każdą wartość mieszczącą się w zakresie adresów `.rodata` traktuj jako potencjalny wskaźnik do ciągu znaków.
4. Następne słowo traktuj jako potencjalną długość.
5. Zastosuj filtry weryfikacyjne (na przykład zachowuj długości od **4** do **100** bajtów).
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

Jest to szczególnie przydatne przy analizie firmware, ponieważ odzyskane ciągi znaków Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, handlery poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykrywa tych ciągów, uruchom własny skrypt/plugin, który stosuje tę samą heurystykę i tworzy dane typu string pod wskazanymi offsetami `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners to dobre źródła wiedzy przy adaptowaniu tego rozwiązania do innych **szerokości słowa, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binariów skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeanalizować binarium Delphi, polecam użyć pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Ten plugin uruchomi binarium i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a breakpoint zostanie osiągnięty na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywoływanej przez ten przycisk.

## Golang

W przypadku zwykłych binariów Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury środowiska uruchomieniowego i poprawić nazwy funkcji w IDA. Załaduj jego plugin Python za pomocą **Alt+F7**.

Jeśli musisz przeanalizować binarium Golang, polecam użyć pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Pozwoli to rozpoznać nazwy funkcji.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet pozbawiony symboli plik wykonywalny Go nadal potrzebuje metadanych środowiska uruchomieniowego, aby mapować liczniki programu na funkcje. [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i analizuje struktury, takie jak `pclntab` i `moduledata`, wykorzystując kod oparty na środowisku uruchomieniowym Go. Umożliwia to odzyskanie granic funkcji, nazw, ścieżek źródłowych, typów i szczegółów kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator może pozostawić te struktury użyteczne, zastępując odzyskane nazwy. Na przykład Garble hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o kompilacji, module i debugowaniu.<sup>[[12]](#references)</sup> Token obfuskowanego pakietu musi pozostać spójny dla funkcji z tego pakietu. Pogrupuj funkcje według powtarzającego się tokenu, wywnioskuj nazwę jednego pakietu na podstawie jego funkcji wywoływanych, ciągów znaków i API, a następnie przypisz tę etykietę całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli runtime z generowaniem czystych referencji i dopasowywaniem grafów przepływu sterowania (CFG). Zastosuj następującą sekwencję:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuscator je usunął, porównaj fragmenty dołączonego Go runtime z referencyjnymi runtime’ami dla różnych wersji. W testach Volexity około `2%` runtime’u wystarczyło do rozróżnienia głównych wersji Go. Potraktuj to jako empiryczną optymalizację, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj pasujące referencje.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, architektury docelowej i prawdopodobnych bibliotek. Dopasowanie toolchaina ogranicza różnice w CFG generowane przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje grafy CFG funkcji i zwraca znormalizowane wyniki od `0.0` do `1.0`. Dopasowywanie podstawowych bloków opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności przyporządkowują funkcje o losowych nazwach do czystej implementacji. Słabsze dopasowania nadal mogą wskazać pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy na podstawie relacji wywołań, stałych, ciągów znaków i efektów ubocznych, a następnie zaimportuj raport JSON za pomocą wtyczki GoResolver do IDA lub Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Domyślny próg istotnego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają wyodrębnić każdy z etapów, natomiast domyślnie uruchamiane są oba, ponieważ odzyskane metadane środowiska uruchomieniowego i informacje z CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG są heurystyczne: inlining, flagi kompilacji, architektura i różnice między wersjami bibliotek mogą zmieniać kształt grafu, dlatego nierozpoznane funkcje należy zachować, zamiast przypisywać im nazwy przy niskim poziomie pewności.<sup>[[13]](#references)</sup>

### Odzyskiwanie tablicy stringów Go

Binarne pliki Go umieszczają bajty stringów ze wszystkich dołączonych pakietów w jednej ciągłej tablicy. Wpisy nie są zakończone bajtem NUL, a struktury środowiska uruchomieniowego nie udostępniają początku ani rozmiaru tablicy. Kompilator porządkuje jednak wpisy najpierw według długości, a następnie alfabetycznie — niezależnie od systemu operacyjnego i architektury. Po znalezieniu jednego wpisu analityk może więc przechodzić do sąsiednich wpisów i używać odwołań do danych, aby powiązać stringi z kodem.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatyzuje ten proces w IDA Pro i Ghidra. Najpierw poczekaj na zakończenie automatycznej analizy, ponieważ wtyczka korzysta z odwołań do segmentów danych. Domyślnym punktem odniesienia jest string środowiska uruchomieniowego `entersyscall`. Następnie narzędzie może skanować w obu kierunkach, zdefiniować odzyskane stringi w bazie danych i wyeksportować mapowanie JSON stringów do odwołujących się do nich funkcji.<sup>[[14]](#references)</sup>

Filtruj raport według pakietu funkcji odwołującej się do stringa, aby oddzielić kod aplikacji lub malware od szumu pochodzącego z dołączonych bibliotek. Ta technika nie pozwala odzyskać literałów zniszczonych przez obfuskację, taką jak transformacja `-literals` w Garble. Może jednak pomóc uporządkować stringi środowiska uruchomieniowego, które nie zostały poddane obfuskacji.<sup>[[14]](#references)[[15]](#references)</sup>

### Odzyskiwanie typów środowiska uruchomieniowego Go

Go osadza informacje o typach środowiska uruchomieniowego wykorzystywane przez funkcje takie jak garbage collection. Gdy informacje o kompilacji zostaną usunięte lub disassembler nie sparsuje tych metadanych, instrukcje mogą wyglądać tak, jakby wczytywały dowolne adresy danych, a docelowy obszar pozostaje nieotagowany. Odzyskanie metadanych zmienia te adresy w czytelne odwołania do typów i ułatwia zrozumienie możliwości pakietów.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) może wyodrębnić symbole i sparsować typy środowiska uruchomieniowego do raportu JSON. Obecna wersja CLI używa podkomendy `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcja `-y`/`--types` włącza parsowanie typów. Zaimportuj raport za pomocą pluginu IDA Pro lub Ghidra dla GoResolver, aby zdefiniować odzyskane typy i zastosować ich odwołania w bazie danych analizy. W formacie raportu wprowadzonym wraz z tą funkcją pominięcie `-y` powoduje, że pola RTTI address i recovered-types mają wartość null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver obsługuje próbki PE, ELF i Mach-O dla x86, AMD64, ARM i ARM64, więc ten sam workflow dotyczy plików binarnych Go z Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje, jak uzyskać kod Pythona ze skompilowanego pliku binarnego ELF/EXE Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli zdobędziesz **plik binarny** gry GBA, możesz użyć różnych narzędzi, aby ją **emulować** i **debugować**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz sprawdzić, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja sterowania no$gba pokazująca mapowanie przycisków Game Boy Advance](<../../images/image (581).png>)

Każdy **klawisz ma przypisaną wartość**, która go identyfikuje:

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

W tego rodzaju programie interesujące będzie więc **to, jak program przetwarza dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![Widok Ghidry przedstawiający odwołanie pliku binarnego GBA do KEYINPUT pod adresem 0x4000130](<../../images/image (447).png>)

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

Ostatni if sprawdza, czy **`uVar4`** znajduje się w **ostatnich Keys** i nie jest bieżącym klawiszem, co oznacza zwolnienie przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).

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
- Następnie wartość jest porównywana z **8** (przyciskiem **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony kod jest poprawny.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli wartości są równe, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany jest i zwiększany licznik (`DAT_030000d4`).\
  Gdy licznik jest mniejszy niż 8, wartości naciśniętych przycisków są sumowane w `DAT_030000d8`.

Zatem w tym wyzwaniu, znając wartości przycisków, należało **nacisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło dla tego tutoriala:** [zarchiwizowany opis rozwiązania wyzwania Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Dekodowanie ciągów znaków Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - ciągi znaków Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversingu GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie reverse engineeringu wspomaganego przez AI — a przynajmniej próby](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania oparte na dopasowywaniu bloków podstawowych](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repozytorium Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: automatyczna deobfuskacja plików binarnych Golang za pomocą podobieństwa grafów przepływu sterowania](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repozytorium Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aktualizacje narzędzi Volexity dla Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Analiza kodu zarządzanego w REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Przewodnik po CLI i dowodach REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
