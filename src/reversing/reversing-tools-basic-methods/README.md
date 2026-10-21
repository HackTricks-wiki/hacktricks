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

## Decompiler Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **decompile** z wasm (plik binarny) do wat (czytelny tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **compile** z wat do wasm
- Możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/) do dekompilacji.

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / buforowany bytecode V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Zwirtualizowane payloady i niestandardowe VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to decompiler, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) i **pliki wykonywalne** (.exe). Po dekompilacji assembly można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego narzędzia jest to, że gdy trzeba odtworzyć utracony kod źródłowy na podstawie starszego assembly, może ono zaoszczędzić czas. Ponadto dotPeek oferuje wygodną nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza pracę programistyczną. Przyjrzyjmy się licznym funkcjom reverse engineeringu oferowanym przez to narzędzie:

- Pokazuje, jak dane przepływają przez bibliotekę lub komponent
- Pokazuje sposób implementacji i użycia języków oraz frameworków .NET
- Wyszukuje nieudokumentowane i nieudostępnione funkcje, aby umożliwić pełniejsze wykorzystanie używanych API i technologii.
- Wyszukuje zależności i różne assembly
- Lokalizuje dokładne miejsce wystąpienia błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego kodu .NET, z którym pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy dla Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): można z niej korzystać w dowolnym systemie operacyjnym (można ją zainstalować bezpośrednio z VSCode, bez konieczności pobierania repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **decompile**, **modify** i ponownie **recompile**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub jego aktywnie rozwijanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Inspekcja kodu zarządzanego bez jego wykonywania za pomocą REA

**REA** może analizować metadane PE/CLI i CIL bez ładowania assembly. Zacznij od identyfikacji artefaktu, a następnie sprawdź elementy i zadeklarowane granice kodu natywnego. Przydaje się to podczas analizy podejrzanych wywołań przed użyciem decompilera lub uruchomieniem programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Przy porównywaniu wersji `compare_managed_members` używa surowej tożsamości CIL/podpisów i fingerprintów zdekodowanych instrukcji, zamiast traktować tokeny metadanych jako stabilne między kompilacjami. Deklaracja P/Invoke nie dowodzi, że uruchomiono kod natywny; `verify_managed_native_boundaries` wymaga pasującego natywnego eksportu lub dowodu dotyczącego funkcji, aby sprawdzić tę granicę. Zachowaj digest artefaktu, MVID i nierozwiązane mapowania wraz z wynikiem.<sup>[[17]](#references)</sup>

### Logowanie w DNSpy

Aby **DNSpy zapisywał niektóre informacje w pliku**, możesz użyć tego fragmentu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie w DNSpy

Aby debugować kod przy użyciu DNSpy, musisz:

Najpierw zmienić atrybuty **Assembly** związane z **debugowaniem**:

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

I kliknij **compile**:

![DNSpy Logging - DNSpy Debugging: Kliknij compile](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik, wybierając _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Następnie zapisz nowy plik, wybierając File Save module](<../../images/image (602).png>)

Jest to konieczne, ponieważ w przeciwnym razie podczas **wykonywania** kodu zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **punkt przerwania nigdy nie zostanie osiągnięty** albo **niektóre zmienne nie będą istnieć**.

Jeśli aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i w **Debug Tab** wybierz **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki i w Debug Tab wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby podłączyć się do IIS server, i kliknij attach](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Teraz, gdy debugujemy proces, zatrzymajmy go i załadujmy wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i kliknij **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i kliknij Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Używanie IDA

- **Załaduj rundll32** (64-bitowy w C:\Windows\System32\rundll32.exe i 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parameters** uruchomienia, podając **path to the DLL** oraz funkcję, którą chcesz wywołać:

![Debugging DLLs - Using IDA: Skonfiguruj parameters uruchomienia, podając path to the DLL oraz funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **wykonywanie zostanie wstrzymane po załadowaniu każdej DLL**. Gdy rundll32 załaduje Twoją DLL, wykonywanie zostanie wstrzymane.

Ta metoda zatrzymuje wykonywanie przy zdarzeniach ładowania modułów, ale dotarcie do entry point załadowanej DLL jest mniej bezpośrednie niż w opisanym niżej sposobie z x64dbg.

### Używanie x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy w C:\Windows\System32\rundll32.exe i 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień Command Line** ( _File --> Change Command Line_ ) i ustaw ścieżkę DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **rozpocznij wykonywanie**. Debugger zatrzyma się przy każdej funkcji dll main; w pewnym momencie **zatrzymasz się w DLL Entry swojej DLL**. Następnie znajdź miejsca, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonywanie zostanie z jakiegokolwiek powodu zatrzymane w win64dbg, informację **w jakim kodzie się znajdujesz** znajdziesz **u góry okna win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Zauważ, że gdy wykonywanie zostanie z jakiegokolwiek powodu zatrzymane w win64dbg, informację, w jakim kodzie się znajdujesz, znajdziesz u góry okna win64dbg](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonywanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do wyszukiwania ważnych wartości zapisanych w pamięci uruchomionej gry i ich zmieniania. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie typu front-end do GNU Project Debugger (GDB) i reverse engineeringu, przeznaczone do gier. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowy front-end dla wielu dekompilatorów. Ta usługa internetowa umożliwia porównanie wyników działania różnych dekompilatorów na małych plikach wykonywalnych.

## Analiza natywna oparta na dowodach za pomocą REA

**REA** udostępnia analizę w Hopper, Ghidra i IDA przez CLI i MCP. Wymaga Node.js 22.x (co najmniej 22.19), 24.x (co najmniej 24.11) lub 26+, a także npm. Najpierw skonfiguruj istniejącego natywnego providera; sprawdź `rea providers --json` i jawnie wybierz providera, jeśli więcej niż jeden obsługuje cel analizy. Zamiast `0x1000` poniżej użyj zaobserwowanej nazwy funkcji lub adresu z inwentarza.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Zacznij od ciągu funkcji lub symbolu, podążaj za referencjami i wywołującymi, a następnie sprawdź dossier wybranej funkcji i pseudokod za pomocą `rea decompile`. REA wiąże sesję z wybranym providerem, zamiast po cichu zastępować go po błędzie. W przypadku powtarzalnych zapytań `--snapshot PATH` ponownie wykorzystuje wyłącznie pasujące bajty artefaktu, providera, ustawienia, operację i parametry; snapshot to lokalna pamięć podręczna, a nie zapisana baza providera. Zachowaj zwrócone Evidence i jawnie wskazane niewiadome, zamiast traktować wywnioskowane ścieżki lub tekst dekompilatora jako oryginalny kod źródłowy.<sup>[[16]](#references)[[18]](#references)</sup>

W przypadku punktów wejścia JavaScript/Electron prowadzących do natywnych add-onów zobacz [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skryptowana analiza IDA i Ghidra z lokalnym mostem TCP

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) działa wewnątrz **już otwartej** bazy danych IDA lub programu Ghidra CodeBrowser i pozwala osobnemu skryptowi wykonywać zapytania dotyczące tej bazy analizy oraz ją modyfikować. Uruchom `ID_Server.py` z poziomu konsoli Python IDA (`import ID_Server`) albo `Ghidra_Server.py` z poziomu Script Manager w Ghidra. IDA nasłuchuje na `127.0.0.1`, zaczynając od portu `5073`, i sprawdza kolejne porty. Obecny skrypt Ghidra zaczyna od portu `5093` i próbuje użyć dziesięciu portów aż do `5102`; jego gniazdo Java wiąże się z adresem wildcard, a nie tylko z adresem loopback. Przed połączeniem sprawdź port wypisany przez instancję. W przeciwieństwie do analizatora bez interfejsu ten most działa na programie aktualnie otwartym w danej instancji GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Wysyłaj **jedno polecenie zakończone znakiem nowej linii na połączenie** i odczytuj odpowiedź zakończoną znakiem nowej linii. Wynikiem jest zazwyczaj JSON. Na przykład po znalezieniu zaimportowanego API powiązanego ze ścieżką wejściową `IMPORTXREF` znajduje miejsca jego wywołań; następnie `DECOMP_XREF` dekompiluje wsadowo wywołujących wskazany adres. `FUNC` analizuje funkcję, a `PCODE` zwraca pośrednią reprezentację dekompilatora. Użyj adresu z aktywnej bazy danych, a nie adresu skopiowanego z inaczej relokowanego pliku binarnego. Poniższy przykład używa domyślnego portu IDA; w przypadku Ghidra użyj portu wypisanego przez jej skrypt.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Ten sam kanał może **zmieniać bazę danych analizy**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` zmieniają nazwy, typy, definicje struktur, granice funkcji lub zapisane bajty. `PATCH` to edycja bazy danych, **a nie** dowód na patchowanie działającego procesu. Żaden z listenerów nie dokumentuje uwierzytelniania. IDA nasłuchuje wyłącznie na loopbacku, ale Ghidra może być dostępna przez interfejsy sieciowe; podczas korzystania z niej ogranicz dostęp do listenera Ghidry. `QUIT` zatrzymuje oba listenery, a IDA udostępnia również `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode'u za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie wydań w GitHubie znajdują się pliki ZIP ze skompilowanymi wersjami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie go zbuduj**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode'u za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 sekund**, wstrzymaj je wewnątrz pętli i przejdź do następnego wywołania, które przekazuje sterowanie do zaalokowanego shellcode'u.

![Debugger wstrzymany w nieskończonej pętli jmp2it tuż przed wywołaniem zaalokowanego shellcode'u](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode'u za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Cutter umożliwia emulowanie shellcode'u i jego dynamiczną inspekcję.

Pamiętaj, że Cutter pozwala wybrać „Open File” i „Open Shellcode”. W moim przypadku po otwarciu shellcode'u jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode'u — nie:

![Cutter pokazujący różne wyniki analizy tych samych bajtów otwartych jako plik lub shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp — wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode'u przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter wstrzymany na wybranym breakpoincie shellcode'u](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie emulowanego stosu shellcode'u w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Deobfuskacja shellcode'u i pobieranie wykonywanych funkcji

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

scDbg oferuje również graficzny launcher, w którym możesz wybrać żądane opcje i wykonać shellcode

![Graficzny launcher scDbg do wybierania opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli podczas działania zostaną wprowadzone jakiekolwiek zmiany w shellcode w pamięci (przydatne do pobrania zdekodowanego shellcode). Opcja **start offset** może się przydać do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** pozwala debugować shellcode za pomocą terminala scDbg (jednak uważam, że lepiej sprawdzą się tu dowolne z wcześniej opisanych opcji, ponieważ umożliwiają użycie IDA lub x64dbg).

### Dezasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższego przepisu, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacja MBA

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących operacje arytmetyczne (`+`, `-`, `*`) i operatory bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyniku dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie**, zanim spróbujesz je uprościć:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenia liniowe z maskami stałych, takimi jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i logika bitowa przeplatają się, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną transformację** za pomocą testów losowych lub dowodu SMT. Jeśli nie można udowodnić równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omijanie spłaszczonego przepływu sterowania za pomocą wąskiego wycinka wykonania

Odtworzenie kompletnego grafu przepływu sterowania często nie jest konieczne. Przy control-flow flattening, nieprzejrzystych predykatach, dużych dispatcherach lub kodzie mocno wykorzystującym MBA prześledź odwołania od zaszyfrowanych blobów i buforów wyjściowych do najmniejszej funkcji, która je przetwarza. Następnie odtwórz tylko ten wycinek przepływu danych lub uruchom go niezależnie; dispatcher nie jest potrzebny do rozwiązania, jeśli odpowiedni stan można zainicjować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow wygląda następująco:<sup>[[7]](#references)</sup>

1. Zinwentaryzuj sekcje wykonywalne i sekcje danych, relokacje oraz odwołania krzyżowe. Zrzuć potencjalne tablice z `.rodata`, zachowując kolejność bajtów i szerokość elementów.
2. Znajdź ostatnią funkcję, która zapisuje tekst jawny lub bufor wyjściowy. Zapisz jej dane wejściowe, używane tablice, wywołania importowane i wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Pythona o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt wielu elementów stanu, wywołaj funkcję w Unicorn, QEMU lub debuggerze i podłącz hooki do nieistotnych importów zamiast emulować cały program.
4. Sprawdź, czy extractor rzeczywiście uzyskuje wynik z dostarczonego pliku binarnego: usuń ciche mechanizmy awaryjne, sprawdź, czy nie zawiera on osadzonych odpowiedzi, i uruchom go na nieznanych kompilacjach ze zmienionymi ciągami znaków, kluczami, identyfikatorami, układami i seedami obfuskacji.

Przydatne polecenia na początek:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywanie wyrażeń MBA ukrywających stałe

Pozornie zależne od wejścia wyrażenie bajtowe może całkowicie wyeliminować wpływ wejścia. Po wyodrębnieniu jego tablic oblicz wartość wyrażenia dla całej 8-bitowej dziedziny; jednoelementowy zbiór wyników dowodzi, że bajt jest stały — bez odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie zawija się przy przepełnieniu szerokości bajtu. Dla szerszej domeny zapytaj solver SMT, czy dla dwóch symbolicznych wejść o tej samej szerokości spełnialne jest `f(x1) != f(x2)`: wynik `unsat` dowodzi niezmienności, a `sat` dostarcza kontrprzykład i oznacza, że nie można odrzucić wejścia.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole antyanalizowe nie muszą powodować skoku ani awarii. Dekoder może włączyć wynik odczytu czujnika do bitu klucza, stałej opaque-predicate lub stanu spłaszczonego dyspozytora, działać dalej normalnie i generować wiarygodny, lecz fałszywy tekst jawny w emulatorze. Dlatego samo poprawianie widocznych gałęzi błędów nie wystarczy; prześledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam fragment na autentycznym urządzeniu i emulatorze oraz sprawdź, jak wymuszenie każdego wyniku odczytu czujnika zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA, przeznaczone do analizy malware i reverse engineeringu chronionych plików binarnych. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków przetwarzania, zamiast stosować jedno ogólne przejście przepisujące do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wyrażenie dla wejść boolowskich, wyznacza sygnaturę i uruchamia równolegle kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja ANF i interpolacja współczynników.
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

- Uruchamiaj CoBRA na **wyrażeniach IR po liftingu** lub wyniku dekompilacji, gdy wyodrębnisz już dokładne obliczenie.
- Używaj jawnie `--bitwidth`, jeśli wyrażenie pochodzi z arytmetyki z maskowaniem lub operacji na rejestrach o mniejszej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, zajrzyj do lokalnych notatek o Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępny jako **plugin passa LLVM** (`libCobraPass.so`), przydatny do normalizowania LLVM IR zawierającego dużo MBA przed późniejszymi passami analizy.
- Nieresztkowe wyrażenia mieszanych domen, których nie da się obsłużyć ze względu na przeniesienia, powinny być sygnałem, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesień.

## Odtwarzanie flatteningu przepływu sterowania opartego na stanie XOR

Flattener w stylu OLLVM może przechowywać stan bieżącego podstawowego bloku w dwóch 64-bitowych rejestrach i odtwarzać go operacją XOR w dispatcherze. Każdy oryginalny blok zapisuje parę rejestrów odpowiadającą jego następnemu stanowi i wykonuje skok z powrotem do dispatchera. Blok warunkowy może używać `CMOVcc`, aby zastąpić jedną połowę pary zgodnie z flagami CPU, więc śledzenie wyłącznie widocznych instrukcji skoku pomija obu następców. W przeciwieństwie do dispatchera z pośrednim skokiem, ta forma może używać bezpośrednich krawędzi powrotnych w całym kodzie.<sup>[[19]](#references)[[20]](#references)</sup>

Aby odtworzyć graf, zidentyfikuj drzewo porównań dispatchera i dwa rejestry stanu, przyporządkuj każdy porównywany stan XOR do bloku docelowego, a następnie prześledź zapisy do pary rejestrów osiągające każdy oryginalny blok. W przypadku zapisów warunkowych uwzględnij instrukcję ustawiającą flagi oraz oba wyniki `CMOVcc`. Zastąp wyjście każdego bloku do dispatchera ustalonym bezpośrednim następnikiem lub skokiem warunkowym; dispatcher stanie się wtedy nieosiągalny bez modyfikowania binariów. Jest to podejście obejmujące cały CFG; jeśli interesuje Cię tylko jeden dekoder, szybszy może być opisany wyżej [workflow wąskiego wycinka wykonania](#bypass-flattened-control-flow-with-a-narrow-execution-slice).<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatyzuje tę formę w Binary Ninja. Skopiuj `plugins/DispatchThis` do katalogu wtyczek użytkownika Binary Ninja i uruchom program ponownie. Wybierz dotkniętą funkcję, otwórz **Function Settings** i wybierz `OLLVM_XOR_64`; jeśli analiza się nie rozpocznie, użyj **Analysis → Reanalyze All Functions**. Ten tryb przepisuje krawędzie przepływu sterowania MLIL, a nie bajty pliku, i nie wymaga Z3 ani resolvera pośrednich skoków. Został przetestowany w Binary Ninja 5.3.9757+; nie usuwa nieaktywnych zapisów stanu w poszczególnych blokach, więc nie należy mylić ich z nadal aktywnymi przejściami.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuskator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Więcej szczegółów:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych plików binarnych [demovfuscator](https://github.com/kirschju/demovfuscator) może odwrócić obfuskację. Ma kilka zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli bierzesz udział w **CTF, ten sposób na znalezienie flagi** może być bardzo przydatny: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje zawierające `::main`, jak na przykładzie:

![Znajdowanie punktu wejścia programu Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nosił nazwę authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Znając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **dane wejściowe** i **wyjściowe**.

### Odzyskiwanie ciągów znaków Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele ciągów statycznych nie jest wskazywanych przez wskaźniki zakończone znakiem NUL w stylu C. Typowy układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągu znaków zapisany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidry mogą łączyć sąsiadujące ciągi znaków albo całkowicie pomijać odwołania krzyżowe.<sup>[[3]](#references)</sup>

Szybki workflow:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar **`.rodata`**.
2. Enumeruj **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako kandydacki wskaźnik na ciąg znaków.
4. Traktuj następne słowo jako kandydacką długość.
5. Zastosuj filtry sensowności (na przykład zachowuj długości od **4** do **100** bajtów).
6. Odczytaj dokładnie `length` bajtów z `.rodata` zamiast skanować aż do `0x00`.

Minimalna logika ekstraktora:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Jest to szczególnie przydatne podczas reversing firmware, ponieważ odzyskane ciągi Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, handlery poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykrywa tych ciągów, uruchom własny skrypt/plugin, który stosuje tę samą heurystykę i tworzy dane typu string pod wskazanymi offsetami `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners są dobrym punktem odniesienia przy dostosowywaniu tego pomysłu do innych **szerokości słów, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binarnych plików skompilowanych w Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reversing binarnego pliku Delphi, sugeruję użyć pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Ten plugin uruchomi plik binarny i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony albo f9), a breakpoint zatrzyma wykonanie na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywoływanej przez ten przycisk.

## Golang

W przypadku zwykłych binarnych plików Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury runtime i poprawić nazwy funkcji w IDA. Załaduj jego plugin Python, naciskając **Alt+F7**.

Jeśli musisz przeprowadzić reversing binarnego pliku Golang, sugeruję użyć pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Pozwoli to rozpoznać nazwy funkcji.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet pozbawiony symboli plik wykonywalny Go nadal potrzebuje metadanych runtime, aby mapować liczniki programu na funkcje. [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i parsuje struktury takie jak `pclntab` i `moduledata`, korzystając z kodu opartego na Go runtime. Pozwala to odzyskać granice funkcji, nazwy, ścieżki źródłowe, typy i informacje o kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator może pozostawić te struktury użyteczne, zastępując odzyskane nazwy. Garble na przykład hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o buildzie, module i debugowaniu.<sup>[[12]](#references)</sup> Obfuskowany token pakietu musi być taki sam dla funkcji z tego pakietu. Pogrupuj funkcje według powtarzającego się tokenu, ustal, do którego pakietu należy jedna z nich, na podstawie wywoływanych przez nią funkcji, ciągów znaków i API, a następnie przypisz tę etykietę pakietu całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli z runtime z generowaniem czystych referencji i dopasowywaniem grafów przepływu sterowania (CFG). Wykonaj kolejno następujące kroki:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuscator je usunął, porównaj fragmenty dołączonego środowiska uruchomieniowego Go z referencyjnymi środowiskami uruchomieniowymi dla poszczególnych wersji. W testach Volexity około `2%` środowiska uruchomieniowego wystarczyło do rozróżnienia głównych wersji Go. Potraktuj to jako empiryczną optymalizację, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj dopasowane referencje.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, architektury docelowej i prawdopodobnych bibliotek. Dopasowanie toolchainu ogranicza różnice w CFG generowane przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje CFG funkcji i zwraca znormalizowane wyniki z zakresu od `0.0` do `1.0`. Dopasowywanie podstawowych bloków opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności pozwalają przypisać losowo nazwanym funkcjom nazwy z czystej implementacji. Słabsze dopasowania nadal mogą wskazać pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy na podstawie relacji między wywołaniami, stałych, ciągów znaków i efektów ubocznych, a następnie zaimportuj raport JSON za pomocą pluginu GoResolver do IDA lub Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Zainstaluj toolchain i uruchom połączony ekstraktor oraz narzędzie do dopasowywania grafów:<sup>[[10]](#references)</sup>

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

Domyślny próg znaczącego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają wyodrębnić każdy z tych etapów, natomiast domyślnie wykonywane są oba, ponieważ odzyskane metadane runtime i informacje z CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG są heurystyczne: inlining, flagi kompilacji, architektura i różnice między wersjami bibliotek mogą zmieniać kształt grafu, dlatego nierozpoznane funkcje należy pozostawić bez nazwy zamiast przypisywać im nazwy przy niskim poziomie pewności.<sup>[[13]](#references)</sup>

### Odzyskiwanie tabeli ciągów Go

Binarne pliki Go umieszczają bajty ciągów ze wszystkich dołączonych pakietów w jednej ciągłej tabeli. Wpisy nie są zakończone bajtem NUL, a struktury runtime nie ujawniają początku ani rozmiaru tabeli. Kompilator porządkuje jednak wpisy najpierw według długości, a następnie alfabetycznie — niezależnie od systemu operacyjnego i architektury. Po znalezieniu jednego wpisu analityk może więc przejść do sąsiednich wpisów i użyć odwołań do danych, aby powiązać ciągi z kodem.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatyzuje ten proces w IDA Pro i Ghidra. Najpierw poczekaj na zakończenie automatycznej analizy, ponieważ wtyczka korzysta z odwołań do segmentu danych. Domyślnym punktem odniesienia jest ciąg runtime `entersyscall`. Następnie wtyczka może skanować w obu kierunkach, zdefiniować odzyskane ciągi w bazie danych i wyeksportować mapowanie ciągów na funkcje, które się do nich odwołują, w formacie JSON.<sup>[[14]](#references)</sup>

Filtruj raport według pakietu funkcji odwołującej się do ciągu, aby oddzielić kod aplikacji lub malware od szumu pochodzącego z dołączonych bibliotek. Ta technika nie odzyska literałów usuniętych przez obfuskację, na przykład w wyniku transformacji Garble `-literals`. Nadal może jednak uporządkować ciągi runtime, które nie zostały poddane obfuskacji.<sup>[[14]](#references)[[15]](#references)</sup>

### Odzyskiwanie typów runtime Go

Go osadza informacje o typach runtime wykorzystywane przez takie mechanizmy jak garbage collection. Gdy informacje o kompilacji zostaną usunięte lub disassembler nie przeanalizuje tych metadanych, instrukcje mogą wyglądać tak, jakby ładowały dowolne adresy danych, a docelowy obszar pozostaje bez określonego typu. Odzyskanie metadanych zamienia te adresy w czytelne odwołania do typów i ułatwia zrozumienie możliwości pakietów.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) może wyodrębniać symbole i analizować typy runtime, tworząc raport JSON. Obecnie CLI używa podkomendy `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcja `-y`/`--types` włącza parsowanie typów. Zaimportuj raport za pomocą pluginu GoResolver dla IDA Pro lub Ghidra, aby zdefiniować odzyskane typy i zastosować ich referencje w bazie danych analizy. W formacie raportu wprowadzonym wraz z tą funkcją pominięcie `-y` powoduje, że pola `RTTI address` i `recovered-types` mają wartość null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver obsługuje pliki PE, ELF i Mach-O dla architektur x86, AMD64, ARM i ARM64, więc ten sam workflow można zastosować do plików binarnych Go z Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje o tym, jak uzyskać kod Pythona ze skompilowanego pliku binarnego ELF/EXE:


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

![Konfiguracja sterowania no$gba pokazująca mapowanie przycisków Game Boy Advance](<../../images/image (581).png>)

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

W tego rodzaju programie interesujące będzie **to, jak program przetwarza dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

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

Ostatni warunek if sprawdza, czy **`uVar4`** znajduje się wśród poprzednich klawiszy i nie jest bieżącym klawiszem, co oznacza puszczenie przycisku (bieżący klawisz jest zapisany w **`uVar1`**).

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
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony kod jest prawidłowy.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli wartości są równe, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany jest licznik (`DAT_030000d4`) i zwiększany.\
  Dopóki licznik jest mniejszy niż 8, wartości naciśniętych przycisków są dodawane do `DAT_030000d8`.

Zatem w tym wyzwaniu, znając wartości przycisków, trzeba było **nacisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło do tego tutoriala:** [zarchiwizowany opis wyzwania Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacja plików binarnych)

## References

- [1] [Upraszczanie obfuskacji MBA za pomocą CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repozytorium CoBRA Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Dekodowanie ciągów Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - ciągi Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversingu GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie reverse engineeringu wspomaganego przez AI, a przynajmniej próby jego pokonania](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania oparte na dopasowywaniu podstawowych bloków](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repozytorium Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: wykorzystanie podobieństwa grafów przepływu sterowania do automatycznej deobfuskacji plików binarnych Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repozytorium Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aktualizacje narzędzi Volexity dla Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: inżynieria wsteczna wszystkiego](https://github.com/morluto/rea)
- [17] [Analiza kodu zarządzanego w REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Przewodnik po CLI i dowodach w REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: workflow usuwania spłaszczania przepływu sterowania w Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: włamanie z użyciem zero-day w PaperCut MF, loader Java, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacja serwera bridge dla IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacja serwera bridge dla Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) wiąże się z adresem wieloznacznym](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
