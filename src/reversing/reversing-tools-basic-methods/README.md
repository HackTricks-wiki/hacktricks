# Narzędzia do reversing i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do reversing oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatyzacja WinDbg w trybie użytkownika

{{#ref}}
windbg-automation.md
{{#endref}}

## Przepływ sterowania w Windows oparty na wyjątkach

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Debugowanie jądra Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** wasm (format binarny) do wat (czytelny tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** wat do wasm
- Do dekompilacji możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode z cache Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Zwirtualizowane payloady i własne maszyny wirtualne

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje różne formaty**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego narzędzia jest możliwość zaoszczędzenia czasu, gdy trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu. Ponadto dotPeek oferuje wygodną nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza proces tworzenia oprogramowania. Przyjrzyjmy się szerokiemu zakresowi usług reverse engineeringu oferowanych przez to narzędzie:

- Pokazuje, jak dane przepływają przez bibliotekę lub komponent
- Umożliwia wgląd w implementację i użycie języków oraz frameworków .NET
- Wyszukuje nieudokumentowane i nieujawnione funkcje, aby lepiej wykorzystać używane API i technologie.
- Wyszukuje zależności i różne zestawy
- Pomaga znaleźć dokładne miejsce występowania błędów w kodzie, komponentach firm trzecich i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): możesz używać jej w dowolnym systemie operacyjnym (możesz zainstalować ją bezpośrednio z VSCode, nie trzeba pobierać repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **dekompilować**, **modyfikować** i ponownie **kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub jego aktywnie rozwijanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Inspekcja zarządzanego kodu bez wykonywania za pomocą REA

**REA** może analizować metadane PE/CLI i CIL bez ładowania zestawu. Zacznij od identyfikacji artefaktu, a następnie sprawdź składowe i zadeklarowane granice kodu natywnego; jest to przydatne podczas analizy podejrzanych wywołań przed użyciem dekompilatora lub uruchomieniem programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Przy porównywaniu wersji `compare_managed_members` używa surowej tożsamości CIL/podpisu i fingerprintów zdekodowanych instrukcji, zamiast traktować tokeny metadanych jako niezmienne między buildami. Deklaracja P/Invoke nie stanowi dowodu, że wykonano kod natywny; `verify_managed_native_boundaries` wymaga zgodnego natywnego exportu lub Evidence funkcji, aby sprawdzić tę granicę. Zachowaj digest artefaktu, MVID i nierozwiązane mapowania razem z wynikiem.<sup>[[17]](#references)</sup>

### Rejestrowanie w DNSpy

Aby **DNSpy zapisywał pewne informacje do pliku**, możesz użyć tego fragmentu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie w DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Najpierw zmienić **atrybuty Assembly** związane z **debugowaniem**:

![Rejestrowanie w DNSpy - debugowanie w DNSpy: najpierw zmień atrybuty Assembly związane z debugowaniem](<../../images/image (973).png>)

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

Jest to konieczne, ponieważ w przeciwnym razie podczas **runtime** kod zostanie poddany kilku **optymalizacjom** i może się zdarzyć, że podczas debugowania **punkt przerwania nigdy nie zostanie osiągnięty** albo niektóre **zmienne nie będą istnieć**.

Następnie, jeśli aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w **karcie Debugowanie** wybierz **Dołącz do procesu...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do **serwera IIS**, i kliknij **Dołącz**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, czas go zatrzymać i załadować wszystkie moduły. Najpierw kliknij _Debugowanie >> Zatrzymaj wszystko_, a następnie kliknij _**Debugowanie >> Okna >> Moduły**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w oknie **Moduły** i wybierz **Otwórz wszystkie moduły**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Eksploratorze zestawów** i wybierz **Sortuj zestawy**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Używanie IDA

- **Załaduj rundll32** (64-bitowy: C:\Windows\System32\rundll32.exe, 32-bitowy: C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Wstrzymuj przy ładowaniu/zwalnianiu biblioteki**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parametry** wykonywania, podając **ścieżkę do DLL** oraz funkcję, którą chcesz wywołać:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Następnie, gdy rozpoczniesz debugowanie, **wykonywanie zostanie wstrzymane przy załadowaniu każdej DLL**. Gdy rundll32 załaduje Twoją DLL, wykonywanie zostanie wstrzymane.

Ta metoda zatrzymuje wykonywanie przy zdarzeniach ładowania modułów, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym poniżej sposobie z użyciem x64dbg.

### Używanie x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy: C:\Windows\System32\rundll32.exe, 32-bitowy: C:\Windows\SysWOW64\rundll32.exe)
- **Zmień wiersz poleceń** ( _Plik --> Zmień wiersz poleceń_ ) i podaj ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień ustawienia w _Opcje --> Ustawienia_ i wybierz "**Punkt wejścia DLL**".
- Następnie **rozpocznij wykonywanie**. Debugger zatrzyma się przy każdej funkcji main DLL, a w pewnym momencie **zatrzymasz się w punkcie wejścia swojej DLL**. Następnie wyszukaj miejsca, w których chcesz ustawić breakpoint.

Zwróć uwagę, że gdy wykonywanie zostanie z jakiegoś powodu zatrzymane w win64dbg, możesz sprawdzić, **w jakim kodzie jesteś**, patrząc na **górną część okna win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonywanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / Gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do wyszukiwania ważnych wartości zapisanych w pamięci uruchomionej gry i ich zmieniania. Więcej informacji:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to nakładka/front-end i narzędzie do reverse engineeringu dla GNU Project Debugger (GDB), przeznaczone głównie do gier. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to webowa nakładka na wiele dekompilatorów. Ta usługa internetowa umożliwia porównanie wyników różnych dekompilatorów dla małych plików wykonywalnych.

### Odszyfrowywanie PCK Godot i odzyskiwanie projektu

W przypadku dystrybuowanej gry Godot znajdź jej PCK jako samodzielny plik `.pck`, dołączony lub osadzony pakiet w pliku wykonywalnym albo w katalogu `assets` pliku APK. Narzędzie [gore](https://github.com/figurophobia/gore) może sprawdzić i wyodrębnić pakiet, natomiast do pełnej rekonstrukcji skryptów i zasobów potrzebne są GDRE Tools (`gore setup` je instaluje; można też użyć `--gdre`). W tym przepływie narzędzie obsługuje formaty PCK Godot 4.x w wersjach v2–v4; może wykrywać nagłówki v1, ale do obsługi v1 wymaga podanego klucza.<sup>[[25]](#references)</sup>

Automatyczne odzyskiwanie klucza wymaga zaszyfrowanej tablicy plików. Jeśli zaszyfrowano tylko zawartość plików, podaj znany klucz. Nieudana próba odzyskania klucza nie dowodzi, że pakiet jest niezaszyfrowany.<sup>[[28]](#references)</sup>

Wyszukiwanie klucza **nie jest atakiem na przestrzeń kluczy AES-256**. Zaszyfrowana tablica plików ujawnia MD5 jej tekstu jawnego, długość tekstu jawnego, IV oraz szyfrogram AES-256-CFB.<sup>[[27]](#references)</sup> `gore` sprawdza 32-bajtowe fragmenty pliku wykonywalnego gry lub sąsiednich plików jako potencjalne klucze. Odrzuca kandydatów na podstawie prawdopodobnej długości odszyfrowanej ścieżki i jej prefiksu, a trafienia znalezione podczas skanowania binarnego weryfikuje przez odszyfrowanie całej tablicy i sprawdzenie jej MD5.<sup>[[26]](#references)[[28]](#references)</sup> Najpierw przeszukuje zainicjalizowane sekcje danych PE/ELF, a następnie, w razie potrzeby, skanuje cały plik; opcja `--scan` dodaje do wyszukiwania inne pliki-kandydatów.<sup>[[28]](#references)</sup>

Jeśli nie znajdzie osadzonego klucza, narzędzie wypróbowuje krótką wbudowaną listę haseł; opcja `--wordlist` pozwala podać inne kandydaty. Każde hasło jest sprawdzane jako reprezentacja klucza wyprowadzona z hasła przez silnik, dosłownie uzupełniona zerami lub jako klucz zapisany w postaci 64 znaków szesnastkowych. W przeciwieństwie do trafień ze skanowania binarnego, trafienia ze słownika w tej implementacji przechodzą jedynie filtr struktury ścieżek. Potwierdź je, otwierając pakiet i sprawdzając wyodrębnione zasoby.<sup>[[26]](#references)[[28]](#references)</sup>

Gdy plik gry jest dostępny lokalnie, wybierz etap odpowiedni do analizy. `recover` uruchamia GDRE w celu odtworzenia projektu, który można otworzyć, natomiast `extract` jedynie rozpakowuje surowe pliki. `key` wyświetla potencjalny klucz do użycia z innym narzędziem.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Analiza natywna oparta na dowodach z użyciem REA

**REA** udostępnia analizę w Hopper, Ghidra i IDA przez CLI i MCP. Wymaga Node.js 22.x (co najmniej 22.19), 24.x (co najmniej 24.11) lub 26+, a także npm. Najpierw skonfiguruj istniejącego natywnego providera; sprawdź `rea providers --json` i jawnie wybierz providera, jeśli więcej niż jeden obsługuje cel. Zamiast `0x1000` poniżej użyj zaobserwowanej nazwy funkcji lub adresu z inwentarza.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Zacznij od ciągu znaków funkcji lub symbolu, prześledź odwołania i wywołujących, a następnie sprawdź dossier wybranej funkcji i pseudokod za pomocą `rea decompile`. REA wiąże sesję z wybranym providerem, zamiast po niepowodzeniu po cichu zastępować go innym. Aby powtarzać zapytania, `--snapshot PATH` ponownie wykorzystuje wyłącznie zgodne bajty artefaktu, providera, ustawienia, operację i parametry; snapshot to lokalna pamięć podręczna, a nie zapisana baza providera. Zachowaj zwrócony obiekt Evidence i wyraźnie wskazane niewiadome, zamiast traktować wywnioskowane ścieżki lub tekst dekompilatora jako oryginalny kod źródłowy.<sup>[[16]](#references)[[18]](#references)</sup>

Informacje o punktach wejścia JavaScript/Electron prowadzących do natywnych dodatków znajdziesz w [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Analiza skryptowa IDA i Ghidra z lokalnym mostem TCP

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) działa w **już otwartej** bazie IDA lub programie Ghidra CodeBrowser i pozwala osobnemu skryptowi odpytywać tę bazę analizy oraz ją modyfikować. Uruchom `ID_Server.py` z konsoli Python w IDA (`import ID_Server`) albo `Ghidra_Server.py` z Script Manager w Ghidra. IDA nasłuchuje na `127.0.0.1`, zaczynając od portu `5073`, i skanuje wyższe porty. Bieżący skrypt Ghidra zaczyna od portu `5093` i próbuje kolejnych dziesięciu portów, aż do `5102`; jego gniazdo Java jest powiązane z adresem wildcard, a nie tylko z interfejsem loopback. Przed połączeniem sprawdź port wyświetlony przez daną instancję. W przeciwieństwie do analizatora headless ten most działa na programie aktualnie otwartym w tej instancji GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Wysyłaj **jedno polecenie zakończone znakiem nowej linii na połączenie** i odczytuj odpowiedź zakończoną znakiem nowej linii. Wynik jest zazwyczaj w formacie JSON. Na przykład po znalezieniu zaimportowanego API związanego ze ścieżką wejściową `IMPORTXREF` wyszukuje miejsca jego wywołań; następnie `DECOMP_XREF` zbiorczo dekompiluje funkcje wywołujące pod wybranym adresem. `FUNC` analizuje funkcję, a `PCODE` zwraca pośrednią reprezentację dekompilatora. Używaj adresu z aktywnej bazy, a nie adresu skopiowanego z binarnego pliku z inną bazą relokacji. Poniższy przykład korzysta z domyślnego portu IDA; w przypadku Ghidra użyj portu wyświetlonego przez skrypt.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Ten sam kanał może **zmieniać bazę analizy**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` zmieniają nazwy, typy, definicje struktur, granice funkcji lub zapisane bajty. `PATCH` to edycja bazy danych, **a nie** dowód na patchowanie działającego procesu. Żaden z listenerów nie dokumentuje uwierzytelniania. IDA nasłuchuje tylko na loopback, ale Ghidra może być dostępna przez interfejsy sieciowe; podczas korzystania z niej ogranicz dostęp do listenera Ghidry. `QUIT` zatrzymuje oba listenery, a IDA udostępnia również `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres w pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie github z wydaniami znajdują się archiwa ZIP ze skompilowanymi wersjami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, po prostu **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie go zbuduj**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i wchodzi w nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 sekund**, wstrzymaj je wewnątrz tej pętli, a następnie przejdź do kolejnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode.

![Debugger wstrzymany w nieskończonej pętli jmp2it, bezpośrednio przed wywołaniem zaalokowanego shellcode](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Cutter umożliwia emulowanie shellcode i jego dynamiczną analizę.

Pamiętaj, że Cutter umożliwia wybranie „Open File” lub „Open Shellcode”. W moim przypadku po otwarciu shellcode jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode — nie:

![Cutter pokazujący różne wyniki analizy tych samych bajtów otwartych jako plik lub jako shellcode](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp. Wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w żądanym miejscu wejścia shellcode przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cuttera wstrzymany na wybranym breakpoincie shellcode](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie stosu emulowanego shellcode w zrzucie szesnastkowym Cuttera](<../../images/image (186).png>)

### Usuwanie obfuskacji shellcode i pozyskiwanie wywoływanych funkcji

Spróbuj użyć [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokaże między innymi, **jakich funkcji** używa shellcode i czy **dekoduje się** w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg jest również wyposażony w graficzny launcher, w którym możesz wybrać żądane opcje i uruchomić shellcode

![Graficzny launcher scDbg do wybierania opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli jego zawartość zostanie zmieniona dynamicznie w pamięci (przydatne do pobrania zdekodowanego shellcode). Opcja **start offset** może być przydatna do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** pozwala debugować shellcode za pomocą terminala scDbg (jednak uważam, że lepiej sprawdzą się dowolne z wcześniej opisanych opcji, ponieważ można wtedy użyć Ida lub x64dbg).

### Dezasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj poniższego przepisu, aby go zdezasemblować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuskacja obfuskacji MBA

Obfuskacja **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za formułami łączącymi operacje arytmetyczne (`+`, `-`, `*`) i operatory bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest to, że te tożsamości są zwykle poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz takie wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny przebieg pracy

1. **Zachowaj oryginalną szerokość bitową** z podniesionego kodu/IR/wyjścia dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenia liniowe z dodatkowymi stałymi maskami, takimi jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i operacje logiki bitowej są przeplatane, często z powtarzającymi się podwyrażeniami
3. **Weryfikuj każde proponowane przekształcenie** za pomocą losowych testów lub dowodu SMT. Jeśli nie można udowodnić równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omijanie spłaszczonego przepływu sterowania za pomocą wąskiego wycinka wykonania

Odzyskanie kompletnego grafu przepływu sterowania często nie jest konieczne. W przypadku spłaszczania przepływu sterowania, nieprzejrzystych predykatów, dużych dispatcherów lub kodu obciążonego MBA podążaj za referencjami od zaszyfrowanych blobów i buforów wyjściowych do najmniejszej procedury, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych albo uruchom go niezależnie; dispatcher nie jest potrzebny do rozwiązania, jeśli odpowiedni stan można zainicjalizować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny przebieg pracy:<sup>[[7]](#references)</sup>

1. Zinwentaryzuj sekcje kodu wykonywalnego i danych, relokacje oraz odwołania krzyżowe. Zrzucaj kandydackie tablice z `.rodata`, zachowując kolejność bajtów i szerokość elementów.
2. Znajdź ostatnią procedurę zapisującą tekst jawny lub bufor wyjściowy. Zapisz jej dane wejściowe, używane tablice, wywołania importowane oraz wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Pythona o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt wielu elementów stanu, wywołaj procedurę w Unicorn, QEMU lub debuggerze i przechwytuj nieistotne importowane funkcje zamiast emulować cały program.
4. Sprawdź, czy ekstraktor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche mechanizmy awaryjne, wyszukaj w nim osadzone odpowiedzi i uruchom go na nieznanych wcześniej kompilacjach ze zmienionymi ciągami znaków, kluczami, identyfikatorami, układami danych i ziarnami obfuskacji.

Przydatne polecenia do wstępnej analizy:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Wykrywanie wyrażeń MBA maskujących stałe

Pozornie zależne od wejścia wyrażenie bajtowe może całkowicie eliminować swoje wejście. Po wyodrębnieniu jego tablic oblicz wartość wyrażenia dla całej 8-bitowej dziedziny; jednoelementowy zbiór wyników dowodzi, że bajt jest stały, bez konieczności odtwarzania otaczającej maszyny stanów.<sup>[[7]](#references)</sup>

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie powoduje zawijanie przy szerokości bajtu. Dla szerszej dziedziny zapytaj solver SMT, czy `f(x1) != f(x2)` jest spełnialne dla dwóch symbolicznych wejść o tej samej szerokości: `unsat` dowodzi niezmienności, natomiast `sat` dostarcza kontrprzykład i oznacza, że wejścia nie można odrzucić.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole anti-analysis nie muszą wykonywać skoku ani powodować awarii. Dekoder może wmieszać wynik odczytu czujnika w bit klucza, stałą opaque predicate lub stan spłaszczonego dispatchera, działać dalej i w emulatorze wygenerować wiarygodny, ale fałszywy tekst jawny. Dlatego samo patchowanie widocznych gałęzi błędów nie wystarczy; śledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam wycinek na autentycznym urządzeniu i w emulatorze oraz sprawdź, jak wymuszenie każdego wyniku czujnika zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA na potrzeby analizy malware i inżynierii wstecznej zabezpieczonych plików binarnych. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków, zamiast stosować jeden ogólny przebieg przepisujący do wszystkiego.<sup>[[2]](#references)</sup>

Szybki przykład użycia:

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

- **Linear MBA**: CoBRA oblicza wartość wyrażenia dla wejść Boolean, wyznacza sygnaturę i równolegle uruchamia kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja do ANF i interpolacja współczynników.
- **Semilinear MBA**: atomy z maskami stałych są odtwarzane za pomocą rekonstrukcji z podziałem na bity, dzięki czemu zamaskowane obszary pozostają poprawne.
- **Polynomial/Mixed MBA**: iloczyny są rozkładane na rdzenie, a powtarzające się podwyrażenia można przenieść do zmiennych tymczasowych przed uproszczeniem relacji zewnętrznej.

Przykład mieszanej tożsamości, której odzyskanie często warto spróbować:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Można to sprowadzić do:

```c
x * y
```

### Notatki dotyczące reverse engineeringu

- Najlepiej uruchamiać CoBRA na **wyrażeniach lifted IR** lub wyniku dekompilacji po wyodrębnieniu dokładnego obliczenia.
- Jeśli wyrażenie pochodzi z arytmetyki z maskowaniem lub wąskich rejestrów, jawnie ustaw `--bitwidth`.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, zajrzyj do lokalnych notatek o Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępne jako **plugin LLVM pass** (`libCobraPass.so`), przydatny do normalizowania LLVM IR zawierającego dużo MBA przed późniejszymi passami analitycznymi.
- Niewspierane reszty mieszanych domen zależne od przeniesienia potraktuj jako sygnał, by zachować oryginalne wyrażenie i ręcznie prześledzić ścieżkę przeniesienia.

## Odtwarzanie control-flow flattening ze stanem XOR

Flattener w stylu OLLVM może przechowywać stan bieżącego basic blocka w dwóch rejestrach 64-bitowych i odtwarzać go za pomocą XOR w dispatcherze. Każdy oryginalny blok zapisuje parę wartości odpowiadającą następnemu stanowi i skacze z powrotem do dispatchera. Blok warunkowy może używać `CMOVcc` do zastąpienia jednej połowy pary zgodnie z flagami procesora, więc śledzenie wyłącznie widocznych instrukcji skoku pomija dwa następniki. W odróżnieniu od dispatchera z pośrednim skokiem, ten wariant może używać bezpośrednich skoków wstecznych w całym kodzie.<sup>[[19]](#references)[[20]](#references)</sup>

Aby odtworzyć graf, znajdź drzewo porównań dispatchera i dwa rejestry stanu, przypisz każdy porównywany stan XOR do bloku docelowego, a następnie prześledź zapisy do pary rejestrów osiągalne w każdym oryginalnym bloku. W przypadku zapisów warunkowych uwzględnij instrukcję ustawiającą flagi oraz oba wyniki `CMOVcc`. Zastąp wyjście każdego bloku do dispatchera rozpoznanym bezpośrednim następnikiem lub skokiem warunkowym; dispatcher stanie się wtedy nieosiągalny bez modyfikowania pliku binarnego. To podejście obejmuje cały CFG; jeśli interesuje Cię tylko jeden dekoder, szybszy może być opisany wyżej [workflow wąskiego wycinka wykonania](#bypass-flattened-control-flow-with-a-narrow-execution-slice).<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatyzuje ten wariant w Binary Ninja. Skopiuj `plugins/DispatchThis` do katalogu pluginów użytkownika Binary Ninja i uruchom program ponownie. W ustawieniach funkcji, której dotyczy problem, otwórz **Function Settings** i wybierz `OLLVM_XOR_64`; jeśli analiza się nie rozpocznie, wybierz **Analysis → Reanalyze All Functions**. Ten tryb przepisuje krawędzie przepływu sterowania MLIL, a nie bajty pliku, i nie wymaga Z3 ani resolvera pośrednich skoków. Został przetestowany w Binary Ninja 5.3.9757+; nie usuwa martwych zapisów stanu w poszczególnych blokach, więc nie należy mylić ich z nadal aktywnymi przejściami.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i wykorzystuje obsługę sygnałów/wyjątków do zmiany przepływu sterowania. Szczegóły:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

W przypadku obsługiwanych plików binarnych narzędzie [demovfuscator](https://github.com/kirschju/demovfuscator) może cofnąć obfuscation. Wymaga kilku zależności.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście pozwalające znaleźć flagę** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **entry point**, wyszukaj funkcje zawierające `::main`, jak w tym przykładzie:

![Znajdowanie entry point w Rust w Ghidrze przez wyszukiwanie nazw funkcji zawierających podwójny dwukropek i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nosił nazwę authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby dowiedzieć się więcej o ich **danych wejściowych** i **wyjściowych**.

### Odzyskiwanie ciągów znaków Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone znakiem NUL, jak w C. Typowy układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągów znaków przechowywany w **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Oznacza to, że `strings` lub domyślna analiza Ghidry może scalać sąsiadujące ciągi znaków albo całkowicie pomijać odwołania krzyżowe.<sup>[[3]](#references)</sup>

Szybki przebieg pracy:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Pobierz adres wirtualny i rozmiar sekcji **`.rodata`**.
2. Enumeruj **`.data.rel.ro`** słowo po słowie.
3. Traktuj każdą wartość mieszczącą się w zakresie adresów `.rodata` jako kandydat na wskaźnik do ciągu znaków.
4. Traktuj następne słowo jako kandydat na długość.
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

Jest to szczególnie przydatne podczas reversingu firmware'u, ponieważ odzyskane ciągi znaków z Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, procedury obsługi poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykrywa tych ciągów, uruchom własny skrypt/wtyczkę, który stosuje tę samą heurystykę i tworzy dane typu string pod wskazanymi offsetami w `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners to dobre punkty odniesienia przy dostosowywaniu tej metody do innych **szerokości słów, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku skompilowanych plików binarnych Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reverse engineering pliku binarnego Delphi, polecam wtyczkę IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować wtyczkę Python, a następnie wybierz plik wtyczki.

Ta wtyczka uruchomi plik binarny i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony przycisk lub f9), a punkt przerwania zostanie osiągnięty na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

W przypadku zwykłych plików binarnych Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury runtime i poprawić nazwy funkcji w IDA. Załaduj jego wtyczkę Python za pomocą **Alt+F7**.

Jeśli musisz przeprowadzić reverse engineering pliku binarnego Golang, polecam wtyczkę IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować wtyczkę Python, a następnie wybierz plik wtyczki.

Pozwoli to rozpoznać nazwy funkcji.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet pozbawiony symboli plik wykonywalny Go potrzebuje metadanych runtime, aby mapować liczniki programu na funkcje. [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i analizuje struktury takie jak `pclntab` i `moduledata`, wykorzystując kod oparty na runtime Go. Pozwala to odzyskać granice funkcji, nazwy, ścieżki źródłowe, typy i szczegóły kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator może pozostawić te struktury użyteczne, jednocześnie zastępując odzyskane nazwy. Na przykład Garble hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o kompilacji, modułach i debugowaniu.<sup>[[12]](#references)</sup> Token obfuskowanego pakietu musi pozostać spójny w funkcjach z tego pakietu. Grupuj funkcje według powtarzającego się tokenu, wywnioskuj nazwę jednego pakietu na podstawie jego funkcji wywoływanych, ciągów znaków i API, a następnie przypisz tę etykietę pakietu całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli runtime z generowaniem czystych plików referencyjnych i dopasowywaniem grafów przepływu sterowania (CFG). Zastosuj następującą kolejność:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuscator je usunął, porównaj fragmenty dołączonego Go runtime z referencyjnymi wersjami runtime. W testach Volexity wystarczyło około `2%` runtime, aby rozróżnić główne wersje Go. Potraktuj to jako empiryczną optymalizację, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj pasujące pliki referencyjne.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, architektury docelowej i prawdopodobnych bibliotek. Dopasowanie toolchaina ogranicza różnice CFG wprowadzone przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje grafy CFG funkcji i generuje znormalizowane wyniki od `0.0` do `1.0`. Dopasowywanie podstawowych bloków opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności pozwalają powiązać losowo nazwane funkcje z czystą implementacją. Słabsze dopasowania nadal mogą wskazać pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy na podstawie relacji wywołań, stałych, ciągów znaków i efektów ubocznych, a następnie zaimportuj raport JSON za pomocą wtyczki GoResolver dla IDA lub Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Domyślny próg istotnego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają uruchomić osobno każdy z etapów, natomiast domyślnie uruchamiane są oba, ponieważ odzyskane metadane środowiska uruchomieniowego i dane CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG mają charakter heurystyczny: inlining, flagi kompilacji, architektura i różnice między wersjami bibliotek mogą zmieniać kształt grafu, dlatego nierozpoznane funkcje należy pozostawić bez nazw, zamiast przypisywać im nazwy na podstawie dopasowań o niskim poziomie pewności.<sup>[[13]](#references)</sup>

### Odzyskiwanie tabeli stringów Go

Binarne pliki Go umieszczają bajty stringów ze wszystkich dołączonych pakietów w jednej ciągłej tabeli. Wpisy nie są zakończone znakiem NUL, a struktury środowiska uruchomieniowego nie udostępniają początku ani rozmiaru tabeli. Kompilator porządkuje jednak wpisy najpierw według długości, a następnie alfabetycznie, niezależnie od systemu operacyjnego i architektury. Po znalezieniu jednego wpisu analityk może więc przejrzeć sąsiednie wpisy i użyć odwołań do danych, by powiązać stringi z kodem.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatyzuje ten proces w IDA Pro i Ghidra. Najpierw zaczekaj na zakończenie autoanalizy, ponieważ wtyczka korzysta z odwołań do segmentu danych. Domyślnym ciągiem kotwiczącym jest string środowiska uruchomieniowego `entersyscall`. Następnie wtyczka może skanować w obu kierunkach, zdefiniować odzyskane stringi w bazie danych i wyeksportować mapowanie stringów na funkcje odwołujące się do nich w formacie JSON.<sup>[[14]](#references)</sup>

Filtruj raport według pakietu funkcji odwołującej się do stringa, aby oddzielić kod aplikacji lub malware od szumu pochodzącego z dołączonych bibliotek. Ta technika nie pozwala odzyskać literałów zniszczonych przez obfuskację, taką jak transformacja `-literals` w Garble. Nadal może jednak uporządkować stringi środowiska uruchomieniowego, które nie zostały poddane obfuskacji.<sup>[[14]](#references)[[15]](#references)</sup>

### Odzyskiwanie typów środowiska uruchomieniowego Go

Go osadza informacje o typach środowiska uruchomieniowego wykorzystywane przez funkcje takie jak garbage collection. Gdy informacje o kompilacji zostały usunięte lub disassembler nie parsuje tych metadanych, instrukcje mogą wyglądać tak, jakby ładowały dowolne adresy danych, a docelowy obszar pozostaje bez określonego typu. Odzyskanie metadanych zamienia te adresy w czytelne odwołania do typów i ułatwia zrozumienie możliwości pakietów.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) może wyodrębniać symbole i parsować typy środowiska uruchomieniowego, tworząc raport JSON. Bieżący CLI używa podkomendy `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcja `-y`/`--types` włącza parsowanie typów. Zaimportuj raport za pomocą wtyczki GoResolver do IDA Pro lub Ghidry, aby zdefiniować odzyskane typy i zastosować odwołania do nich w bazie danych analizy. W formacie raportu wprowadzonym wraz z tą funkcją pominięcie `-y` powoduje, że pola RTTI address i recovered-types mają wartość null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver obsługuje próbki PE, ELF i Mach-O dla x86, AMD64, ARM i ARM64, więc ten sam proces można zastosować do plików binarnych Go z Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje o tym, jak odzyskać kod Pythona ze skompilowanego pliku binarnego ELF/EXE:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli masz **plik binarny** gry GBA, możesz użyć różnych narzędzi do jej **emulowania** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Wtyczka Ghidry
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Wtyczka Ghidry

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

Ostatni warunek `if` sprawdza, czy **`uVar4`** znajduje się w **ostatnim Keys** i nie jest bieżącym klawiszem — oznacza to puszczenie przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).

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

W poprzednim kodzie widać, że porównujemy **uVar1** (miejsce, w którym znajduje się **wartość naciśniętego przycisku**) z kilkoma wartościami:

- Najpierw jest porównywana z **wartością 4** (przycisk **SELECT**): w tym challenge ten przycisk czyści ekran.
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym challenge ta ścieżka sprawdza, czy wprowadzony kod jest prawidłowy.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartości są takie same, wykonywany jest pewien kod.
- W każdym innym przypadku sprawdzany jest licznik (`DAT_030000d4`) i zwiększany o 1.\
  Gdy licznik jest mniejszy niż 8, wartości naciśniętych przycisków są sumowane w `DAT_030000d8`.

A zatem w tym challenge, znając wartości przycisków, trzeba było **nacisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło do tego tutoriala:** [zarchiwizowany opis rozwiązania challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Dekodowanie ciągów znaków w Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - ciągi znaków w Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reverse engineeringu GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Pokonywanie reverse engineeringu wspomaganego przez AI — a przynajmniej próby](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania oparte na dopasowywaniu podstawowych bloków](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repozytorium Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: automatyczna deobfuskacja plików binarnych Golang za pomocą podobieństwa grafów przepływu sterowania](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repozytorium Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aktualizacje narzędzi Volexity dla Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: reverse engineering czegokolwiek](https://github.com/morluto/rea)
- [17] [Analiza kodu zarządzanego w REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Przewodnik po CLI i dowodach w REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: workflow usuwania spłaszczania przepływu sterowania w Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: włamanie wykorzystujące lukę zero-day w PaperCut MF, loader Java, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacja serwera bridge IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacja serwera bridge Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) wiąże się z adresem wieloznacznym](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: zestaw narzędzi do reverse engineeringu Godot](https://github.com/figurophobia/gore)
- [26] [Implementacja odzyskiwania klucza w gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Format zaszyfrowanych blobów gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implementacja poleceń i odzyskiwania w gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
