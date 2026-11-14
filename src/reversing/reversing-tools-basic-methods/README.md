# Narzędzia do reverse engineeringu i podstawowe metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do reverse engineeringu oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatyzacja WinDbg w trybie użytkownika

{{#ref}}
windbg-automation.md
{{#endref}}

## Przepływ sterowania oparty na wyjątkach w systemie Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Debugowanie jądra systemu Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Dekompilator Wasm / kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **zdekompilować** wasm (plik binarny) do wat (czytelnego tekstu)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **skompilować** wat do wasm
- Do dekompilacji możesz też wypróbować [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bajtkod z pamięci podręcznej Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Zwirtualizowane payloady i niestandardowe maszyny wirtualne

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych systemu Windows** (.winmd) oraz **pliki wykonywalne** (.exe). Po dekompilacji zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą tego narzędzia jest to, że może zaoszczędzić czas, gdy trzeba odtworzyć utracony kod źródłowy na podstawie starszego zestawu. Ponadto dotPeek ułatwia nawigację po zdekompilowanym kodzie, dzięki czemu jest jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki rozbudowanemu modelowi dodatków i API, które pozwala dostosować narzędzie do konkretnych potrzeb, .NET Reflector oszczędza czas i upraszcza pracę programistyczną. Oto niektóre z licznych możliwości reverse engineeringu, jakie oferuje to narzędzie:

- Pokazuje, jak dane przepływają przez bibliotekę lub komponent
- Umożliwia wgląd w implementację i użycie języków oraz frameworków .NET
- Wykrywa nieudokumentowane i nieudostępnione funkcje, pozwalając lepiej wykorzystać używane API i technologie.
- Wykrywa zależności i różne zestawy
- Pomaga znaleźć dokładne miejsce występowania błędów w kodzie, komponentach innych firm i bibliotekach.
- Umożliwia debugowanie kodu źródłowego całego używanego kodu .NET.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Wtyczka ILSpy do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz używać jej w dowolnym systemie operacyjnym (możesz zainstalować ją bezpośrednio z VSCode — nie musisz pobierać repozytorium git. Kliknij **Extensions** i **wyszukaj ILSpy**).\
Jeśli chcesz **zdekompilować**, **zmodyfikować** i ponownie **skompilować** kod, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub jego aktywnie rozwijanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem myszy -> Modify Method**, aby zmienić coś wewnątrz funkcji).

### Inspekcja kodu zarządzanego bez jego wykonywania za pomocą REA

**REA** umożliwia inspekcję metadanych PE/CLI i CIL bez ładowania zestawu. Zacznij od ustalenia tożsamości artefaktu, a następnie sprawdź składowe i zadeklarowane granice kodu natywnego. Jest to przydatne podczas analizy podejrzanych wywołań przed użyciem dekompilatora lub uruchomieniem programu.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Przy diffowaniu wersji `compare_managed_members` używa surowej tożsamości CIL/podpisu i fingerprintów zdekodowanych instrukcji, zamiast traktować tokeny metadanych jako stabilne między buildami. Deklaracja P/Invoke nie jest dowodem na wykonanie kodu natywnego; `verify_managed_native_boundaries` wymaga zgodnego natywnego eksportu lub Evidence funkcji, aby sprawdzić tę granicę. Zachowaj digest artefaktu, MVID i nierozwiązane mapowania wraz z wynikiem.<sup>[[17]](#references)</sup>

### Logowanie w DNSpy

Aby **DNSpy zapisywał pewne informacje w pliku**, możesz użyć tego fragmentu:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugowanie w DNSpy

Aby debugować kod za pomocą DNSpy, należy:

Najpierw zmienić **atrybuty zestawu** związane z **debugowaniem**:

![DNSpy Logging - Debugowanie w DNSpy: Najpierw zmień atrybuty zestawu związane z debugowaniem](<../../images/image (973).png>)

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

Jest to konieczne, ponieważ w przeciwnym razie podczas **runtime** kod zostanie poddany różnym **optymalizacjom** i może się zdarzyć, że podczas debugowania **punkt przerwania nigdy nie zostanie osiągnięty** albo niektóre **zmienne nie będą istnieć**.

Następnie, jeśli aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:

```
iisreset /noforce
```

Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w **Debug Tab** wybierz **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Następnie, aby rozpocząć debugowanie, zamknij wszystkie otwarte pliki, a w Debug Tab wybierz Attach to Process](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do **IIS server**, i kliknij **attach**:

![DNSpy Logging - DNSpy Debugging: Następnie wybierz w3wp.exe, aby dołączyć do IIS server, i kliknij attach](<../../images/image (113).png>)

Po rozpoczęciu debugowania procesu zatrzymaj go i załaduj wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie kliknij _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Po rozpoczęciu debugowania procesu zatrzymaj go i załaduj wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Po rozpoczęciu debugowania procesu zatrzymaj go i załaduj wszystkie moduły. Najpierw kliknij Debug Break All, a następnie Debug Windows Modules](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Kliknij dowolny moduł w Modules i wybierz Open All Modules](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i kliknij **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Kliknij prawym przyciskiem myszy dowolny moduł w Assembly Explorer i kliknij Sort Assemblies](<../../images/image (339).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Używanie IDA

- **Załaduj rundll32** (64-bitowy w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![Debugowanie DLL - Używanie IDA: Wybierz " Suspend on library load/unload "](<../../images/image (868).png>)

- Skonfiguruj **parametry** uruchomienia, podając **ścieżkę do DLL** i funkcję, którą chcesz wywołać:

![Debugowanie DLL - Używanie IDA: Skonfiguruj parametry uruchomienia, podając ścieżkę do DLL i funkcję, którą chcesz wywołać](<../../images/image (704).png>)

Po rozpoczęciu debugowania **wykonywanie zostanie zatrzymane po załadowaniu każdej DLL**. Gdy rundll32 załaduje Twoją DLL, wykonywanie zostanie zatrzymane.

Ta metoda zatrzymuje wykonywanie podczas zdarzeń ładowania modułów, ale dotarcie do punktu wejścia załadowanej DLL jest mniej bezpośrednie niż w opisanym poniżej sposobie z użyciem x64dbg.

### Używanie x64dbg/x32dbg

- **Załaduj rundll32** (64-bitowy w C:\Windows\System32\rundll32.exe, a 32-bitowy w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień wiersz poleceń** ( _File --> Change Command Line_ ) i podaj ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień ustawienie w _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **rozpocznij wykonywanie**. Debugger zatrzyma się przy każdej funkcji dll main, a w pewnym momencie **zatrzymasz się w punkcie wejścia swojej DLL**. Następnie znajdź miejsca, w których chcesz ustawić breakpoint.

Zauważ, że gdy wykonywanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, **w jakim kodzie się znajdujesz**, patrząc na **górną część okna win64dbg**:

![Używanie IDA - Używanie x64dbg/x32dbg: Zauważ, że gdy wykonywanie zostanie zatrzymane z dowolnego powodu w win64dbg, możesz sprawdzić, w jakim kodzie się znajdujesz, patrząc na górną część okna win64dbg](<../../images/image (842).png>)

Ten wskaźnik potwierdza, że wykonywanie zostało zatrzymane wewnątrz DLL, którą chcesz debugować.

## Aplikacje GUI / gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania i zmieniania wartości zapisywanych w pamięci uruchomionej gry. Więcej informacji:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie typu front-end do GNU Project Debugger (GDB), służące do reverse engineeringu i skupione na grach. Można go jednak używać do dowolnych zadań związanych z reverse engineeringiem.

[**Decompiler Explorer**](https://dogbolt.org/) to internetowy front-end dla wielu dekompilatorów. Ta usługa internetowa pozwala porównywać wyniki różnych dekompilatorów dla małych plików wykonywalnych.

### Odszyfrowywanie PCK Godot i odzyskiwanie projektu

W przypadku dystrybuowanej gry Godot znajdź jej PCK w osobnym pliku `.pck`, dołączonym lub osadzonym pakiecie wykonywalnym albo w katalogu `assets` pliku APK. [gore](https://github.com/figurophobia/gore) może sprawdzić i wyodrębnić pakiet, natomiast pełne odtworzenie skryptów i zasobów wymaga GDRE Tools (`gore setup` je instaluje albo można użyć `--gdre`). W tym procesie narzędzie obsługuje formaty PCK Godot 4.x w wersjach v2–v4; potrafi wykrywać nagłówki v1, ale do obsługi v1 wymaga podania klucza.<sup>[[25]](#references)</sup>

Automatyczne odzyskiwanie klucza wymaga zaszyfrowanej tabeli plików. Jeśli zaszyfrowana jest tylko zawartość plików, podaj znany klucz. Nieudana próba odzyskiwania nie dowodzi, że pakiet nie jest zaszyfrowany.<sup>[[28]](#references)</sup>

Wyszukiwanie klucza **nie jest atakiem na przestrzeń kluczy AES-256**. Zaszyfrowana tabela plików udostępnia MD5 jej tekstu jawnego, długość tekstu jawnego, IV oraz szyfrogram AES-256-CFB.<sup>[[27]](#references)</sup> `gore` sprawdza 32-bajtowe fragmenty pliku wykonywalnego gry lub sąsiednich plików jako potencjalne klucze. Odrzuca kandydatów na podstawie prawdopodobnej długości odszyfrowanej ścieżki i jej prefiksu, a trafienia ze skanowania binarnego potwierdza przez odszyfrowanie całej tabeli i sprawdzenie jej MD5.<sup>[[26]](#references)[[28]](#references)</sup> Najpierw przeszukuje zainicjalizowane sekcje danych PE/ELF, a w razie potrzeby skanuje cały plik; `--scan` dodaje inne pliki do przeszukania.<sup>[[28]](#references)</sup>

Jeśli nie zostanie znaleziony osadzony klucz, narzędzie sprawdza krótką wbudowaną listę haseł; `--wordlist` pozwala podać inne kandydatury. Każde hasło jest sprawdzane w postaci reprezentacji klucza wyprowadzonej przez silnik z hasła, literału dopełnionego zerami lub klucza w postaci 64 znaków szesnastkowych. W przeciwieństwie do trafień ze skanowania binarnego, trafienia z listy haseł są w tej implementacji sprawdzane tylko pod kątem struktury ścieżek. Potwierdź je, otwierając pakiet i sprawdzając wyodrębnione zasoby.<sup>[[26]](#references)[[28]](#references)</sup>

Gdy artefakt gry jest dostępny lokalnie, wybierz etap odpowiedni do analizy. `recover` uruchamia GDRE w celu odtworzenia projektu, który można otworzyć, natomiast `extract` jedynie wypakowuje surowe pliki. `key` wyświetla potencjalny klucz do użycia z innym narzędziem.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Natywne badanie oparte na dowodach z REA

**REA** udostępnia analizę w Hopper, Ghidra i IDA przez CLI i MCP. Wymaga Node.js 22.x (co najmniej 22.19), 24.x (co najmniej 24.11) lub 26+ oraz npm. Najpierw skonfiguruj istniejącego natywnego dostawcę; sprawdź `rea providers --json` i jawnie wybierz dostawcę, jeśli więcej niż jeden obsługuje cel. Zamiast `0x1000` poniżej użyj zaobserwowanej nazwy funkcji lub adresu z inwentarza.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Zacznij od ciągu funkcji lub symbolu, podążaj za odwołaniami i wywołującymi, a następnie sprawdź opis wybranej funkcji i pseudokod za pomocą `rea decompile`. REA wiąże sesję z wybranym providerem, zamiast po cichu zastępować go po błędzie. Aby uzyskać powtarzalne wyniki zapytań, `--snapshot PATH` ponownie wykorzystuje wyłącznie pasujące bajty artefaktów, provider, ustawienia, operację i parametry; snapshot to lokalna pamięć podręczna, a nie zapisana baza danych providera. Zachowaj zwrócone Evidence i jawne niewiadome, zamiast traktować wywnioskowane ścieżki lub tekst dekompilatora jako oryginalny kod źródłowy.<sup>[[16]](#references)[[18]](#references)</sup>

Informacje o punktach wejścia JavaScript/Electron prowadzących do natywnych dodatków znajdziesz w [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Skryptowana analiza IDA i Ghidra z lokalnym mostem TCP

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) działa wewnątrz **już otwartej** bazy danych IDA lub programu Ghidra CodeBrowser i pozwala osobnemu skryptowi odpytywać tę bazę analizy oraz ją modyfikować. Uruchom `ID_Server.py` z poziomu konsoli Python IDA (`import ID_Server`) lub `Ghidra_Server.py` z poziomu Script Manager Ghidra. IDA nasłuchuje na `127.0.0.1`, zaczynając od portu `5073`, i sprawdza kolejne wyższe porty. Aktualny skrypt Ghidra zaczyna od portu `5093` i próbuje użyć dziesięciu portów, aż do `5102`; jego gniazdo Java wiąże się z adresem wildcard, a nie tylko z loopbackiem. Przed połączeniem sprawdź port wypisany przez instancję. W przeciwieństwie do analizatora działającego bez interfejsu graficznego, ten most działa na programie aktualnie otwartym w danej instancji GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Wysyłaj **jedno polecenie zakończone znakiem nowej linii na każde połączenie** i odczytuj odpowiedź zakończoną znakiem nowej linii. Wynik jest zazwyczaj w formacie JSON. Na przykład po znalezieniu zaimportowanego API istotnego dla ścieżki wejściowej `IMPORTXREF` znajduje miejsca jego wywołań; następnie `DECOMP_XREF` przeprowadza dekompilację wsadową funkcji wywołujących podany adres. `FUNC` analizuje funkcję, a `PCODE` zwraca reprezentację pośrednią dekompilatora. Używaj adresu z aktywnej bazy danych, a nie adresu skopiowanego z pliku binarnego z inną bazą relokacji. Poniższy przykład używa domyślnego portu IDA; w przypadku Ghidra użyj portu wypisanego przez jej skrypt.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Ten sam kanał może **zmieniać bazę analizy**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` i `PATCH` zmieniają nazwy, typy, definicje struktur, granice funkcji lub zapisane bajty. `PATCH` to edycja bazy, **a nie** dowód na patch działający w uruchomionym procesie. Żaden z listenerów nie dokumentuje uwierzytelniania. Listener IDA nasłuchuje tylko na loopback, ale Ghidra może być dostępna przez interfejsy sieciowe; podczas korzystania z niej ogranicz dostęp do listenera Ghidry. `QUIT` zatrzymuje oba listenery, a IDA udostępnia też `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode'u za pomocą blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alokuje **shellcode**, wyświetla jego **adres pamięci** i wstrzymuje wykonanie.\
Podłącz debugger, taki jak IDA lub x64dbg, ustaw breakpoint pod wyświetlonym adresem i wznów wykonanie, aby debugować shellcode.

Na stronie wydań GitHuba znajdują się archiwa ZIP ze skompilowanymi wydaniami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Nieco zmodyfikowaną wersję Blobrunner znajdziesz pod poniższym linkiem. Aby ją skompilować, **utwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod, a następnie zbuduj projekt**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode'u za pomocą jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) działa podobnie do BlobRunner. Alokuje shellcode i uruchamia nieskończoną pętlę. Podłącz debugger, wznów wykonanie na **2–5 sekund**, wstrzymaj je wewnątrz pętli i przejdź do następnego wywołania, które przekazuje wykonanie do zaalokowanego shellcode'u.

![Debugger wstrzymany w nieskończonej pętli jmp2it, bezpośrednio przed wywołaniem zaalokowanego shellcode'u](<../../images/image (509).png>)

Skompilowaną wersję [jmp2it możesz pobrać ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode'u za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to graficzny interfejs radare. Za pomocą Cutter możesz emulować shellcode i analizować go dynamicznie.

Pamiętaj, że Cutter pozwala wybrać „Open File” lub „Open Shellcode”. W moim przypadku po otwarciu shellcode'u jako pliku został on poprawnie zdekompilowany, ale po otwarciu go jako shellcode'u już nie:

![Cutter wyświetlający różne wyniki analizy po otwarciu tych samych bajtów jako pliku lub jako shellcode'u](<../../images/image (562).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam bp — wygląda na to, że Cutter automatycznie rozpocznie emulację od tego miejsca:

![Ustawianie breakpointu w wybranym punkcie wejścia shellcode'u przed rozpoczęciem emulacji w Cutter](<../../images/image (589).png>)

![Emulator Cutter wstrzymany na wybranym breakpoincie shellcode'u](<../../images/image (387).png>)

Możesz na przykład wyświetlić stos w zrzucie szesnastkowym:

![Wyświetlanie emulowanego stosu shellcode'u w zrzucie szesnastkowym Cutter](<../../images/image (186).png>)

### Deobfuskacja shellcode'u i wyszukiwanie wywoływanych funkcji

Warto wypróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Pokaże między innymi, **których funkcji** używa shellcode i czy **dekoduje** się w pamięci.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ma również graficzny launcher, w którym można wybrać potrzebne opcje i uruchomić shellcode

![Graficzny launcher scDbg do wyboru opcji emulacji i śledzenia shellcode](<../../images/image (258).png>)

Opcja **Create Dump** zapisze końcowy shellcode, jeśli jego zawartość zostanie dynamicznie zmieniona w pamięci (przydatne do pobrania zdekodowanego shellcode). **start offset** może być przydatny do uruchomienia shellcode od określonego offsetu. Opcja **Debug Shell** umożliwia debugowanie shellcode za pomocą terminala scDbg (uważam jednak, że lepiej sprawdzą się dowolne z wcześniej opisanych opcji, ponieważ można wtedy użyć Ida lub x64dbg).

### Deasemblacja za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj następującej receptury, aby go zdeasemblować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Obfuscation **Mixed Boolean-Arithmetic (MBA)** ukrywa proste wyrażenia, takie jak `x + y`, za pomocą formuł łączących działania arytmetyczne (`+`, `-`, `*`) i operatory bitowe (`&`, `|`, `^`, `~`, przesunięcia). Ważne jest, że te tożsamości są zwykle poprawne tylko przy **arytmetyce modularnej o stałej szerokości**, dlatego przeniesienia i przepełnienia mają znaczenie:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Jeśli uprościsz tego rodzaju wyrażenie za pomocą ogólnych narzędzi algebry, możesz łatwo uzyskać błędny wynik, ponieważ pominięto semantykę szerokości bitowej.<sup>[[1]](#references)</sup>

### Praktyczny workflow

1. **Zachowaj oryginalną szerokość bitową** z kodu/IR/dekompilatora (`8/16/32/64` bitów).
2. **Sklasyfikuj wyrażenie** przed próbą jego uproszczenia:
   - **Liniowe**: sumy ważone atomów bitowych
   - **Semiliniowe**: wyrażenie liniowe z dodatkowymi stałymi maskami, takimi jak `x & 0xFF`
   - **Wielomianowe**: występują iloczyny
   - **Mieszane**: iloczyny i logika bitowa przeplatają się, często z powtarzającymi się podwyrażeniami
3. **Zweryfikuj każdą proponowaną transformację** za pomocą testów losowych lub dowodu SMT. Jeśli nie da się udowodnić równoważności, zachowaj oryginalne wyrażenie zamiast zgadywać.

### Omijanie spłaszczonego przepływu sterowania za pomocą wąskiego wycinka wykonania

Odzyskanie kompletnego grafu przepływu sterowania często nie jest konieczne. W przypadku spłaszczania przepływu sterowania, nieprzezroczystych predykatów, dużych dispatcherów lub kodu z dużą ilością MBA śledź odwołania od zaszyfrowanych bloków danych i buforów wyjściowych do najmniejszej procedury, która je przekształca. Następnie odtwórz tylko ten wycinek przepływu danych lub uruchom go niezależnie; dispatcher nie jest częścią wymaganego rozwiązania, jeśli odpowiedni stan można zainicjalizować bezpośrednio.<sup>[[7]](#references)</sup>

Praktyczny workflow:<sup>[[7]](#references)</sup>

1. Zinwentaryzuj sekcje wykonywalne i sekcje danych, relokacje oraz odwołania krzyżowe. Zrzuć kandydatów na tablice z `.rodata`, zachowując kolejność bajtów i szerokość elementów.
2. Znajdź ostatnią procedurę, która zapisuje tekst jawny lub bufor wyjściowy. Zapisz jej dane wejściowe, używane tablice, wywołania importowanych funkcji i wymagany stan globalny.
3. Przenieś tylko te operacje do modelu Pythona o stałej szerokości bitowej. Jeśli wycinek nadal zależy od zbyt dużej liczby elementów stanu, wywołaj procedurę za pomocą Unicorn, QEMU lub debuggera i podmieniaj nieistotne importowane funkcje zamiast emulować cały program.
4. Zweryfikuj, czy ekstraktor rzeczywiście wyprowadza wynik z dostarczonego pliku binarnego: usuń ciche mechanizmy awaryjne, wyszukaj w nim osadzone odpowiedzi i uruchom go na nieznanych kompilacjach z innymi ciągami znaków, kluczami, identyfikatorami, układami i ziarnami obfuskacji.

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

Zachowaj końcową maskę, ponieważ pierwotne dodawanie powoduje zawijanie przy szerokości bajtu. Dla szerszej dziedziny zapytaj solver SMT, czy `f(x1) != f(x2)` jest spełnialne dla dwóch symbolicznych wejść o tej samej szerokości: `unsat` dowodzi niezmienności, a `sat` dostarcza kontrprzykład i oznacza, że wejścia nie można odrzucić.<sup>[[7]](#references)</sup>

#### Rozpoznawanie dekodowania zależnego od środowiska

Kontrole Anti-analysis nie muszą powodować skoku ani awarii. Dekoder może włączyć wynik odczytu z czujnika do bitu klucza, stałej opaque-predicate lub stanu flattened-dispatcher, działać dalej normalnie i wygenerować wiarygodny, lecz fałszywy tekst jawny w emulatorze. Dlatego samo poprawianie widocznych gałęzi awarii nie wystarczy; prześledź zależności danych od sond środowiskowych do stanu dekodera, porównaj ten sam fragment na autentycznym urządzeniu i emulatorze oraz sprawdź, jak wymuszenie poszczególnych wyników odczytu z czujników zmienia końcowy bufor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) to praktyczne narzędzie do upraszczania MBA, przydatne w analizie malware i inżynierii wstecznej zabezpieczonych plików binarnych. Klasyfikuje wyrażenie i kieruje je do wyspecjalizowanych potoków przetwarzania, zamiast stosować jeden ogólny zestaw przekształceń do wszystkiego.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA oblicza wyrażenie dla wejść boolowskich, wyznacza sygnaturę i uruchamia równolegle kilka metod odzyskiwania, takich jak dopasowywanie wzorców, konwersja do ANF i interpolacja współczynników.
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

- Uruchamiaj CoBRA najlepiej na **wyrażeniach lifted IR** lub wyniku dekompilacji, gdy wyizolujesz już dokładne obliczenie.
- Używaj jawnie `--bitwidth`, jeśli wyrażenie pochodzi z arytmetyki maskowanej lub rejestrów o mniejszej szerokości.
- Jeśli potrzebujesz mocniejszego kroku dowodowego, sprawdź lokalne notatki dotyczące Z3:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA jest również dostępny jako **wtyczka LLVM pass** (`libCobraPass.so`), przydatna do normalizacji IR LLVM z dużą ilością MBA przed późniejszymi etapami analizy.
- Niewspierane reszty mieszanych dziedzin zależne od przeniesienia potraktuj jako sygnał, by zachować oryginalne wyrażenie i ręcznie przeanalizować ścieżkę przeniesienia.

## Odtwarzanie flatteningu przepływu sterowania ze stanem XOR

Flattener w stylu OLLVM może przechowywać stan bieżącego bloku podstawowego w dwóch 64-bitowych rejestrach i odtwarzać go za pomocą XOR w dispatcherze. Każdy oryginalny blok zapisuje parę odpowiadającą następnemu stanowi i wraca skokiem do dispatchera. Blok warunkowy może używać `CMOVcc`, aby na podstawie flag procesora zastąpić jedną połowę pary, więc śledzenie wyłącznie widocznych instrukcji skoku pomija oba następniki. W odróżnieniu od dispatchera ze skokiem pośrednim, ten wariant może wszędzie używać bezpośrednich skoków wstecznych.<sup>[[19]](#references)[[20]](#references)</sup>

Aby odtworzyć graf, zidentyfikuj drzewo porównań dispatchera i oba rejestry stanu, przyporządkuj każdy porównywany stan XOR do docelowego bloku, a następnie prześledź zapisy docierające do pary rejestrów w każdym oryginalnym bloku. W przypadku zapisów warunkowych uwzględnij instrukcję ustawiającą flagi i oba warianty `CMOVcc`. Zastąp wyjście każdego bloku do dispatchera ustalonym bezpośrednim następnikiem lub skokiem warunkowym; dispatcher stanie się wtedy nieosiągalny bez modyfikowania pliku binarnego. To podejście obejmuje cały CFG; jeśli interesuje Cię tylko jeden dekoder, szybszy może być opisany wyżej [wąski przepływ pracy oparty na wycinku wykonania](#bypass-flattened-control-flow-with-a-narrow-execution-slice).<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatyzuje ten wariant w Binary Ninja. Skopiuj `plugins/DispatchThis` do katalogu wtyczek użytkownika Binary Ninja i uruchom program ponownie. W przypadku analizowanej funkcji otwórz **Function Settings** i wybierz `OLLVM_XOR_64`; jeśli analiza się nie rozpocznie, użyj **Analysis → Reanalyze All Functions**. Ten tryb przepisuje krawędzie przepływu sterowania MLIL, a nie bajty pliku, i nie wymaga Z3 ani resolvera skoków pośrednich. Testowano go w Binary Ninja 5.3.9757+; nie usuwa nieaktywnych zapisów stanu w poszczególnych blokach, więc nie myl ich z nadal aktywnymi przejściami.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuskator zastępuje operacje programu sekwencjami instrukcji opartymi na `mov` i używa obsługi sygnałów/wyjątków do zmiany przepływu sterowania. Więcej informacji:

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

![Znajdowanie punktu wejścia w Rust w Ghidrze przez wyszukanie nazw funkcji zawierających dwa dwukropki i main](<../../images/image (1080).png>)

W tym przypadku plik binarny nazywał się authenticator, więc dość oczywiste jest, że to właśnie ta funkcja main jest interesująca.\
Mając **nazwy** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby poznać ich **dane wejściowe** i **wyjściowe**.

### Odzyskiwanie ciągów znaków Rust z firmware ELF

W plikach binarnych **Rust ELF** wiele statycznych ciągów znaków nie jest wskazywanych przez wskaźniki zakończone znakiem NUL, jak w C. Często spotykany układ `rustc` to **krotka wskaźnik/długość** w sekcji **`.data.rel.ro`**, wskazująca na właściwy blok ciągu znaków przechowywany w **`.rodata`**:

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
3. Traktuj każdą wartość z zakresu adresów `.rodata` jako kandydata na wskaźnik do ciągu znaków.
4. Traktuj następne słowo jako kandydacką długość.
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

Jest to szczególnie przydatne podczas reversing firmware, ponieważ odzyskane ciągi znaków Rust często ujawniają **trasy HTTP, nazwy RPC, komunikaty logów, asercje, nazwy plików, klucze konfiguracji, handlery poleceń i logikę związaną z uwierzytelnianiem**.

Jeśli Ghidra nie wykryje tych ciągów, uruchom własny skrypt/plugin, który zastosuje tę samą heurystykę i utworzy dane typu string pod wskazanymi offsetami w `.rodata`. Opublikowane narzędzia `rust-strings` i `RustStrings.py` od Pen Test Partners to dobre materiały źródłowe przy dostosowywaniu tego rozwiązania do innych **rozmiarów słów, kolejności bajtów i układów sekcji**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

W przypadku binarnych plików skompilowanych z Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz przeprowadzić reversing binarnego pliku Delphi, polecam użyć pluginu IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Ten plugin uruchomi binarny plik i dynamicznie rozpozna nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony przycisk lub f9), a breakpoint zostanie wyzwolony na początku właściwego kodu.

Jeśli naciśniesz przycisk w aplikacji graficznej, debugger może zatrzymać się w funkcji wywołanej przez ten przycisk.

## Golang

W przypadku standardowych binarnych plików Go narzędzie [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) może odzyskać struktury środowiska uruchomieniowego i poprawić nazwy funkcji w IDA. Załaduj jego plugin Python za pomocą **Alt+F7**.

Jeśli musisz przeprowadzić reversing binarnego pliku Golang, polecam użyć pluginu IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Naciśnij **Alt+F7** w IDA, aby załadować plugin Python, a następnie wybierz plik pluginu.

Umożliwi to rozpoznanie nazw funkcji.

### Odzyskiwanie metadanych bez tablicy symboli

Nawet pozbawiony symboli plik wykonywalny Go nadal potrzebuje metadanych środowiska uruchomieniowego, aby mapować liczniki programu na funkcje. [GoReSym](https://github.com/mandiant/GoReSym) lokalizuje i analizuje struktury, takie jak `pclntab` i `moduledata`, wykorzystując kod pochodzący ze środowiska uruchomieniowego Go. Pozwala to odzyskać granice funkcji, nazwy, ścieżki źródłowe, typy i szczegóły kompilacji bez polegania na konwencjonalnej tablicy symboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Obfuscator może pozostawić te struktury użyteczne, zastępując odzyskane nazwy. Na przykład Garble hashuje identyfikatory i ścieżki pakietów oraz usuwa informacje o kompilacji, module i debugowaniu.<sup>[[12]](#references)</sup> Token obfuskowanego pakietu musi pozostać spójny w funkcjach z tego pakietu. Pogrupuj funkcje według powtarzającego się tokenu, ustal jeden pakiet na podstawie jego funkcji wywoływanych, ciągów znaków i API, a następnie przypisz etykietę tego pakietu całej grupie.<sup>[[13]](#references)</sup>

### Odzyskiwanie nazw Garble za pomocą GoResolver

[GoResolver](https://github.com/volexity/GoResolver) łączy ekstrakcję symboli środowiska uruchomieniowego z generowaniem czystych plików referencyjnych i dopasowywaniem grafów przepływu sterowania (CFG). Wykonaj kolejno następujące kroki:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Ustal wersję kompilatora.** Najpierw sprawdź `BuildInfo` i osadzone ciągi wersji. Jeśli obfuscator je usunął, porównaj fragmenty dołączonego środowiska uruchomieniowego Go z referencyjnymi środowiskami uruchomieniowymi różnych wersji. W testach Volexity około `2%` środowiska uruchomieniowego wystarczyło do rozróżnienia głównych wersji Go. Traktuj to jako empiryczną optymalizację, a nie uniwersalny próg.<sup>[[13]](#references)</sup>
2. **Przygotuj pasujące pliki referencyjne.** Wygeneruj czyste pliki binarne dla ustalonej wersji Go, docelowej architektury i prawdopodobnych bibliotek. Dopasowanie łańcucha narzędzi ogranicza różnice w CFG generowanym przez kompilator.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Porównaj funkcje.** GoGrapher dopasowuje CFG funkcji i generuje znormalizowane wyniki od `0.0` do `1.0`. Dopasowywanie podstawowych bloków opiera się na ważonym porównaniu podobnych instrukcji. Dopasowania o wysokim poziomie pewności przypisują losowo zmienionym funkcjom nazwy czystej implementacji. Słabsze dopasowania nadal mogą pomóc ustalić pakiet lub moduł.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Zweryfikuj i zaimportuj.** Potwierdź proponowane nazwy na podstawie relacji wywołań, stałych, ciągów znaków i efektów ubocznych, a następnie zaimportuj raport JSON za pomocą wtyczki GoResolver dla IDA lub Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Domyślny próg istotnego dopasowania wynosi `0.9`. Przełączniki `--extract` i `--graph` pozwalają uruchomić osobno każdy z etapów. Domyślnie wykonywane są oba, ponieważ odzyskane metadane runtime i informacje z CFG wzajemnie się uzupełniają.<sup>[[10]](#references)</sup> Wyniki CFG są heurystyczne: inlining, flagi kompilacji, architektura i różnice między wersjami bibliotek mogą zmieniać kształt grafu, dlatego nierozpoznane funkcje należy pozostawić bez nazw, zamiast przypisywać im nazwy na podstawie mało wiarygodnych dopasowań.<sup>[[13]](#references)</sup>

### Odzyskiwanie tabeli ciągów znaków Go

Binarne pliki Go umieszczają bajty ciągów znaków ze wszystkich dołączonych pakietów w jednej ciągłej tabeli. Wpisy nie są zakończone znakiem NUL, a struktury runtime nie udostępniają początku ani rozmiaru tabeli. Kompilator porządkuje jednak wpisy najpierw według długości, a następnie alfabetycznie — niezależnie od systemu operacyjnego i architektury. Po znalezieniu jednego wpisu analityk może więc przechodzić do sąsiednich wpisów i użyć odwołań do danych, aby powiązać ciągi znaków z kodem.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatyzuje ten proces w IDA Pro i Ghidra. Najpierw poczekaj na zakończenie automatycznej analizy, ponieważ plugin korzysta z odwołań do segmentu danych. Domyślnym ciągiem kotwiczącym jest `entersyscall` z runtime. Następnie narzędzie może skanować w obu kierunkach, zdefiniować odzyskane ciągi znaków w bazie danych i wyeksportować mapowanie ciągów znaków na odwołujące się do nich funkcje w formacie JSON.<sup>[[14]](#references)</sup>

Filtruj raport według pakietu funkcji odwołującej się do ciągu, aby oddzielić kod aplikacji lub malware od szumu generowanego przez dołączone biblioteki. Ta technika nie pozwala odzyskać literałów zniszczonych przez obfuskację, taką jak transformacja Garble `-literals`. Nadal może jednak uporządkować ciągi znaków runtime, które nie zostały poddane obfuskacji.<sup>[[14]](#references)[[15]](#references)</sup>

### Odzyskiwanie typów runtime Go

Go osadza informacje o typach runtime wykorzystywane przez takie funkcje jak garbage collection. Gdy informacje o kompilacji zostały usunięte lub disassembler nie parsuje tych metadanych, instrukcje mogą wyglądać tak, jakby ładowały dowolne adresy danych, a docelowy obszar pozostaje bez określonego typu. Odzyskanie metadanych zamienia te adresy w czytelne odwołania do typów i ułatwia zrozumienie możliwości pakietu.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) może wyodrębniać symbole i parsować typy runtime do raportu JSON. Obecnie CLI używa podkomendy `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Opcja `-y`/`--types` włącza parsowanie typów. Zaimportuj raport za pomocą pluginu GoResolver dla IDA Pro lub Ghidra, aby zdefiniować odzyskane typy i zastosować odwołania do nich w bazie danych analizy. W formacie raportu wprowadzonym wraz z tą funkcją pominięcie `-y` powoduje, że pola RTTI address i recovered-types mają wartość null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver obsługuje próbki PE, ELF i Mach-O dla architektur x86, AMD64, ARM i ARM64, więc ten sam przepływ pracy ma zastosowanie do plików binarnych Go z Windows, Linux i macOS.<sup>[[10]](#references)</sup>

## Skompilowany Python

Na tej stronie znajdziesz informacje, jak odzyskać kod Python z pliku binarnego ELF/EXE skompilowanego z użyciem Pythona:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Jeśli zdobędziesz **plik binarny** gry GBA, możesz użyć różnych narzędzi do jej **emulacji** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debug_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io)- Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - plugin Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz sprawdzić, jak naciskać **przyciski** Game Boy Advance

![Konfiguracja sterowania no$gba pokazująca mapowanie przycisków Game Boy Advance](<../../images/image (581).png>)

Po naciśnięciu każdy **klawisz ma przypisaną wartość**, która go identyfikuje:

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

Ostatnia instrukcja if sprawdza, czy **`uVar4`** znajduje się w **ostatnich klawiszach** i nie jest bieżącym klawiszem — oznacza to zwolnienie przycisku (bieżący klawisz jest przechowywany w **`uVar1`**).

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

- Najpierw jest porównywana z **wartością 4** (przycisk **SELECT**): w tym wyzwaniu ten przycisk czyści ekran.
- Następnie wartość jest porównywana z **8** (przycisk **START**); w tym wyzwaniu ta ścieżka sprawdza, czy wprowadzony kod jest prawidłowy.
  - W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3 i jeśli wartości są takie same, wykonywany jest określony kod.
- W każdym innym przypadku sprawdzany i zwiększany jest licznik (`DAT_030000d4`).\
  Dopóki licznik jest mniejszy niż 8, wartości wciśniętych przycisków są sumowane w `DAT_030000d8`.

W tym wyzwaniu, znając wartości przycisków, trzeba było **wcisnąć kombinację krótszą niż 8 przycisków, której suma wynosi 0xf3.**

**Źródło do tego poradnika:** [zarchiwizowany opis rozwiązania wyzwania Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - poradnik reversing GBA (zarchiwizowany)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Jak pokonać wspomagany przez AI reverse engineering, a przynajmniej spróbować](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Podejście do porównywania grafów przepływu sterowania na podstawie dopasowywania bloków podstawowych](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repozytorium Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mechanizm obfuskacji Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: automatyczna deobfuskacja plików binarnych Golang za pomocą podobieństwa grafów przepływu sterowania](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repozytorium Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aktualizacje narzędzi Volexity dla Golang](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: inżynieria wsteczna wszystkiego](https://github.com/morluto/rea)
- [17] [Analiza kodu zarządzanego w REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA: przewodnik po CLI i dowodach](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: przepływ pracy spłaszczania przepływu sterowania w Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: włamanie typu zero-day do PaperCut MF, loader Java, web shell i AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementacja serwera bridge dla IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementacja serwera bridge dla Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) wiąże się z adresem wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: zestaw narzędzi do reverse engineeringu Godot](https://github.com/figurophobia/gore)
- [26] [Implementacja odzyskiwania klucza w gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Format zaszyfrowanych danych gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implementacja polecenia i odzyskiwania danych w gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
