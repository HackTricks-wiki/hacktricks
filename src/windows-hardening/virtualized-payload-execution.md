# Wykonywanie payloadu w środowisku wirtualnym i omijanie zabezpieczeń za pomocą własnej maszyny wirtualnej

{{#include ../banners/hacktricks-training.md}}

Wirtualizacja payloadu kompiluje logikę ofensywną do zestawu instrukcji maszyny gościa i wykonuje ją za pomocą natywnego interpretera. W przeciwieństwie do packera, który w końcu musi udostępnić oryginalne natywne instrukcje w pamięci, zwirtualizowany payload może przez cały czas działania przechowywać chronioną logikę jako bytecode. Eliminuje to konkretne okno, w którym można rozpakować payload, ale **nie** ukrywa zachowania widocznego dla hosta, takiego jak syscalle, aktywność sieciowa czy granica między VM a wywołaniami natywnymi.<sup>[[2]](#references)[[3]](#references)</sup>

## Rehosting WebAssembly w celu utrudnienia analizy statycznej

Zamiast modyfikować narzędzie Go z wieloma sygnaturami, można skompilować je jako gościa `wasip1` i osadzić w osobnym natywnym loaderze. Gość jest budowany na podstawie poprawionego GOROOT, w którym nieobsługiwane operacje, takie jak `net.Dial`, `net.Listen`, `os/exec` i `os.Pipe`, są przekierowywane przez `//go:wasmimport`; moduł hosta Wazero implementuje następnie sockety, operacje na procesach, wywołania Win32 i wywołania frameworków macOS. Dzięki temu użycie API Go z oryginalnego projektu pozostaje bez zmian, a większość jego logiki trafia do zaszyfrowanego modułu WASM, którego narzędzia do statycznej analizy PE mogą nie rozumieć.<sup>[[4]](#references)</sup>

### Łączenie pamięci liniowej z natywnymi API

Wskaźnik gościa to 32-bitowe przesunięcie w pamięci liniowej WASM, a nie wirtualny adres hosta. Przed natywnym wywołaniem mostek może przekształcić argument tylko wtedy, gdy jest oznaczony jako wskaźnik lokalny i mieści się w zakresie `0x10000 <= value < wasmMemorySize`, uzyskując `wasmMemoryBase + value`. Dolna granica zapobiega nadpisywaniu małych uchwytów, flag i `nil`; maski dla poszczególnych API, wygenerowane na podstawie `win32metadata`, odróżniają właściwe wskaźniki od uchwytów, rozmiarów i adresów zdalnych procesów, a poprawki obsługują nieprawidłowe lub niejednoznaczne metadane.<sup>[[4]](#references)</sup>

Natywne API mogą też zwracać wskaźniki hosta przez bufory wyjściowe gościa. Tabela lustrzana może przypisywać takim obiektom reprezentacje w pamięci gościa i przechowywać odwzorowanie zwrotne na oryginalny adres hosta. COM wymaga lustrzanego odwzorowania zarówno interfejsu, jak i jego vtable: wskaźniki do danych można śledzić i odwzorowywać, natomiast wskaźniki wykonywalne w regionach `MEM_IMAGE` muszą pozostać nieprzezroczystymi tokenami, ponieważ WASM nie potrafi wykonywać natywnych instrukcji. Ten model nie obsługuje bezpośrednio API wywołań zwrotnych hosta do gościa, takich jak `EnumWindows` czy `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Polimorfizm VM WASM dla każdej kompilacji

Środowisko wykonawcze i payload można wspólnie przekształcać przy każdej kompilacji: przetasować tabelę przypisującą opcode’y do handlerów, przepisać każdy opcode gościa zgodnie z nowym mapowaniem, losować identyfikatory sekcji, zastąpić standardową sygnaturę `\0asm` markerem specyficznym dla kompilacji i zmieniać sygnaturę cache środowiska wykonawczego. Ten sam kod źródłowy daje wtedy moduły różniące się bajt po bajcie, a zwykłe narzędzia WASM nie mogą przeanalizować payloadu, dopóki analityk nie odzyska niestandardowego mapowania i formatu z loadera hosta.<sup>[[4]](#references)</sup>

Aby przeprowadzić inżynierię wsteczną, zacznij od natywnego hosta, zamiast szukać wyłącznie `\0asm`: zidentyfikuj skompilowany marker, ścieżkę deszyfrowania modułu, tabelę dispatch opcode’ów i rejestracje funkcji hosta `env`, a następnie odtwórz standardowy moduł lub instrumentuj granicę importu. Mostek pozostaje użytecznym punktem obserwacji zachowania, ponieważ przechodzą przez niego wywołania dotyczące sieci, tworzenia procesów, dostępu do rejestru, dynamicznego ładowania i ogólnego dispatchu Win32, nawet gdy osadzony bytecode zmienia się między kompilacjami.<sup>[[4]](#references)</sup>

### Maskowanie zewnętrznego pliku wykonywalnego Go

Sama zmiana gościa nadal pozostawia rozpoznawalny loader. Wykazane przekształcenia zewnętrznego pliku binarnego wstawiają do `gopclntab` gęste profile symboli pobrane z legalnych projektów Go, rotują niewielki, wiarygodny zestaw importów DLL oraz zmieniają `VERSIONINFO` PE i ciągi tożsamości Authenticode. Przekształcenia te są ukierunkowane na statyczne i uczenia maszynowego cechy kontenera; nie usuwają zachowania środowiska wykonawczego ujawnianego przez shimy hosta.<sup>[[4]](#references)</sup>

## Model wykonania

Kompaktowy zwirtualizowany loader może podzielić wykonanie na następujące warstwy.<sup>[[3]](#references)</sup>

1. Skompiluj freestanding C, kod BOF lub biblioteki środowiska wykonawczego za pomocą LLVM do niestandardowego ISA bytecode.
2. Uruchom mały natywny interpreter i zainicjalizuj mapowanie opcode’ów właściwe dla kompilacji.
3. Uruchom sam linker-loader PE jako bytecode: analizuj nagłówki, mapuj sekcje, stosuj relokacje, rozwiązuj importy i wypełniaj IAT.
4. Pozostaw wywołania między gośćmi wewnątrz interpretera. Przekierowuj cele spoza obszaru bytecode, takie jak zaimportowane funkcje DLL, przez natywny thunk wywołań hosta.
5. Przenieś funkcje pomocnicze, takie jak formatowanie HTTP, TLS i części środowiska uruchomieniowego C, za tę samą granicę interpretacji.

Ten model pozwala uniknąć przydzielania osobnego natywnego regionu kodu dla każdej wtyczki i zapobiega pojawieniu się oryginalnego payloadu jako rozpoznawalnego strumienia instrukcji x86-64. Nadal jest to granica utrudniająca wykrywanie i zaciemniająca kod, a nie granica bezpieczeństwa: natywny interpreter i każdy efekt zewnętrzny pozostają widoczne.<sup>[[2]](#references)[[3]](#references)</sup>

## Mostek hosta ze współdzieloną pamięcią

Odizolowana VM przedstawia wskaźniki jako przesunięcia w buforze gościa, dlatego każde wywołanie API hosta wymaga translacji wskaźników i specjalnej obsługi parametrów wyjściowych. VM ze współdzieloną pamięcią używa adresów gościa, które są prawidłowymi adresami w procesie hosta. Odczyty i zapisy mogą więc korzystać z operacji w stylu `memcpy`, a wskaźnik zwrócony przez natywną alokację ECALL można bezpośrednio dereferencjonować w bytecode. RISC-Y Business pokazał, że taki projekt może ograniczyć mostek do pobrania PEB i wykonywania dowolnych wywołań hosta.<sup>[[1]](#references)</sup>

W systemie Windows x64 wirtualny zestaw rejestrów może odwzorowywać ABI: umieścić pierwsze cztery argumenty całkowite lub wskaźnikowe w `RCX`, `RDX`, `R8` i `R9`, a kolejne argumenty oraz shadow space na stosie. Gdy wirtualne `CALL` wskazuje adres spoza zakresu bytecode, uniwersalny thunk przekazuje ten stan do natywnego wywołania i kopiuje wartość zwrotną z powrotem do VM. Umożliwia to wywołania IAT, alokację sterty i operacje na socketach bez korygowania wskaźników.<sup>[[2]](#references)[[3]](#references)</sup>

Kompromisem jest całkowita utrata izolacji. Uszkodzenie pamięci gościa może bezpośrednio wpłynąć na hosta, natywne funkcje wywołane przez gościa mogą zachować lub zmodyfikować wskaźniki gościa, a interpreter musi traktować bytecode jako w pełni zaufany. Wywołania zwrotne z natywnego kodu do VM również wymagają mostka zwrotnego; VM obsługująca wyłącznie wywołania wychodzące nie może bezpośrednio obsłużyć API opartych na callbackach, takich jak `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfizm ISA dla każdej kompilacji

Niestandardowy ISA o stałej szerokości instrukcji upraszcza dekodowanie, dispatch, relokację i mapowanie rejestrów wirtualnych. Centurion używa 18-bajtowego formatu instrukcji inspirowanego x86-64, co poświęca gęstość kodu na rzecz przewidywalnego parsowania, a także pozostawia możliwość tłumaczenia istniejących artefaktów x86-64 na bytecode.<sup>[[3]](#references)</sup>

Losowanie mapowania opcode’ów na handlery dla każdej kompilacji sprawia, że identyczna logika gościa daje różne sekwencje bajtów. Zaszyfrowanie tabeli mapowania i odtwarzanie jej dopiero w czasie działania dodatkowo usuwa stabilny słownik opcode’ów z pliku. Utrudnia to stosowanie stałych sygnatur i wielokrotne używanie reguł deasemblacji, ale samo w sobie nie zmienia polimorficznie natywnego dispatchera, procedury deszyfrowania tabeli ani granicy wywołań hosta.<sup>[[3]](#references)</sup>

## Przenoszenie środowiska wykonawczego do VM

Proces hosta można ograniczyć do pamięci, syscalli i prymitywów socketów, a freestanding biblioteki mogą zapewniać usługi wyższego poziomu wewnątrz VM. Na przykład FreeRTOS coreHTTP może obsługiwać formatowanie HTTP, a mbedTLS — TLS, bez wywoływania WinHTTP ani systemowego API TLS. Surowe sockety przez `afd.sys` lub podobny interfejs stają się wtedy wąską natywną granicą sieciową.<sup>[[3]](#references)</sup>

Taka konstrukcja **Bring Your Own Execution Environment (BYOEE)** może również umieścić ładowanie PE, obsługę środowiska wykonawczego i system plików w pamięci za interpreterem. Ogranicza to liczbę rozpoznawalnych natywnych implementacji, ale nie eliminuje telemetrii: operacje na surowych socketach pozostają widoczne, a środowiska wymagające jawnych proxy lub inspekcji TLS mogą uniemożliwić działanie takiego rozwiązania sieciowego.<sup>[[3]](#references)</sup>

## Selektywne przyspieszanie natywne

Interpretowanie każdej instrukcji jest szczególnie kosztowne w kryptografii klucza publicznego. Praktyczny podział wykorzystuje hooki `MBEDTLS_ALT` biblioteki mbedTLS jako interfejs koprocesora programowego: zachowuje stan TLS, parsowanie certyfikatów, negocjacje, alokację i kod bignum wysokiego poziomu w bytecode, ale uruchamia najbardziej obciążające obliczeniowo jądra z `bignum_core.c` przez natywne wywołania ECALL. W prototypie Centurion pliki `bignum.c`, `bignum_mod.c` i `bignum_mod_raw.c` pozostały zwirtualizowane, podczas gdy wewnętrzne pętle działały natywnie, skracając uzgadnianie ECDHE z minut do sekund.<sup>[[3]](#references)</sup>

Ustaw akceleratory jako opcjonalne, aby payloady niewymagające TLS pomijały dodatkowe natywne punkty wejścia. Ten wzorzec można zastosować do każdego obciążenia interpretera: najpierw wykonaj profilowanie, a następnie udostępnij możliwie najmniejszy natywny prymityw, zamiast przenosić cały podsystem poza VM.<sup>[[3]](#references)</sup>

Centurion zweryfikował cały łańcuch za pomocą bind shella TLS 1.2: loader bytecode mapował PE, wywołania socketów przechodziły przez uniwersalny thunk, mbedTLS obsługiwał protokół wewnątrz VM, a natywne wywołania ECALL przyspieszały obliczenia ECDHE. Natywny interpreter o rozmiarze około 18 KB obsługiwał więc zaszyfrowany kanał poleceń bez materializowania payloadu jako natywnego kodu x86-64.<sup>[[3]](#references)</sup>

## Wskazówki przydatne przy inżynierii wstecznej i wykrywaniu

Poniższe wskazówki analityczne wynikają z tej architektury; wirtualizacja zmienia miejsca, w których analitycy obserwują zachowanie, ale go nie eliminuje.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Zidentyfikuj pętlę pobierania/dekodowania/dispatchu, wirtualny licznik programu, zestaw rejestrów i powtarzające się kroki o stałej szerokości instrukcji.
- Zrzutuj tabelę opcode’ów po jej odszyfrowaniu w czasie działania i przypisz adresy handlerów do operacji semantycznych, zamiast dopasowywać zaszyfrowany bytecode na dysku.
- Ustaw breakpoint na uniwersalnym thunk lub dispatcherze ECALL, aby zapisać natywny cel, wirtualne rejestry argumentów, argumenty stosu i wartość zwrotną.
- Śledź dostęp do PEB, rozwiązywanie eksportów, parsowanie nagłówków PE, zapisy relokacji i wypełnianie IAT, nawet gdy sam loader jest zaimplementowany w bytecode.
- Koreluj tworzenie socketów i ruch `afd.sys` z brakiem oczekiwanych wywołań WinHTTP lub natywnych wywołań TLS; brak importów wysokiego poziomu to wskazówka, a nie dowód nieszkodliwego działania.
- Traktuj natywne akceleratory arytmetyczne jako semantyczne punkty obserwacji: ich wywołujący mogą ujawnić wymianę kluczy i aktywność związaną z walidacją certyfikatów, nawet jeśli otaczająca je maszyna stanów TLS pozostaje zwirtualizowana.

Więcej informacji o przepływach pracy analitycznej rozpoczynających się od dispatchera, a nie od oryginalnego grafu przepływu sterowania, znajdziesz w [wskazówkach dotyczących analizy malware’u i wirtualizowania packerów](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Ograniczenia operacyjne

Wirtualizacja wiąże się z narzutem interpretacji, zwiększa złożoność toolchaina i ABI oraz nie rozwiązuje problemu wykrywania behawioralnego. Pamięć współdzielona jest z założenia niebezpieczna, komunikacja sieciowa przez surowe sockety może nie działać za obowiązkowymi proxy, a API Win32 intensywnie wykorzystujące callbacki wymagają trampoline’ów z natywnego kodu do VM. Interpreter, mostek syscalli i wszelkie natywne akceleratory również pozostają typowym natywnym elementem, który obrońcy mogą sygnaturować lub instrumentować.<sup>[[2]](#references)[[3]](#references)</sup>

## Powiązane strony

Informacje o pakowaniu VMProtect 3.x znajdziesz w artykule [emulowane rozpakowywanie i naprawa importów](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: budowanie maszyny wirtualnej RISC-V do zaciemniania payloadów](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming w erze EDR — omijanie zabezpieczeń dzięki wirtualizacji malware’u](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — własne środowisko wykonawcze](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Oto WasmForge: kompilowanie Sliver do WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
