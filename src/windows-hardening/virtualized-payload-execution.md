# Wirtualizowane uruchamianie payloadu i omijanie detekcji przez niestandardową maszynę wirtualną

{{#include ../banners/hacktricks-training.md}}

Wirtualizacja payloadu kompiluje logikę ofensywną do zestawu instrukcji gościa i uruchamia ją za pomocą natywnego interpretera. W przeciwieństwie do packera, który musi w końcu ujawnić oryginalne natywne instrukcje w pamięci, wirtualizowany payload może przechowywać chronioną logikę jako bytecode przez cały czas działania. Eliminuje to konkretną okazję do rozpakowania, ale **nie** ukrywa zachowań widocznych dla hosta, takich jak syscalle, aktywność sieciowa czy granica wywołań VM–native.<sup>[[2]](#references)[[3]](#references)</sup>

## Model wykonania

Kompaktowy wirtualizowany loader może podzielić wykonanie na następujące warstwy.<sup>[[3]](#references)</sup>

1. Skompiluj kod C bez zależności od środowiska uruchomieniowego, kod BOF lub biblioteki runtime za pomocą LLVM do niestandardowego bytecode ISA.
2. Uruchom mały natywny interpreter i zainicjuj mapowanie opcode’ów specyficzne dla danego buildu.
3. Uruchom sam linker-loader PE jako bytecode: przetwórz nagłówki, mapuj sekcje, zastosuj relokacje, rozwiąż importy i wypełnij IAT.
4. Pozostaw wywołania między gośćmi wewnątrz interpretera. Kieruj cele spoza obszaru bytecode, takie jak importowane funkcje DLL, przez natywny thunk wywołań hosta.
5. Przenieś funkcje pomocnicze, takie jak obsługa HTTP, TLS i część biblioteki C runtime, za tę samą granicę interpretacji.

Ten model pozwala uniknąć alokowania osobnego natywnego obszaru kodu dla każdego pluginu i zapobiega pojawieniu się oryginalnego payloadu w postaci rozpoznawalnego strumienia instrukcji x86-64. Jest to jednak granica utrudniająca analizę i zapewniająca obfuskację, a nie granica bezpieczeństwa: natywny interpreter i każdy efekt zewnętrzny pozostają widoczne.<sup>[[2]](#references)[[3]](#references)</sup>

## Most współdzielonej pamięci do hosta

Odizolowana VM reprezentuje wskaźniki jako offsety w buforze gościa, dlatego każde przejście przez API hosta wymaga translacji wskaźników i specjalnej obsługi parametrów wyjściowych. VM korzystająca ze współdzielonej pamięci sprawia natomiast, że adresy gościa są prawidłowymi adresami w procesie hosta. Odczyt i zapis mogą więc korzystać z operacji w stylu `memcpy`, a wskaźnik zwrócony przez natywny ECALL alokacji można bezpośrednio dereferencjonować w bytecode. RISC-Y Business pokazał, że ten projekt może ograniczyć most do pobrania PEB i wykonywania dowolnych wywołań hosta.<sup>[[1]](#references)</sup>

W systemie Windows x64 wirtualny zestaw rejestrów może odzwierciedlać ABI: umieszczać pierwsze cztery argumenty całkowite lub wskaźnikowe w `RCX`, `RDX`, `R8` i `R9`, a kolejne argumenty oraz shadow space na stosie. Gdy wirtualne `CALL` wskazuje cel spoza zakresu bytecode, uniwersalny thunk przekazuje ten stan do natywnego wywołania i kopiuje wartość zwracaną z powrotem do VM. Umożliwia to wywołania IAT, alokację pamięci na stercie i operacje na socketach bez naprawiania wskaźników.<sup>[[2]](#references)[[3]](#references)</sup>

Kompromisem jest całkowita utrata izolacji. Uszkodzenie pamięci gościa może bezpośrednio wpłynąć na hosta, natywne funkcje wywołujące mogą zachować lub zmodyfikować wskaźniki gościa, a interpreter musi traktować bytecode jako w pełni zaufany. Wywołania zwrotne z natywnego kodu do VM wymagają również mostu w przeciwnym kierunku; VM obsługująca wyłącznie wywołania wychodzące nie może bezpośrednio obsługiwać API opartych na callbackach, takich jak `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfizm ISA dla każdego buildu

Niestandardowy ISA o stałej długości instrukcji upraszcza dekodowanie, dispatch, relokację i mapowanie rejestrów wirtualnych. Centurion używa 18-bajtowego formatu instrukcji inspirowanego x86-64, co zmniejsza gęstość kodu na rzecz przewidywalnego parsowania, a jednocześnie otwiera drogę do tłumaczenia istniejących artefaktów x86-64 na bytecode.<sup>[[3]](#references)</sup>

Losowanie mapowania opcode’ów na handlery dla każdego buildu sprawia, że identyczna logika gościa generuje różne sekwencje bajtów. Dodatkowe zaszyfrowanie tabeli mapowania i odtworzenie jej dopiero w czasie działania eliminuje stabilny słownik opcode’ów zapisany na dysku. Utrudnia to stosowanie stałych sygnatur i wielokrotnego użytku reguł dezasemblacji, ale samo w sobie nie zapewnia polimorfizmu natywnemu dispatcherowi, procedurze odszyfrowywania tabeli ani granicy wywołań hosta.<sup>[[3]](#references)</sup>

## Przeniesienie środowiska wykonawczego do VM

Proces hosta można ograniczyć do prymitywów pamięci, syscalli i socketów, a biblioteki freestanding mogą zapewniać usługi wyższego poziomu wewnątrz VM. Na przykład FreeRTOS coreHTTP może obsługiwać formatowanie HTTP, a mbedTLS — TLS, bez wywoływania WinHTTP ani systemowego API TLS. Surowe sockety obsługiwane przez `afd.sys` lub podobny interfejs stają się wtedy wąską natywną granicą sieciową.<sup>[[3]](#references)</sup>

Ta architektura **Bring Your Own Execution Environment (BYOEE)** może również umieścić ładowanie PE, obsługę runtime i system plików w pamięci za interpreterem. Ogranicza obecność rozpoznawalnych natywnych implementacji, ale nie eliminuje telemetrii: operacje na surowych socketach pozostają widoczne, a środowiska wymagające jawnych proxy lub inspekcji TLS mogą uniemożliwić działanie tej architektury sieciowej.<sup>[[3]](#references)</sup>

## Selektywne przyspieszanie natywne

Interpretowanie każdej instrukcji jest szczególnie kosztowne w kryptografii klucza publicznego. Praktyczny podział wykorzystuje hooki `MBEDTLS_ALT` w mbedTLS jako interfejs programowego koprocesora: stan TLS, parsowanie certyfikatów, negocjację, alokację i kod bignum wyższego poziomu pozostawia w bytecode, a gorące kernele arytmetyczne z `bignum_core.c` wywołuje natywnie przez ECALL. W prototypie Centuriona pliki `bignum.c`, `bignum_mod.c` i `bignum_mod_raw.c` pozostały zwirtualizowane, podczas gdy pętle wewnętrzne działały natywnie, skracając handshake ECDHE z minut do sekund.<sup>[[3]](#references)</sup>

Uczyń akceleratory opcjonalnymi, aby payloady niewymagające TLS pomijały dodatkowe natywne punkty wejścia. Ten wzorzec można zastosować do dowolnego obciążenia interpretera: najpierw przeprowadź profilowanie, a następnie udostępnij możliwie najmniejszy natywny prymityw zamiast przenosić cały podsystem poza VM.<sup>[[3]](#references)</sup>

Centurion zweryfikował cały łańcuch za pomocą powłoki bind shell z TLS 1.2: loader bytecode zmapował PE, wywołania socketów przechodziły przez uniwersalny thunk, mbedTLS obsługiwał protokół wewnątrz VM, a natywne ECALL przyspieszały arytmetykę ECDHE. Natywny interpreter o rozmiarze około 18 KB obsługiwał więc szyfrowany kanał poleceń bez materializowania payloadu jako natywnego kodu x86-64.<sup>[[3]](#references)</sup>

## Punkty zaczepienia w analizie i detekcji

Poniższe punkty stanowią praktyczne wskazówki analityczne wywnioskowane z architektury; wirtualizacja zmienia miejsca, w których analitycy obserwują zachowanie, ale go nie eliminuje.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Zidentyfikuj pętlę pobierania, dekodowania i dispatchu, wirtualny licznik programu, zestaw rejestrów oraz powtarzające się przechodzenie przez instrukcje o stałej długości.
- Zrzuć tabelę opcode’ów po odszyfrowaniu w czasie działania i przypisz adresy handlerów do operacji semantycznych, zamiast dopasowywać zaszyfrowany bytecode na dysku.
- Ustaw breakpoint na uniwersalnym thunk lub dispatcherze ECALL, aby rejestrować natywny cel, wirtualne rejestry argumentów, argumenty na stosie i wartość zwracaną.
- Śledź dostęp do PEB, rozwiązywanie eksportów, parsowanie nagłówków PE, zapisy relokacji i wypełnianie IAT, nawet gdy sama implementacja loadera jest bytecode.
- Powiąż tworzenie socketów i ruch `afd.sys` z brakiem oczekiwanych wywołań WinHTTP lub natywnych wywołań TLS; brak importów wysokiego poziomu jest wskazówką, a nie dowodem nieszkodliwego działania.
- Traktuj natywne akceleratory arytmetyczne jako semantyczne punkty kontrolne: ich wywołujący mogą ujawnić wymianę kluczy i aktywność związaną z walidacją certyfikatów, podczas gdy otaczająca je maszyna stanów TLS pozostaje zwirtualizowana.

Informacje o analizie rozpoczynającej się od dispatchera, a nie od oryginalnego grafu przepływu sterowania, znajdziesz w [wskazówkach dotyczących analizy malware w przypadku wirtualizowanych packerów](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Ograniczenia operacyjne

Wirtualizacja powoduje narzut interpretacji, zwiększa złożoność toolchaina i ABI oraz nie rozwiązuje problemu detekcji behawioralnej. Współdzielona pamięć jest z założenia niebezpieczna, sieć oparta na surowych socketach może nie działać za obowiązkowymi proxy, a API Win32 intensywnie korzystające z callbacków wymagają trampoline’ów z kodu natywnego do VM. Interpreter, most syscalli i wszystkie natywne akceleratory pozostają również konwencjonalnym natywnym footprintem, który obrońcy mogą sygnaturować lub instrumentować.<sup>[[2]](#references)[[3]](#references)</sup>

## Powiązane strony

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Budowanie maszyny wirtualnej RISC-V do obfuskacji payloadu](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming w erze EDR — omijanie detekcji przez wirtualizację malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — własne środowisko wykonawcze](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
