# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Dlaczego unwinding oparty na metadanych można spoofować

Niektóre narzędzia bezpieczeństwa macOS zlecają zbieranie stosów wątków programowi `/usr/sbin/spindump` lub w inny sposób ufają konwencjonalnemu unwinderowi opartemu na metadanych. Implant może wykorzystać tę granicę zaufania, umieszczając na swoim stosie syntetyczne rekordy zgodne z ABI, dzięki czemu wygląda, jakby do wrażliwego API prowadziły wybrane przez atakującego funkcje w dyld i załadowanych frameworkach Apple, a nie niepowiązany kod implantu. To oszustwo telemetryczne, a nie zmiana pliku wykonywalnego ani jego metadanych unwind.<sup>[[1]](#references)</sup>

Zobacz [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots), aby poznać kontekst zbierania danych.

Unwinder nie potwierdza, że rekord został utworzony przez prolog wygenerowany przez kompilator. Wielokrotnie używa bieżącego `PC`, aby wybrać recepturę Mach-O, stosuje ją do `SP`, `x29`, `x30`, pamięci stosu i zadeklarowanych rejestrów nieulotnych, a następnie używa odzyskanego `PC` wywołującego do wybrania kolejnej receptury. Jeśli pamięć kontrolowana przez atakującego spełnia wymagania każdej wybranej receptury, otrzymany łańcuch może być strukturalnie poprawny i możliwy do symbolizacji, mimo że te wywołania nigdy nie miały miejsca.<sup>[[1]](#references)</sup>

## Stan ramki ARM64

[ARM64 assembly overview](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) omawia role rejestrów i konwencję wywołań. W przypadku konwencjonalnej ramki utworzonej za pomocą `stp x29, x30, [sp, #-16]!`, a następnie `mov x29, sp`, Canonical Frame Address (CFA), reprezentujący wejściowy `SP` wywołującego, wynosi `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Rekordy ramek tworzą listę wiązaną przez `[FP]`, ale bezrefleksyjne podążanie za tą listą nie wystarcza: funkcje liściowe mogą nie mieć ramek, tail calls mogą usuwać przejścia logiczne, a nietypowe układy korzystają z DWARF CFI. Reguła wybrana na podstawie bieżącego adresu określa, czy unwinder w ogóle odczytuje łańcuch FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Wybór reguły unwind dla Mach-O

Finalne obrazy po linkowaniu przechowują skompaktowane dane unwind w `__TEXT,__unwind_info`. Nagłówek sekcji wskazuje indeks funkcji pierwszego poziomu; każdy zakres indeksu wskazuje stronę drugiego poziomu — zwykłą (`kind=2`) lub skompresowaną (`kind=3`). Układy, których nie da się opisać za pomocą skompaktowanego unwind, używają FDE i instrukcji call-frame w `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Dla każdego kandydującego PC w czasie wykonywania:<sup>[[1]](#references)[[2]](#references)</sup>

1. Usuń lub znormalizuj bity PAC ARM64e wyłącznie na potrzeby wyszukiwania.
2. Znajdź załadowany plik Mach-O, którego wykonywalny zakres `__TEXT` zawiera ten adres.
3. Oblicz `functionOffset = normalizedPC - loadedImageBase` i odrzuć ujemne wyniki lub wartości większe niż `UINT32_MAX`.
4. Wybierz zakres pierwszego poziomu spełniający warunek `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Przeanalizuj wskazaną stronę drugiego poziomu, wybierz najbliższy wpis, którego początek nie przekracza przesunięcia, i sprawdź, czy adres leży przed następnym wpisem lub końcem zakresu pierwszego poziomu.
6. Zdekoduj ten wpis i odtwórz dokładnie opisany przez niego stan.

Gdy adres pochodzi z zapisanego LR, wyszukiwanie może użyć `PC-1`, aby adres bezpośrednio za wywołaniem nadal mieścił się w zakresie objętym przez kod wywołujący. Zmienia to wybór reguły, a nie żadne przesunięcie na stosie.<sup>[[1]](#references)</sup>

Parser musi sprawdzać granice każdego nagłówka i tablicy, wymagać wersji sekcji `1`, uwzględniać końcowy sentinel pierwszego poziomu, odrzucać zerowe przesunięcie strony drugiego poziomu oraz rozróżniać strony zwykłe i skompresowane. Na zwykłej stronie `entryPageOffset` jest liczone względem początku tej strony, natomiast przesunięcie strony pierwszego poziomu — względem początku `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

Ogólna maska trybu to `encoding & 0x0F000000`. Aktualne definicje LLVM obejmują następujące tryby; parser nie powinien traktować każdej wartości innej niż DWARF jako klasycznej ramki:<sup>[[1]](#references)[[2]](#references)</sup>

| Tryb | Wartość | Odtworzenie stanu wywołującego |
| --- | --- | --- |
| Brak skompaktowanej reguły | `0x00000000` | Zatrzymaj się lub użyj niezależnego fallbacku. |
| Bez ramki | `0x02000000` | Dodaj zakodowany rozmiar stosu do bieżącego `SP`; PC wywołującego znajduje się w aktywnym LR. |
| DWARF | `0x03000000` | Wykonaj FDE/CFI wskazane przez dolne 24 bity. |
| Ramka | `0x04000000` | Odczytaj standardowy rekord ramki `x29`. |
| Ramka arm64e z uwierzytelnionym zakresem LR | `0x05000000` | Obsłuż `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; jego pole przesunięcia wskazuje położenie `pacibsppc` w objętym zakresie. |

W trybie bezramkowym `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. W trybie ramki pięć najmłodszych bitów określa kolejne pary zapisanych rejestrów GPR: od `x19/x20` do `x27/x28`; bity `0x100-0x800` analogicznie określają pary rejestrów `d8-d15`. Te zapisane rejestry mogą nie być potrzebne do znalezienia kolejnego PC, ale wiarygodny wirtualny stan wywołującego musi spełniać wymagania dotyczące każdego pola odtwarzanego przez odbiorcę.<sup>[[1]](#references)[[2]](#references)</sup>

## Konstruowanie syntetycznych rekordów w trybie ramki

Proces konstruowania odwraca działanie unwindera zamiast przeszukiwać stos w poszukiwaniu wartości przypominających adresy:<sup>[[1]](#references)</sup>

1. Wybierz rzeczywisty, wykonywalny PC z aktualnie załadowanego obrazu.
2. Zdekoduj regułę obejmującą dokładnie ten PC lub adres miejsca wywołania.
3. Przydziel syntetyczny rekord z wymaganym wyrównaniem i relacją CFA.
4. Zapisz kolejny syntetyczny FP pod `[FP]`, zapisany PC wywołującego danej ramki pod `[FP+8]`, a wszystkie zapisywane rejestry GPR/FPR zadeklarowane przez kodowanie — poniżej FP.
5. Połącz kilka rekordów i umieść pierwszy z nich w aktywnym `x29`.
6. Ustaw aktywny LR i ścieżkę powrotu API tak, aby unwind wchodził w wybrany łańcuch, a jednocześnie umożliwiał bezpieczne przywrócenie wykonywania.

Na przykład `0x04000001` oznacza tryb ramki oraz parę `x19/x20`. Odpowiadająca temu transformacja stanu i wymagana pamięć to:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Adres, który wygląda na prawidłowy, nie wystarczy. Każdy odzyskany PC staje się kluczem do następnego wyszukiwania, więc pojedynczy adres, którego kodowanie nie zgadza się ze sfabrykowanym układem, przerywa łańcuch albo powoduje, że odbiorca odtwarza niespójny stan rejestrów.<sup>[[1]](#references)</sup>

## Wymagania ARM64e PAC

PAC przechowuje kluczowaną wartość integralności w wolnych bitach wskaźnika; nie szyfruje adresu. Schemat adresu powrotu arm64e w Clang używa klucza instrukcji B oraz wskaźnika stosu z chwili wejścia do funkcji jako dyskryminatora. W konwencjonalnej ramce ten początkowy `SP` jest CFA, więc zapisany LR pod `[FP+8]` jest powiązany z `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Każdy syntetyczny LR musi być podpisany niezależnie, ponieważ przeniesienie już podpisanego LR do ramki z innym CFA zmienia discriminator i powoduje niepowodzenie uwierzytelniania. `ptrauth_strip()` nadaje się do normalizacji adresów i wyszukiwania symboli, ale **nie** potwierdza autentyczności; każde rzeczywiste return lub uwierzytelnione branch pośrednie musi używać klucza i modyfikatora oczekiwanych przy danym przejściu.<sup>[[1]](#references)[[3]](#references)</sup>

Typowa funkcja arm64e niebędąca funkcją liściową podpisuje LR przed zapisaniem go i uwierzytelnia po przywróceniu wejściowego SP:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline i restore bridge

Syntetyczne rekordy muszą jedynie spełniać wymagania unwinder; nie zawierają pełnego kontekstu wykonania. Powrót z wrażliwego API bezpośrednio do spreparowanych funkcji wywołujących zwykle spowodowałby awarię. Praktyczne rozwiązanie umieszcza więc ramkę gadgetu bezpośrednio poniżej API: API wraca do wykonywalnego kodu w załadowanym frameworku, a następnie gadget skacze przez kontrolowany rejestr callee-saved do restore bridge w implancie.<sup>[[1]](#references)</sup>

Przydatny gadget zachowuje LR i przekazuje sterowanie przez kontrolowany rejestr, na przykład za pomocą odpowiedniej sekwencji `br`, `braa` lub `brab`. Restore bridge musi odtworzyć oryginalne wartości `x19-x30` i `SP` przed wznowieniem wykonywania implantu. Na arm64e każdy uwierzytelniony powrót lub skok na ścieżce API-to-gadget, gadget-to-bridge i bridge-to-implant wymaga wskaźnika podpisanego kluczem i z użyciem dyskryminatora stosowanych przez daną instrukcję.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Wynik ten ujawnia istotne naruszenie granicy zaufania w przypadku detekcji opartych na stosie: łańcuch może zawierać wyłącznie zmapowane adresy PC z frameworków Apple, dla których można rozpoznać symbole, a mimo to nie odzwierciedlać rzeczywistego przepływu sterowania. Dlatego wynik unwind należy weryfikować niezależnymi dowodami dotyczącymi pochodzenia pamięci wykonywalnej wątku oraz rzeczywistych przejść wokół wrażliwego API, zamiast traktować go jako ślad wykonania.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Wewnętrzne działanie stosu ARM64 i obfuskacja na Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definicje kodowania compact unwind Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Uwierzytelnianie wskaźników](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Standard wywoływania procedur dla architektury Arm 64-bit](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
