# Metodologia Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

W **mutational grammar fuzzing** wejścia są modyfikowane przy zachowaniu **poprawności względem gramatyki**. W trybie coverage-guided zapisywane jako corpus seeds są tylko próbki wywołujące **nowe pokrycie**. W przypadku **language targets** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/dataflow**, w których wynik jednej konstrukcji staje się wejściem kolejnej.

**Failure mode:** fuzzer znajduje seeds, które niezależnie uruchamiają `document()` i `generate-id()` (lub podobne primitives), ale **nie zachowuje łańcuchowego dataflow**, więc próbka „bliższa błędowi” zostaje odrzucona, ponieważ nie zwiększa pokrycia. Przy **3+ zależnych krokach** losowa rekombinacja staje się kosztowna, a feedback dotyczący pokrycia nie pomaga w prowadzeniu wyszukiwania.

**Implikacja:** w przypadku grammar z dużą liczbą zależności rozważ **hybrydyzację faz mutational i generative** albo ukierunkowanie generowania na wzorce **function chaining** (a nie wyłącznie na coverage).<sup>[[1]](#references)</sup>

## Problemy z różnorodnością Corpus

Mutacja sterowana pokryciem jest **zachłanna**: próbka z nowym pokryciem jest zapisywana natychmiast i często zachowuje duże, niezmienione obszary. Z czasem corpus staje się zbiorem **niemal identycznych próbek** o niewielkiej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca grammar**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukuje szum, zachowując wystarczającą strukturę otoczenia, aby ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing brzmi: **preferuj niewielki zestaw strukturalnie różnych seeds maksymalizujących coverage** zamiast dużego zbioru niemal identycznych próbek. W praktyce zwykle oznacza to:<sup>[[1]](#references)</sup>

- Rozpocznij od **próbek pochodzących z rzeczywistego świata** (publicznych corpus, crawlingu, przechwyconego ruchu, zbiorów plików z ekosystemu celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpus na podstawie coverage**, zamiast zachowywać każdą poprawną próbkę.
- Seeds powinny być **wystarczająco małe**, aby mutacje trafiały w znaczące pola, zamiast zużywać większość cykli na nieistotne bajty.
- Ponownie uruchamiaj minimalizację corpus po większych zmianach harnessu/instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą reachability.

## Mutation Uwzględniająca Comparisons Dla Magic Values

Częstą przyczyną plateau fuzzers nie jest składnia, lecz **trudne comparisons**: magic bytes, sprawdzanie długości, strings enum, checksums lub wartości dispatch parsera chronione przez `memcmp`, tabele switch albo kaskadowe porównania. Czysta losowa mutacja marnuje cykle na próby odgadnięcia tych wartości bajt po bajcie.

W przypadku takich celów używaj **comparison tracing** (na przykład workflow w stylu AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować operandy z nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>
```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```
**Uwagi praktyczne:**

- Jest to szczególnie przydatne, gdy target warunkuje głębszą logikę za pomocą **sygnatur plików**, **czasowników protokołu**, **tagów typów** lub **bitów funkcji zależnych od wersji**.
- Połącz to ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołu lub logów debugowania. Mały słownik zawierający tokeny gramatyki, nazwy chunków, czasowniki i delimitery jest często cenniejszy niż ogromna, generyczna wordlista.
- Jeśli target wykonuje wiele sekwencyjnych testów, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj wynikowy corpus, aby kolejne etapy rozpoczynały się od już poprawnych prefiksów.

## Stateful Fuzzing: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych workflow** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Połączenie całego transcriptu w jeden plik i jego ślepe mutowanie jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok w równym stopniu, nawet gdy tylko późniejszy komunikat dociera do podatnego stanu.

Skuteczniejszy wzorzec polega na traktowaniu **samej sekwencji jako seeda** i wykorzystywaniu **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, zwracanych typów obiektów) jako dodatkowego feedbacku:<sup>[[4]](#references)</sup>

- Zachowuj stabilność **poprawnych komunikatów prefiksowych** i skup mutacje na komunikacie **sterującym przejściem**.
- Cache'uj identyfikatory i wartości generowane przez serwer z poprzednich odpowiedzi, gdy kolejny krok jest od nich zależny.
- Preferuj mutowanie/splicing poszczególnych komunikatów zamiast mutowania całego zserializowanego transcriptu jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego oracle stanu**, aby priorytetyzować sekwencje przechodzące głębiej.

Z tego samego powodu vanilla file-style fuzzing często pomija błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po handshake'u”: fuzzer musi zachowywać **kolejność, stan i zależności**, a nie tylko strukturę.

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem na połączenie **generatywnej nowości** z **ponownym wykorzystywaniem coverage** jest **restartowanie krótkotrwałych workerów** kierowanych do persistent servera. Każdy worker rozpoczyna od pustego corpusu, synchronizuje się po `T` sekundach, działa przez kolejne `T` sekund na połączonym corpusie, ponownie się synchronizuje, a następnie kończy działanie. Zapewnia to **świeże struktury w każdej generacji**, jednocześnie nadal wykorzystując zgromadzone coverage.<sup>[[2]](#references)</sup>

**Serwer:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjne workery (przykładowa pętla):**

<details>
<summary>Pętla restartowania workera Jackalope</summary>
```python
import subprocess
import time

T = 3600

while True:
subprocess.run(["rm", "-rf", "workerout"])
p = subprocess.Popen([
"/path/to/fuzzer",
"-grammar", "grammar.txt",
"-instrumentation", "sancov",
"-in", "empty",
"-out", "workerout",
"-t", "1000",
"-delivery", "shmem",
"-iterations", "10000",
"-mute_child",
"-nthreads", "6",
"-server", "127.0.0.1:8337",
"-server_update_interval", str(T),
"--", "./harness", "-m", "@@",
])
time.sleep(T * 2)
p.kill()
```
</details>

**Uwagi:**

- `-in empty` wymusza **świeży korpus** przy każdym generowaniu.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowości, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja serwera jest domyślnie pomijana** (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalna wartość `T` **zależy od targetu**; najlepsze rezultaty zwykle daje przełączenie po znalezieniu przez workera większości „łatwego” coverage.

## Snapshot Fuzzing dla targetów trudnych do objęcia harnessami

Gdy kod, który chcesz testować, staje się osiągalny dopiero **po dużym koszcie przygotowania** (uruchomieniu VM, ukończeniu logowania, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), użyteczną alternatywą jest **snapshot fuzzing**:

1. Uruchom target, aż interesujący stan będzie gotowy.
2. Wykonaj snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane dane wejściowe bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj kod do momentu crash/timeout/reset.
5. Przywróć tylko **zmodyfikowane strony** i powtórz.

Pozwala to uniknąć ponoszenia pełnego kosztu przygotowania w każdej iteracji i jest szczególnie przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku po uwierzytelnieniu** oraz **targetów dostępnych wyłącznie w postaci binarnej**, które trudno przekształcić w klasyczny in-process harness.

Praktycznym rozwiązaniem jest natychmiastowe zatrzymanie wykonania za punktem `recv`/`read`/deserializacji pakietu, zapisanie adresu bufora danych wejściowych, a następnie wykonanie w tym miejscu snapshotu i bezpośrednia modyfikacja tego bufora w każdej iteracji. Umożliwia to fuzzowanie głębokiej logiki parsowania bez odtwarzania całego handshake'u za każdym razem.

## Introspekcja harnessu: wcześnie znajdź płytkie fuzzery

Gdy kampania utknie, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/coverage**, aby znaleźć funkcje, które są statycznie osiągalne z targetu fuzzowania, ale dynamicznie są pokrywane rzadko lub wcale. Funkcje te zwykle wskazują na jeden z trzech problemów:

- Harness wchodzi do targetu zbyt późno lub zbyt wcześnie.
- W seed corpus brakuje całej rodziny funkcji.
- Target rzeczywiście wymaga **drugiego harnessu**, zamiast jednego, zbyt rozbudowanego harnessu typu „zrób wszystko”.

Jeśli korzystasz z workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector jest przydatny podczas tego triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze entry points.

## Wybór fuzz targetów i triage mutacji w oparciu o graf

Jeśli masz już **wyniki analizy statycznej**, **survivors z mutation testing** oraz **raporty pokrycia**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, dodaj do węzłów informacje o **złożoności cyklomatycznej**, **osiągalności z entrypointów/niezaufanego wejścia** oraz wszelkich zewnętrznych wynikach, a następnie zadawaj pytania dotyczące grafu:<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanego wejścia?
- Które mutation survivors znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi choke pointami o nietypowo dużym **blast radius**?

Zwykle pozwala to znaleźć lepsze fuzz targety niż samo „najniższe pokrycie”. Parser/decoder o **wysokiej złożoności** i potwierdzonej **zewnętrznej osiągalności** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper o słabym pokryciu, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny workflow triage

1. Zbuduj **graf kodu** na podstawie codebase i wyodrębnij metryki złożoności/branchy dla każdej funkcji.
2. Wylicz **entrypointy** przyjmujące dane kontrolowane przez atakującego: request handlery, decodery, importery, parsery protokołów, czytniki CLI/plików.
3. Uruchom **zapytania o ścieżki** od tych entrypointów do funkcji kandydujących, aby oddzielić osiągalny attack surface od kodu martwego/wyłącznie wewnętrznego.
4. Nadaj priorytet węzłom, które łączą:
- wysoką **złożoność cyklomatyczną**
- potwierdzoną **osiągalność z niezaufanego wejścia**
- duży **blast radius** lub wielu zależnych odbiorców
- dodatkowe potwierdzające dane, takie jak wyniki **SARIF**, notatki z audytu lub mutation survivors
5. Najpierw twórz skoncentrowane harnesses dla najlepiej ocenionych węzłów, szczególnie **parserów/codeców**, takich jak decodery hex/Base64/IP/message.

### Mutation survivors: equivalent vs actionable

Mutation testing często generuje zaszumioną listę survivors. Zanim uznasz każdego survivora za lukę w bezpieczeństwie, użyj grafu i zadaj pytania:

- Czy zmodyfikowana funkcja jest osiągalna z entrypointu kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone przez silniejsze invariants niż zmodyfikowany check?
- Czy węzeł znajduje się w martwym kodzie, logice dotyczącej wyłącznie formatowania, czy w wysoko wpływowej ścieżce arytmetycznej/parsera?

Survivors, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **equivalent mutants**. Survivors, które pozostają **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek overflow/carry** lub **krytycznej dla bezpieczeństwa arytmetyki/parsing**, powinny zostać przekształcone w:

- nowe fuzz harnesses
- bezpośrednie testy właściwości/invariants
- ukierunkowane wektory edge-case

### Korelacja zewnętrznych wyników z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, nanieś wyniki na węzły grafu według **pliku + zakresu linii** i użyj grafu do rozszerzenia analizy wpływu:

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy wynik znajduje się na którejkolwiek ścieżce od entrypointu
- grupuj pobliskie wyniki, które sprowadzają się do tego samego choke pointu

Jest to przydatne przy podejmowaniu decyzji, czy poświęcić czas fuzzing na konkretną funkcję: węzeł, który jest **osiągalny**, **złożony** i ma już wyniki **SAST**, jest często lepszym targetem niż jedynie złożony węzeł bez ścieżki ataku.

Przykładowy workflow z Trailmark:<sup>[[6]](#references)</sup>
```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```
Ważną metodologią jest przecięcie: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości bezpieczeństwa, a następnie użyj ocalałych mutacji, aby określić, które granice i niezmienniki musi testować Twój harness.

## Fuzzing Go z gosentry: silniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu za pomocą [gosentry](https://github.com/trailofbits/gosentry) — rozwidlonego toolchaina Go, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach wymagających intensywnego parsowania**. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` dla seedów i `f.Fuzz(...)` dla callbacka.
- Używaj tego samego harnessu, ale uruchamiaj go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj wynikową kampanię jak zwykłe uruchomienie sterowane pokryciem kodu, ale z mechanizmami planowania/mutacji LibAFL i lepszymi dodatkowymi detektorami.

### Zamiana cichych awarii w wyniki fuzzingu

Powtarzającym się problemem podczas assessmentów Go jest to, że niebezpieczne zachowanie często **domyślnie nie powoduje crasha**. Za pomocą gosentry możesz przekształcić kilka klas „złych, ale cichych” stanów w wyniki fuzzingu:

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/obsługi błędów zachowują się jak crashe (przydatne w przypadku ścieżek kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie uruchamia nowo odkryte wpisy kolejki z użyciem race detectora Go.
- `--catch-leaks=true` ponownie uruchamia nowe wpisy kolejki z użyciem `goleak` i zatrzymuje się po wykryciu leaków goroutine.
- Obsługa hangów przez LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pozwalać, aby zniknęły jako timeouty.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego oraz opcjonalne kontrole obcięcia za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie wartościowe w przypadku targetów, w których wpływ na bezpieczeństwo wynika z **awarii parsera bez paniki**, **błędu współbieżności** lub **hangów powodujących wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go obsługuje głównie skalary, takie jak `[]byte`, `string` i liczby. Jeśli testowany kod korzysta z typowanych obiektów, gosentry może fuzzować bezpośrednio **wartości złożone** (struktury, slice'y, tablice, wskaźniki), jednocześnie mutując znajdujące się pod nimi bajty.
```go
type Input struct {
Data []byte
S    string
N    int
}

func FuzzStructInput(f *testing.F) {
f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
f.Fuzz(func(t *testing.T, in Input) {
Process(in)
})
}
```
Użyj tego podczas budowania fałszywego formatu przewodowego tylko na potrzeby fuzzing, ponieważ ukrywałoby to błędy logiczne za kodem parsowania używanym wyłącznie przez harness. W przypadku kampanii różnicowych lub opartych na gramatyce pozostaw dane wejściowe harness jako pojedyncze `[]byte` lub `string` i parsuj je zamiast tego wewnątrz callback.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków danych wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** na bazie LibAFL. Gramatyka jest tablicą reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Uwagi dotyczące metodologii:

- Używaj trybu grammar, gdy mutacje na poziomie bajtów najczęściej kończą się na wczesnych sprawdzeniach składni.
- Skup grammar na **podzbiorze języka/protokołu istotnym z punktu widzenia bezpieczeństwa**, zamiast modelować pełną specyfikację.
- Używaj dużych wartości granicznych w terminalach/nonterminalach, aby testować granice liczb całkowitych, długości i maszyn stanów.
- Tryb grammar utrzymuje dane wejściowe w formie zgodnej z grammar, ale target nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i sprawdzanie semantyczne nadal odbywają się wewnątrz kodu objętego harnessingiem.

### Differential fuzzing: porównuj implementacje, a nie tylko crashe

Silnym wzorcem dla ekosystemów Go jest **grammar-based differential fuzzing**: generuj poprawne, ustrukturyzowane dane wejściowe i przekazuj je do dwóch parserów, klientów lub silników przejść między stanami.
```go
f.Fuzz(func(t *testing.T, data []byte) {
gotA, errA := ParseA(data)
gotB, errB := ParseB(data)
if (errA == nil) != (errB == nil) {
t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
}
_ = gotA
_ = gotB
})
```
Traktuj następujące sytuacje jako findings:

- jedna implementacja wywołuje panic, podczas gdy druga poprawnie odrzuca dane
- niezgodność między zaakceptowanymi i odrzuconymi danymi wejściowymi
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanów, wartości nonce, salda lub state roots

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** oraz **rozbieżności między specyfikacją a implementacją**, których często nie wykrywa samo fuzzing crashów.

### Ponowne wykorzystanie corpus kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany corpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania oddzielnego corpusu:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Uruchom polecenie z **tego samego pakietu** i z tym samym celem `-fuzz`, aby gosentry rozpoznał właściwy zapisany w cache stan kampanii.

## Referencje

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing dogłębnie](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzing brakowało połowy zestawu narzędzi. Rozwid­liliśmy toolchain, aby to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
