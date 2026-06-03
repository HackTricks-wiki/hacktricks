# Metodologia Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

W **mutational grammar fuzzing**, wejścia są mutowane, przy jednoczesnym zachowaniu zgodności z **grammar**. W trybie guided by coverage, zapisywane jako seedy corpus są tylko próbki, które wywołują **new coverage**. Dla **language targets** (parserów, interpreterów, engine’ów) może to pomijać bugi wymagające **semantic/dataflow chains**, gdzie wyjście jednego konstruktora staje się wejściem kolejnego.

**Failure mode:** fuzzer znajduje seedy, które osobno uruchamiają `document()` i `generate-id()` (lub podobne primitive), ale **nie zachowuje chained dataflow**, więc próbka „bliższa bugowi” jest odrzucana, ponieważ nie dodaje coverage. Przy **3+ dependent steps**, losowa recombinacja staje się kosztowna, a coverage feedback nie prowadzi search.

**Implikacja:** dla grammar o dużej liczbie zależności rozważ **hybridizing mutational and generative phases** albo biasing generation w stronę wzorców **function chaining** (nie tylko coverage).

## Pułapki różnorodności corpus

Coverage-guided mutation jest **greedy**: próbka z new-coverage jest zapisywana natychmiast, często z zachowaniem dużych niezmienionych regionów. Z czasem corpus staje się zbiorem **near-duplicates** o niskiej różnorodności strukturalnej. Agresywna minimization może usunąć przydatny kontekst, więc praktyczny kompromis to **grammar-aware minimization**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukuje noise, zachowując wystarczająco dużo otaczającej struktury, by pozostać przyjazną dla mutacji).

Praktyczna zasada dla corpus w mutational fuzzing to: **preferuj mały zestaw strukturalnie różnych seedów, które maksymalizują coverage**, zamiast dużej sterty near-duplicates. W praktyce zwykle oznacza to:

- Zacznij od **real-world samples** (public corpus, crawling, captured traffic, zestawy plików z ekosystemu targetu).
- Odfiltruj je za pomocą **coverage-based corpus minimization** zamiast trzymać każdą poprawną próbkę.
- Trzymaj seedy na tyle **małe**, aby mutacje trafiały w istotne pola, zamiast zużywać większość cykli na nieistotne bajty.
- Ponownie uruchom corpus minimization po większych zmianach w harness/instrumentation, ponieważ „najlepsze” corpus zmienia się wraz ze zmianą reachability.

## Comparison-Aware Mutation For Magic Values

Częstym powodem, dla którego fuzzer osiąga plateau, nie jest składnia, lecz **hard comparisons**: magic bytes, sprawdzenia długości, ciągi enumów, checksumy albo wartości dispatch parsera chronione przez `memcmp`, switch tables lub kaskadowe porównania. Czysta random mutation marnuje cykle, próbując zgadywać te wartości bajt po bajcie.

Dla takich targetów używaj **comparison tracing** (na przykład AFL++ `CMPLOG` / workflow w stylu Redqueen), aby fuzzer mógł obserwować operandy z nieudanych porównań i biasing mutations w kierunku wartości, które je spełniają.
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
**Praktyczne uwagi:**

- Jest to szczególnie użyteczne, gdy cel ukrywa głęboką logikę za **file signatures**, **protocol verbs**, **type tags** lub **version-dependent feature bits**.
- Połącz to z **dictionaries** wyodrębnionymi z prawdziwych próbek, specyfikacji protokołów lub logów debug. Mały słownik z tokenami gramatyki, nazwami chunków, verbami i separatorami często jest cenniejszy niż ogromna generyczna wordlist.
- Jeśli cel wykonuje wiele sekwencyjnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a potem ponownie zminimalizuj wynikowy corpus, aby późniejsze etapy startowały z już poprawnych prefiksów.

## Stateful Fuzzing: Sequences Are Seeds

W przypadku **protocols**, **authenticated workflows** i **multi-stage parsers** interesującą jednostką często nie jest pojedynczy blob, lecz **message sequence**. Sklejenie całej transkrypcji do jednego pliku i ślepe jej mutowanie jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok tak samo, nawet gdy tylko późniejsza wiadomość dociera do kruchego stanu.

Skuteczniejszy wzorzec polega na traktowaniu **samej sekwencji jako seeda** i używaniu **observable state** (response codes, protocol states, parser phases, returned object types) jako dodatkowego feedback:

- Zachowuj **valid prefix messages** stabilne i skup mutacje na wiadomości **transition-driving**.
- Cachuj identyfikatory i wartości generowane przez serwer z poprzednich odpowiedzi, gdy następny krok od nich zależy.
- Preferuj mutację/splicing per-message zamiast mutowania całej zserializowanej transkrypcji jako nieprzezroczystego bloba.
- Jeśli protocol udostępnia znaczące response codes, używaj ich jako **cheap state oracle**, aby priorytetyzować sekwencje, które przechodzą głębiej.

To z tego samego powodu authenticated bugs, ukryte przejścia lub błędy parsera typu „only-after-handshake” są często pomijane przez zwykłe file-style fuzzing: fuzzer musi zachować **order, state i dependencies**, a nie tylko strukturę.

## Single-Machine Diversity Trick (Jackalope-Style)

Praktyczny sposób na hybrydyzację **generative novelty** z **coverage reuse** to **restartowanie krótkotrwałych workerów** przeciwko persistent server. Każdy worker startuje z pustym corpus, synchronizuje się po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, znów się synchronizuje, a potem kończy działanie. Daje to **fresh structures each generation** przy jednoczesnym wykorzystaniu zgromadzonego coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjni workerzy (przykładowa pętla):**

<details>
<summary>Pętla restartu workerów Jackalope</summary>
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

- `-in empty` wymusza **świeży corpus** przy każdym generowaniu.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowość, potem reuse).
- W trybie grammar fuzzing początkowa synchronizacja z server jest domyślnie pomijana (nie trzeba `-skip_initial_server_sync`).
- Optymalne `T` zależy od **target**; przełączanie po tym, jak worker znajdzie większość „łatwego” coverage, zwykle działa najlepiej.

## Snapshot Fuzzing For Hard-To-Harness Targets

Gdy kod, który chcesz testować, staje się osiągalny dopiero **po dużym koszcie przygotowania** (booting VM, ukończenie login, odebranie packet, parsowanie container, inicjalizacja service), użyteczną alternatywą jest **snapshot fuzzing**:

1. Uruchom target aż interesujący stan będzie gotowy.
2. Zrób snapshot **memory + registers** w tym punkcie.
3. Dla każdego test case zapisz zmodyfikowany input bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj do crash/timeout/reset.
5. Przywróć tylko **dirty pages** i powtórz.

Pozwala to uniknąć ponoszenia pełnego kosztu przygotowania przy każdej iteracji i jest szczególnie przydatne dla **network services**, **firmware**, **post-auth attack surfaces** oraz **binary-only targets**, które trudno przerobić na klasyczny in-process harness.

Praktyczny trik polega na natychmiastowym zatrzymaniu po punkcie `recv`/`read`/packet-deserialization, zanotowaniu adresu bufora input, wykonaniu tam snapshot, a następnie bezpośrednim mutowaniu tego bufora w każdej iteracji. Dzięki temu możesz fuzzować głęboką logikę parsowania bez przebudowywania całego handshake za każdym razem.

## Harness Introspection: Find Shallow Fuzzers Early

Gdy kampania staje, problemem często nie jest mutator, lecz **harness**. Użyj **reachability/coverage introspection**, aby znaleźć funkcje, które są statycznie osiągalne z twojego fuzz target, ale dynamicznie są rzadko albo nigdy nie pokrywane. Takie funkcje zwykle wskazują na jeden z trzech problemów:

- Harness wchodzi do target za późno albo za wcześnie.
- Seed corpus nie zawiera całej rodziny funkcji.
- Target naprawdę potrzebuje **drugiego harness** zamiast jednego zbyt dużego harness „do wszystkiego”.

Jeśli używasz workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector jest przydatny do takiego triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Użyj reportu, aby zdecydować, czy dodać nowy harness dla nietestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze entry points.

## Wybór celu fuzzingu i triage mutacji na podstawie grafu

Jeśli masz już **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nie triage’uj ich jako niezależnych list. Najpierw zbuduj **call graph**, oznacz węzły **cyclomatic complexity**, **entrypoint/untrusted-input reachability** oraz wszelkie zewnętrzne findings, a potem zadaj pytania grafowe:

- Które funkcje o wysokiej złożoności są osiągalne z untrusted input?
- Które mutation survivors znajdują się na ścieżkach od parserów/handlerów do security-critical code?
- Które funkcje są architektonicznymi punktami krytycznymi o nietypowo dużym **blast radius**?

To zwykle ujawnia lepsze cele fuzzingu niż samo „najniższe coverage”. Parser/decoder o **wysokiej złożoności** i potwierdzonej **external reachability** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper z niskim coverage, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny workflow triage

1. Zbuduj **code graph** z codebase i wyodrębnij metryki złożoności/branch dla każdej funkcji.
2. Wylicz **entrypoints**, które przyjmują dane kontrolowane przez atakującego: request handlers, decodery, importery, protocol parsers, CLI/file readers.
3. Uruchom zapytania o **path** z tych entrypoints do funkcji-kandydatów, aby oddzielić reachable attack surface od martwego/kod tylko wewnętrznego.
4. Priorytetyzuj węzły, które łączą:
- wysoką **cyclomatic complexity**
- potwierdzoną **reachability from untrusted input**
- duży **blast radius** albo wielu downstream dependents
- potwierdzające evidence, takie jak findings z **SARIF**, notatki z audytu albo mutation survivors
5. Napisz skoncentrowane harnesses najpierw dla węzłów z najwyższym score, szczególnie **parsers/codecs** takich jak decodery hex/Base64/IP/message.

### Mutation survivors: equivalent vs actionable

Mutation testing często generuje hałaśliwą listę survivors. Zanim uznasz każdego survivora za lukę security, użyj grafu i zapytaj:

- Czy zmutowana funkcja jest osiągalna z attacker-controlled entrypoint?
- Czy wszystkie ścieżki wywołań są ograniczone przez silniejsze invariants niż zmutowany check?
- Czy węzeł znajduje się w dead code, w logice tylko do formatowania, czy w ścieżce arytmetycznej/parserowej o wysokim wpływie?

Survivors, które pozostają nieosiągalne albo są strukturalnie ograniczone, są często **equivalent mutants**. Survivors, które pozostają **reachable** i dotykają **boundary conditions**, **overflow/carry paths** albo **security-critical arithmetic/parsing**, powinny zostać awansowane do:

- nowych fuzz harnesses
- bezpośrednich testów właściwości/invariantów
- ukierunkowanych wektorów edge-case

### Skoreluj zewnętrzne findings na grafie

Jeśli Twój pipeline SAST eksportuje **SARIF**, nanieś findings na węzły grafu przez **file + line range** i użyj grafu do rozszerzenia wpływu:

- oblicz **blast radius** wskazanej funkcji
- sprawdź, czy finding leży na jakiejkolwiek ścieżce od entrypoint
- zgrupuj pobliskie findings, które zapadają się w ten sam choke point

Jest to użyteczne przy decyzji, czy poświęcić czas fuzzingu na konkretną funkcję: węzeł, który jest **reachable**, **complex** i już ma **SAST hits**, często jest lepszym celem niż tylko złożony węzeł bez ścieżki atakującego.

Przykładowy workflow z Trailmark:
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
Ważną metodologią jest przecięcie: **complexity x exposure x impact**. Użyj wykresu, aby wybierać cele fuzzingowe o najwyższej oczekiwanej wartości bezpieczeństwa, a następnie wykorzystaj mutation survivors, aby zdecydować, które granice i invariants Twój harness musi stresować.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką upgrade jest uruchomienie tego samego harnessu z [gosentry](https://github.com/trailofbits/gosentry), forkiem toolchaina Go, który zachowuje `go test -fuzz`, ale podmienia backend na **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **hard comparisons**, **typed inputs** albo formatach z dużą ilością logiki parsera. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` dla seedów i `f.Fuzz(...)` dla callbacku.
- Ponownie użyj tego samego harness, ale uruchom go z binarnym `go` od gosentry zamiast stock toolchain.
- Traktuj wynikową kampanię jak zwykły coverage-guided run, ale z LibAFL scheduling/mutation i lepszymi detectorami wokół.

### Zamień ciche failures w fuzz findings

Powtarzającym się problemem w ocenach Go jest to, że niebezpieczne zachowanie często domyślnie nie powoduje **crash**. Z gosentry możesz zamienić kilka klas „złych, ale cichych” stanów w findings:

- `--panic-on=pkg.Func,...` aby wybrane ścieżki logging/error zachowywały się jak crash (przydatne dla kodu w stylu `log.Fatal`, który inaczej tylko loguje i kontynuuje).
- `--catch-races=true` aby odtwarzać nowo odkryte wpisy kolejki z Go race detector.
- `--catch-leaks=true` aby odtwarzać nowe wpisy kolejki z `goleak` i zatrzymywać się na goroutine leaks.
- Obsługa hang przez LibAFL, aby trzymać **infinite loops / very slow inputs** jako fuzz findings zamiast pozwalać im znikać jako timeouts.
- Wbudowane sprawdzanie overflow arytmetycznego domyślnie, plus opcjonalne sprawdzanie truncation przez instrumentację w stylu go-panikint.

Jest to szczególnie wartościowe dla celów, w których wpływ na bezpieczeństwo to **panicless parser failure**, **concurrency bug** albo tylko **DoS-only hang**, a nie memory corruption.

### Struct-aware fuzzing dla typed Go APIs

Natywne fuzzing Go głównie oczekuje scalarów, takich jak `[]byte`, `string` i liczby. Jeśli kod pod testem przyjmuje typed objects, gosentry może fuzzować **composite values** bezpośrednio (structs, slices, arrays, pointers), nadal mutując bytes pod spodem.
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
Używaj tego podczas budowania fałszywego formatu wire tylko do fuzzingu, ponieważ ukryje błędy logiki za kodem parsowania tylko dla harness. W kampaniach różnicowych lub opartych na gramatyce trzymaj wejście harness jako pojedyncze `[]byte` lub `string` i parsuj wewnątrz callbacka.

### Fuzzing oparty na gramatyce dla parserów i wejść protokołów

Dla parserów, formatów i języków wejściowych, gosentry może uruchamiać **Nautilus grammar fuzzing** na bazie LibAFL. Gramatyka to tablica JSON reguł produkcji, a harness zwykle powinien przyjmować pojedynczy argument `[]byte` lub `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Uwagi metodologiczne:

- Użyj trybu grammar, gdy mutacje na poziomie bajtów głównie giną na wczesnych sprawdzeniach składni.
- Utrzymuj grammar skupioną na **podzbiorze istotnym z punktu widzenia bezpieczeństwa** języka/protokołu, zamiast modelować pełną specyfikację.
- Używaj dużych wartości brzegowych w terminalach/nonterminalach, aby obciążać granice integer, length i machine state.
- Tryb grammar utrzymuje inputs zgodne z grammar, ale target nadal otrzymuje **bytes/strings**, więc parsowanie i sprawdzenia semantyczne pozostają wewnątrz code poddawanego harness.

### Differential fuzzing: compare implementations, not just crashes

Silnym wzorcem dla ekosystemów Go jest **grammar-based differential fuzzing**: generuj poprawne, ustrukturyzowane inputs i podawaj je dwóm parserom, clients, albo state-transition engines.
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
Traktuj następujące jako findings:

- jedna implementacja panikuje, podczas gdy druga odrzuca poprawnie
- niedopasowania accepted/rejected input
- różne parse trees lub zdekodowane obiekty
- rozbieżne przejścia stanu, nonces, balances lub state roots

To praktyczny sposób na znalezienie **consensus mismatches**, **parser ambiguity** i **spec-vs-implementation drift**, które czyste crash fuzzing często pomija.

### Ponownie użyj corpus kampanii do raportowania coverage

Po kampanii odtwórz zapisany queue corpus, aby wygenerować raport Go coverage bez ręcznego eksportowania osobnego corpus:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Uruchom polecenie z **tego samego package** i z tym samym celem `-fuzz`, aby gosentry odnalazł właściwy zapisany stan kampanii.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
