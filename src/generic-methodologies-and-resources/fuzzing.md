# Metodologia Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

W **mutational grammar fuzzing**, dane wejściowe są mutowane, pozostając **grammar-valid**. W trybie guided by coverage zapisywane są tylko próbki, które wyzwalają **new coverage**, jako ziarna korpusu. Dla **language targets** (parserów, interpreterów, engine’ów) może to pomijać bugi, które wymagają **semantic/dataflow chains**, gdzie wyjście jednego konstruktora staje się wejściem kolejnego.

**Failure mode:** fuzzer znajduje ziarna, które osobno uruchamiają `document()` i `generate-id()` (lub podobne primitive), ale **nie zachowuje połączonego dataflow**, więc próbka „bliższa bugowi” jest odrzucana, bo nie dodaje coverage. Przy **3+ dependent steps** losowe rekombinacje stają się kosztowne, a feedback z coverage nie kieruje wyszukiwaniem.

**Implication:** dla gramatyk silnie zależnych od dependencies rozważ **hybridizing mutational and generative phases** albo ustawianie generacji pod kątem wzorców **function chaining** (a nie tylko coverage).

## Corpus Diversity Pitfalls

Mutation guided by coverage jest **greedy**: próbka z new-coverage jest zapisywana natychmiast, często z zachowaniem dużych niezmienionych fragmentów. Z czasem korpusy stają się **near-duplicates** o niskiej różnorodności strukturalnej. Agresywna minimizacja może usuwać przydatny kontekst, więc praktyczny kompromis to **grammar-aware minimization**, które **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (mniej szumu, ale nadal wystarczająco dużo otaczającej struktury, by mutacje były skuteczne).

Praktyczna zasada dla korpusu przy mutational fuzzing brzmi: **preferuj mały zestaw strukturalnie różnych seedów, które maksymalizują coverage**, zamiast dużej sterty near-duplicates. W praktyce zwykle oznacza to:

- Zacznij od **real-world samples** (public corpora, crawling, captured traffic, zestawy plików z ekosystemu celu).
- Odfiltruj je przez **coverage-based corpus minimization** zamiast trzymać każdą poprawną próbkę.
- Trzymaj seedy **na tyle małe**, by mutacje trafiały w istotne pola, zamiast marnować większość cykli na nieistotne bajty.
- Uruchamiaj ponowną minimizację korpusu po większych zmianach harness/instrumentation, bo „najlepszy” korpus zmienia się wraz ze zmianą reachability.

## Comparison-Aware Mutation For Magic Values

Częstym powodem, dla którego fuzzery plateauują, nie jest składnia, tylko **hard comparisons**: magic bytes, sprawdzanie długości, ciągi enum, checksumy lub wartości dispatch parsera chronione przez `memcmp`, tabele switch albo kaskadowe porównania. Czysto losowa mutacja marnuje cykle, próbując odgadnąć te wartości bajt po bajcie.

Dla takich celów użyj **comparison tracing** (na przykład workflow AFL++ `CMPLOG` / Redqueen-style), aby fuzzer mógł obserwować operandy z nieudanych porównań i kierować mutacje w stronę wartości, które je spełnią.
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

- Jest to szczególnie przydatne, gdy cel ukrywa głęboką logikę za **file signatures**, **protocol verbs**, **type tags** lub **version-dependent feature bits**.
- Połącz to z **dictionaries** wyekstrahowanymi z prawdziwych próbek, specyfikacji protocol lub logów debug. Mały dictionary z tokenami gramatyki, nazwami chunków, verbami i delimiterami jest często cenniejszy niż ogromny generyczny wordlist.
- Jeśli cel wykonuje wiele sekwencyjnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a potem ponownie zminimalizuj wynikowy corpus, aby późniejsze etapy startowały już od wcześniej poprawnych prefiksów.

## Stateful Fuzzing: Sequences Are Seeds

W przypadku **protocols**, **authenticated workflows** i **multi-stage parsers** interesującą jednostką często nie jest pojedynczy blob, lecz **message sequence**. Sklejenie całego transcript do jednego pliku i mutowanie go na oślep zwykle jest nieefektywne, ponieważ fuzzer mutuje każdy krok jednakowo, nawet jeśli tylko późniejsza wiadomość dociera do kruchego stanu.

Bardziej skuteczny wzorzec polega na traktowaniu samej **sequence** jako seed i używaniu **observable state** (response codes, protocol states, parser phases, returned object types) jako dodatkowego feedback:

- Zachowuj **valid prefix messages** stabilne i skup mutacje na wiadomości **transition-driving**.
- Cache identyfikatory i wartości wygenerowane przez server z poprzednich odpowiedzi, gdy następny krok od nich zależy.
- Preferuj mutację/splicing per-message zamiast mutowania całego serializowanego transcript jako nieprzezroczystego blob.
- Jeśli protocol udostępnia znaczące response codes, używaj ich jako **cheap state oracle**, aby priorytetyzować sequence, które przechodzą głębiej.

To ten sam powód, dla którego bugs authenticated, ukryte transitions albo błędy parsera typu „only-after-handshake” są często pomijane przez zwykłe file-style fuzzing: fuzzer musi zachować **order, state i dependencies**, a nie tylko strukturę.

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem na hybrydyzację **generative novelty** z **coverage reuse** jest **restartowanie krótkotrwałych workerów** przeciwko persistent server. Każdy worker startuje z pustym corpus, synchronizuje się po `T` sekundach, działa jeszcze `T` sekund na połączonym corpus, synchronizuje się ponownie, a następnie kończy pracę. Daje to **fresh structures each generation** przy jednoczesnym wykorzystaniu zgromadzonego coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjni workers (przykładowa pętla):**

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
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw novelty, później reuse).
- W trybie grammar fuzzing, początkowa synchronizacja z server jest domyślnie pomijana (nie ma potrzeby używać `-skip_initial_server_sync`).
- Optymalne `T` zależy od **target**; przełączanie po tym, jak worker znajdzie większość „łatwego” coverage, zwykle działa najlepiej.

## Snapshot Fuzzing For Hard-To-Harness Targets

Gdy kod, który chcesz testować, staje się osiągalny dopiero **po dużym koszcie setupu** (uruchomienie VM, dokończenie login, odebranie pakietu, parsowanie kontenera, inicjalizacja service), przydatną alternatywą jest **snapshot fuzzing**:

1. Uruchom target aż interesujący stan będzie gotowy.
2. Zrób snapshot **pamięci + rejestrów** w tym punkcie.
3. Dla każdego test case zapisz zmodyfikowany input bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj aż do crash/timeout/reset.
5. Przywróć tylko **dirty pages** i powtórz.

To pozwala uniknąć pełnego kosztu setupu przy każdej iteracji i jest szczególnie użyteczne dla **network services**, **firmware**, **post-auth attack surfaces** oraz **binary-only targets**, które trudno przerobić na klasyczny in-process harness.

Praktyczny trik: zatrzymaj się natychmiast po punkcie `recv`/`read`/packet-deserialization, zanotuj adres bufora input, zrób tam snapshot, a potem mutuj ten bufor bezpośrednio w każdej iteracji. Dzięki temu możesz fuzzować głęboką logikę parsowania bez przebudowywania całego handshake za każdym razem.

## Harness Introspection: Find Shallow Fuzzers Early

Gdy kampania staje w miejscu, problemem często nie jest mutator, tylko **harness**. Użyj **reachability/coverage introspection**, aby znaleźć funkcje, które są statycznie osiągalne z twojego fuzz target, ale dynamicznie są rzadko lub nigdy nie pokrywane. Takie funkcje zwykle wskazują na jeden z trzech problemów:

- Harness wchodzi do target za późno albo za wcześnie.
- Seed corpus nie zawiera całej rodziny funkcji.
- Target naprawdę potrzebuje **second harness** zamiast jednego przeładowanego harness „do wszystkiego”.

Jeśli używasz workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector jest przydatny do takiego triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Wybór celu fuzzingu i triage mutacji na podstawie grafu

Jeśli masz już **wyniki analizy statycznej**, **survivors z mutation testing** i **raporty pokrycia**, nie triage’uj ich jako niezależnych list. Najpierw zbuduj **call graph**, opisz węzły za pomocą **cyclomatic complexity**, **reachability z entrypoint/untrusted-input** oraz wszelkich zewnętrznych wyników, a potem zadaj pytania grafowe:

- Które funkcje o wysokiej złożoności są osiągalne z untrusted input?
- Które mutation survivors znajdują się na ścieżkach od parserów/handlerów do security-critical code?
- Które funkcje są architektonicznymi chokepoints o nietypowo dużym **blast radius**?

To zwykle ujawnia lepsze cele fuzzingowe niż samo „najniższe coverage”. Parser/decoder o **wysokiej złożoności** i potwierdzonej **reachability z zewnętrznego wejścia** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper ze słabym coverage, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny workflow triage

1. Zbuduj **code graph** z codebase i wyodrębnij metryki złożoności/gałęzi dla każdej funkcji.
2. Wylicz **entrypoints**, które przyjmują wejście kontrolowane przez atakującego: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Uruchom zapytania o **path** z tych entrypoints do funkcji-kandydatów, aby oddzielić reachable attack surface od martwego/kod tylko wewnętrznego.
4. Nadaj priorytet węzłom, które łączą:
- wysoką **cyclomatic complexity**
- potwierdzoną **reachability z untrusted input**
- wysoki **blast radius** lub wielu zależnych downstream
- potwierdzające dowody, takie jak wyniki **SARIF**, notatki z audytu lub mutation survivors
5. Najpierw pisz skoncentrowane harnesses dla najlepiej ocenionych węzłów, zwłaszcza **parsers/codecs** takich jak hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing często generuje szumową listę survivors. Zanim potraktujesz każdego survivora jako lukę bezpieczeństwa, użyj grafu, aby zadać pytania:

- Czy zmodyfikowana funkcja jest osiągalna z entrypoint kontrolowanego przez atakującego?
- Czy wszystkie call paths są ograniczone przez silniejsze invariants niż zmodyfikowany check?
- Czy węzeł znajduje się w dead code, w logice tylko do formatowania, czy w ścieżce o wysokim wpływie, związanej z arytmetyką/parserem?

Survivors, które nadal są unreachable albo są strukturalnie ograniczone, to często **equivalent mutants**. Survivors, które pozostają **reachable** i dotykają **boundary conditions**, **overflow/carry paths** lub **security-critical arithmetic/parsing**, powinny zostać promowane do:

- nowych fuzz harnesses
- bezpośrednich testów property/invariant
- ukierunkowanych wektorów edge-case

### Koreluj zewnętrzne wyniki na grafie

Jeśli twój pipeline SAST eksportuje **SARIF**, nanieś wyniki na węzły grafu po **plik + zakres linii** i użyj grafu do oszacowania wpływu:

- oblicz **blast radius** flagowanej funkcji
- sprawdź, czy wynik leży na jakiejkolwiek ścieżce z entrypoint
- zgrupuj pobliskie wyniki, które zapadają się w ten sam chokepoint

To jest przydatne przy decyzji, czy poświęcić czas fuzzingowy na konkretną funkcję: węzeł, który jest **reachable**, **complex** i już ma **SAST hits**, często jest lepszym celem niż po prostu złożony węzeł bez ścieżki atakującego.

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
Ważna metodologia to przecięcie: **complexity x exposure x impact**. Użyj grafu, aby wybierać cele fuzzingowe o najwyższej oczekiwanej wartości bezpieczeństwa, a następnie użyj mutational survivors, aby zdecydować, które granice i invariants musi stresować Twój harness.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
