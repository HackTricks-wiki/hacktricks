# Metodologia Fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

W **mutational grammar fuzzing**, wejścia są mutowane, ale pozostają **grammar-valid**. W trybie guided by coverage, tylko próbki, które wywołują **new coverage**, są zapisywane jako corpus seeds. Dla **language targets** (parsers, interpreters, engines) może to pomijać bugs, które wymagają **semantic/dataflow chains**, gdzie output jednego konstruktu staje się inputem kolejnego.

**Failure mode:** fuzzer znajduje seeds, które osobno wykonują `document()` i `generate-id()` (lub podobne primitives), ale **nie zachowuje chained dataflow**, więc próbka „closer-to-bug” jest odrzucana, ponieważ nie dodaje coverage. Przy **3+ dependent steps**, losowe recombination staje się kosztowne, a feedback z coverage nie kieruje search.

**Implication:** dla grammars z ciężkimi dependency, rozważ **hybridizing mutational and generative phases** albo biasing generation w stronę wzorców **function chaining** (nie tylko coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation jest **greedy**: próbka z new coverage jest zapisywana natychmiast, często z zachowaniem dużych niezmienionych regionów. Z czasem corpora stają się **near-duplicates** o niskiej structural diversity. Agresywna minimization może usunąć użyteczny context, więc praktycznym kompromisem jest **grammar-aware minimization**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukcja noise przy zachowaniu wystarczającej struktury otoczenia, by pozostała podatność na mutation).

Praktyczna zasada dla corpus przy mutational fuzzing to: **preferować mały zestaw strukturalnie różnych seeds, które maksymalizują coverage**, zamiast dużego stosu near-duplicates. W praktyce zwykle oznacza to:

- Zacznij od **real-world samples** (public corpora, crawling, captured traffic, zestawy plików z ekosystemu targetu).
- Odfiltruj je przy użyciu **coverage-based corpus minimization** zamiast trzymać każdą poprawną próbkę.
- Trzymaj seeds na tyle **małe**, aby mutacje trafiały w znaczące pola, zamiast marnować większość cykli na nieistotne bajty.
- Uruchamiaj corpus minimization ponownie po większych zmianach harness/instrumentation, ponieważ „najlepsze” corpus zmienia się wraz ze zmianą reachability.

## Comparison-Aware Mutation For Magic Values

Częstym powodem, dla którego fuzzery się plateau, nie jest składnia, lecz **hard comparisons**: magic bytes, length checks, strings enum, checksums lub parser dispatch values chronione przez `memcmp`, switch tables albo cascaded comparisons. Czysta random mutation marnuje cykle, próbując odgadnąć te wartości bajt po bajcie.

Dla takich targetów użyj **comparison tracing** (na przykład workflow AFL++ `CMPLOG` / Redqueen-style), aby fuzzer mógł obserwować operandy z nieudanych comparisons i biasować mutacje w stronę wartości, które je spełniają.
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
- Połącz to z **dictionaries** wyodrębnionymi z prawdziwych próbek, specyfikacji protokołów lub logów debug. Mały dictionary z tokenami gramatyki, nazwami chunków, czasownikami i delimiterami jest często cenniejszy niż ogromny ogólny wordlist.
- Jeśli cel wykonuje wiele sekwencyjnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a potem ponownie zminimalizuj wynikowy corpus, aby późniejsze etapy startowały już z poprawnych prefiksów.

## Stateful Fuzzing: Sequences Are Seeds

W przypadku **protocols**, **authenticated workflows** i **multi-stage parsers**, interesującą jednostką często nie jest pojedynczy blob, lecz **message sequence**. Sklejanie całego transcript do jednego pliku i ślepa mutacja zwykle jest nieefektywna, ponieważ fuzzer mutuje każdy krok równie mocno, nawet gdy tylko późniejsza wiadomość trafia do kruchego stanu.

Skuteczniejszym podejściem jest traktowanie samej **sequence** jako seed i używanie **observable state** (kodów odpowiedzi, stanów protokołu, faz parsera, zwróconych typów obiektów) jako dodatkowego feedback:

- Zachowuj **valid prefix messages** stabilne i skup mutacje na wiadomości **transition-driving**.
- Buforuj identyfikatory i wartości generowane przez serwer z poprzednich odpowiedzi, gdy następny krok od nich zależy.
- Preferuj mutację/splicing per wiadomość zamiast mutowania całego serializowanego transcript jako nieprzejrzystego blob.
- Jeśli protocol udostępnia znaczące response codes, używaj ich jako **cheap state oracle**, aby priorytetyzować sekwencje, które przechodzą głębiej.

To ten sam powód, dla którego bugs wymagające uwierzytelnienia, ukryte przejścia lub błędy parsera typu „only-after-handshake” są często pomijane przez zwykłe fuzzing w stylu file: fuzzer musi zachować **order, state i dependencies**, a nie tylko strukturę.

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem na hybrydowe połączenie **generative novelty** z **coverage reuse** jest **restartowanie krótkotrwałych workerów** przeciwko trwałemu server. Każdy worker startuje z pustym corpus, synchronizuje się po `T` sekundach, działa kolejne `T` sekund na połączonym corpus, synchronizuje się ponownie, a następnie kończy działanie. Daje to **fresh structures each generation** przy jednoczesnym wykorzystaniu zgromadzonego coverage.

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
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowość, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie ma potrzeby używać `-skip_initial_server_sync`).
- Optymalne `T` jest **zależne od targetu**; przełączanie po tym, jak worker znalazł większość „łatwego” coverage, zwykle działa najlepiej.

## Snapshot Fuzzing Dla Trudnych Do Opracowania Targetów

Gdy kod, który chcesz testować, staje się osiągalny dopiero **po dużym koszcie przygotowania** (uruchomienie VM, ukończenie logowania, odebranie pakietu, sparsowanie kontenera, inicjalizacja usługi), użyteczną alternatywą jest **snapshot fuzzing**:

1. Uruchom target do momentu, aż interesujący stan będzie gotowy.
2. Zrób snapshot **pamięci + rejestrów** w tym punkcie.
3. Dla każdego test case zapisz zmodyfikowane wejście bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj do crash/timeout/reset.
5. Przywracaj tylko **dirty pages** i powtarzaj.

Dzięki temu nie płacisz pełnego kosztu przygotowania przy każdej iteracji, co jest szczególnie przydatne dla **network services**, **firmware**, **post-auth attack surfaces** oraz **binary-only targets**, które trudno przerobić na klasyczny in-process harness.

Praktyczny trik polega na tym, aby przerwać natychmiast po punkcie `recv`/`read`/packet-deserialization, zanotować adres bufora wejściowego, zrobić snapshot w tym miejscu, a następnie w każdej iteracji mutować ten bufor bezpośrednio. Pozwala to fuzzować głęboką logikę parsowania bez przebudowywania całego handshake za każdym razem.

## Harness Introspection: Znajdź Płytkie Fuzzers We Wczesnym Etapie

Gdy kampania staje w miejscu, problemem często nie jest mutator, tylko **harness**. Użyj **reachability/coverage introspection**, aby znaleźć funkcje, które są statycznie osiągalne z twojego fuzz target, ale dynamicznie są rzadko lub nigdy nie pokrywane. Takie funkcje zwykle wskazują na jeden z trzech problemów:

- Harness wchodzi do targetu za późno albo za wcześnie.
- Seed corpus nie zawiera całej rodziny funkcji.
- Target naprawdę potrzebuje **drugiego harness** zamiast jednego zbyt dużego harness „do wszystkiego”.

Jeśli używasz workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector jest przydatny do tego triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze punkty wejścia.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
