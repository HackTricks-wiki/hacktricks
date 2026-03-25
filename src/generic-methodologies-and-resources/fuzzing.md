# Metodologia Fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Pokrycie vs. Semantyka

W **mutational grammar fuzzing** wejścia są modyfikowane przy zachowaniu zgodności z gramatyką (**grammar-valid**). W trybie **coverage-guided** zapisywane jako corpus seeds są tylko próbki, które wywołują nowe **coverage**. Dla **language targets** (parsers, interpreters, engines) może to przegapić błędy wymagające łańcuchów semantycznych/dataflow, gdzie wyjście jednej konstrukcji staje się wejściem innej.

**Tryb awarii:** fuzzer znajduje seeds, które pojedynczo ćwiczą `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje złączonego dataflow**, więc próbka „bliższa błędu” jest odrzucana, ponieważ nie dodaje coverage. Przy **3+ dependent steps** losowa rekombinacja staje się kosztowna, a feedback z coverage nie kieruje poszukiwaniem.

**Implikacja:** dla gramatyk z dużą liczbą zależności rozważ hybrydyzację faz mutational i generative lub uprzedzenie generacji w kierunku wzorców function chaining (nie tylko coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation jest **zachłanna**: próbka dająca new coverage jest zapisywana natychmiast, często zachowując duże niezmienione regiony. Z czasem korpusy stają się **near-duplicates** o niskiej różnorodności strukturalnej. Agresywna minimization może usunąć użyteczny kontekst, więc praktycznym kompromisem jest **grammar-aware minimization**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukuje szum przy jednoczesnym zachowaniu wystarczającej otaczającej struktury, by pozostać przyjazną dla mutacji).

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem na hybrydyzację **generative novelty** z **coverage reuse** jest restartowanie krótkotrwałych workerów przeciwko persistent server. Każdy worker startuje z pustym corpus, synchronizuje się po `T` sekundach, działa kolejne `T` sekund na połączonym korpusie, synchronizuje się ponownie, a następnie kończy. To daje **świeże struktury przy każdej generacji** przy jednoczesnym wykorzystaniu zgromadzonego coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjni workerzy (przykładowa pętla):**

<details>
<summary>Pętla restartu workera Jackalope</summary>
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

- `-in empty` wymusza **świeży korpus** przy każdej generacji.
- `-server_update_interval T` symuluje **opóźnioną synchronizację** (najpierw nowość, później ponowne użycie).
- W trybie grammar fuzzing, **initial server sync jest domyślnie pomijany** (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalne `T` jest **target-dependent**; przełączanie po tym, jak worker znalazł większość “easy” coverage, zwykle działa najlepiej.

## Źródła

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
