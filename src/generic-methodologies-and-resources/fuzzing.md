# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

U **mutational grammar fuzzing**, ulazi se mutiraju dok ostaju **grammar-valid**. U coverage-guided režimu, samo uzorci koji pokrenu **new coverage** se čuvaju kao corpus seeds. Za **language targets** (parsers, interpreters, engines), ovo može propustiti greške koje zahtevaju **semantic/dataflow chains** gde izlaz jednog konstrukta postaje ulaz za drugi.

**Mod otkaza:** fuzzer pronađe seed-ove koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva chained dataflow**, pa se uzorak koji je „bliži grešci“ odbaci zato što ne dodaje coverage. Sa **3+ dependent steps**, nasumična rekombinacija postaje skupa i coverage feedback ne usmerava pretragu.

**Implikacija:** za gramatike sa mnogo zavisnosti, razmotrite **hybridizing mutational and generative phases** ili pristrasnost pri generisanju ka šablonima **function chaining** (ne samo coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation je **greedy**: new-coverage uzorak se odmah čuva, često zadržavajući velike nepromenjene regione. Vremenom, corpora postaju **near-duplicates** sa niskom strukturnom raznolikošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **grammar-aware minimization** koja **stops after a minimum token threshold** (smanjuje šum dok zadržava dovoljno okolne strukture da ostane mutation-friendly).

## Single-Machine Diversity Trick (Jackalope-Style)

Praktičan način da se hybridize **generative novelty** sa **coverage reuse** je da **restart short-lived workers** protiv persistent servera. Svaki worker počinje sa praznim corpusom, sync-uje posle `T` sekundi, radi još `T` sekundi na kombinovanom corpus-u, ponovo sync-uje, pa zatim izlazi. Ovo daje **fresh structures each generation** dok i dalje koristi akumulirani coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni workers (primer loop):**

<details>
<summary>Jackalope worker restart loop</summary>
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

**Napomene:**

- `-in empty` primorava na **novi korpus** za svaku generaciju.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo noviteti, kasnije ponovna upotreba).
- In grammar fuzzing mode, **inicijalna sinhronizacija servera se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimal `T` is **target-dependent**; prebacivanje nakon što je worker pronašao većinu “easy” coverage obično daje najbolje rezultate.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
