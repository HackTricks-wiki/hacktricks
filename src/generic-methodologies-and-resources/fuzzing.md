# Metodologija Fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

U **mutational grammar fuzzing-u**, ulazi se mutiraju dok ostaju **gramar-validni**. U coverage-guided režimu, čuvaju se samo uzorci koji pokreću **novi coverage** kao corpus seeds. Za **language targets** (parsers, interpreters, engines), ovo može da propusti greške koje zahtevaju **semantic/dataflow chains** gde izlaz jedne konstrukcije postaje ulaz druge.

**Failure mode:** fuzzer pronalazi seeds koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva chained dataflow**, pa se uzorak “bliži-bugu” odbacuje jer ne dodaje coverage. Sa **3+ dependent steps**, nasumično recombination postaje skupo, a coverage feedback ne usmerava pretragu.

**Implication:** za gramatike sa mnogo zavisnosti, razmotrite **hybridizing mutational and generative phases** ili pristrasno generisanje ka obrascima **function chaining** (ne samo coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation je **greedy**: uzorak sa novim coverage-om se odmah čuva, često zadržavajući velike neizmenjene regione. Vremenom, corpora postaju **near-duplicates** sa niskom strukturnom raznolikošću. Agresivna minimization može ukloniti koristan kontekst, pa je praktičan kompromis **grammar-aware minimization** koja **staje nakon minimum token threshold-a** (smanjiti noise uz zadržavanje dovoljno okolne strukture da ostane pogodna za mutation).

Praktično pravilo za corpus kod mutational fuzzing-a je: **preferirajte mali skup strukturno različitih seeds-a koji maksimizuju coverage** umesto velike gomile near-duplicates. U praksi, to obično znači:

- Krenite od **real-world samples** (public corpora, crawling, captured traffic, file sets iz target ekosistema).
- Distilirajte ih pomoću **coverage-based corpus minimization** umesto da čuvate svaki validan uzorak.
- Držite seeds dovoljno **male** da mutations pogađaju značajna polja, umesto da većinu ciklusa troše na irelevantne bajtove.
- Ponovo pokrenite corpus minimization nakon većih harness/instrumentation promena, jer se “najbolji” corpus menja kada se promeni reachability.

## Comparison-Aware Mutation For Magic Values

Čest razlog zašto fuzzers plateau nije syntax već **hard comparisons**: magic bytes, length checks, enum strings, checksums, ili parser dispatch values zaštićene pomoću `memcmp`, switch tables, ili cascaded comparisons. Čista nasumična mutation troši cikluse pokušavajući da pogodi ove vrednosti bajt-po-bajt.

Za ove ciljeve, koristite **comparison tracing** (na primer AFL++ `CMPLOG` / Redqueen-style workflows) tako da fuzzer može da posmatra operande iz neuspelih poređenja i pristrasno menja vrednosti ka onima koje ih zadovoljavaju.
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
**Praktične napomene:**

- Ovo je posebno korisno kada meta skriva duboku logiku iza **file signatures**, **protocol verbs**, **type tags**, ili **version-dependent feature bits**.
- Upari to sa **dictionaries** izdvojenim iz stvarnih uzoraka, protocol spec-ova, ili debug logova. Mala dictionary sa grammar tokenima, chunk imenima, verbovima i delimiterima je često vrednija od ogromne generičke wordlist.
- Ako meta radi mnogo sekvencijalnih provera, prvo reši najranija “magic” poređenja, a zatim ponovo minimizuj dobijeni corpus tako da kasnije faze startuju od već važećih prefiksa.

## Stateful Fuzzing: Sequences Are Seeds

Za **protocols**, **authenticated workflows**, i **multi-stage parsers**, zanimljiva jedinica često nije jedan blob, već **message sequence**. Spajanje celog transcript-a u jedan fajl i njegovo slepo mutiranje obično je neefikasno, jer fuzzer jednako mutira svaki korak, čak i kada samo kasnija poruka dostiže krhko stanje.

Efikasniji pristup je da se **sekvenca sama tretira kao seed** i da se kao dodatni feedback koriste **observable state** (response codes, protocol states, parser phases, returned object types):

- Zadrži **valid prefix messages** stabilnim i fokusiraj mutacije na poruku koja pokreće **transition**.
- Keširaj identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada naredni korak zavisi od njih.
- Preferiraj mutiranje/spajanje po poruci umesto mutiranja celog serializovanog transcript-a kao neprozirnog bloba.
- Ako protocol izlaže smislen response codes, koristi ih kao **cheap state oracle** da prioritet daš sekvencama koje napreduju dublje.

To je isti razlog zašto se authenticated bugs, skrivene tranzicije, ili parser bugovi koji se javljaju “samo posle handshake-a” često propuštaju kod običnog file-style fuzzing-a: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.

## Single-Machine Diversity Trick (Jackalope-Style)

Praktičan način da se hibridizuju **generative novelty** i **coverage reuse** je da se **restartuju kratkotrajni worker-i** nad persistent serverom. Svaki worker kreće sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi nad kombinovanim corpus-om, ponovo se sinhronizuje, pa izlazi. To daje **fresh structures each generation** uz istovremeno korišćenje akumuliranog coverage-a.

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

- `-in empty` forsira **svaki put novu korpus** pri svakoj generaciji.
- `-server_update_interval T` aproksimira **odloženu sinhronizaciju** (novitet prvo, ponovno korišćenje kasnije).
- U grammar fuzzing režimu, **početna server sinhronizacija se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalni `T` je **zavisan od targeta**; prelazak nakon što worker pronađe većinu “lakog” coverage obično radi najbolje.

## Snapshot Fuzzing Za Teške Targete Za Hookovanje

Kada kod koji želite da testirate postaje dostupan tek **nakon velikog setup troška** (podizanje VM, završavanje logina, prijem paketa, parsiranje containera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**:

1. Pokrenite target dok zanimljivo stanje ne bude spremno.
2. Napravite snapshot **memorije + registara** u tom trenutku.
3. Za svaki test case, upišite mutirani input direktno u odgovarajući guest/process buffer.
4. Izvršavajte do crash/timeout/reset.
5. Vratite samo **dirty pages** i ponovite.

Ovo izbegava plaćanje punog setup troška pri svakoj iteraciji i posebno je korisno za **network services**, **firmware**, **post-auth attack surfaces**, i **binary-only targets** koje je teško refaktorisati u klasičan in-process harness.

Praktičan trik je da odmah prekinete nakon `recv`/`read`/packet-deserialization tačke, zabeležite adresu input buffera, napravite snapshot tamo, a zatim mutirate taj buffer direktno u svakoj iteraciji. Ovo vam omogućava da fuzzingujete duboku parsing logiku bez ponovnog građenja celog handshake-a svaki put.

## Harness Introspection: Pronađite Plitke Fuzzer-e Rano

Kada kampanja stane, problem često nije mutator već **harness**. Koristite **reachability/coverage introspection** da pronađete funkcije koje su statički dostupne iz vašeg fuzz targeta, ali su dinamički retko ili nikad pokrivene. Te funkcije obično ukazuju na jedan od tri problema:

- Harness ulazi u target prekasno ili prerano.
- Seed corpusu nedostaje cela familija funkcija.
- Targetu je zaista potreban **drugi harness** umesto jednog prevelikog “do everything” harness-a.

Ako koristite OSS-Fuzz / ClusterFuzz-style workflow, Fuzz Introspector je koristan za ovu trijažu:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Koristite izveštaj da odlučite da li treba dodati novi harness za netestiranu parser putanju, proširiti corpus za određenu funkciju, ili podeliti monolitni harness na manje entry point-ove.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
