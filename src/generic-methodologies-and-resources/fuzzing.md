# Fuzzing Metodologija

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

U **mutational grammar fuzzing**, ulazi se menjaju dok ostaju **grammar-valid**. U coverage-guided režimu, čuvaju se samo uzorci koji aktiviraju **new coverage** kao corpus seeds. Za **language targets** (parsers, interpreters, engines), ovo može da propusti bugove koji zahtevaju **semantic/dataflow chains** gde izlaz jedne konstrukcije postaje ulaz druge.

**Failure mode:** fuzzer pronalazi seeds koji pojedinačno koriste `document()` i `generate-id()` (ili slične primitive), ali **ne čuva povezani dataflow**, pa se sample bliži bugu odbacuje jer ne dodaje coverage. Sa **3+ dependent steps**, nasumično recombination postaje skupo i coverage feedback ne usmerava pretragu.

**Implikacija:** za grammars sa mnogo zavisnosti, razmotrite **hybridizing mutational and generative phases** ili pristrasivanje generisanja ka obrascima **function chaining** (ne samo coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation je **greedy**: sample sa new-coverage se odmah čuva, često uz zadržavanje velikih nepromenjenih regiona. Vremenom, corpora postaju **near-duplicates** sa niskom strukturnom raznolikošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **grammar-aware minimization** koja **staje nakon minimalnog token threshold-a** (smanjiti noise, ali zadržati dovoljno okolne strukture da ostane pogodna za mutacije).

Praktično pravilo za corpus kod mutational fuzzing je: **preferirajte mali skup strukturno različitih seeds koji maksimizuju coverage** umesto velike gomile near-duplicates. U praksi, to obično znači:

- Počnite od **real-world samples** (public corpora, crawling, captured traffic, file sets iz target ecosystem).
- Destilujte ih pomoću **coverage-based corpus minimization** umesto da čuvate svaki validan sample.
- Držite seeds dovoljno **male** da mutacije padaju na značajna polja, a ne da većinu ciklusa troše na nebitne bajtove.
- Ponovo pokrenite corpus minimization posle većih harness/instrumentation promena, jer se “najbolji” corpus menja kada se promeni reachability.

## Comparison-Aware Mutation For Magic Values

Uobičajen razlog zašto fuzzer zastane nije sintaksa već **hard comparisons**: magic bytes, length checks, enum strings, checksums, ili parser dispatch values zaštićeni `memcmp`, switch tabelama ili kaskadnim poređenjima. Čista nasumična mutacija troši cikluse pokušavajući da pogodi te vrednosti bajt po bajt.

Za ove ciljeve koristite **comparison tracing** (na primer AFL++ `CMPLOG` / Redqueen-style workflows) tako da fuzzer može da posmatra operande iz neuspelih poređenja i pristrasi mutacije ka vrednostima koje ih zadovoljavaju.
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

- Ovo je posebno korisno kada cilj skriva duboku logiku iza **file signatures**, **protocol verbs**, **type tags**, ili **version-dependent feature bits**.
- Uparite to sa **dictionaries** izdvojenim iz stvarnih uzoraka, protocol specs, ili debug logs. Mala dictionary sa grammar tokens, chunk names, verbs, i delimiters je često vrednija od ogromne generičke wordlist.
- Ako cilj izvršava mnogo sekvencijalnih provera, prvo rešite najranija “magic” poređenja, a zatim ponovo minimizujte dobijeni corpus tako da kasnije faze krenu od već važećih prefiksa.

## Stateful Fuzzing: Sekvence su Seeds

Za **protocols**, **authenticated workflows**, i **multi-stage parsers**, zanimljiva jedinica često nije jedan blob već **message sequence**. Spajanje celog transcript-a u jedan fajl i njegovo nasumično menjanje je obično neefikasno zato što fuzzer podjednako menja svaki korak, čak i kada samo kasnija poruka dostiže krhko stanje.

Efikasniji obrazac je da se **sekvenca sama tretira kao seed** i da se **observable state** (response codes, protocol states, parser phases, returned object types) koristi kao dodatna povratna informacija:

- Zadržite **valid prefix messages** stabilnim i fokusirajte promene na poruku koja pokreće **transition**.
- Keširajte identifikatore i vrednosti koje generiše server iz ranijih odgovora kada naredni korak zavisi od njih.
- Dajte prednost mutaciji/spajanju po poruci umesto mutiranja celog serijalizovanog transcript-a kao neprozirnog bloba.
- Ako protocol izlaže smislenе response codes, koristite ih kao **jeftin state oracle** da biste prioritet dali sekvencama koje napreduju dublje.

To je isti razlog zbog kog se authenticated bugs, skrivene transitions, ili parser bugs “samo-posle-handshake” često propuštaju običnim file-style fuzzing-om: fuzzer mora da očuva **redosled, stanje, i zavisnosti**, a ne samo strukturu.

## Trik sa raznolikošću na jednoj mašini (Jackalope-Style)

Praktičan način da se hibridizuju **generative novelty** i **coverage reuse** jeste da se **restartuju kratkotrajni workers** prema persistent serveru. Svaki worker kreće od praznog corpus-a, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi nad kombinovanim corpus-om, ponovo se sinhronizuje, a zatim izlazi. Ovo daje **sveže strukture pri svakoj generaciji** dok i dalje koristi akumuliranu coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni radnici (primer petlje):**

<details>
<summary>Jackalope worker restart petlja</summary>
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

- `-in empty` forsira **fresh corpus** pri svakoj generaciji.
- `-server_update_interval T` aproksimira **delayed sync** (novelty first, reuse later).
- U grammar fuzzing režimu, **initial server sync se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalni `T` je **zavisan od target-a**; prebacivanje nakon što worker pronađe većinu “easy” coverage obično radi najbolje.

## Snapshot Fuzzing Za Teške Za Harnessovanje Target-e

Kada kod koji želite da testirate postaje dostupan tek **nakon velikog setup troška** (bootovanje VM-a, završavanje login-a, primanje paketa, parsiranje kontejnera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**:

1. Pokrenite target dok interesantno stanje ne bude spremno.
2. Napravite snapshot **memory + registers** u tom trenutku.
3. Za svaki test case, upišite mutirani input direktno u odgovarajući guest/process buffer.
4. Izvršavajte do crash/timeout/reset.
5. Vratite samo **dirty pages** i ponovite.

Ovo izbegava plaćanje punog setup troška pri svakoj iteraciji i posebno je korisno za **network services**, **firmware**, **post-auth attack surfaces**, i **binary-only targets** koje je teško refaktorisati u klasični in-process harness.

Praktičan trik je da se odmah prekine nakon `recv`/`read`/packet-deserialization tačke, zabeleži adresa input buffera, napravi snapshot tu, a zatim da se taj buffer direktno mutira u svakoj iteraciji. Ovo vam omogućava da fuzzing-ujete duboku parsing logiku bez ponovnog građenja celog handshake-a svaki put.

## Harness Introspection: Pronađite Shallow Fuzzers Rano

Kada campaign zastane, problem često nije mutator već **harness**. Koristite **reachability/coverage introspection** da pronađete funkcije koje su statički dostižne iz vašeg fuzz target-a, ali retko ili nikad dinamički pokrivene. Te funkcije obično ukazuju na jedan od tri problema:

- Harness ulazi u target prekasno ili prerano.
- Seed corpus nema celu porodicu feature-a.
- Targetu stvarno treba **second harness** umesto jednog prevelikog “do everything” harness-a.

Ako koristite OSS-Fuzz / ClusterFuzz-style workflow-e, Fuzz Introspector je koristan za ovu trijažu:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

Ako već imate **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nemojte ih tretirati kao nezavisne liste. Prvo napravite **call graph**, anotirajte čvorove sa **cyclomatic complexity**, **entrypoint/untrusted-input reachability** i bilo kojim spoljnim nalazima, pa onda postavite graf pitanja:

- Koje funkcije visoke kompleksnosti su dostupne iz untrusted input?
- Koji mutation survivors se nalaze na putanjama od parsera/handlera do security-critical koda?
- Koje funkcije su arhitekturne choke point tačke sa neobično visokim **blast radius**?

Ovo obično otkriva bolje fuzz targete nego samo "najniža coverage". Parser/decoder sa **visokom kompleksnošću** i potvrđenom **external reachability** je jači kandidat za harness nego izolovani interni helper sa slabom coverage, ali bez attacker-controlled puta.

### Practical triage workflow

1. Napravite **code graph** iz codebase-a i izdvojite metrics za kompleksnost/grananje po funkciji.
2. Nabrojite **entrypoints** koji prihvataju attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Pokrenite **path queries** od tih entrypoints do kandidat funkcija da biste odvojili reachable attack surface od dead/internal-only koda.
4. Prioritizujte čvorove koji kombinuju:
- visoku **cyclomatic complexity**
- potvrđenu **reachability from untrusted input**
- visok **blast radius** ili mnogo downstream dependents
- potvrđene dokaze kao što su **SARIF** findings, audit notes ili mutation survivors
5. Pišite fokusirane harnesses za najbolje ocenjene čvorove prve, posebno **parsers/codecs** kao što su hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing često proizvodi bučnu listu survivors. Pre nego što svakog survivora tretirate kao security gap, koristite graf da biste pitali:

- Da li je mutirana funkcija dostupna iz attacker-controlled entrypoint?
- Da li su sve call paths ograničene jačim invariantima nego što je mutirana provera?
- Da li se čvor nalazi u dead code, formatting-only logici ili u visokoučinkovitoj arithmetic/parser putanji?

Survivors koji ostaju unreachable ili su strukturno ograničeni često su **equivalent mutants**. Survivors koji ostaju **reachable** i dodiruju **boundary conditions**, **overflow/carry paths** ili **security-critical arithmetic/parsing** treba da se promovišu u:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Ako vaš SAST pipeline izvozi **SARIF**, projicirajte findings na graf čvorove po **file + line range** i koristite graf da proširite uticaj:

- izračunajte **blast radius** označene funkcije
- proverite da li je nalaz na bilo kojoj putanji od entrypoint-a
- grupišite bliske nalaze koji se slivaju u isti choke point

Ovo je korisno kada odlučujete da li da potrošite fuzzing vreme na određenu funkciju: čvor koji je **reachable**, **complex**, i već ima **SAST hits** je često bolji target nego samo kompleksan čvor bez attacker puta.

Example workflow with Trailmark:
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
Važna metodologija je presek: **kompleksnost x izloženost x uticaj**. Koristi graf da izabereš fuzz ciljeve sa najvećom očekivanom bezbednosnom vrednošću, a zatim koristi mutacione preživele da odlučiš koje granice i invariants tvoj harness mora da stresira.

## Go Fuzzing With gosentry: Jači engine, Typed Inputs, I Differential Checks

Ako Go target već ima native `testing.F` harness, praktičan put nadogradnje je da se isti harness pokrene sa [gosentry](https://github.com/trailofbits/gosentry), forkovanim Go toolchain-om koji zadržava `go test -fuzz` ali menja backend na **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Ovo je korisno kada native Go fuzzer zastane na **hard comparisons**, **typed inputs** ili formatima sa mnogo parser logike. Metodologija ostaje ista:

- Nastavi da koristiš `f.Add(...)` za seeds i `f.Fuzz(...)` za callback.
- Ponovo koristi isti harness, ali ga pokreni sa gosentry `go` binary umesto standardnog toolchain-a.
- Tretiraj dobijenu kampanju kao normalan coverage-guided run, ali sa LibAFL scheduling/mutation i boljim okolnim detector-ima.

### Pretvori tihe failure-e u fuzz findings

Ponavljajući problem u Go procenama je to što opasno ponašanje često ne dovodi do crash-a po default-u. Sa gosentry, možeš nekoliko klasa “loših ali tihih” stanja da pretvoriš u findings:

- `--panic-on=pkg.Func,...` da izabrani logging/error path-ovi ponašaju se kao crash-evi (korisno za `log.Fatal`-style code path-ove koji bi inače samo logovali i nastavili).
- `--catch-races=true` da ponovo izvrši newly discovered queue entries sa Go race detector-om.
- `--catch-leaks=true` da ponovo izvrši nove queue entries sa `goleak` i zaustavi se na goroutine leak-ovima.
- LibAFL hang handling da zadrži **infinite loops / very slow inputs** kao fuzz findings umesto da nestanu kao timeout-i.
- Ugrađene arithmetic overflow provere po default-u, plus opciono truncation provere kroz go-panikint-style instrumentation.

Ovo je posebno vredno za ciljeve gde je security impact **panicless parser failure**, **concurrency bug**, ili **DoS-only hang**, a ne memory corruption.

### Struct-aware fuzzing za typed Go API-je

Native Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira prima typed objects, gosentry može direktno da fuzz-uje **composite values** (structs, slices, arrays, pointers), dok i dalje mutira bytes ispod toga.
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
Koristite ovo kada gradite fake wire format samo za fuzzing, jer biste time sakrili logičke bugove iza harness-only parsing koda. Za differential ili grammar-based kampanje, umesto toga držite harness input kao jedan `[]byte` ili `string` i parse-ujte unutar callback-a.

### Grammar-based fuzzing za parsers i protocol inputs

Za parsers, formate i input languages, gosentry može da pokrene **Nautilus grammar fuzzing** na vrhu LibAFL. Grammar je JSON array production rules, a harness bi obično trebalo da prima jedan `[]byte` ili `string` argument.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Napomene o metodologiji:

- Koristi grammar mode kada byte-level mutacije uglavnom umiru u ranim syntax proverama.
- Drži grammar fokusiran na **security-relevant subset** jezika/protokola umesto da modeluješ punu specifikaciju.
- Koristi velike boundary vrednosti u terminalima/nonterminalima da opteretiš integer, length i state-machine granice.
- Grammar mode održava inputs grammar-valid, ali target i dalje prima **bytes/strings**, tako da parsing i semantic checks ostaju unutar harnessed koda.

### Differential fuzzing: poredi implementations, ne samo crashes

Jak obrazac za Go ecosystems je **grammar-based differential fuzzing**: generiši valid structured inputs i prosledi ih dvema parsers, clients ili state-transition engines.
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
Tretirajte sledeće kao findings:

- jedna implementacija panic-uje dok druga odbija cleanly
- accepted/rejected input mismatches
- različita parse trees ili dekodirani objects
- divergent state transitions, nonces, balances ili state roots

Ovo je praktičan način da se pronađu **consensus mismatches**, **parser ambiguity** i **spec-vs-implementation drift** koje čisti crash fuzzing često promašuje.

### Ponovo iskoristite campaign corpus za coverage reporting

Nakon campaign, replayujte sačuvani queue corpus da biste generisali Go coverage report bez ručnog exportovanja posebnog corpus-a:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Pokrenite komandu iz **istog package** i sa istim `-fuzz` targetom kako bi gosentry rešio ispravno keširano stanje kampanje.

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
