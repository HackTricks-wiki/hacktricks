# Fuzzing Metodologija

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

U **mutational grammar fuzzing**, inputi se mutiraju dok ostaju **grammar-valid**. U coverage-guided režimu, samo uzorci koji pokrenu **new coverage** se čuvaju kao corpus seeds. Za **language targets** (parsers, interpreters, engines), ovo može propustiti bagove koji zahtevaju **semantic/dataflow chains** gde izlaz jedne konstrukcije postaje ulaz druge.

**Failure mode:** fuzzer pronađe seeds koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva povezani dataflow**, pa se uzorak “bliži bagu” odbacuje jer ne dodaje coverage. Sa **3+ dependent steps**, nasumično recombining postaje skupo i coverage feedback ne vodi pretragu.

**Implication:** za grammar-e sa mnogo zavisnosti, razmotrite **hybridizing mutational and generative phases** ili biasing generisanje ka obrascima **function chaining** (ne samo coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation je **greedy**: uzorak sa novim coverage-om se odmah čuva, često zadržavajući velike neizmenjene regione. Vremenom, corpora postaju **near-duplicates** sa niskom strukturnom raznovrsnošću. Agresivna minimization može ukloniti koristan kontekst, pa je praktičan kompromis **grammar-aware minimization** koja **staje nakon minimum token threshold-a** (smanjiti šum dok se zadržava dovoljno okolne strukture da ostane pogodna za mutaciju).

Praktično pravilo za corpus kod mutational fuzzing-a je: **preferirajte mali skup strukturno različitih seeds koji maksimizuju coverage** umesto velike gomile near-duplicates. U praksi, to obično znači:

- Počnite od **real-world samples** (public corpora, crawling, captured traffic, file sets iz target ekosistema).
- Destilujte ih pomoću **coverage-based corpus minimization** umesto da čuvate svaki valid sample.
- Držite seeds dovoljno **male** da mutacije pogode značajna polja, umesto da većinu ciklusa troše na nebitne bajtove.
- Ponovo pokrenite corpus minimization nakon velikih promena u harness/instrumentation, jer se “najbolji” corpus menja kada se promeni reachability.

## Comparison-Aware Mutation For Magic Values

Čest razlog zašto fuzzers platoiraju nije sintaksa već **hard comparisons**: magic bytes, length checks, enum strings, checksums, ili parser dispatch vrednosti zaštićene pomoću `memcmp`, switch table-ova, ili kaskadnih poređenja. Čista nasumična mutacija troši cikluse pokušavajući da pogodi ove vrednosti bajt po bajt.

Za ove targete, koristite **comparison tracing** (na primer AFL++ `CMPLOG` / Redqueen-style workflows) tako da fuzzer može da posmatra operande iz neuspelih poređenja i usmeri mutacije ka vrednostima koje ih zadovoljavaju.
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
- Kombinujte to sa **dictionaries** izdvojenim iz pravih uzoraka, protocol specs, ili debug logs. Mala dictionary sa grammar tokenima, chunk imenima, verbovima i delimiterima često je vrednija od ogromne generičke wordlist.
- Ako cilj radi mnogo sekvencijalnih provera, prvo rešite najranija “magic” poređenja, a zatim ponovo minimizujte dobijeni corpus tako da kasnije faze počnu od već važećih prefiksa.

## Stateful Fuzzing: Sequences Are Seeds

Za **protocols**, **authenticated workflows**, i **multi-stage parsers**, zanimljiva jedinica često nije jedan blob, već **message sequence**. Spajanje celog transcript-a u jedan file i njegovo slepo mutiranje je obično neefikasno zato što fuzzer podjednako menja svaki korak, čak i kada samo kasnija poruka dostiže osetljivo stanje.

Efikasniji obrazac je da se **sekvenca sama tretira kao seed** i da se koristi **observable state** (response codes, protocol states, parser phases, returned object types) kao dodatni feedback:

- Zadržite **valid prefix messages** stabilnim i fokusirajte mutacije na poruku koja **pokreće prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Preferirajte mutaciju/spajanje po poruci umesto mutiranja celog serijalizovanog transcript-a kao neprozirnog bloba.
- Ako protocol izlaže značajne response codes, koristite ih kao **cheap state oracle** da biste prioritizovali sekvence koje napreduju dublje.

To je isti razlog zbog kog se authenticated bugs, hidden transitions, ili parser bugs tipa “samo-posle-handshake” često promašuju klasičnim file-style fuzzing-om: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.

## Single-Machine Diversity Trick (Jackalope-Style)

Praktičan način da se **generative novelty** poveže sa **coverage reuse** jeste da se **restartuju kratkotrajni worker-i** nad persistent serverom. Svaki worker kreće od praznog corpus-a, sinhronizuje se posle `T` sekundi, radi još `T` sekundi na kombinovanom corpus-u, ponovo se sinhronizuje, pa izlazi. Ovo daje **svake generacije sveže strukture** uz istovremeno korišćenje akumuliranog coverage-a.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni workers (primer loop-a):**

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

- `-in empty` forsira **fresh corpus** pri svakoj generaciji.
- `-server_update_interval T` aproksimira **delayed sync** (novitet prvo, reuse kasnije).
- U grammar fuzzing modu, **početni server sync se preskače podrazumevano** (nema potrebe za `-skip_initial_server_sync`).
- Optimalno `T` je **zavisan od target-a**; menjanje nakon što worker pronađe većinu “easy” coverage obično radi najbolje.

## Snapshot Fuzzing Za Hard-To-Harness Target-e

Kada kod koji želite da testirate postane dostupan tek **nakon velikog setup cost-a** (booting a VM, completing a login, receiving a packet, parsing a container, initializing a service), korisna alternativa je **snapshot fuzzing**:

1. Pokrenite target dok zanimljivo stanje ne bude spremno.
2. Snapshot-ujte **memory + registers** u tom trenutku.
3. Za svaki test case, upišite mutirani input direktno u odgovarajući guest/process buffer.
4. Izvršavajte do crash/timeout/reset.
5. Vratite samo **dirty pages** i ponovite.

Ovo izbegava plaćanje celog setup cost-a pri svakoj iteraciji i posebno je korisno za **network services**, **firmware**, **post-auth attack surfaces**, i **binary-only targets** koje je teško refaktorirati u klasični in-process harness.

Praktičan trik je da se odmah prekine posle `recv`/`read`/packet-deserialization tačke, zabeleži adresa input buffera, snapshot-uje tu, a zatim mutira taj buffer direktno u svakoj iteraciji. To vam omogućava da fuzzujete deep parsing logic bez ponovnog izgrađivanja celog handshake-a svaki put.

## Harness Introspection: Pronađite Shallow Fuzzers Rano

Kada kampanja stane, problem često nije mutator nego **harness**. Koristite **reachability/coverage introspection** da pronađete funkcije koje su statički dostupne iz vašeg fuzz target-a, ali su dinamički retko ili nikad pokrivene. Te funkcije obično ukazuju na jedan od tri problema:

- Harness ulazi u target prekasno ili prerano.
- Seed corpus nema celu family funkcionalnosti.
- Target-u zaista treba **second harness** umesto jednog prevelikog “do everything” harness-a.

Ako koristite OSS-Fuzz / ClusterFuzz-style workflows, Fuzz Introspector je koristan za ovu trijažu:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Koristite izveštaj da odlučite da li da dodate novi harness za neproverenu putanju parsera, proširite corpus za određenu funkciju, ili podelite monolitni harness na manje entry points.

## Izbor fuzz targeta i trijaža mutacija zasnovani na grafu

Ako već imate **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nemojte ih trijažirati kao nezavisne liste. Prvo napravite **call graph**, označite čvorove sa **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, i svim spoljnim nalazima, pa onda postavljajte graf pitanja:

- Koje funkcije velike kompleksnosti su dostižne iz untrusted input?
- Koji mutation survivors se nalaze na putanjama od parsers/handlers do security-critical koda?
- Koje funkcije su arhitektonski choke point-ovi sa neobično velikim **blast radius**?

Ovo obično otkriva bolje fuzz targete nego samo "najniži coverage". Parser/decoder sa **visokom kompleksnošću** i potvrđenom **external reachability** je jači kandidat za harness od izolovanog internog helper-a sa slabim coverage-om, ali bez puta kojim upravlja napadač.

### Praktični workflow za trijažu

1. Izgradite **code graph** iz codebase-a i izdvojite metrike kompleksnosti/grananja po funkciji.
2. Nabrojte **entrypoints** koji prihvataju input kojim upravlja napadač: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Pokrenite **path queries** od tih entrypoints do kandidatskih funkcija da biste odvojili dostižnu attack surface od mrtvog/samo-internog koda.
4. Dajte prioritet čvorovima koji kombinuju:
- visoku **cyclomatic complexity**
- potvrđenu **reachability from untrusted input**
- visok **blast radius** ili mnogo downstream dependents
- potkrepljujuće dokaze kao što su **SARIF** findings, audit notes, ili mutation survivors
5. Napišite fokusirane harness-e za najbolje rangirane čvorove prvo, posebno za **parsers/codecs** kao što su hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing često proizvodi bučnu listu survivors. Pre nego što svakog survivor-a tretirate kao security gap, koristite graf da postavite pitanja:

- Da li je mutirana funkcija dostižna iz attacker-controlled entrypoint-a?
- Da li su sve call path-ove ograničene jačim invariants nego mutirana provera?
- Da li se čvor nalazi u dead code, formatting-only logici, ili u high-impact arithmetic/parser putanji?

Survivors koji ostaju nedostižni ili su strukturno ograničeni su često **equivalent mutants**. Survivors koji ostaju **reachable** i dotiču **boundary conditions**, **overflow/carry paths**, ili **security-critical arithmetic/parsing** treba da budu prebačeni u:

- nove fuzz harness-e
- direktne property/invariant testove
- ciljane edge-case vektore

### Korelacija spoljašnjih nalaza na graf

Ako vaš SAST pipeline izvozi **SARIF**, projicirajte findings na graf čvorove po **file + line range** i koristite graf da proširite uticaj:

- izračunajte **blast radius** označene funkcije
- proverite da li je finding na bilo kojoj putanji od entrypoint-a
- grupišite bliske findings koji se slivaju u isti choke point

Ovo je korisno kada odlučujete da li da potrošite vreme na fuzzing određene funkcije: čvor koji je **reachable**, **complex**, i već ima **SAST hits** je često bolji target nego samo kompleksan čvor bez puta za napadača.

Primer workflow-a sa Trailmark:
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
Važna metodologija je presek: **complexity x exposure x impact**. Koristite graf da izaberete fuzz ciljeve sa najvećom očekivanom sigurnosnom vrednošću, a zatim koristite mutation survivors da odlučite koje granice i invarijante vaš harness mora da optereti.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
