# Metodologija fuzzing-a

## Mutational Grammar Fuzzing: Coverage naspram semantike

U **mutational grammar fuzzing-u**, ulazi se mutiraju uz zadržavanje **grammar-valid** svojstava. U coverage-guided režimu, samo uzorci koji pokrenu **novi coverage** čuvaju se kao corpus seeds. Kod **language target-a** (parsera, interpretera, engine-a), ovim se mogu propustiti bugovi koji zahtevaju **semantic/dataflow lance**, gde izlaz jedne konstrukcije postaje ulaz druge.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer pronalazi seed-ove koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani dataflow**, pa se uzorak „bliži bug-u“ odbacuje zato što ne dodaje coverage. Sa **3+ zavisna koraka**, nasumična rekombinacija postaje skupa, a feedback zasnovan na coverage-u ne usmerava pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** kod grammar-a sa mnogo zavisnosti razmotrite **hybridizing mutational and generative phases** ili usmeravanje generisanja ka obrascima **function chaining-a** (ne samo ka coverage-u).<sup>[[1]](#references)</sup>

## Zamke raznovrsnosti corpus-a

Coverage-guided mutation je **greedy**: uzorak sa novim coverage-om čuva se odmah, često zadržavajući velike neizmenjene delove. Vremenom corpus-i postaju **near-duplicates** sa malom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **grammar-aware minimization** koja se **zaustavlja nakon dostizanja minimalnog praga tokena** (smanjuje šum, a zadržava dovoljno okolne strukture da ostane pogodna za mutacije).<sup>[[1]](#references)</sup>

Praktično pravilo za corpus kod mutational fuzzing-a jeste: **dajte prednost malom skupu strukturno različitih seed-ova koji maksimizuju coverage** u odnosu na veliku gomilu near-duplicates. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **real-world uzoraka** (javni corpus-i, crawling, uhvaćen saobraćaj, skupovi fajlova iz ekosistema target-a).
- Prečistite ih pomoću **coverage-based corpus minimization-a**, umesto da zadržite svaki validan uzorak.
- Seed-ovi treba da budu **dovoljno mali** da mutacije pogađaju smislena polja, umesto da se većina ciklusa troši na nerelevantne bajtove.
- Ponovo pokrenite corpus minimization nakon velikih promena harness-a ili instrumentation-a, jer se „najbolji“ corpus menja kada se promeni reachability.

## Comparison-Aware Mutation For Magic Values

Čest razlog zbog kog fuzzer-i dostignu plato nisu sintaksa, već **hard comparisons**: magic bytes, provere dužine, enum stringovi, checksum-i ili parser dispatch vrednosti zaštićene pomoću `memcmp`, switch tabela ili ulančanih poređenja. Čista nasumična mutacija troši cikluse pokušavajući da pogodi ove vrednosti bajt po bajt.

Za ovakve target-e koristite **comparison tracing** (na primer AFL++ `CMPLOG` / Redqueen-style workflow-e), kako bi fuzzer mogao da posmatra operande iz neuspešnih poređenja i usmerava mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>
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

- Ovo je posebno korisno kada ciljnu logiku dublje u procesu kontrolišu **file signatures**, **protocol verbs**, **type tags** ili **version-dependent feature bits**.
- Uparite ga sa **dictionaries** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali rečnik sa grammar tokenima, nazivima chunk-ova, glagolima i delimiterima često je vredniji od ogromne generičke wordliste.
- Ako cilj izvršava mnogo sekvencijalnih provera, prvo rešite najranija poređenja „magic“, a zatim ponovo minimizujte dobijeni corpus kako bi kasnije faze počele od već validnih prefiksa.

## Stateful Fuzzing: Sekvence su seed-ovi

Kod **protocols**, **authenticated workflows** i **multi-stage parsers**, zanimljiva jedinica često nije jedan blob, već **message sequence**. Spajanje celog transkripta u jedan fajl i njegovo nasumično menjanje obično je neefikasno jer fuzzer jednako menja svaki korak, čak i kada samo kasnija poruka dolazi do ranjivog stanja.<sup>[[4]](#references)</sup>

Efikasniji pristup je tretirati **sequence** kao seed i koristiti **observable state** (response codes, protocol states, parser phases, returned object types) kao dodatni feedback.<sup>[[4]](#references)</sup>

- Održavajte **valid prefix messages** stabilnim i usmerite mutacije na poruku koja pokreće **transition**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Dajte prednost mutaciji/spajanju po poruci umesto menjanja celog serijalizovanog transkripta kao neprozirnog bloba.
- Ako protokol izlaže smislene response codes, koristite ih kao jeftin **state oracle** za davanje prioriteta sekvencama koje napreduju dublje.

To je isti razlog zbog kog authenticated bug-ovi, skrivene tranzicije ili parser bug-ovi koji se javljaju „only-after-handshake“ često promaknu kod klasičnog file-style fuzzing-a: fuzzer mora da očuva **order, state i dependencies**, a ne samo strukturu.<sup>[[4]](#references)</sup>

## Trik za raznovrsnost na jednoj mašini (Jackalope-Style)

Praktičan način za kombinovanje **generative novelty** sa **coverage reuse** jeste ponovno pokretanje kratkotrajnih worker-a nad persistent serverom. Svaki worker počinje sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi nad kombinovanim corpus-om, ponovo se sinhronizuje, a zatim se gasi. Tako se dobijaju **fresh structures u svakoj generaciji**, uz istovremeno korišćenje akumuliranog coverage-a.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni worker-i (primer petlje):**

<details>
<summary>Jackalope petlja za ponovno pokretanje worker-a</summary>
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

- `-in empty` forsira **svež corpus** pri svakoj generaciji.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (novina prvo, ponovna upotreba kasnije).
- U grammar fuzzing režimu, **početna sinhronizacija servera se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalna vrednost `T` zavisi od **targeta**; najbolje rezultate obično daje prebacivanje nakon što worker pronađe većinu „lake“ coverage.

## Snapshot Fuzzing za targete koje je teško pripremiti

Kada kod koji želite da testirate postaje dostupan tek nakon velikog troška pripreme (pokretanje VM-a, završavanje prijavljivanja, primanje paketa, parsiranje containera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog procesa ili VM-a, ubacite svaki test case u ulaznu putanju targeta, izvršavajte do crash-a/time-outa, a zatim vratite snapshot. Ovo izbegava ponavljanje inicijalizacije ili protokolskih prefiksa i korisno je za **network servise**, **firmware**, **post-auth attack surface** i **binary-only targete**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite target dok zanimljivo stanje ne bude spremno.
2. Sačuvajte snapshot **memorije + registara** u tom trenutku.
3. Za svaki test case upišite mutirani input direktno u odgovarajući guest/process buffer.
4. Izvršavajte do crash-a/time-outa/resetovanja.
5. Vratite snapshot; za VM targete, kada je podržano, vratite samo **dirty pages**, a zatim ponovite postupak.

Postavite snapshot što je praktičnije bliže prvom skupom koraku parsiranja/dispatch-a, na primer nakon tačke `recv`/`read` ili deserializacije paketa, i zabeležite input buffer koji target koristi. Ovo prati princip adaptivnog postavljanja: pomeranje snapshota dublje u obradu inputa kako bi se izbeglo ponavljanje posla.<sup>[[11]](#references)</sup>

## Introspekcija Harness-a: rano pronađite plitke fuzzere

Kada kampanja stagnira, problem često nije mutator već **harness**. Koristite **introspekciju reachability/coverage** da pronađete funkcije koje su statički dostižne iz vašeg fuzz targeta, ali su retko ili nikada pokrivene dinamički. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u target prekasno ili prerano.
- Seed corpus-u nedostaje čitava familija funkcionalnosti.
- Targetu je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a koji „radi sve“.

Ako koristite workflow-e u stilu OSS-Fuzz / ClusterFuzz, Fuzz Introspector može da uporedi statičku reachability sa runtime coverage i generiše izveštaje na osnovu vremenski ograničenog run-a ili javnog corpusa.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Koristi izveštaj da odlučiš da li treba dodati novi harness za neproverenu parser putanju, proširiti corpus za određenu funkcionalnost ili podeliti monolitni harness na manje entrypoint-e.

## Graph-First Fuzz Target Selection And Mutation Triage

Ako već imaš nalaze **static-analysis**, preživele mutacije iz **mutation-testing** procesa i izveštaje o coverage-u, nemoj ih analizirati kao nezavisne liste. Najpre napravi **call graph**, označi čvorove pomoću **cyclomatic complexity**, **entrypoint/untrusted-input reachability** i svih eksternih nalaza, a zatim postavi pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostupne preko untrusted input-a?
- Koji mutation survivors se nalaze na putanjama od parsera/handlera do security-critical koda?
- Koje funkcije predstavljaju arhitektonske choke point-e sa neuobičajeno velikim **blast radius**-om?

Ovim se obično otkrivaju bolji fuzz target-i nego korišćenjem samo kriterijuma „najniži coverage“. Parser/decoder sa **high complexity** i potvrđenim **external reachability** predstavlja bolji kandidat za harness nego izolovani interni helper sa slabim coverage-om, ali bez attacker-controlled putanje.

### Praktični tok triage-a

1. Napravi **code graph** na osnovu codebase-a i izvuci metrike složenosti/grana za svaku funkciju.
2. Nabroj **entrypoint-e** koji prihvataju attacker-controlled input: request handler-e, decoder-e, importer-e, protocol parser-e, CLI/file reader-e.
3. Pokreni **path queries** od tih entrypoint-a do funkcija kandidata kako bi odvojio dostupnu attack surface od dead/internal-only koda.
4. Daj prioritet čvorovima koji kombinuju:
- visoku **cyclomatic complexity**
- potvrđenu **reachability from untrusted input**
- veliki **blast radius** ili veliki broj downstream dependents
- dodatne dokaze, kao što su **SARIF** nalazi, audit beleške ili mutation survivors
5. Najpre napiši fokusirane harness-e za čvorove sa najboljim rezultatom, naročito za **parsers/codecs** kao što su hex/Base64/IP/message decoder-i.

### Mutation survivors: equivalent vs actionable

Mutation testing često proizvodi bučnu listu preživelih mutacija. Pre nego što svakog survivor-a proglasiš security gap-om, koristi graf za sledeća pitanja:

- Da li je izmenjena funkcija dostupna preko attacker-controlled entrypoint-a?
- Da li su sve call path-e ograničene jačim invariantama od one koju je izmenjena provera trebalo da nametne?
- Da li se čvor nalazi u dead code-u, logici koja utiče samo na formatting ili u arithmetic/parser putanji velikog uticaja?

Survivori koji ostaju nedostupni ili su strukturno ograničeni često su **equivalent mutants**. Survivori koji ostaju **reachable** i dotiču **boundary conditions**, **overflow/carry paths** ili **security-critical arithmetic/parsing** treba da budu unapređeni u:

- nove fuzz harness-e
- direktne property/invariant testove
- ciljane edge-case vektore

### Correlate external findings onto the graph

Ako tvoj SAST pipeline izvozi **SARIF**, projektuj nalaze na čvorove grafa prema **file + line range** i koristi graf za proširivanje uticaja.<sup>[[6]](#references)</sup>

- izračunaj **blast radius** označene funkcije
- proveri da li se nalaz nalazi na bilo kojoj putanji od entrypoint-a
- grupiši obližnje nalaze koji se svode na isti choke point

Ovo je korisno kada odlučuješ da li da vreme za fuzzing potrošiš na određenu funkciju: čvor koji je **reachable**, složen i već ima **SAST hits** često je bolji target od samo složenog čvora bez attacker path-a.

Primer workflow-a sa Trailmark-om.<sup>[[6]](#references)</sup>
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
Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite grafikon da izaberete fuzz targets sa najvećom očekivanom bezbednosnom vrednošću, a zatim koristite preživele mutacije da odlučite koje granice i invarijante vaš harness mora da testira.<sup>[[5]](#references)</sup>

## Go Fuzzing sa gosentry: Snažniji engine, tipizirani ulazi i diferencijalne provere

Ako Go target već ima izvorni `testing.F` harness, praktičan put za nadogradnju jeste pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), forkovanog Go toolchain-a koji zadržava `go test -fuzz`, ali menja backend u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Ovo je korisno kada native Go fuzzer zapne na **složenim poređenjima**, **tipiziranim ulazima** ili formatima koji zahtevaju intenzivno parsiranje. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za seed-ove i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite pomoću gosentry-jevog `go` binary-ja umesto standardnog toolchain-a.
- Tretirajte rezultujuću campaign kao uobičajeno coverage-guided pokretanje, ali sa LibAFL scheduling/mutation mehanizmima i boljim pratećim detector-ima.

### Pretvaranje tihih grešaka u fuzz nalaze

Čest problem u Go procenama jeste to što se opasno ponašanje često **podrazumevano ne završava crash-om**. Uz gosentry, nekoliko klasa „loših, ali tihih“ stanja možete pretvoriti u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` kako bi odabrane logging/error putanje funkcionisale kao crash-evi (korisno za code path-ove u stilu `log.Fatal`, koji bi inače samo upisali log i nastavili izvršavanje).
- `--catch-races=true` za ponovno pokretanje novootkrivenih queue entry-ja pomoću Go race detector-a.
- `--catch-leaks=true` za ponovno pokretanje novih queue entry-ja pomoću `goleak` i zaustavljanje pri otkrivanju goroutine leak-ova.
- LibAFL hang handling kako bi **beskonačne petlje / veoma spori inputi** ostali fuzz nalazi, umesto da nestanu kao timeout-i.
- Ugrađene provere arithmetic overflow-a su podrazumevano uključene, uz opcione provere truncation-a kroz instrumentation u stilu go-panikint-a.

Ovo je naročito korisno za target-e kod kojih je bezbednosni uticaj **parser failure bez panic-a**, **concurrency bug** ili **hang koji omogućava samo DoS**, a ne memory corruption.

### Struct-aware fuzzing za tipizirane Go API-je

Native Go fuzzing uglavnom očekuje scalar vrednosti kao što su `[]byte`, `string` i brojevi. Ako code under test prihvata tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (struct-ove, slice-ove, array-je, pointer-e), uz istovremenu mutaciju bajtova u pozadini.<sup>[[7]](#references)[[8]](#references)</sup>
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
Koristite ovo kada pravite lažni wire format samo za fuzzing, jer bi se greške u logici sakrile iza parsing koda koji postoji samo u harnessu. Za diferencijalne ili grammar-based kampanje, zadržite ulaz u harnessu kao jednu `[]byte` ili `string` vrednost i obavite parsing unutar callback-a.

### Grammar-based fuzzing za parsere i protokolske ulaze

Za parsere, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** na vrhu LibAFL-a. Gramatika je JSON niz production rules, a harness bi obično trebalo da prihvata jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- Koristite grammar mode kada byte-level mutations uglavnom odumiru u ranim syntax proverama.
- Usmerite grammar na **bezbednosno relevantan podskup** jezika/protokola umesto modelovanja kompletne specifikacije.
- Koristite velike granične vrednosti u terminalima/neterminalima kako biste opteretili granice integer-a, dužine i state machine-a.
- Grammar mode održava inputs validnim prema grammar-u, ali target i dalje prima **bytes/strings**, tako da parsing i semantic checks ostaju unutar harnessed code-a.

### Differential fuzzing: poređenje implementacija, ne samo crash-eva

Snažan obrazac za Go ekosisteme jeste **grammar-based differential fuzzing**: generišite validne strukturisane inputs i prosledite ih dvama parserima, klijentima ili state-transition engine-ima.<sup>[[7]](#references)[[8]](#references)</sup>
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
Tretirajte sledeće kao nalaze:

- jedna implementacija izaziva panic, dok druga uredno odbija
- nepodudarnosti između prihvaćenog i odbijenog inputa
- različita stabla parsiranja ili dekodirani objekti
- različite tranzicije stanja, nonce vrednosti, bilansi ili koreni stanja

Ovo je praktičan način za pronalaženje **nepodudarnosti konsenzusa**, **dvosmislenosti parsera** i **odstupanja specifikacije od implementacije**, koje čisto crash fuzzing testiranje često propušta.

### Ponovna upotreba corpus-a kampanje za izveštavanje o coverage-u

Nakon kampanje, ponovo reprodukujte sačuvani queue corpus da biste generisali Go coverage report bez ručnog izvoza zasebnog corpus-a.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Pokrenite komandu iz **istog paketa** i sa **istim ciljem `-fuzz`** kako bi gosentry razrešio odgovarajuće stanje keširane kampanje.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing u dubinu](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: Fuzzing mrežnih protokola vođen pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Forkovali smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brzi greybox fuzzer za stateful mrežne protokole pomoću snapshotova](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: Ka fuzzingu Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasan fuzzing sa adaptivnim i promenljivim snapshotovima](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
