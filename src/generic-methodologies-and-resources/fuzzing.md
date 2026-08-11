# Mutational Grammar Fuzzing: Coverage vs. Semantics

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage naspram Semantike

Kod **mutational grammar fuzzing**, inputs se menjaju tako da ostanu **grammar-valid**. U coverage-guided režimu, samo samples koji pokrenu **novi coverage** čuvaju se kao corpus seeds. Kod **language targets** (parseri, interpreteri, engine-i), ovim se mogu propustiti bugovi koji zahtevaju **semantic/dataflow chains**, gde output jedne konstrukcije postaje input druge.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer pronalazi seeds koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva chained dataflow**, pa se sample „bliži bugu“ odbacuje zato što ne dodaje coverage. Kod **3+ dependent steps**, random recombination postaje skupa, a coverage feedback ne usmerava pretragu.<sup>[[1]](#references)</sup>

**Implication:** kod grammar-a sa mnogo dependencies, razmotrite **hybridizing mutational and generative phases** ili usmeravanje generacije ka obrascima **function chaining** (ne samo ka coverage-u).<sup>[[1]](#references)</sup>

## Zamke Raznovrsnosti Corpusa

Coverage-guided mutation je **greedy**: sample sa novim coverage-om čuva se odmah, često zadržavajući velike nepromenjene delove. Vremenom corpora postaju **near-duplicates** sa malom strukturalnom raznovrsnošću. Aggressive minimization može ukloniti koristan context, pa je praktičan kompromis **grammar-aware minimization** koje se **zaustavlja nakon minimalnog praga tokena** (smanjuje noise, ali zadržava dovoljno okolne strukture da ostane pogodna za mutation).<sup>[[1]](#references)</sup>

Praktično corpus pravilo za mutational fuzzing je: **dajte prednost malom skupu strukturalno različitih seeds koji maksimizuju coverage** u odnosu na veliku gomilu near-duplicates. U praksi, to obično znači sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **real-world samples** (javni corpora, crawling, captured traffic, file sets iz target ecosystem-a).
- Distilujte ih pomoću **coverage-based corpus minimization** umesto čuvanja svakog validnog sample-a.
- Seeds neka budu **dovoljno mali** da mutations pogađaju meaningful fields, umesto da većinu cycles troše na irelevantne bytes.
- Ponovo pokrenite corpus minimization nakon velikih promena harness-a/instrumentation-a, jer se „najbolji“ corpus menja kada se promeni reachability.

## Comparison-Aware Mutation za Magic Values

Čest razlog zbog kog fuzzers dostignu plateau nisu syntax, već **hard comparisons**: magic bytes, length checks, enum strings, checksums ili parser dispatch values zaštićeni pomoću `memcmp`, switch tabela ili lančanih poređenja. Čista random mutation troši cycles pokušavajući da pogodi ove vrednosti byte-po-byte.

Za ove targets koristite **comparison tracing** (na primer AFL++ `CMPLOG` / Redqueen-style workflows), kako bi fuzzer mogao da posmatra operands iz failed comparisons i usmerava mutations ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>
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

- Ovo je naročito korisno kada cilj skriva duboku logiku iza **file signatures**, **protocol verbs**, **type tags** ili **version-dependent feature bits**.
- Kombinujte ga sa **dictionaries** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali dictionary sa grammar tokenima, nazivima chunk-ova, glagolima i delimiterima često je vredniji od ogromne generičke wordlist-e.
- Ako cilj izvršava mnogo uzastopnih provera, prvo rešite najranija „magic“ poređenja, a zatim ponovo minimizujte dobijeni corpus kako bi kasnije faze počele sa već validnim prefiksima.

## Stateful Fuzzing: Sequences Are Seeds

Kod **protocols**, **authenticated workflows** i **multi-stage parsers**, zanimljiva jedinica često nije jedan blob, već **message sequence**. Spajanje celog transcript-a u jedan fajl i njegovo nasumično mutiranje obično je neefikasno, jer fuzzer jednako mutira svaki korak, čak i kada samo kasnija poruka doseže ranjivo stanje.<sup>[[4]](#references)</sup>

Efikasniji obrazac je tretirati **sequence** kao seed i koristiti **observable state** (response codes, protocol states, parser phases, returned object types) kao dodatni feedback.<sup>[[4]](#references)</sup>

- Održavajte **valid prefix messages** stabilnim i usmerite mutacije na poruku koja pokreće **transition**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Dajte prednost mutiranju/spajanju po poruci umesto mutiranja celog serijalizovanog transcript-a kao opaque blob-a.
- Ako protocol izlaže smislene response codes, koristite ih kao jeftin **state oracle** za davanje prioriteta sekvencama koje napreduju dublje.

To je isti razlog zbog kog authenticated bug-ovi, skrivene tranzicije ili parser bug-ovi koji se pojavljuju „only-after-handshake“ često promaknu vanilla file-style fuzzing-u: fuzzer mora da očuva **order, state i dependencies**, a ne samo strukturu.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Praktičan način za hibridizaciju **generative novelty** sa **coverage reuse** jeste **restartovanje kratkotrajnih worker-a** prema persistent server-u. Svaki worker počinje sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, zatim radi još `T` sekundi nad kombinovanim corpus-om, ponovo se sinhronizuje i izlazi. Tako se dobijaju **fresh structures svake generacije**, uz istovremeno korišćenje akumuliranog coverage-a.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni worker-i (primer petlje):**

<details>
<summary>Petlja za restartovanje Jackalope worker-a</summary>
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

**Beleške:**

- `-in empty` nameće **fresh corpus** pri svakoj generaciji.
- `-server_update_interval T` približno simulira **delayed sync** (novost prvo, ponovna upotreba kasnije).
- U grammar fuzzing režimu, **initial server sync** se podrazumevano preskače (nema potrebe za `-skip_initial_server_sync`).
- Optimalna vrednost `T` zavisi od **target-a**; najbolje rezultate obično daje prebacivanje nakon što worker pronađe većinu „lake“ coverage.

## Snapshot Fuzzing za ciljeve koje je teško obuhvatiti harness-om

Kada kod koji želite da testirate postane dostupan tek nakon velikog troška inicijalnog podešavanja (pokretanje VM-a, završavanje prijavljivanja, prijem paketa, parsiranje container-a, inicijalizacija service-a), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog process-a ili VM-a, ubacite svaki test case u ulaznu putanju target-a, izvršavajte do crash-a/timeout-a, a zatim vratite snapshot. Time se izbegava ponavljanje inicijalizacije ili protocol prefix-a i pristup je koristan za **network services**, **firmware**, **post-auth attack surfaces** i **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite target dok interesantno stanje ne bude spremno.
2. U tom trenutku sačuvajte snapshot **memory + registers**.
3. Za svaki test case upišite mutirani input direktno u odgovarajući guest/process buffer.
4. Izvršavajte do crash-a/timeout-a/reset-a.
5. Vratite snapshot; za VM target-e, kada je podržano, vratite samo **dirty pages**, a zatim ponovite postupak.

Postavite snapshot što je praktičnije moguće bliže prvom skupom koraku parsiranja/dispatch-a, na primer nakon `recv`/`read` ili tačke deserijalizacije paketa, i zabeležite input buffer koji target koristi. Ovo prati princip adaptivnog postavljanja: pomeranje snapshot-a dublje u obradu input-a kako bi se izbeglo ponavljanje posla.<sup>[[11]](#references)</sup>

## Introspekcija harness-a: rano pronađite plitke fuzzere

Kada campaign stagnira, problem često nije mutator, već **harness**. Koristite **reachability/coverage introspection** da biste pronašli funkcije koje su statički dostupne iz vašeg fuzz target-a, ali se dinamički retko ili nikada ne pokrivaju. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u target prekasno ili prerano.
- Seed corpus-u nedostaje čitava familija funkcionalnosti.
- Target-u je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a koji „radi sve“.

Ako koristite tokove rada u stilu OSS-Fuzz / ClusterFuzz, Fuzz Introspector može da uporedi statičku reachability sa runtime coverage i da generiše izveštaje iz vremenski ograničenog run-a ili javnog corpus-a.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Koristite izveštaj da odlučite da li treba dodati novi harness za neproverenu putanju parsera, proširiti corpus za određenu funkcionalnost ili podeliti monolitni harness na manje entrypoint-e.

## Graph-First izbor Fuzz Target-a i trijaža mutacija

Ako već imate nalaze **static analysis**, preživele mutacije iz **mutation testing-a** i izveštaje o coverage-u, nemojte ih tretirati kao nezavisne liste. Najpre izgradite **call graph**, anotirajte čvorove pomoću **cyclomatic complexity**, dostupnosti iz **entrypoint-a/nepoverljivog inputa** i svih eksternih nalaza, a zatim postavljajte pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostupne iz nepoverljivog inputa?
- Koje preživele mutacije se nalaze na putanjama od parsera/handler-a do security-critical koda?
- Koje funkcije predstavljaju arhitektonska uska grla sa neuobičajeno velikim **blast radius**-om?

Ovo obično otkriva bolje fuzz target-e nego oslanjanje samo na „najniži coverage“. Parser/decoder sa **visokim nivoom složenosti** i potvrđenom **eksternom dostupnošću** bolji je kandidat za harness nego izolovani interni helper sa slabim coverage-om, ali bez putanje pod kontrolom napadača.

### Praktičan tok trijaže

1. Izgradite **code graph** iz codebase-a i izdvojite metrike složenosti/grana za svaku funkciju.
2. Nabrojte **entrypoint-e** koji prihvataju input pod kontrolom napadača: request handler-e, decoder-e, importer-e, protocol parser-e, CLI/file reader-e.
3. Pokrenite **path query-je** od tih entrypoint-a do kandidatnih funkcija kako biste razdvojili dostupnu attack surface od neaktivnog/inter­no dostupnog koda.
4. Dajte prioritet čvorovima koji objedinjuju:
- visoku **cyclomatic complexity**
- potvrđenu **dostupnost iz nepoverljivog inputa**
- veliki **blast radius** ili veliki broj zavisnih komponenti
- dodatne dokaze kao što su **SARIF** nalazi, audit beleške ili preživele mutacije
5. Najpre napišite fokusirane harness-e za čvorove sa najboljim rezultatom, naročito za **parser-e/codecs** kao što su hex/Base64/IP/message decoder-i.

### Preživele mutacije: equivalent naspram actionable

Mutation testing često proizvodi bučnu listu preživelih mutacija. Pre nego što svaku preživelu mutaciju proglasite security gap-om, pomoću grafa proverite:

- Da li je mutirana funkcija dostupna iz entrypoint-a pod kontrolom napadača?
- Da li su sve call path-e ograničene jačim invariantama od izmenjene provere?
- Da li se čvor nalazi u neaktivnom kodu, logici koja utiče samo na formatiranje ili u aritmetičkoj/parser putanji visokog uticaja?

Preživele mutacije koje su i dalje nedostupne ili strukturno ograničene često su **equivalent mutants**. Preživele mutacije koje ostaju **dostupne** i dotiču **granične uslove**, **overflow/carry putanje** ili **security-critical aritmetiku/parsing** treba promovisati u:

- nove fuzz harness-e
- direktne property/invariant testove
- ciljane vektore za edge case-ove

### Mapiranje eksternih nalaza na graf

Ako vaš SAST pipeline izvozi **SARIF**, projektujte nalaze na čvorove grafa prema **file + line range** i pomoću grafa proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **blast radius** označene funkcije
- proverite da li se nalaz nalazi na bilo kojoj putanji od entrypoint-a
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno kada odlučujete da li da vreme za fuzzing utrošite na određenu funkciju: čvor koji je **dostupan**, **složen** i već ima **SAST nalaze** često je bolji target od samo složenog čvora bez putanje pod kontrolom napadača.

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
Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite graf da odaberete fuzz targets sa najvećom očekivanom bezbednosnom vrednošću, a zatim koristite mutation survivors da odlučite koje granice i invarijante vaš harness mora da testira.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Ako Go target već ima native `testing.F` harness, praktičan put za nadogradnju jeste pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), forked Go toolchain-a koji zadržava `go test -fuzz`, ali menja backend u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Ovo je korisno kada native Go fuzzer zapne na **hard comparisons**, **typed inputs** ili formatima sa intenzivnim parsiranjem. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za seed-ove i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite gosentry-jevim `go` binaryjem umesto standardnog toolchain-a.
- Tretirajte dobijenu campaign kao uobičajeno coverage-guided pokretanje, ali uz LibAFL scheduling/mutation i bolje prateće detektore.

### Pretvorite tihe greške u fuzz findings

Čest problem u Go procenama jeste to što opasno ponašanje često podrazumevano **ne izaziva crash**. Uz gosentry, nekoliko klasa „loših, ali tihih“ stanja možete pretvoriti u findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da izabrane logging/error putanje funkcionišu kao crash-evi (korisno za putanje koda u stilu `log.Fatal`, koje bi inače samo zabeležile grešku i nastavile izvršavanje).
- `--catch-races=true` da novootkrivene queue entries ponovo pokrenete uz Go race detector.
- `--catch-leaks=true` da nove queue entries ponovo pokrenete uz `goleak` i prekinete izvršavanje kada se otkriju goroutine leaks.
- LibAFL hang handling, koji zadržava **infinite loops / very slow inputs** kao fuzz findings umesto da nestanu kao timeouts.
- Ugrađene provere arithmetic overflow-a podrazumevano, uz opcione provere truncation-a kroz instrumentation u stilu go-panikint-a.

Ovo je naročito vredno za targete kod kojih je security impact **panicless parser failure**, **concurrency bug** ili hang koji izaziva samo **DoS**, a ne memory corruption.

### Fuzzing uz poznavanje struct-ova za tipizirane Go API-je

Native Go fuzzing uglavnom očekuje scalars kao što su `[]byte`, `string` i brojevi. Ako kod koji testirate koristi typed objects, gosentry može direktno da fuzz-uje **composite values** (structs, slices, arrays, pointers), dok i dalje mutira bytes u pozadini.<sup>[[7]](#references)[[8]](#references)</sup>
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
Koristite ovo kada pravite lažni wire format samo za fuzzing, jer bi se greške u logici sakrile iza koda za parsiranje specifičnog za harness. Za differential ili grammar-based kampanje, zadržite ulaz za harness kao jedan `[]byte` ili `string` i parsirajte ga unutar callback-a.

### Grammar-based fuzzing za parsere i protokolarne ulaze

Za parsere, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** na vrhu LibAFL-a. Gramatika je JSON niz produkcionih pravila, a harness obično treba da prima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Napomene o metodologiji:

- Koristite **grammar mode** kada byte-level mutations uglavnom završe u ranim syntax proverama.
- Održavajte grammar fokusiranim na **security-relevant subset** jezika/protokola umesto modelovanja cele specifikacije.
- Koristite velike granične vrednosti u terminalima/nonterminalima da biste opteretili integer, length i state-machine granice.
- Grammar mode održava inpute validnim prema grammar-u, ali target i dalje prima **bytes/strings**, tako da parsing i semantic provere ostaju unutar koda obuhvaćenog harness-om.

### Differential fuzzing: upoređivanje implementacija, a ne samo crash-eva

Snažan obrazac za Go ekosisteme je **grammar-based differential fuzzing**: generišite validne strukturirane inpute i prosledite ih dvama parserima, klijentima ili state-transition engine-ima.<sup>[[7]](#references)[[8]](#references)</sup>
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

- jedna implementacija izaziva panic, dok druga uredno odbija unos
- nepodudaranja između prihvaćenih i odbijenih unosa
- različita stabla parsiranja ili dekodirani objekti
- različite tranzicije stanja, nonce vrednosti, bilansi ili koreni stanja

Ovo je praktičan način za pronalaženje **neslaganja konsenzusa**, **dvosmislenosti parsera** i **odstupanja specifikacije od implementacije**, što čisto fuzzing testiranje usmereno na crash često propušta.

### Ponovna upotreba campaign corpus-a za izveštavanje o coverage-u

Nakon campaign-a, ponovo reprodukujte sačuvani queue corpus da biste generisali Go coverage izveštaj bez ručnog izvoza zasebnog corpus-a.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` kako bi gosentry razrešio ispravno stanje keširane kampanje.

## References

- [1] [Mutaciono fuzzing testiranje gramatike](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing testiranje protokola vođeno pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing testiranju je nedostajala polovina alata. Forkovali smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brzi greybox fuzzer za stateful mrežne protokole pomoću snapshotova](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: ka fuzzing testiranju Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasno fuzzing testiranje sa adaptivnim i promenljivim snapshotovima](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
