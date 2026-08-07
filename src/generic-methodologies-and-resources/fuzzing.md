# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage naspram semantike

Kod **mutational grammar fuzzing**, ulazi se menjaju tako da ostanu **grammar-valid**. U režimu vođenom coverage-om, samo uzorci koji pokrenu **novi coverage** čuvaju se kao seeds korpusa. Kod **language targets** (parseri, interpreteri, engine-i), ovim se mogu propustiti bug-ovi koji zahtevaju **semantic/dataflow chains**, gde izlaz jedne konstrukcije postaje ulaz druge.

**Failure mode:** fuzzer pronalazi seed-ove koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani dataflow**, pa se uzorak „bliži bug-u“ odbacuje zato što ne dodaje coverage. Sa **3+ dependent steps**, nasumična rekombinacija postaje skupa, a feedback zasnovan na coverage-u ne usmerava pretragu.

**Implikacija:** kod grammar-ja sa mnogo dependency-ja razmotrite **hybridizing mutational and generative phases** ili usmeravanje generisanja ka obrascima **function chaining** (ne samo ka coverage-u).<sup>[[1]](#references)</sup>

## Zamke raznovrsnosti korpusa

Mutation vođen coverage-om je **greedy**: uzorak sa novim coverage-om čuva se odmah, često zadržavajući velike nepromenjene delove. Vremenom korpusi postaju **near-duplicates** sa niskom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **grammar-aware minimization** koja se **zaustavlja nakon dostizanja minimalnog praga tokena** (smanjuje šum, a zadržava dovoljno okolne strukture da ostane pogodna za mutacije).<sup>[[1]](#references)</sup>

Praktično pravilo za korpus kod mutational fuzzing-a je: **dajte prednost malom skupu strukturalno različitih seed-ova koji maksimizuju coverage** u odnosu na veliku količinu near-duplicates. U praksi to obično znači:<sup>[[1]](#references)</sup>

- Počnite od **real-world samples** (javni korpusi, crawling, captured traffic, skupovi fajlova iz ekosistema target-a).
- Svedite ih pomoću **coverage-based corpus minimization**, umesto da zadržite svaki validan uzorak.
- Seed-ovi treba da budu **dovoljno mali** da mutacije pogode smislena polja, umesto da se većina ciklusa troši na irelevantne bajtove.
- Ponovo pokrenite corpus minimization nakon većih izmena harness-a/instrumentacije, jer se „najbolji“ korpus menja kada se promeni reachability.

## Comparison-Aware Mutation For Magic Values

Čest razlog zbog kog fuzzer-i dostignu plato nisu syntax već **hard comparisons**: magic bytes, provere dužine, enum string-ovi, checksum-ovi ili parser dispatch vrednosti zaštićene pomoću `memcmp`, switch tabela ili lančanih poređenja. Čiste nasumične mutacije troše cikluse pokušavajući da pogode ove vrednosti bajt po bajt.

Za ove target-e koristite **comparison tracing** (na primer AFL++ `CMPLOG` / Redqueen-style workflows), kako bi fuzzer mogao da posmatra operande iz neuspešnih poređenja i usmeri mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>
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
- Uparite ga sa **dictionaries** izdvojenim iz stvarnih primera, specifikacija protokola ili debug logova. Mali dictionary sa gramatičkim tokenima, imenima chunk-ova, glagolima i delimiterima često je vredniji od ogromnog generičkog wordlist-a.
- Ako cilj izvršava mnogo sekvencijalnih provera, prvo rešite najranija „magic“ poređenja, a zatim ponovo minimizujte dobijeni corpus kako bi kasnije faze počele sa već validnim prefiksima.

## Stateful Fuzzing: Sekvence su seed-ovi

Kod **protokola**, **authenticated workflows** i **multi-stage parser-a**, zanimljiva jedinica često nije jedan blob, već **sekvenca poruka**. Spajanje celog transkripta u jedan fajl i njegovo nasumično mutiranje obično je neefikasno, jer fuzzer podjednako menja svaki korak, čak i kada samo kasnija poruka doseže ranjivo stanje.

Efikasniji obrazac je tretirati **samu sekvencu kao seed** i koristiti **observable state** (response codes, stanja protokola, faze parser-a, tipove vraćenih objekata) kao dodatni feedback:<sup>[[4]](#references)</sup>

- Održavajte **valid prefix messages** stabilnim i usmerite mutacije na poruku koja **pokreće tranziciju**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Dajte prednost mutiranju/spajanju po poruci u odnosu na mutiranje celog serijalizovanog transkripta kao opaque blob-a.
- Ako protokol izlaže smislene response codes, koristite ih kao **jeftin oracle stanja** za davanje prioriteta sekvencama koje napreduju dublje.

To je isti razlog zbog kog authenticated bug-ovi, skrivene tranzicije ili parser bug-ovi koji se javljaju „tek nakon handshake-a“ često promaknu vanilla file-style fuzzing-u: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.

## Trik za raznovrsnost na jednoj mašini (u stilu Jackalope-a)

Praktičan način za hibridizaciju **generative novelty** sa **coverage reuse** jeste **restartovanje kratkotrajnih worker-a** nad persistent serverom. Svaki worker počinje sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi nad kombinovanim corpus-om, ponovo se sinhronizuje, a zatim se gasi. Tako se u svakoj generaciji dobijaju **sveže strukture**, uz istovremeno korišćenje akumuliranog coverage-a.<sup>[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni worker-i (primer petlje):**

<details>
<summary>Jackalope petlja ponovnog pokretanja worker-a</summary>
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

- `-in empty` primorava **novi corpus** pri svakoj generaciji.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (noviteti prvo, ponovna upotreba kasnije).
- U grammar fuzzing režimu, **početna server sinhronizacija se podrazumevano preskače** (nije potreban `-skip_initial_server_sync`).
- Optimalni `T` zavisi od **target-a**; prebacivanje nakon što worker pronađe većinu „lake“ coverage obično daje najbolje rezultate.

## Snapshot Fuzzing Za Target-e Koje Je Teško Harness-ovati

Kada kod koji želite da testirate postaje dostupan tek **nakon velikog troška inicijalnog podešavanja** (pokretanje VM-a, završavanje prijavljivanja, prijem paketa, parsiranje container-a, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**:

1. Pokrenite target dok zanimljivo stanje ne bude spremno.
2. Napravite snapshot **memorije + registara** u toj tački.
3. Za svaki test case, upišite mutirani input direktno u relevantni guest/process buffer.
4. Izvršavajte dok ne dođe do crash-a/timeout-a/reset-a.
5. Vratite samo **dirty pages** i ponovite postupak.

Ovim se izbegava plaćanje punog troška inicijalnog podešavanja u svakoj iteraciji i naročito je korisno za **network services**, **firmware**, **post-auth attack surfaces** i **binary-only target-e** koje je teško refaktorisati u klasičan in-process harness.

Praktičan trik je da se odmah zaustavite nakon tačke `recv`/`read`/deserializacije paketa, zabeležite adresu input buffer-a, napravite snapshot na tom mestu, a zatim direktno mutirate taj buffer u svakoj iteraciji. Ovo vam omogućava da fuzz-ujete duboku logiku parsiranja bez ponovne izgradnje celog handshake-a svaki put.

## Harness Introspection: Rano Pronalaženje Shallow Fuzzer-a

Kada campaign zastane, problem često nije u mutator-u već u **harness-u**. Koristite **reachability/coverage introspection** da pronađete funkcije koje su statički dostupne iz vašeg fuzz target-a, ali su retko ili nikada dinamički pokrivene. Te funkcije obično ukazuju na jedan od tri problema:

- Harness ulazi u target prekasno ili prerano.
- Seed corpus-u nedostaje cela familija funkcionalnosti.
- Target-u je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a koji „radi sve“.

Ako koristite OSS-Fuzz / ClusterFuzz stil workflow-a, Fuzz Introspector je koristan za ovu trijažu:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Koristite izveštaj da odlučite da li treba dodati novi harness za netestiranu putanju parsera, proširiti corpus za određenu funkcionalnost ili podeliti monolitni harness na manje entry point-e.

## Graph-First odabir fuzz meta i trijaža mutation rezultata

Ako već imate **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nemojte ih trijažirati kao nezavisne liste. Najpre izgradite **call graph**, označite čvorove pomoću **cyclomatic complexity**, **entrypoint/untrusted-input reachability** i svih eksternih nalaza, a zatim postavite pitanja o grafu:<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostupne preko untrusted input-a?
- Koji mutation survivors se nalaze na putanjama od parsera/handlera do security-critical koda?
- Koje funkcije predstavljaju arhitektonske choke point-e sa neuobičajeno velikim **blast radius**?

Ovim se obično pronalaze bolji fuzz target-i nego oslanjanjem samo na „najniži coverage“. Parser/decoder sa **high complexity** i potvrđenom **external reachability** jači je kandidat za harness od izolovanog internog helper-a sa slabim coverage-om, ali bez putanje pod kontrolom napadača.

### Praktičan workflow trijaže

1. Izgradite **code graph** iz codebase-a i izdvojite metrike složenosti/grana za svaku funkciju.
2. Nabrojte **entrypoints** koji prihvataju input pod kontrolom napadača: request handler-e, decoder-e, importer-e, protocol parser-e, CLI/file reader-e.
3. Pokrenite **path queries** od tih entrypoint-a do kandidatskih funkcija kako biste odvojili dostižnu attack surface od neaktivnog ili samo internog koda.
4. Dajte prioritet čvorovima koji kombinuju:
- visoku **cyclomatic complexity**
- potvrđenu **reachability from untrusted input**
- veliki **blast radius** ili veliki broj downstream dependents
- dodatne dokaze, kao što su **SARIF** findings, audit beleške ili mutation survivors
5. Najpre napišite fokusirane harness-e za čvorove sa najboljim rezultatom, naročito za **parser/codecs** kao što su hex/Base64/IP/message decoder-i.

### Mutation survivors: equivalent naspram actionable

Mutation testing često proizvodi bučnu listu survivor-a. Pre nego što svakog survivor-a proglasite security gap-om, pomoću grafa postavite sledeća pitanja:

- Da li je mutated function dostupna preko attacker-controlled entrypoint-a?
- Da li su sve call path-e ograničene jačim invariant-ima od onog koji je mutated?
- Da li se čvor nalazi u dead code-u, logici koja služi samo za formatiranje ili u arithmetic/parser path-u sa velikim uticajem?

Survivors koji ostaju nedostižni ili su strukturno ograničeni često su **equivalent mutants**. Survivors koji ostaju **reachable** i dotiču **boundary conditions**, **overflow/carry paths** ili **security-critical arithmetic/parsing** treba promovisati u:

- nove fuzz harness-e
- direktne property/invariant tests
- ciljane edge-case vectors

### Korelacija eksternih nalaza sa grafom

Ako vaš SAST pipeline eksportuje **SARIF**, projektujte nalaze na čvorove grafa prema **file + line range** i koristite graf za proširivanje procene uticaja:

- izračunajte **blast radius** označene funkcije
- proverite da li se nalaz nalazi na bilo kojoj putanji od entrypoint-a
- grupišite obližnje nalaze koji se svode na isti choke point

Ovo je korisno pri odlučivanju da li vreme za fuzzing treba potrošiti na određenu funkciju: čvor koji je **reachable**, složen i već ima **SAST hits** često je bolja meta od samo složenog čvora bez attacker path-a.

Primer workflow-a sa Trailmark:<sup>[[6]](#references)</sup>
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
Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite graf da izaberete fuzz ciljeve sa najvećom očekivanom bezbednosnom vrednošću, a zatim koristite preživele mutacije da odlučite koje granice i invarijante vaš harness mora da testira.

## Go Fuzzing sa gosentry: Snažniji engine, tipizirani ulazi i diferencijalne provere

Ako Go cilj već ima native `testing.F` harness, praktičan put nadogradnje je pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), forkovanog Go toolchain-a koji zadržava `go test -fuzz`, ali menja backend u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Ovo je korisno kada native Go fuzzer zastane na **složenim poređenjima**, **tipiziranim ulazima** ili **formatima sa intenzivnim parsiranjem**. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za seedove i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite gosentry `go` binarnim fajlom umesto standardnog toolchain-a.
- Tretirajte rezultujuću kampanju kao uobičajeno coverage-guided pokretanje, ali sa LibAFL scheduling/mutation mehanizmima i boljim pratećim detektorima.

### Pretvaranje tihih grešaka u fuzz nalaze

Čest problem u Go procenama jeste to što se opasno ponašanje često **podrazumevano ne završava crash-om**. Uz gosentry, nekoliko klasa „loših, ali tihih“ stanja možete pretvoriti u nalaze:

- `--panic-on=pkg.Func,...` kako bi odabrane logging/error putanje funkcionisale kao crash-ovi (korisno za putanje koda u stilu `log.Fatal`, koje bi inače samo evidentirale grešku i nastavile izvršavanje).
- `--catch-races=true` kako bi se novootkriveni unosi iz queue-a ponovo pokrenuli sa Go race detector-om.
- `--catch-leaks=true` kako bi se novi unosi iz queue-a ponovo pokrenuli pomoću `goleak` i izvršavanje zaustavilo pri otkrivanju curenja goroutine-a.
- LibAFL hang handling kako bi **beskonačne petlje / veoma spori ulazi** ostali fuzz nalazi umesto da nestanu kao timeout-i.
- Ugrađene provere arithmetic overflow-a su podrazumevano uključene, uz opcione provere truncation-a kroz instrumentation u stilu go-panikint-a.

Ovo je naročito vredno za targete kod kojih je bezbednosni uticaj **parser failure bez panic-a**, **concurrency bug** ili hang koji izaziva samo **DoS**, a ne memory corruption.

### Fuzzing prilagođen struct tipovima za tipizirane Go API-je

Native Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira koristi tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (struct-ove, slice-ove, array-e, pointer-e), uz istovremeno mutiranje bajtova u pozadini.
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
Koristite ovo kada pravite lažni wire format samo za fuzzing, jer bi parsing kod koji postoji samo u harness-u sakrio logičke greške. Za differential ili grammar-based kampanje, zadržite ulaz u harness-u kao jednu vrednost tipa `[]byte` ili `string` i izvršite parsing unutar callback-a.

### Grammar-based fuzzing za parsere i protokolarne ulaze

Za parsere, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** povrh LibAFL-a. Gramatika je JSON niz production rules, a harness obično treba da prihvata jedan argument tipa `[]byte` ili `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Beleške o metodologiji:

- Koristite grammar mode kada mutacije na nivou bajtova uglavnom ne prolaze rane provere sintakse.
- Ograničite gramatiku na **security-relevant podskup** jezika/protokola umesto modelovanja cele specifikacije.
- Koristite velike granične vrednosti u terminalima/nonterminalima da biste opteretili ivice celih brojeva, dužina i state machine-a.
- Grammar mode održava ulaze validnim prema gramatici, ali target i dalje prima **bajtove/stringove**, tako da parsiranje i semantičke provere ostaju unutar harnessed koda.

### Differential fuzzing: upoređujte implementacije, ne samo crash-eve

Snažan obrazac za Go ekosisteme je **grammar-based differential fuzzing**: generišite validne strukturisane ulaze i prosledite ih dvama parserima, klijentima ili engine-ima za prelazak između stanja.
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
- nepodudaranja između prihvaćenih/odbijenih unosa
- različita stabla parsiranja ili dekodirani objekti
- različite tranzicije stanja, nonce vrednosti, bilansi ili koreni stanja

Ovo je praktičan način za pronalaženje **nepodudaranja u konsenzusu**, **dvosmislenosti parsera** i **odstupanja implementacije od specifikacije**, koja klasični fuzzing usmeren samo na crash često ne otkriva.

### Ponovna upotreba corpus-a kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo reprodukujte sačuvani queue corpus da biste generisali Go izveštaj o pokrivenosti bez ručnog izvoza zasebnog corpus-a:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Pokrenite komandu iz **istog package-a** i sa istim `-fuzz` targetom, kako bi gosentry razrešio odgovarajuće stanje keširane kampanje.

## Reference

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
