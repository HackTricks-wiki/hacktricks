# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutaciono grammar fuzzing testiranje: Coverage naspram semantike

Kod **mutacionog grammar fuzzing testiranja**, ulazi se menjaju dok ostaju **validni prema gramatici**. U režimu vođenom coverage-om, kao corpus seeds čuvaju se samo uzorci koji aktiviraju **novi coverage**. Kod **jezičkih targeta** (parseri, interpreteri, engine-i), ovim se mogu propustiti bugovi koji zahtevaju **semantičke/dataflow lance**, gde izlaz jedne konstrukcije postaje ulaz druge.<sup>[[1]](#references)</sup>

**Režim greške:** fuzzer pronalazi seed-ove koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani dataflow**, pa se uzorak „bliži-bugu“ odbacuje jer ne dodaje coverage. Sa **3+ zavisna koraka**, nasumična rekombinacija postaje skupa, a feedback na osnovu coverage-a ne usmerava pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** kod grammar-a sa mnogo zavisnosti razmotrite **hibridizaciju mutacionih i generativnih faza** ili usmeravanje generisanja ka obrascima **ulančavanja funkcija** (ne samo ka coverage-u).<sup>[[1]](#references)</sup>

## Zamke raznovrsnosti corpusa

Mutation vođen coverage-om je **pohlepan**: uzorak sa novim coverage-om odmah se čuva, često uz zadržavanje velikih neizmenjenih delova. Vremenom corpora postaju **skoro identični primerci** sa malom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **minimizacija prilagođena grammar-u** koja **zaustavlja proces nakon dostizanja minimalnog praga tokena** (smanjuje šum, ali zadržava dovoljno okolne strukture da ostane pogodna za mutation).<sup>[[1]](#references)</sup>

Praktično pravilo za corpus kod mutacionog fuzzing-a jeste: **dajte prednost malom skupu strukturno različitih seed-ova koji maksimizuju coverage** u odnosu na veliku gomilu skoro identičnih primeraka. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni corpora, crawling, uhvaćen saobraćaj, skupovi fajlova iz ekosistema targeta).
- Preradite ih pomoću **minimizacije corpusa zasnovane na coverage-u**, umesto da zadržite svaki validan uzorak.
- Seed-ovi treba da budu **dovoljno mali** da mutacije pogađaju smislena polja, umesto da se većina ciklusa troši na nebitne bajtove.
- Ponovo pokrenite minimizaciju corpusa nakon većih promena harness-a/instrumentacije, jer se „najbolji“ corpus menja kada se promeni reachability.

## Mutation zasnovan na poređenju za magic vrednosti

Čest razlog zbog kog fuzzer dostigne plato nisu sintaksa, već **teška poređenja**: magic bajtovi, provere dužine, enum stringovi, checksum-ovi ili dispatch vrednosti parsera zaštićene pomoću `memcmp`, switch tabela ili kaskadnih poređenja. Čista nasumična mutation troši cikluse pokušavajući da pogodi ove vrednosti bajt po bajt.

Za ove targete koristite **praćenje poređenja** (na primer AFL++ `CMPLOG` / Redqueen-style workflows), kako bi fuzzer mogao da posmatra operande iz neuspešnih poređenja i usmerava mutation ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>
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
- Kombinujte ga sa **dictionaries** izdvojenim iz stvarnih primera, specifikacija protokola ili debug logova. Mali rečnik sa grammar tokenima, nazivima chunk-ova, glagolima i delimiterima često je vredniji od ogromne generičke wordliste.
- Ako cilj izvršava mnogo sekvencijalnih provera, prvo rešite najranija poređenja „magic“ vrednosti, a zatim ponovo minimizujte dobijeni korpus kako bi kasnije faze počele sa već validnim prefiksima.

## Bogatije povratne informacije kada se Edge Coverage-om spajaju različite putanje

Normalni edge coverage ne može da razlikuje dva izvršavanja koja prolaze kroz isti helper preko različitih pozivalaca ili koriste različite kombinacije grana unutar funkcije. Ovo je važno kod deljenih decoder-a, protocol dispatcher-a i interpreter helper-a, gde **ruta** do edge-a određuje aktivno stanje. Naivno praćenje svakog calling context-a takođe je opasno: coverage mapa i queue mogu nekontrolisano da narastu. Istraživanja context-sensitive fuzzing-a zato preporučuju da se preciziraju samo obećavajući konteksti, umesto da se ceo call graph tretira kao context-sensitive.<sup>[[14]](#references)</sup>

Novije AFL++ verzije pružaju **Ball-Larus per-function path coverage** pored normalnog edge coverage-a. Dodeljuje feature svakoj acikličnoj putanji kroz funkciju; loop back-edge-ovi se uklanjaju, pa ove povratne informacije razlikuju kombinacije grana, ali **ne i broj iteracija petlje**. Počnite sa opuštenim nivoom `1`, a zatim strože režime ograničite na sumnjivi parser/state-machine kod, jer broj putanja može eksponencijalno da raste.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Za pomoćnu funkciju koju pozivaju mnoga bezbednosno relevantna mesta, LTO režim može kombinovati putanju svake funkcije sa njenim neposrednim mestom poziva:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Smernice za kampanju:** oprezno primenjujte bogatiji feedback i pratite njegov trošak u pogledu mape pokrivenosti i queue-a.<sup>[[13]](#references)[[14]](#references)</sup>

- Pokrenite paralelno običnu instancu sa edge-coverage-om; bogatiji feedback je koristan samo ako dodatni trošak queue-a/mape ne smanji broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da ograničite path/caller instrumentation kada velike biblioteke sa mnogo template-a ili generički utility kod dominiraju mapom.
- Funkcije sa previše acikličnih putanja mogu se preskočiti pomoću AFL++; upozorenja tokom kompajliranja ukazuju na to da target zahteva allowlisting ili manje strog nivo.
- Caller + path coverage podržava samo jednu dubinu caller-a. Nemojte ga kombinovati sa dubljim context stack-ovima.
- Path ID-jevi mogu da se promene između glavnih LLVM verzija. Koristite isti toolchain tokom kampanje i nemojte sinhronizovati corpora zasnovane na PATH-u kao da su njihovi feature ID-jevi stabilni između build-ova.
- Ovaj feedback dopunjuje `CMPLOG`: tracing poređenja rešava **koja vrednost prolazi guard**, dok path/caller feedback čuva **koja ruta i kombinacija grana je do nje dovela**.

## Stateful Fuzzing: Sekvence su seed-ovi

Kod **protokola**, **autentifikovanih workflow-a** i **parsera u više faza**, interesantna jedinica često nije jedan blob, već **sekvenca poruka**. Spajanje celog transkripta u jedan fajl i njegovo nasumično mutiranje obično je neefikasno jer fuzzer podjednako mutira svaki korak, čak i kada samo kasnija poruka doseže osetljivo stanje.<sup>[[4]](#references)</sup>

Efikasniji pristup je da se **sama sekvenca** tretira kao seed i da se **uočljivo stanje** (response kodovi, stanja protokola, faze parsera, tipovi vraćenih objekata) koristi kao dodatni feedback.<sup>[[4]](#references)</sup>

- Održavajte **validne prefiksne poruke** stabilnim i fokusirajte mutacije na poruku koja **pokreće tranziciju**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Dajte prednost mutiranju/spajanju po porukama u odnosu na mutiranje celog serijalizovanog transkripta kao neprovidnog blob-a.
- Ako protokol izlaže značajne response kodove, koristite ih kao **jeftin oracle stanja** za davanje prioriteta sekvencama koje napreduju dublje.

To je isti razlog zbog kog vanilla file-style fuzzing često propušta autentifikovane bugove, skrivene tranzicije ili parser bugove koji se javljaju „tek nakon handshake-a“: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

## Trik za raznovrsnost na jednoj mašini (u stilu Jackalope-a)

Praktičan način za hibridizaciju **generativne novine** sa **ponovnim korišćenjem coverage-a** jeste **restartovanje kratkotrajnih worker-a** nad persistent serverom. Svaki worker počinje sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi nad kombinovanim corpus-om, zatim se gasi. Time se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno korišćenje akumuliranog coverage-a.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekvencijalni workers (primer petlje):**

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

- `-in empty` forsira **novi corpus** pri svakoj generaciji.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo novine, kasnije ponovna upotreba).
- U režimu grammar fuzzing, **početna sinhronizacija servera se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalni `T` zavisi od **targeta**; prebacivanje nakon što worker pronađe većinu „lake“ coverage obično daje najbolje rezultate.

## Snapshot Fuzzing For Hard-To-Harness Targets

Kada kod koji želite da testirate postane dostupan tek nakon velikog troška inicijalnog podešavanja (pokretanje VM-a, završavanje prijavljivanja, prijem paketa, parsiranje containera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog procesa ili VM-a, ubacite svaki test case u ulaznu putanju targeta, izvršavajte do crash-a/timeout-a i vratite snapshot. Ovo izbegava ponavljanje inicijalizacije ili protokolskih prefiksa i korisno je za **network services**, **firmware**, **post-auth attack surfaces** i **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite target dok interesantno stanje ne bude spremno.
2. Napravite snapshot **memorije + registara** u tom trenutku.
3. Za svaki test case upišite izmenjeni input direktno u relevantni guest/process buffer.
4. Izvršavajte do crash-a/timeout-a/reset-a.
5. Vratite snapshot; za VM targete, kada je podržano, vratite samo **dirty pages**, a zatim ponovite postupak.

Postavite snapshot što je praktičnije moguće blizu prvog skupog koraka parsiranja/dispečovanja, na primer nakon tačke `recv`/`read` ili deserializacije paketa, i zabeležite input buffer koji target koristi. Ovo prati princip adaptivnog postavljanja: pomeranje snapshota dublje u obradu inputa kako bi se izbeglo ponavljanje posla.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Kada campaign stagnira, problem često nije u mutatoru, već u **harness-u**. Koristite **reachability/coverage introspection** da pronađete funkcije koje su statički dostupne iz vašeg fuzz targeta, ali se retko ili nikada ne pokrivaju dinamički. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u target prekasno ili prerano.
- Seed corpus-u nedostaje cela familija funkcionalnosti.
- Targetu je zaista potreban **drugi harness**, umesto jednog prevelikog „radi sve“ harness-a.

Ako koristite OSS-Fuzz / ClusterFuzz-style workflow-e, Fuzz Introspector može da uporedi statičku reachability sa runtime coverage-om i generiše izveštaje na osnovu vremenski ograničenog pokretanja ili javnog corpusa.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Koristite izveštaj da odlučite da li treba dodati novi harness za neproverenu putanju parsera, proširiti corpus za određenu funkcionalnost ili podeliti monolitni harness na manje entry point-e.

## Graph-First izbor Fuzz Target-a i trijaža mutacija

Ako već imate **static-analysis nalaze**, **mutation-testing survivore** i **coverage izveštaje**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **call graph**, anotirajte čvorove sa **cyclomatic complexity**, dostižnošću iz **entrypoint-a/nepoverljivog inputa** i svim spoljnim nalazima, a zatim postavljajte pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostižne iz nepoverljivog inputa?
- Koji mutation survivori se nalaze na putanjama od parsera/handlera do security-critical koda?
- Koje funkcije predstavljaju arhitektonske uska grla sa neuobičajeno velikim **blast radius**-om?

Ovim se obično otkrivaju bolji fuzz target-i nego korišćenjem kriterijuma „najmanji coverage“. Parser/decoder sa **visokom složenošću** i potvrđenom **spoljnom dostižnošću** bolji je kandidat za harness nego izolovani interni helper sa slabim coverage-om, ali bez putanje kojom upravlja napadač.

### Praktični workflow trijaže

1. Napravite **code graph** iz codebase-a i izdvojite metrike složenosti/grana za svaku funkciju.
2. Nabrojte **entrypoint-e** koji prihvataju input pod kontrolom napadača: request handler-e, decoder-e, importer-e, protocol parser-e, CLI/file reader-e.
3. Pokrenite **path query-je** od tih entrypoint-a do kandidatskih funkcija kako biste odvojili dostižnu attack surface od mrtvog koda ili koda dostupnog samo interno.
4. Dajte prioritet čvorovima koji kombinuju:
- visoku **cyclomatic complexity**
- potvrđenu **dostižnost iz nepoverljivog inputa**
- veliki **blast radius** ili veliki broj downstream zavisnosti
- dodatne dokaze, kao što su **SARIF** nalazi, beleške iz audita ili mutation survivori
5. Najpre napišite fokusirane harness-e za čvorove sa najboljim skorom, naročito za **parser/codecs** kao što su hex/Base64/IP/message decoder-i.

### Mutation survivori: equivalent nasuprot actionable

Mutation testing često proizvodi bučnu listu survivora. Pre nego što svaki survivor tretirate kao security gap, koristite graf da postavite sledeća pitanja:

- Da li je izmenjena funkcija dostižna iz entrypoint-a pod kontrolom napadača?
- Da li su sve call path-e ograničene jačim invariantama od izmenjene provere?
- Da li se čvor nalazi u mrtvom kodu, logici koja utiče samo na formatiranje ili u arithmetic/parser putanji sa velikim uticajem?

Survivori koji ostaju nedostižni ili strukturno ograničeni često su **equivalent mutants**. Survivori koji ostaju **dostižni** i dodiruju **granične uslove**, **overflow/carry putanje** ili **security-critical arithmetic/parsing** treba da budu promovisani u:

- nove fuzz harness-e
- direktne property/invariant testove
- ciljane vektore za edge case-ove

### Korelacija spoljnih nalaza sa grafom

Ako vaš SAST pipeline izvozi **SARIF**, projektujte nalaze na čvorove grafa prema **file + line range** i koristite graf za proširivanje procene uticaja.<sup>[[6]](#references)</sup>

- izračunajte **blast radius** označene funkcije
- proverite da li se nalaz nalazi na bilo kojoj putanji od entrypoint-a
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno kada odlučujete da li da vreme za fuzzing potrošite na određenu funkciju: čvor koji je **dostižan**, **složen** i već ima **SAST nalaze** često je bolji target od samo složenog čvora bez attack path-e.

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
Važna metodologija je presek: **complexity x exposure x impact**. Koristite graf da izaberete fuzz targets sa najvećom očekivanom bezbednosnom vrednošću, a zatim koristite mutation survivors da odlučite koje granice i invarijante vaš harness mora da testira.<sup>[[5]](#references)</sup>

## Go Fuzzing sa gosentry: Jači engine, tipizirani inputi i differential checks

Ako Go target već ima native `testing.F` harness, praktičan put za nadogradnju jeste pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), forked Go toolchain-a koji zadržava `go test -fuzz`, ali menja backend u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Ovo je korisno kada se native Go fuzzer zaustavi na **hard comparisons**, **typed inputs** ili formatima koji intenzivno koriste **parser**. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za seed-ove i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite pomoću gosentry `go` binarnog fajla umesto standardnog toolchain-a.
- Tretirajte dobijenu kampanju kao normalno coverage-guided izvršavanje, ali sa LibAFL scheduling/mutation mehanizmima i boljim pratećim detektorima.

### Pretvaranje tihih grešaka u fuzz nalaze

Čest problem u Go procenama jeste to što se opasno ponašanje često podrazumevano **ne završava crash-om**. Uz gosentry, nekoliko klasa „loših, ali tihih“ stanja možete pretvoriti u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` omogućava da odabrane logging/error putanje rade kao crash-ovi (korisno za `log.Fatal`-stil putanja koje bi inače samo zapisale log i nastavile izvršavanje).
- `--catch-races=true` ponovo izvršava novootkrivene stavke queue-a pomoću Go race detector-a.
- `--catch-leaks=true` ponovo izvršava nove stavke queue-a pomoću `goleak` i zaustavlja se pri otkrivanju goroutine leak-ova.
- LibAFL hang handling zadržava **infinite loops / veoma spore inpute** kao fuzz nalaze, umesto da nestanu kao timeout-i.
- Ugrađene provere arithmetic overflow-a su podrazumevano uključene, uz opcione provere truncation-a kroz instrumentation u stilu go-panikint-a.

Ovo je naročito vredno za targete kod kojih je bezbednosni uticaj **parser failure bez panic-a**, **concurrency bug** ili hang koji izaziva samo **DoS**, a ne memory corruption.

### Struct-aware fuzzing za typed Go API-je

Native Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira koristi typed objekte, gosentry može direktno da fuzz-uje **composite values** (struct-ove, slice-ove, array-e i pointer-e), uz istovremenu mutaciju bajtova u pozadini.<sup>[[7]](#references)[[8]](#references)</sup>
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
Koristite ovo prilikom izrade lažnog wire formata samo za fuzzing, jer bi logičke greške bile skrivene iza koda za parsiranje koji postoji samo u harness-u. Za differential ili grammar-based kampanje, zadržite ulaz u harness-u kao jedan `[]byte` ili `string` i parsirajte ga unutar callback-a.

### Grammar-based fuzzing za parser-e i protokole

Za parser-e, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** povrh LibAFL-a. Grammar je JSON niz produkcionih pravila, a harness obično treba da prihvata jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Napomene o metodologiji:

- Koristite grammar mode kada byte-level mutacije uglavnom bivaju odbačene u ranim proverama sintakse.
- Održavajte grammar usmerenom na **bezbednosno relevantan podskup** jezika/protokola, umesto modelovanja kompletne specifikacije.
- Koristite velike granične vrednosti u terminalima/neterminalima kako biste opteretili granice celih brojeva, dužina i state machine-a.
- Grammar mode održava ulaze validnim prema grammar-u, ali target i dalje dobija **byte-ove/string-ove**, tako da parsiranje i semantičke provere ostaju unutar koda obuhvaćenog harness-om.

### Differential fuzzing: poređenje implementacija, a ne samo crash-eva

Snažan obrazac za Go ekosisteme jeste **grammar-based differential fuzzing**: generišite validne strukturirane ulaze i prosledite ih dvama parserima, klijentima ili engine-ima za tranzicije stanja.<sup>[[7]](#references)[[8]](#references)</sup>
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
- nepodudaranja između prihvaćenih/odbijenih inputa
- različita stabla parsiranja ili dekodirani objekti
- različite tranzicije stanja, nonce vrednosti, balansi ili koreni stanja

Ovo je praktičan način za pronalaženje **consensus mismatches**, **parser ambiguity** i **spec-vs-implementation drift** problema koje čisto fuzzing testiranje usmereno na crash često ne otkriva.

### Ponovna upotreba campaign corpusa za izveštavanje o coverage-u

Nakon campaign-a, replay-ujte sačuvani queue corpus da biste generisali Go coverage report bez ručnog exportovanja zasebnog corpusa.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Pokrenite komandu iz **istog paketa** i sa istim `-fuzz` ciljem kako bi gosentry razrešio odgovarajuće keširano stanje campaign-a.



## References

- [1] [Fuzzing mutacionom gramatikom](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing protokola vođen pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Forkovali smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: brzi greybox fuzzer za stateful mrežne protokole koji koristi snapshot-e](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: ka fuzzingu Linux kernela bez opisa system call-ova](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: efikasan fuzzing sa adaptivnim i promenljivim snapshot-ima](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivni context-sensitive fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
