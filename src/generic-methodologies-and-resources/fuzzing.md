# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage naspram semantike

Kod **mutational grammar fuzzing-a**, ulazi se mutiraju tako da ostanu **grammar-valid**. U režimu vođenom coverage-om, kao corpus seeds čuvaju se samo uzorci koji aktiviraju **novi coverage**. Kod **jezičkih ciljeva** (parsera, interpretera, engine-a), ovim se mogu propustiti bagovi koji zahtevaju **semantičke/dataflow lance**, gde izlaz jedne konstrukcije postaje ulaz druge.<sup>[[1]](#references)</sup>

**Način otkaza:** fuzzer pronalazi seeds koji pojedinačno aktiviraju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva povezani dataflow**, pa se uzorak koji je „bliži bugu“ odbacuje jer ne doprinosi novom coverage-u. Kada postoje **3+ zavisna koraka**, nasumična rekombinacija postaje skupa, a povratna informacija o coverage-u ne usmerava pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** za gramatike sa mnogo zavisnosti, razmotrite **kombinovanje mutational i generative faza** ili usmeravanje generisanja ka obrascima **function chaining-a** (ne samo ka coverage-u).<sup>[[1]](#references)</sup>

## Zamke u raznovrsnosti corpusa

Mutacija vođena coverage-om je **pohlepna**: uzorak koji donosi novi coverage čuva se odmah, često uz zadržavanje velikih neizmenjenih delova. Vremenom corpora postaju **skoro identični duplikati** sa malom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **minimizacija koja uzima u obzir gramatiku** i **zaustavlja se nakon dostizanja minimalnog broja tokena** (smanjuje šum, ali zadržava dovoljno okolne strukture da bi uzorak i dalje bio pogodan za mutacije).<sup>[[1]](#references)</sup>

Praktično pravilo za corpus pri mutational fuzzing-u glasi: **dajte prednost malom skupu strukturno različitih seed-ova koji maksimizuju coverage-u** u odnosu na veliku gomilu skoro identičnih duplikata. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni corpora, crawling, zabeleženi saobraćaj, skupovi fajlova iz ekosistema cilja).
- Svedite ih na manju meru pomoću **minimizacije corpusa zasnovane na coverage-u**, umesto da zadržite svaki validan uzorak.
- Zadržite seeds dovoljno malim da mutacije pogađaju smislena polja, umesto da troše većinu ciklusa na nebitne bajtove.
- Ponovo pokrenite minimizaciju corpusa nakon većih izmena harness-a/instrumentacije, jer se „najbolji“ corpus menja kada se promeni dostupnost putanja.

## Mutation koja uzima u obzir poređenja za magic vrednosti

Čest razlog zbog kog fuzzers prestaju da napreduju nisu sintaksne prepreke, već **direktna poređenja**: magic bajtovi, provere dužine, enum stringovi, kontrolne sume ili vrednosti za usmeravanje parsera koje su zaštićene pomoću `memcmp`, switch tabela ili niza poređenja. Čista nasumična mutacija uzalud troši cikluse pokušavajući da pogodi ove vrednosti bajt po bajt.

Za ove ciljeve koristite **praćenje poređenja** (na primer, AFL++ `CMPLOG` / Redqueen-style tokove rada) kako bi fuzzer mogao da posmatra operande neuspelih poređenja i usmerava mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>

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

- Ovo je posebno korisno kada cilj skriva dublju logiku iza **potpisa datoteka**, **glagola protokola**, **oznaka tipova** ili **bitova funkcionalnosti koji zavise od verzije**.
- Kombinujte ga sa **dictionaries** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali dictionary sa gramatičkim tokenima, nazivima chunkova, glagolima i delimiterima često je vredniji od ogromne generičke liste reči.
- Ako cilj izvršava mnogo uzastopnih provera, prvo rešite najranija poređenja „magic“, a zatim ponovo minimizujte dobijeni corpus kako bi kasnije faze počele sa već validnim prefiksima.

## Bogatije povratne informacije kada edge coverage stapa različite putanje

Uobičajeni edge coverage ne može da razlikuje dva izvršavanja koja prolaze kroz isti helper iz različitih pozivalaca ili koriste različite kombinacije grana unutar funkcije. Ovo je važno u deljenim decoderima, dispečerima protokola i helperima interpretera, gde **putanja** do ivice određuje aktivno stanje. Naivno praćenje svakog konteksta pozivanja takođe je rizično: mapa pokrivenosti i red čekanja mogu naglo da porastu. Zato istraživanja context-sensitive fuzzinga preporučuju da se preciziraju samo obećavajući konteksti, umesto da se ceo graf poziva tretira kao context-sensitive.<sup>[[14]](#references)</sup>

Novije verzije AFL++-a, pored uobičajenog edge coverage-a, nude **Ball-Larus pokrivenost putanja po funkciji**. Ona dodeljuje feature svakoj acikličnoj putanji kroz funkciju; povratne ivice petlji se uklanjaju, pa ova povratna informacija razlikuje kombinacije grana, ali **ne i broj iteracija petlje**. Počnite sa opuštenim nivoom `1`, a zatim strože režime ograničite na sumnjivi kod parsera i mašina stanja, jer broj putanja može eksponencijalno da raste.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Za pomoćnu funkciju koja se poziva sa mnogih bezbednosno relevantnih mesta, LTO režim može da kombinuje putanju svake funkcije sa njenim neposrednim mestom poziva:<sup>[[13]](#references)</sup>

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

**Smernice za kampanju:** oprezno primenjujte bogatiji feedback i pratite njegovu cenu u map/queue resursima.<sup>[[13]](#references)[[14]](#references)</sup>

- Paralelno pokrenite običnu instancu sa edge coverage; bogatiji feedback je koristan samo ako dodatni trošak za queue/map ne smanjuje broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da ograničite path/caller instrumentaciju kada velike biblioteke sa mnogo template-a ili generički uslužni kod dominiraju mapom.
- Funkcije sa prevelikim brojem acikličnih putanja mogu se preskočiti pomoću AFL++; upozorenja tokom kompilacije ukazuju na to da cilj zahteva allowlisting ili manje strog nivo.
- Caller + path coverage podržava samo jednu dubinu caller-a. Nemojte je kombinovati sa dubljim context stack-ovima.
- Path ID-jevi mogu da se promene između glavnih verzija LLVM-a. Tokom kampanje koristite isti toolchain i nemojte sinhronizovati korpuse zasnovane na PATH-u kao da su njihovi ID-jevi feature-a stabilni između build-ova.
- Ovaj feedback dopunjuje `CMPLOG`: praćenje poređenja utvrđuje **koja vrednost prolazi guard**, dok path/caller feedback čuva **koja putanja i kombinacija grana su dovele do njega**.

## Stateful Fuzzing: Sekvence su seed-ovi

Kod **protokola**, **autentifikovanih radnih tokova** i **parsera u više faza**, zanimljiva jedinica često nije jedan blob, već **sekvenca poruka**. Spajanje celog transkripta u jednu datoteku i nasumično menjanje obično je neefikasno, jer fuzzer menja svaki korak podjednako, čak i kada samo kasnija poruka dovodi do krhkog stanja.<sup>[[4]](#references)</sup>

Učinkovitiji obrazac je da se **sama sekvenca** tretira kao seed, a da se **uočljivo stanje** (kodovi odgovora, stanja protokola, faze parsera, tipovi vraćenih objekata) koristi kao dodatni feedback.<sup>[[4]](#references)</sup>

- Održavajte **validne poruke prefiksa** nepromenjenim, a mutacije usmerite na poruku koja **pokreće prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada od njih zavisi sledeći korak.
- Dajte prednost mutaciji/splicing-u po poruci, a ne mutiranju celog serijalizovanog transkripta kao neprozirnog bloba.
- Ako protokol izlaže smislene kodove odgovora, koristite ih kao **jeftin state oracle** za davanje prioriteta sekvencama koje napreduju dublje.

Iz istog razloga, bagovi u autentifikovanim tokovima, skriveni prelazi ili bagovi parsera koji se javljaju „tek nakon handshake-a“ često promaknu klasičnom fuzzing-u datoteka: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing drajvera sa više klijenata

Visok edge coverage i dalje može da propusti bagove IPC drajvera, jer coverage ne opisuje **vlasništvo nad objektima, brojače referenci, poruke na čekanju, redosled čišćenja ni preplitanje niti**. Stranica [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) pokriva model objekata drajvera; ovaj primer se fokusira na harness fuzzera. Android Binder je koristan model: nije dovoljno dosegnuti i putanje za alokaciju i oslobađanje ako fuzzer ne može da navede više procesa da rade nad istim kernel objektom zahtevanim redosledom.<sup>[[15]](#references)</sup>

#### Modelujte protokol, a ne izolovane `ioctl` baferе

Predstavite testni slučaj kao uređenu gramatiku oblika **identitet klijenta + operacija + strukturisani argumenti**. Binder LKL fuzzer koristi protobuf i `libprotobuf-mutator`, uz jedan persistent klijent za context manager i dva obična klijenta. Semantički harness zatim čuva relacije koje bi slepa mutacija bajtova uništila.<sup>[[15]](#references)</sup>

- Keširajte vrednosti koje vraćaju ranije operacije. Na primer, `BC_FREE_BUFFER` mora ponovo da upotrebi pokazivač na transakциони bafer vraćen prethodnim `ioctl` pozivom.
- Generišite validne podrazumevane odgovore kako bi sinhrone transakcije mogle da se završe i da kasnije operacije ostanu dostupne.
- Odbacujte nemoguće prelaze, kao što su transakcije ka samom sebi ili više transakcija na čekanju ka istom cilju.
- Držite singleton bootstrap stanje izvan resetovanja po ulazu. Binder dozvoljava samo jednu registraciju `BINDER_SET_CONTEXT_MGR` tokom jednog boot-a, pa bi ponovljeno uništavanje i ponovno kreiranje tog klijenta učinilo kasnije ulaze nevalidnim.

Korisni obrazac za lifetime race jeste da jedan klijent prenese objekat, pokrene čišćenje niti ili procesa, a da prijemni klijent istovremeno oslobodi transakcioni bafer. U primeru CVE-2020-0423, prenos `BINDER_TYPE_WEAK_BINDER`, praćen trkom između `BINDER_THREAD_EXIT` i `BC_FREE_BUFFER`, mogao je da oslobodi ugrađeni `binder_work` dok ga je putanja za čišćenje izlazeće niti još koristila.<sup>[[15]](#references)</sup>

#### Ponovo uvedite kontrolisana preplitanja u kernelu iz userspace-a

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) povezuje stvarni kernel kod sa harness-om iz userspace-a i izlaže njegov syscall interfejs preko `lkl_syscall`. Tako je lako usklađivati protobuf stanje, coverage i KASAN u jednom procesu. LKL, međutim, obično izvršava syscall bez prekidanja druge kernel niti. Za race kampanje umetnite tačke `schedule()` oko odabranih granica zaključavanja/otključavanja i lifetime granica, a zatim prepustite harness-u da nasumično bira sledećeg klijenta pri svakom ustupanju izvršavanja. Pažljivo birajte ove tačke jer svaka od njih umnožava prostor pretrage rasporeda. Randomizovani scheduler koji su opisali istraživači **nije** deo upstream Binder fuzzera.<sup>[[15]](#references)</sup>

#### Napravite i ponovo reprodukujte serijalizovane regresione seed-ove

Upstream harness fiksira kompatibilnu verziju `libprotobuf-mutator`, uključuje LKL fuzzing instrumentaciju i KASAN pomoću `LKL_FUZZING=1`, a za Binder uključuje `CONFIG_MMU` pomoću `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nakon što preuzmete namerno ranjivu reviziju ili primenite rollback zakrpe dokumentovane u upstream-u, serijalizovani seed može da reprodukuje ceo prelaz stanja za više klijenata, bez potrebe da ga rekonstruišete u ad hoc C proof of concept-u:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tretirajte nastali KASAN use-after-free kao potvrdu da je seed stigao do ranjivog lifetime puta. To **ne** pokazuje kasnije primitive neophodne za izvršavanje koda u kernelu ili eskalaciju privilegija.<sup>[[16]](#references)</sup>

## Trik raznovrsnosti na jednoj mašini (u stilu Jackalope)

Praktičan način da se kombinuju **generativna novina** i **ponovna upotreba coverage-a** jeste da se **kratkotrajni worker-i restartuju** dok rade protiv persistent servera. Svaki worker počinje sa praznim corpus-om, sinhronizuje se posle `T` sekundi, zatim radi još `T` sekundi na kombinovanom corpus-u, ponovo se sinhronizuje i izlazi. Tako se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno korišćenje akumuliranog coverage-a.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sekvencijalni radnici (primer petlje):**

<details>
<summary>Petlja ponovnog pokretanja Jackalope radnika</summary>

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

- `-in empty` forsira **novi korpus** pri svakom generisanju.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo novine, kasnije ponovna upotreba).
- U režimu grammar fuzzing-a, **početna sinhronizacija sa serverom se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalna vrednost `T` **zavisi od cilja**; najbolje je preći na drugu vrednost kada worker pronađe većinu „lake“ pokrivenosti.

## Snapshot Fuzzing Za Ciljeve Koje Je Teško Obuhvatiti Harness-om

Kada kod koji želite da testirate postaje dostupan tek **nakon dugotrajne pripreme** (pokretanje VM-a, dovršavanje prijave, primanje paketa, parsiranje kontejnera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog procesa ili VM-a, ubacite svaki testni slučaj u putanju ulaza cilja, izvršavajte do pada/isteka vremena i vratite snapshot. Tako izbegavate ponavljanje inicijalizacije ili prefiksa protokola, a korisno je za **mrežne servise**, **firmware**, **attack surface nakon autentifikacije** i **binarne ciljeve**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite cilj dok ne bude spreman za zanimljivo stanje.
2. U tom trenutku napravite snapshot **memorije + registara**.
3. Za svaki testni slučaj, upišite izmenjeni ulaz direktno u odgovarajući bafer guest-a/procesa.
4. Izvršavajte do pada/isteka vremena/resetovanja.
5. Vratite snapshot; za VM ciljeve, vratite samo **izmenjene stranice** ako je to podržano, pa ponovite.

Postavite snapshot što je moguće bliže prvom skupom koraku parsiranja/dispatch-a, na primer nakon tačke `recv`/`read` ili deserijalizacije paketa, i zabeležite ulazni bafer koji cilj koristi. Ovo prati princip adaptivnog pozicioniranja: pomerajte snapshot dublje u obradu ulaza da biste izbegli ponavljanje posla.<sup>[[11]](#references)</sup>

## Introspekcija Harness-a: Rano Otkrijte Površne Fuzzere

Kada kampanja zastane, problem često nije mutator, već **harness**. Koristite **introspekciju dostupnosti/pokrivenosti** da pronađete funkcije koje su statički dostupne iz vašeg fuzz cilja, ali se retko ili nikada ne pokrivaju dinamički. Takve funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u cilj prekasno ili prerano.
- U seed korpusu nedostaje cela grupa funkcionalnosti.
- Cilju je zaista potreban **drugi harness**, a ne jedan preveliki harness koji „radi sve“.

Ako koristite tok rada u stilu OSS-Fuzz / ClusterFuzz, Fuzz Introspector može da uporedi statičku dostupnost sa runtime pokrivenošću i generiše izveštaje na osnovu vremenski ograničenog pokretanja ili javnog korpusa.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Koristite izveštaj da odlučite da li da dodate novi harness za neproverenu putanju parsera, proširite korpus za određenu funkcionalnost ili podelite monolitni harness na manje ulazne tačke.

## Izbor fuzz ciljeva i trijaža mutacija na osnovu grafa

Ako već imate **nalaze statičke analize**, **preživele mutacije iz testiranja mutacijama** i **izveštaje o pokrivenosti**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **graf poziva**, označite čvorove **ciklomatskom složenošću**, **dostupnošću sa entrypoint-a/nepouzdanim ulazom** i svim spoljnim nalazima, a zatim postavite pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije velike složenosti su dostupne iz nepouzdanog ulaza?
- Koje preživele mutacije se nalaze na putanjama od parsera/handlera do bezbednosno kritičnog koda?
- Koje funkcije predstavljaju arhitektonska uska grla sa neuobičajeno velikim **radijusom uticaja**?

Ovim se obično pronalaze bolji fuzz ciljevi nego samo na osnovu „najmanje pokrivenosti“. Parser/dekoder **visoke složenosti** sa potvrđenom **dostupnošću spolja** bolji je kandidat za harness od izolovanog internog pomoćnog koda sa slabom pokrivenošću, ali bez putanje kojom napadač može da utiče na njega.

### Praktični tok trijaže

1. Napravite **graf koda** na osnovu baze koda i izdvojite metrike složenosti/grana za svaku funkciju.
2. Navedite **entrypoint-e** koji prihvataju ulaz pod kontrolom napadača: handler-e zahteva, dekodere, uvoznike, parser-e protokola, čitače CLI-ja/datoteka.
3. Pokrenite **upite nad putanjama** od tih entrypoint-a do kandidatskih funkcija da biste odvojili dostupnu površinu za napad od neaktivnog koda ili koda dostupnog samo interno.
4. Dajte prioritet čvorovima koji objedinjuju:
   - visoku **ciklomatsku složenost**
   - potvrđenu **dostupnost iz nepouzdanog ulaza**
   - veliki **radijus uticaja** ili veliki broj zavisnih komponenti
   - dodatne dokaze kao što su nalazi **SARIF**-a, beleške iz revizije ili preživele mutacije
5. Najpre napišite fokusirane harness-e za čvorove sa najboljim rezultatom, posebno za **parser-e/kodeke** kao što su dekoderi za hex/Base64/IP/poruke.

### Preživele mutacije: ekvivalentne ili korisne za dalje postupanje

Testiranje mutacijama često daje bučnu listu preživelih mutacija. Pre nego što svaku preživelu mutaciju protumačite kao bezbednosni propust, pomoću grafa proverite:

- Da li je mutirana funkcija dostupna sa entrypoint-a pod kontrolom napadača?
- Da li su sve putanje poziva ograničene jačim invariantama od mutirane provere?
- Da li se čvor nalazi u neaktivnom kodu, logici koja služi samo za formatiranje ili putanji sa aritmetikom/parserom velikog uticaja?

Mutacije koje ostaju nedostupne ili su strukturno ograničene često su **ekvivalentni mutanti**. Mutacije koje ostaju **dostupne** i dotiču **granične uslove**, **putanje overflow-a/prenosa** ili **bezbednosno kritičnu aritmetiku/parsiranje** treba unaprediti u:

- nove fuzz harness-e
- direktne testove svojstava/invarijanti
- ciljane skupove vektora za granične slučajeve

### Povežite spoljne nalaze sa grafom

Ako vaš SAST pipeline izvozi **SARIF**, mapirajte nalaze na čvorove grafa prema **datoteci i opsegu redova** i pomoću grafa proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **radijus uticaja** označene funkcije
- proverite da li se nalaz nalazi na nekoj putanji od entrypoint-a
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno pri odlučivanju da li da vreme za fuzzing uložite u određenu funkciju: čvor koji je **dostupan**, **složen** i već ima **SAST nalaze** često je bolja meta od čvora koji je samo složen, ali nema putanju dostupnu napadaču.

Primer toka rada pomoću Trailmark-a.<sup>[[6]](#references)</sup>

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

Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite graf da biste izabrali fuzz mete s najvećom očekivanom bezbednosnom vrednošću, a zatim pomoću mutacija koje prežive odlučite koje granice i invarijante vaš harness treba da testira.<sup>[[5]](#references)</sup>

## Fuzzing u Go-u pomoću gosentry: Snažniji mehanizam, tipizirani ulazi i diferencijalne provere

Ako Go meta već ima nativni `testing.F` harness, praktičan način za nadogradnju jeste da pokrenete isti harness pomoću [gosentry](https://github.com/trailofbits/gosentry), fork-ovanog Go toolchain-a koji zadržava `go test -fuzz`, ali menja backend u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Ovo je korisno kada izvorni Go fuzzer zapne na **teškim poređenjima**, **tipiziranim ulazima** ili **formatima koji zahtevaju mnogo parsiranja**. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za početne vrednosti i `f.Fuzz(...)` za callback.
- Ponovo upotrebite isti harness, ali ga pokrenite gosentry-jevim binarnim fajlom `go` umesto standardnog toolchain-a.
- Tretirajte dobijenu kampanju kao uobičajeno fuzzing pokretanje vođeno pokrivenošću, ali uz LibAFL raspoređivanje/mutacije i bolje prateće detektore.

### Pretvaranje tihih grešaka u fuzz nalaze

Čest problem u Go procenama jeste to što opasno ponašanje često **ne izazove** podrazumevani crash. Pomoću gosentry-ja možete više klasa „loših, ali tihih“ stanja pretvoriti u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da bi odabrane putanje za logovanje/greške izazivale crash (korisno za putanje koda u stilu `log.Fatal`, koje bi inače samo zabeležile grešku i nastavile dalje).
- `--catch-races=true` da bi se novootkrivene stavke reda ponovo izvršile uz Go detektor race uslova.
- `--catch-leaks=true` da bi se nove stavke reda ponovo izvršile uz `goleak` i zaustavile pri otkrivanju curenja gorutina.
- Obrada hang-ova u LibAFL-u, koja čuva **beskonačne petlje / veoma spore ulaze** kao fuzz nalaze umesto da ih odbaci kao prekoračenja vremena.
- Podrazumevano uključene ugrađene provere aritmetičkog prekoračenja, uz opcione provere skraćivanja pomoću instrumentacije u stilu go-panikint-a.

Ovo je naročito korisno za ciljeve kod kojih je bezbednosni uticaj **greška parsera bez panike**, **greška konkurentnosti** ili **hang koji izaziva samo DoS**, a ne oštećenje memorije.

### Fuzzing Go API-ja sa tipiziranim strukturama

Izvorni Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira koristi tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (strukture, slice-ove, nizove, pokazivače), uz istovremeno menjanje bajtova u pozadini.<sup>[[7]](#references)[[8]](#references)</sup>

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

Ovo koristite kada bi pravljenje lažnog wire formata samo za fuzzing sakrilo logičke greške iza koda za parsiranje koji postoji samo u harness-u. Za differential ili grammar-based kampanje, zadržite ulaz za harness kao jedan `[]byte` ili `string`, a parsirajte ga unutar callback-a.

### Grammar-based fuzzing za parser-e i protokolarne ulaze

Za parser-e, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** povrh LibAFL-a. Gramatika je JSON niz produkcionih pravila, a harness bi obično trebalo da uzima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Napomene o metodologiji:

- Koristite režim gramatike kada mutacije na nivou bajtova uglavnom ne prolaze rane provere sintakse.
- Ograničite gramatiku na **bezbednosno relevantan podskup** jezika/protokola, umesto da modelujete celu specifikaciju.
- Koristite velike granične vrednosti u terminalima/neterminalima da biste opteretili granice celih brojeva, dužina i mašine stanja.
- Režim gramatike održava ulaze validnim prema gramatici, ali cilj i dalje prima **bajtove/niske**, tako da parsiranje i semantičke provere ostaju unutar koda obuhvaćenog harness-om.

### Differential fuzzing: upoređujte implementacije, ne samo crash-eve

Za Go ekosisteme, snažan obrazac je **fuzzing zasnovan na gramatici i diferencijalnom poređenju**: generišite validne strukturirane ulaze i prosleđujte ih dvama parserima, klijentima ili mašinama za prelaze stanja.<sup>[[7]](#references)[[8]](#references)</sup>

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

Smatrajte sledeće nalazima:

- jedna implementacija izaziva panic, dok druga uredno odbacuje unos
- nepodudaranja u prihvatanju/odbacivanju unosa
- različita stabla parsiranja ili dekodirani objekti
- različite promene stanja, nonce vrednosti, stanja na računima ili koreni stanja

Ovo je praktičan način za pronalaženje **nepodudaranja u konsenzusu**, **dvosmislenosti parsera** i **odstupanja između specifikacije i implementacije**, koje čisto fuzz testiranje padova često ne otkriva.

### Ponovo iskoristite korpus kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo pokrenite sačuvani korpus iz reda čekanja da biste generisali Go izveštaj o pokrivenosti bez ručnog izvoza zasebnog korpusa.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` kako bi gosentry razrešio odgovarajuće keširano stanje kampanje.



## References

- [1] [Mutaciono fuzzing testiranje gramatike](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing testiranje izbliza](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing testiranje protokola vođeno pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Forkovali smo lanac alata da to popravimo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brz greybox fuzzer za mrežne protokole sa stanjima pomoću snimaka](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: ka fuzzing testiranju Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasno fuzzing testiranje sa prilagodljivim i promenljivim snimcima](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentacija: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivno fuzzing testiranje osetljivo na kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - fuzzing testiranje Binder-a](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - dokumentacija za build i regresione seed-ove](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
