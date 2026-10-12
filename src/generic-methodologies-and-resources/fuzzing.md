# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage naspram semantike

Kod **mutational grammar fuzzing-a**, ulazi se menjaju tako da ostanu **validni prema gramatici**. U režimu vođenom coverage-om, kao corpus seeds čuvaju se samo uzorci koji ostvaruju **novi coverage**. Kod **jezičkih ciljeva** (parsera, interpretera, engine-a), ovim se mogu propustiti greške koje zahtevaju **semantičke/dataflow lance**, gde izlaz jednog konstrukta postaje ulaz drugog.<sup>[[1]](#references)</sup>

**Način otkaza:** fuzzer pronalazi seeds koji pojedinačno aktiviraju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani dataflow**, pa se uzorak „bliži grešci“ odbacuje jer ne povećava coverage. Kada postoje **3+ zavisna koraka**, nasumično ponovno kombinovanje postaje skupo, a povratne informacije o coverage-u ne usmeravaju pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** kod gramatika sa mnogo zavisnosti, razmotrite **kombinovanje mutacionih i generativnih faza** ili usmeravanje generisanja ka obrascima **ulančavanja funkcija** (ne samo ka coverage-u).<sup>[[1]](#references)</sup>

## Zamke u raznovrsnosti corpus-a

Mutacije vođene coverage-om su **pohlepe**: uzorak koji donosi novi coverage odmah se čuva, često uz zadržavanje velikih neizmenjenih delova. Vremenom corpus-i postaju **skoro duplikati** sa malom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **minimizacija koja uvažava gramatiku** i **zaustavlja se nakon dostizanja minimalnog broja tokena** (smanjuje šum, a zadržava dovoljno okolne strukture da bi uzorak ostao pogodan za mutacije).<sup>[[1]](#references)</sup>

Praktično pravilo za corpus pri mutacionom fuzzing-u glasi: **prednost dajte malom skupu strukturno različitih seed-ova koji maksimizuju coverage-u**, umesto velikoj gomili skoro duplikata. U praksi to obično znači sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni corpus-i, crawling, zabeležen saobraćaj, skupovi datoteka iz ciljnog ekosistema).
- Pročistite ih pomoću **minimizacije corpus-a zasnovane na coverage-u**, umesto da zadržite svaki validan uzorak.
- Seed-ove zadržite **dovoljno malim** da mutacije pogađaju smislena polja, umesto da se većina ciklusa troši na nebitne bajtove.
- Ponovo pokrenite minimizaciju corpus-a nakon većih izmena harness-a/instrumentacije, jer se „najbolji“ corpus menja kada se promeni dostupnost putanja u programu.

## Mutacije koje uzimaju u obzir poređenja za magične vrednosti

Čest razlog zbog kog fuzzers prestaju da napreduju nisu sintaksne prepreke, već **stroga poređenja**: magični bajtovi, provere dužine, enum stringovi, kontrolne sume ili vrednosti za usmeravanje parsera, koje se proveravaju pomoću `memcmp`, switch tabela ili nizova poređenja. Čiste nasumične mutacije troše cikluse pokušavajući da pogode te vrednosti bajt po bajt.

Za ove ciljeve koristite **praćenje poređenja** (na primer, tokove rada u stilu AFL++ `CMPLOG` / Redqueen), kako bi fuzzer mogao da posmatra operande neuspelih poređenja i usmerava mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>

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

- Ovo je naročito korisno kada cilj skriva naprednu logiku iza **potpisa datoteka**, **protocol verbs**, **type tags** ili bitova funkcija koji zavise od verzije.
- Kombinujte ga sa **rečnicima** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali rečnik sa gramatičkim tokenima, nazivima chunk-ova, glagolima i delimiterima često je vredniji od ogromne generičke liste reči.
- Ako cilj obavlja mnogo uzastopnih provera, prvo rešite najranija poređenja „magic“ vrednosti, a zatim ponovo minimizujte dobijeni korpus kako bi kasnije faze počele od već validnih prefiksa.

## Bogatije povratne informacije kada pokrivenost ivica svodi različite putanje na iste

Uobičajena pokrivenost ivica ne može da razlikuje dva izvršavanja koja prolaze kroz isti pomoćni kod, ali imaju različite pozivaoce ili prolaze kroz različite kombinacije grananja unutar funkcije. Ovo je važno u deljenim dekoderima, protocol dispatcher-ima i pomoćnim funkcijama interpretera, gde **putanja** do ivice određuje aktivno stanje. Naivno praćenje svakog konteksta poziva takođe je rizično: mapa pokrivenosti i red čekanja mogu nekontrolisano da narastu. Istraživanja context-sensitive fuzzing-a zato preporučuju da se preciziraju samo obećavajući konteksti, umesto da se ceo graf poziva tretira kao context-sensitive.<sup>[[14]](#references)</sup>

Novije verzije AFL++ obezbeđuju **Ball-Larus pokrivenost putanja po funkciji** kao dodatak uobičajenoj pokrivenosti ivica. Dodeljuje karakteristiku svakoj acikličkoj putanji kroz funkciju; povratne ivice petlji se uklanjaju, pa ove povratne informacije razlikuju kombinacije grananja, ali **ne i broj iteracija petlje**. Počnite od opuštenog nivoa `1`, a zatim strože režime ograničite na sumnjiv parser/state-machine kod jer broj putanja može eksponencijalno da poraste.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Za pomoćnu funkciju koja se poziva sa mnogo bezbednosno relevantnih mesta, LTO režim može da kombinuje putanju svake funkcije sa njenim neposrednim mestom poziva:<sup>[[13]](#references)</sup>

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

**Smernice za kampanju:** konzervativno primenjujte bogatije povratne informacije i pratite njihov uticaj na mapu pokrivenosti/red.<sup>[[13]](#references)[[14]](#references)</sup>

- Paralelno pokrenite uobičajenu instancu sa edge-coverage-om; bogatije povratne informacije su korisne samo ako dodatni trošak reda/mape ne smanji broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da ograničite instrumentaciju putanja/pozivalaca kada velike biblioteke s mnogo šablona ili generički pomoćni kod dominiraju mapom.
- Funkcije sa previše acikličnih putanja mogu da se preskoče u AFL++; upozorenja tokom kompilacije ukazuju na to da cilj treba allowlisting ili manje strog nivo.
- Caller + path coverage podržava samo jedan nivo pozivaoca. Nemojte ga kombinovati sa dubljim stekovima konteksta.
- ID-jevi putanja mogu da se promene između glavnih verzija LLVM-a. Zadržite isti toolchain tokom kampanje i nemojte sinhronizovati korpuse zasnovane na PATH-u kao da su njihovi ID-jevi funkcija stabilni između verzija.
- Ove povratne informacije dopunjuju `CMPLOG`: praćenje poređenja rešava pitanje **koja vrednost prolazi kroz zaštitni uslov**, dok povratne informacije o putanji/pozivaocu čuvaju **koja ruta i kombinacija grananja su do njih dovele**.

## Stateful fuzzing: sekvence su seed-ovi

Kod **protokola**, **autentifikovanih tokova rada** i **višefaznih parsera**, zanimljiva jedinica često nije pojedinačni blob, već **sekvenca poruka**. Spajanje celog transkripta u jednu datoteku i njegovo nasumično menjanje obično je neefikasno jer fuzzer podjednako menja svaki korak, čak i kada samo kasnija poruka stiže do osetljivog stanja.<sup>[[4]](#references)</sup>

Efikasniji pristup je da se **sama sekvenca** tretira kao seed i da se **uočljivo stanje** (kodovi odgovora, stanja protokola, faze parsera, tipovi vraćenih objekata) koristi kao dodatna povratna informacija.<sup>[[4]](#references)</sup>

- Održavajte **validne poruke prefiksa** stabilnim i usmerite izmene na poruku koja **pokreće prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Dajte prednost izmenama/ukrštanju pojedinačnih poruka umesto menjanju celog serijalizovanog transkripta kao neprozirnog bloba.
- Ako protokol izlaže smislene kodove odgovora, koristite ih kao **jeftin oracle stanja** za davanje prioriteta sekvencama koje napreduju dublje.

Iz istog razloga vanilla fuzzing u stilu rada sa datotekama često propušta autentifikovane bagove, skrivene prelaze ili bagove parsera koji se javljaju „tek nakon rukovanja“: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing drajvera sa više klijenata

Visoka pokrivenost grana i dalje može da propusti bagove IPC drajvera jer pokrivenost ne opisuje **vlasništvo nad objektima, brojače referenci, poruke na čekanju, redosled čišćenja ili preplitanje niti**. Stranica [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) obrađuje model objekata drajvera; ovaj primer se fokusira na fuzzer harness. Android Binder je koristan model: nije dovoljno stići i do putanja za alokaciju i do putanja za oslobađanje ako fuzzer ne može da natera više procesa da rade nad istim objektom kernela zahtevanym redosledom.<sup>[[15]](#references)</sup>

#### Modelujte protokol, a ne izolovane `ioctl` bafere

Predstavite testni slučaj kao uređenu gramatiku **identiteta klijenta + operacije + strukturiranih argumenata**. Binder LKL fuzzer koristi protobuf i `libprotobuf-mutator`, uz jednog persistentnog klijenta upravljača konteksta i dva obična klijenta. Semantički harness zatim čuva odnose koje bi nasumično menjanje bajtova uništilo.<sup>[[15]](#references)</sup>

- Keširajte vrednosti vraćene ranijim operacijama. Na primer, `BC_FREE_BUFFER` mora ponovo da koristi pokazivač na bafer transakcije koji je vratio prethodni `ioctl`.
- Generišite validne podrazumevane odgovore kako bi sinhrone transakcije mogle da se završe, a kasnije operacije ostale dostižne.
- Odbacujte nemoguće prelaze, kao što su transakcije samom sebi ili više transakcija na čekanju za isti cilj.
- Držite stanje singleton bootstrap-a izvan resetovanja po ulazu. Binder dozvoljava samo jednu registraciju `BINDER_SET_CONTEXT_MGR` po pokretanju sistema, pa bi stalno uništavanje i ponovno kreiranje tog klijenta učinilo kasnije ulaze nevažećim.

Korisni obrazac trke oko životnog ciklusa jeste da jedan klijent prenese objekat, pokrene čišćenje niti ili procesa, a zatim istovremeno natera klijenta primaoca da oslobodi bafer transakcije. U primeru CVE-2020-0423, prenos `BINDER_TYPE_WEAK_BINDER`, praćen operacijom `BINDER_THREAD_EXIT` koja se trka sa `BC_FREE_BUFFER`, mogao je da oslobodi ugrađeni `binder_work` dok ga je putanja čišćenja niti koja se gasila još koristila.<sup>[[15]](#references)</sup>

#### Ponovo uvedite kontrolisano preplitanje u kernelu u korisničkom prostoru

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) povezuje stvarni kernel kod u harness-u za korisnički prostor i izlaže njegov syscall interfejs preko `lkl_syscall`. Tako je jednostavno koordinisati protobuf stanje, pokrivenost i KASAN u jednom procesu. Međutim, LKL obično izvršava syscall bez prekidanja druge niti kernela. Za kampanje trka, umetnite tačke `schedule()` oko odabranih granica zaključavanja/otključavanja i životnog ciklusa, a zatим pustite da harness nasumično bira sledećeg klijenta pri svakom ustupanju izvršavanja. Pažljivo birajte te tačke jer svaka od njih umnožava prostor za pretraživanje rasporeda. Nasumični planer koji su opisali istraživači **nije** deo upstream Binder fuzzera.<sup>[[15]](#references)</sup>

#### Izgradite i ponovo reprodukujte serijalizovane regresione seed-ove

Upstream harness fiksira kompatibilnu verziju `libprotobuf-mutator`, omogućava LKL fuzzing instrumentaciju i KASAN pomoću `LKL_FUZZING=1`, a za Binder omogućava `CONFIG_MMU` pomoću `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nakon što proverite namerno ranjivu reviziju ili primenite rollback zakrpe dokumentovane upstream, serijalizovani seed može da reprodukuje čitav prelaz stanja između više klijenata bez rekonstruisanja u ad-hoc C proof of conceptu:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tretirajte dobijeni KASAN use-after-free kao potvrdu da je seed dospeo do ranjive putanje životnog ciklusa. To **ne** dokazuje postojanje kasnijih primitiva potrebnih za izvršavanje koda u kernelu ili eskalaciju privilegija.<sup>[[16]](#references)</sup>

## Trik za raznovrsnost na jednoj mašini (u stilu Jackalope-a)

Praktičan način da se kombinuju **generativna novina** i **ponovna upotreba pokrivenosti** jeste da se **kratkotrajni worker-i restartuju** uz rad sa perzistentnim serverom. Svaki worker počinje sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi koristeći objedinjeni corpus, ponovo se sinhronizuje, a zatim se gasi. Tako se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno korišćenje akumulirane pokrivenosti.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sekvencijalni worker-i (primer petlje):**

<details>
<summary>Petlja za ponovno pokretanje Jackalope worker-a</summary>

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

- `-in empty` forsira **novi corpus** pri svakom generisanju.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo novine, kasnije ponovna upotreba).
- U režimu grammar fuzzing-a, **početna sinhronizacija sa serverom se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalna vrednost `T` zavisi od **cilja**; najbolje je promeniti je nakon što worker pronađe većinu „lake“ pokrivenosti.

## Snapshot Fuzzing za ciljeve koje je teško pripremiti za testiranje

Kada kod koji želite da testirate postane dostupan tek **nakon dugotrajne pripreme** (pokretanje VM-a, završetak prijave, prijem paketa, parsiranje kontejnera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog procesa ili VM-a, ubacite svaki testni slučaj u ulaznu putanju cilja, izvršavajte do pada/vremenskog ograničenja, pa vratite snapshot. Tako se izbegava ponavljanje inicijalizacije ili prefiksa protokola, a korisno je za **mrežne servise**, **firmware**, **površine napada nakon autentifikacije** i **ciljeve dostupne samo kao binarne datoteke**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite cilj dok ne bude spreman željeni deo izvršavanja.
2. Napravite snapshot **memorije i registara** u tom trenutku.
3. Za svaki testni slučaj, upišite izmenjeni ulaz direktno u odgovarajući bafer gosta/procesa.
4. Izvršavajte do pada/vremenskog ograničenja/resetovanja.
5. Vratite snapshot; za VM ciljeve, vratite samo **izmenjene stranice** kada je to podržano, pa ponovite postupak.

Postavite snapshot što je moguće bliže prvom skupom koraku parsiranja/dispečovanja, na primer nakon tačke `recv`/`read` ili deserijalizacije paketa, i zabeležite ulazni bafer koji koristi cilj. Ovo sledi načelo adaptivnog postavljanja: pomerajte snapshot dublje u obradu ulaza kako biste izbegli ponavljanje posla.<sup>[[11]](#references)</sup>

## Istraživanje trka u Linux kernelu pomoću MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) pretvara vremenski osetljive trke u Linux kernelu u ponovljive rasporede pristupa memoriji. Može automatski da nabroji izvršavanja **A-B-A** u dva konteksta ili da omogući analitičaru da zada ograničenja redosleda putem terminalskog korisničkog interfejsa/grafičkog korisničkog interfejsa. Ovo je eksperimentalni istraživački alat, a ne kompletan concurrency fuzzer: trenutno zahteva LLVM 23+ i kernel projekta sa zakrpama, alati komandne linije podržavaju dve testne niti, a predloženi sloj za fuzzing u userspace-u nije implementiran.<sup>[[17]](#references)[[18]](#references)</sup>

### Prikupljanje tačaka komunikacije između konteksta

Izgradite instrumentisani kernel sa KASAN outline callback-ovima i podrškom zakrpljenog KCOV-a za beleženje memorije. README projekta takođe preporučuje isključivanje optimizacije sibling-call kako bi stekovi poziva ostali upotrebljivi.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) pretvara instrumentirane pristupe u pozive pomoćnih funkcija. MAccConc kernel zakrpe isključuju `asan-opt-same-temp` kako se uzastopni pristupi ne bi spajali; isključite i optimizaciju `asan-opt-globals` kada trke nad globalnim promenljivama moraju biti vidljive. KCOV prenosi dobijene zapise u userspace. Uporedite pristupe iz različitih konteksta izvršavanja i zadržite parove čiji se opsezi bajtova preklapaju i gde bar jedna strana vrši upis; tretirajte `kfree()` kao upis kako bi i promene životnog veka postale kandidati.<sup>[[17]](#references)</sup>

Za rad koji se nastavlja izvan početnog zadatka, kao što su obrada paketa ili RCU callback-ovi, podsistem mora da prosledi KCOV remote-coverage handle. Uzvodni remote KCOV je opcioni i nije automatski dostupan za proizvoljan rad u pozadini, pa izostanak prosleđivanja može učiniti stvarnu interakciju nevidljivom.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifikujte isti dinamički pristup pri svakom pokretanju

Nemojte ponavljati izvršavanje nad konkretnom heap adresom, koja se može promeniti nakon svake alokacije, niti samo nad adresom instrukcije, koja je dvosmislena unutar pomoćnih funkcija kao što su `memcpy()` i `spin_lock()`. MAccConc koristi **count-augmented stack trace**: svaki okvir identifikuje pozvanu funkciju i broj njenog pozivanja unutar pozivaoca, a poslednji element identifikuje instrukciju za pristup memoriji. Zapisi za ulazak u funkciju i izlazak iz nje koje generiše SanitizerCoverage omogućavaju userspace-u da rekonstruiše ovaj dinamički identifikator, koji ostaje stabilan uprkos promenama adresa i nepovezanim promenama toka upravljanja.<sup>[[17]](#references)</sup>

### Pretvorite parove kandidata u prinudne rasporede

Zakrpljeni `KCOV_SET_DI` ioctl povezuje identifikator pristupa sa proširenim brojanjem u steku sa radnjom nad zajedničkom zastavicom.<sup>[[17]](#references)</sup>

| Radnja | Semantika |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Postavi zastavicu *N* neposredno pre izabranog pristupa. |
| `DI_STACK_WAIT` | Pre izabranog pristupa, čekaj u petlji dok se zastavica *N* ne postavi ili dok ne istekne podešeno ograničenje. |
| `DI_STACK_WAKE_POST` | Postavi zastavicu *N* neposredno nakon izabranog pristupa. |

Za delimično ograničenje **A-happens-before-B**, povežite `DI_STACK_WAKE_POST` sa A, a `DI_STACK_WAIT` sa B, koristeći istu zastavicu. Za potpuno specificiran raspored sa dva konteksta, pokrenite B u blokiranom stanju, zatim neka A probudi B i sačeka na prvoj tački predaje; B obavlja obrnutu radnju na sledećoj tački predaje. Ovo drugo funkcioniše poput determinističkog prebacivanja konteksta i koristi ga automatski A-B-A explorer.<sup>[[17]](#references)</sup>

Minimalna kampanja podrazumeva kompajliranje četvorofunkcijskog testnog slučaja (`test_setup`, dve funkcije niti i `test_end`) kao shared library-ja, prikupljanje traga bez ograničenja, a zatim nabrajanje A-B-A kandidata ili dodavanje ručnih ograničenja oko sumnjivih pristupa.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeout-e tumačite odvojeno od uspešnih promena redosleda: traženi redosled možda nije moguć zato što lock ili zavisnost pri inicijalizaciji/objavljivanju sprečava drugi kontekst da dođe do tačke ubrizgavanja. Imajte na umu i KASAN-ove slepe tačke: direktni pristupi steku obično se ne instrumentiraju, osim ako postoji mogućnost da prekorače granice; globalne promenljive se izostavljaju pri podrazumevanoj optimizaciji; a trenutni kompajleri ne mogu istovremeno da emituju ASAN i TSAN hookove. Uz to, prototip gubi svoj KCOV bafer kada se guest sruši, zato obezbedite nezavisnu konzolu/oracle za pad.<sup>[[17]](#references)</sup>

Za buduće fuzzing testiranje vođeno konkurentnošću, beležite sažetke pristupa memoriji za svaki ulaz ili syscall, uparujte operacije koje bi formirale tačke komunikacije između konteksta, a zatim istražujte samo te kombinacije. VM snimci stanja stabilizuju globalno stanje i adrese; bez njih, metapodaci o mestu alokacije mogu da apstrahuju objekte između pokretanja. Ovo je predloženo proširenje, a ne mogućnost trenutnih MAccConc userspace alata.<sup>[[17]](#references)</sup>

## Introspekcija harness-a: rano otkrivanje površnih fuzzera

Kada kampanja zapne, problem često nije mutator, već **harness**. Koristite **introspekciju dostižnosti/pokrivenosti** da biste pronašli funkcije koje su statički dostižne iz vašeg fuzz target-a, ali se retko ili nikada ne pokrivaju dinamički. Takve funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u target prekasno ili prerano.
- U korpusu početnih ulaza nedostaje čitava porodica funkcionalnosti.
- Target-u je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a „radi sve“.

Ako koristite tokove rada u stilu OSS-Fuzz / ClusterFuzz, Fuzz Introspector može da uporedi statičku dostižnost sa pokrivenošću tokom izvršavanja i da generiše izveštaje na osnovu vremenski ograničenog pokretanja ili javnog korpusa.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Na osnovu izveštaja odlučite da li da dodate novi harness za neispitanu putanju parsera, proširite korpus za određenu funkciju ili podelite monolitni harness na manje ulazne tačke.

## Izbor fuzz ciljeva na osnovu grafa i trijaža mutacija

Ako već imate **nalaze statičke analize**, **preživele mutacije** i **izveštaje o pokrivenosti**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **graf poziva**, označite čvorove **ciklomatskom složenošću**, **dostupnošću sa ulaznih tačaka/nepoverljivog ulaza** i svim spoljnim nalazima, a zatim postavljajte pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostupne iz nepoverljivog ulaza?
- Koje preživele mutacije se nalaze na putanjama od parsera/handlera do bezbednosno kritičnog koda?
- Koje funkcije predstavljaju arhitektonska uska grla sa neobično velikim **radijusom uticaja**?

Ovim se obično otkrivaju bolji fuzz ciljevi nego kada se gleda samo „najniža pokrivenost“. Parser/dekoder sa **visokom složenošću** i potvrđenom **dostupnošću spolja** bolji je kandidat za harness nego izolovani interni pomoćni kod sa slabom pokrivenošću, ali bez putanje kojom napadač može da upravlja.

### Praktični tok trijaže

1. Napravite **graf koda** na osnovu baze koda i izdvojite metrike složenosti/grananja za svaku funkciju.
2. Nabrojte **ulazne tačke** koje prihvataju podatke pod kontrolom napadača: obrađivače zahteva, dekodere, uvoznike, parsere protokola, čitače CLI-ja/datoteka.
3. Pokrenite **upite nad putanjama** od tih ulaznih tačaka do kandidata za funkcije da biste razdvojili dostupnu površinu za napad od mrtvog koda ili koda dostupnog samo interno.
4. Dajte prioritet čvorovima koji objedinjuju:
   - visoku **ciklomatsku složenost**
   - potvrđenu **dostupnost iz nepoverljivog ulaza**
   - veliki **radijus uticaja** ili mnogo nizvodnih zavisnih elemenata
   - potkrepljujuće dokaze, kao što su nalazi **SARIF**, beleške iz bezbednosne revizije ili preživele mutacije
5. Najpre napišite ciljane harness-e za čvorove sa najboljim rezultatom, naročito za **parser-e/kodeke**, kao što su dekoderi za hex/Base64/IP/poruke.

### Preživele mutacije: ekvivalentne ili primenljive

Testiranje mutacijama često daje bučnu listu preživelih mutacija. Pre nego što svaku preživelu mutaciju proglasite bezbednosnim propustom, pomoću grafa proverite:

- Da li je izmenjena funkcija dostupna sa ulazne tačke pod kontrolom napadača?
- Da li su sve putanje poziva ograničene jačim invarijantama od izmenjene provere?
- Da li se čvor nalazi u mrtvom kodu, logici koja služi samo za formatiranje ili u aritmetičkoj/parser putanji velikog uticaja?

Mutacije koje ostanu nedostupne ili strukturno ograničene često su **ekvivalentni mutanti**. Mutacije koje ostanu **dostupne** i dotiču se **graničnih uslova**, **putanja prekoračenja/carry-ja** ili **bezbednosno kritične aritmetike/parsiranja** treba unaprediti u:

- nove fuzz harness-e
- direktne testove svojstava/invarijanti
- ciljane vektore graničnih slučajeva

### Mapirajte spoljne nalaze na graf

Ako vaš SAST pipeline izvozi **SARIF**, mapirajte nalaze na čvorove grafa prema **datoteci + opsegu redova** i pomoću grafa proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **radijus uticaja** označene funkcije
- proverite da li se nalaz nalazi na nekoj putanji od ulazne tačke
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno kada odlučujete da li da vreme za fuzzing uložite u određenu funkciju: čvor koji je **dostupan**, **složen** i već ima **SAST nalaze** često je bolji cilj nego samo složen čvor bez putanje kojom napadač može da upravlja.

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

Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristi graf da izabereš ciljeve fuzz testiranja sa najvećom očekivanom bezbednosnom vrednošću, a zatim pomoću mutanata koji su preživeli odredi koje granice i invarijante tvoj harness treba da testira.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Jači mehanizam, tipizirani ulazi i diferencijalne provere

Ako Go cilj već ima nativni `testing.F` harness, praktičan put za nadogradnju je da isti harness pokreneš pomoću [gosentry](https://github.com/trailofbits/gosentry), forkovanog Go toolchain-a koji zadržava `go test -fuzz`, ali menja backend u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Ovo je korisno kada se native Go fuzzer zaglavi na **teškim poređenjima**, **tipiziranim ulazima** ili **formatima sa složenim parserima**. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za početne ulaze i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite gosentry-jevom `go` binarnom datotekom umesto standardnim toolchain-om.
- Tretirajte dobijenu kampanju kao uobičajeno pokretanje vođeno pokrivenošću, ali uz LibAFL raspoređivanje/mutaciju i bolje prateće detektore.

### Pretvaranje tihih grešaka u nalaze fuzzing-a

Čest problem pri Go procenama jeste to što se opasno ponašanje često podrazumevano **ne završava padom**. Pomoću gosentry-ja možete da pretvorite nekoliko klasa „loših, ali tihih“ stanja u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da bi izabrane putanje za logovanje/greške izazvale pad (korisno za putanje koda u stilu `log.Fatal` koje inače samo zabeleže grešku i nastave sa radom).
- `--catch-races=true` да би се новооткривени уноси у реду поново покренули са Go детектором race услова.
- `--catch-leaks=true` да би се нови уноси у реду поново покренули помоћу `goleak` и зауставили при откривању цурења goroutine-а.
- LibAFL обрада заглављивања како би се **бесконачне петље / веома спори улази** задржали као налази fuzzing-а, уместо да нестану као временска ограничења.
- Уграђене провере аритметичког прекорачења су подразумевано укључене, уз опционе провере скраћивања помоћу инструментације у стилу go-panikint.

Ово је посебно корисно за циљеве код којих је безбедносни утицај **грешка parser-а без панике**, **concurrency грешка** или **заглављивање које омогућава само DoS**, а не оштећење меморије.

### Fuzzing свестан структура за типизиране Go API-је

Native Go fuzzing углавном очекује скаларне вредности као што су `[]byte`, `string` и бројеви. Ако код који се тестира користи типизиране објекте, gosentry може директно да fuzz-ује **сложене вредности** (структуре, слице, низове, показиваче), а да притом и даље мутира бајтове испод површине.<sup>[[7]](#references)[[8]](#references)</sup>

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

Koristite ovo kada bi izrada lažnog wire formata samo za fuzzing sakrila logičke greške iza koda za parsiranje koji postoji samo u harness-u. Za diferencijalne kampanje ili kampanje zasnovane na gramatici, ulaz harness-a zadržite kao jedan `[]byte` ili `string` i parsirajte ga unutar callback-a.

### Fuzzing zasnovan na gramatici za parsere i protokolarne ulaze

Za parsere, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** povrh LibAFL-a. Gramatika je JSON niz produkcionih pravila, a harness bi obično trebalo da prima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodološke napomene:

- Koristite grammar mode kada mutacije na nivou bajtova uglavnom ne prolaze rane provere sintakse.
- Ograničite gramatiku na **podskup jezika/protokola relevantan za bezbednost**, umesto da modelujete celu specifikaciju.
- Koristite velike granične vrednosti u terminalima/neterminalima da biste testirali rubne slučajeve za cele brojeve, dužine i mašine stanja.
- Grammar mode obezbeđuje da ulazi budu validni prema gramatici, ali cilj i dalje prima **bajtove/nizove znakova**, tako da parsiranje i semantičke provere ostaju unutar koda koji se testira.

### Differential fuzzing: uporedite implementacije, ne samo padove

Dobar obrazac za Go ekosisteme je **grammar-based differential fuzzing**: generišite validne strukturirane ulaze i prosledite ih dvama parserima, klijentima ili mehanizmima za promenu stanja.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacija izazove paniku, dok druga ispravno odbije ulaz
- nepodudaranja u prihvatanju/odbijanju ulaza
- različita stabla parsiranja ili dekodirani objekti
- različiti prelazi stanja, nonce vrednosti, stanja računa ili koreni stanja

Ovo je praktičan način za otkrivanje **nepodudaranja u konsenzusu**, **dvosmislenosti parsera** i **odstupanja između specifikacije i implementacije** koje čisto fuzzing testiranje radi pronalaženja padova često ne otkriva.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponovo upotrebite korpus kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo pokrenite sačuvani korpus reda čekanja da biste generisali Go izveštaj o pokrivenosti, bez ručnog izvoza zasebnog korpusa.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` da bi gosentry razrešio odgovarajuće keširano stanje kampanje.



## References

- [1] [Fuzzing zasnovan na mutacionoj gramatici](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: o fuzzingu protokola vođenom pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Napravili smo fork toolchain-a da to popravimo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: brz greybox fuzzer za stateful mrežne protokole pomoću snimaka](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: ka fuzzingu Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: efikasan fuzzing uz adaptivne i promenljive snimke](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentacija: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivni kontekstno osetljivi fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - dokumentacija za izgradnju i regresione seed-ove](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: istraživanje race condition-a u Linux kernelu pomoću kontrolisanih preplitanja pristupa memoriji](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrivenost koda za fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
