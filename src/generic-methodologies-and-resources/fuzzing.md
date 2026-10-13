# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutacioni grammar fuzzing: pokrivenost naspram semantike

Kod **mutacionog grammar fuzzing-a**, ulazi se menjaju tako da ostanu **gramatički ispravni**. U režimu vođenom pokrivenošću, samo uzorci koji izazovu **novu pokrivenost** čuvaju se kao seed-ovi korpusa. Kod **jezičkih ciljeva** (parsera, interpretera, engine-a), ovim se mogu propustiti greške koje zahtevaju **semantičke lance/tokove podataka**, gde izlaz jednog konstrukta postaje ulaz drugog.<sup>[[1]](#references)</sup>

**Način otkaza:** fuzzer pronalazi seed-ove koji pojedinačno pokrivaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani tok podataka**, pa se uzorak „bliži grešci“ odbacuje jer ne dodaje pokrivenost. Kada postoje **3+ međuzavisnih koraka**, nasumično rekombinovanje postaje skupo, a povratne informacije o pokrivenosti ne usmeravaju pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** kod gramatika sa mnogo zavisnosti, razmotrite **kombinovanje mutacionih i generativnih faza** ili davanje prednosti obrascima **ulančavanja funkcija** (ne samo pokrivenosti).<sup>[[1]](#references)</sup>

## Zamke raznovrsnosti korpusa

Mutacija vođena pokrivenošću je **pohlepna**: uzorak koji donese novu pokrivenost odmah se čuva, često zadržavajući velike neizmenjene delove. Vremenom korpusi postaju **skoro duplikati** sa malom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **minimizacija koja uvažava gramatiku** i **zaustavlja se kada dostigne minimalni broj tokena** (uklanja šum, a zadržava dovoljno okolne strukture da bi uzorak i dalje bio pogodan za mutacije).<sup>[[1]](#references)</sup>

Praktično pravilo za korpus pri mutacionom fuzzing-u: **dajte prednost malom skupu strukturno različitih seed-ova koji maksimizuju pokrivenost** u odnosu na veliku gomilu skoro duplikata. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni korpusi, crawling, uhvaćen saobraćaj, skupovi fajlova iz ekosistema cilja).
- Svedite ih na manji skup pomoću **minimizacije korpusa zasnovane na pokrivenosti**, umesto da zadržite svaki ispravan uzorak.
- Seed-ove održavajte **dovoljno malim** da mutacije pogađaju smislena polja, umesto da većinu ciklusa troše na nebitne bajtove.
- Ponovo pokrenite minimizaciju korpusa nakon većih izmena harness-a/instrumentacije, jer se „najbolji“ korpus menja kada se promeni dostižnost koda.

## Mutacije prilagođene poređenjima za magične vrednosti

Čest razlog zbog kog fuzzing zapne nisu sintaksne prepreke, već **stroga poređenja**: magični bajtovi, provere dužine, enum stringovi, kontrolne sume ili vrednosti za izbor parsera koje se proveravaju pomoću `memcmp`, switch tabela ili niza uslovnih poređenja. Čiste nasumične mutacije uzalud troše cikluse pokušavajući da pogode ove vrednosti bajt po bajt.

Za ove ciljeve koristite **praćenje poređenja** (na primer, AFL++ `CMPLOG` / Redqueen pristupe) kako bi fuzzer mogao da posmatra operande neuspelih poređenja i usmerava mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>

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

- Ovo je naročito korisno kada cilj skriva složenu logiku iza **potpisa datoteka**, **glagola protokola**, **oznaka tipova** ili **bitova funkcionalnosti zavisnih od verzije**.
- Kombinujte ovo sa **rečnicima** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali rečnik sa gramatičkim tokenima, nazivima blokova, glagolima i graničnicima često je korisniji od ogromne generičke liste reči.
- Ako cilj obavlja mnogo uzastopnih provera, prvo rešite najranija poređenja „magic“, a zatim ponovo minimizujte dobijeni korpus kako bi kasnije faze počele sa već validnim prefiksima.

## Fuzzing API-ja za datoteke koji skrivaju jezik naziva datoteka

Parametar nazvan `filename`, `path` ili `URL` može biti ulazna tačka za interpreter, a ne doslovno traženje datoteke. Na primer, CFITSIO Extended Filename Syntax (EFS) obrađuje selektore u uglastim zagradama, izraze za redove/piksele, izračunate kolone, histograme i transformacije pre nego što vrati otvoreni objekat; neki oblici takođe prave privremene kopije. Tokom mapiranja površine napada, klasifikujte svaki API za otvaranje/uvoz kao **literal-path** ili **interpreted-path**, a zatим fuzz-ujte produkcionu ulaznu tačku koju aplikacije zaista pozivaju.<sup>[[20]](#references)[[22]](#references)</sup>

Za rezultujuće primitive za SSRF, kopiranje datoteka i rukovaoce protokolima — kao i bezbednije API-je za literal-path — pogledajte [Mini-jezici naziva datoteka kao primitive za SSRF/rad sa datotekama](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Držite prateći objekat odvojeno od fuzz-ovanog programa

Kada se gramatika nalazi u sufiksu naziva datoteke, menjanje samo bajtova referencirane datoteke ne obuhvata parser. Umesto toga, mali harness može da pročita jedan testcase kao string i prosledi ga API-ju za otvaranje koji tumači ulaz; CFITSIO kampanja je dosegla većinu EFS parsera i evaluatora pozivanjem funkcije `fits_open_file()` u režimu samo za čitanje. Dostupne validne prateće datoteke držite odvojeno kako bi mutacije mogle da se usredsrede na jezik selektora/izraza, umesto da neprestano kvare osnovnu putanju.<sup>[[22]](#references)</sup>

Koristite seed-ove koji svaki dosežu različitu porodicu gramatika, a zatim izvedite kompaktan rečnik iz specifikacije i izvornog koda lexer-a/parsera. Ako se pokrivenost ne povećava, a ulazi stalno padaju na istoj putanji sintaksne greške, sačuvajte validne prefikse i dodajte graničnike, operatore, ključne reči, nazive funkcija i reprezentativna imena polja, umesto da samo produžavate vreme nasumičnih mutacija.<sup>[[22]](#references)</sup>

Pokrenite harness sa rečnikom gramatike, na primer:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograničite neželjene efekte „read-only“ harness-a

Oznaka read-only u biblioteci ne garantuje da testcase neće imati neželjene efekte: jezik naziva datoteka može da prepiše ulaz, kreira izlazne datoteke ili materijalizuje privremene objekte. CFITSIO kampanja je u početku uništavala seed datoteke i ostavljala neočekivane datoteke širom fajl sistema, pa su bili neophodni čišćenje i izolacija.<sup>[[22]](#references)</sup>

- Obezbedite svakom worker-u privremeni radni direktorijum i privatni privremeni direktorijum.
- Izložite kopije kanonskih datoteka; nikada ne dozvolite da target menja jedinu kopiju corpus-a.
- Onemogućite mrežni pristup osim ako su udaljeni backend-ovi cilj testiranja i ograničite putanje za upisivanje pomoću kontejnera, mount namespace-a ili ekvivalentnog sandbox-a.
- Resetujte direktorijum posle svakog izvršavanja ili batch-a worker-a i tretirajte neočekivane izmene fajl sistema kao dodatne nalaze.

### Petlja crash-to-patch-to-fuzz

Grupišite crash-eve pre popravke da hiljade artefakata ne bi postale hiljade zadataka za patch. U proceni CFITSIO-a, AFLTriage je sveo početni skup crash-eva na nekoliko osnovnih uzroka; rezultat je savetodavno obaveštenje koje prikazuje različite greške, uključujući neispravne provere veličine odredišta, zastarele pokazivače posle `realloc()`, aritmetičke greške i nesigurne putanje čišćenja parser-a.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimizujte reprezentativni ulaz za svaki klaster i reprodukujte ga pod AddressSanitizer-om.
2. Zabeležite tačan neispravan pristup, lokaciju u izvornom kodu, istoriju alokacija i oslobađanja memorije i stanje parser-a zbog kojeg je invarijanta prekršena.
3. Primените један уско фокусиран кандидатски patch и поново изградите бинарни фајл са истом инструментацијом за coverage и sanitizer.
4. Ponovo pokrenite originalni reproducer **i svaki ulaz iz njegovog klastera**; uključite i detekciju leak-ova jer ispravka problema sa bezbednošću memorije može da naruši upravljanje vlasništvom na putanji greške.
5. Pokrenite funkcionalne testove sa stvarnim datotekama, pa nastavite od akumuliranog queue-a (ili ponovo uvezite taj queue ako engine zahteva nov izlazni direktorijum nakon izmene binarnog fajla).
6. Ponavljajte: uklanjanje prvog, površinskog crash-a često omogućava postojećim seed-ovima da stignu do dubljeg stanja parser-a.

LLM može da ubrza korak 2 i pripremi nacrt koraka 3 ako dobije ulaz koji izaziva crash, izveštaj sanitizer-a, harness i relevantni izvorni kod, ali njegov patch ostaje nepouzdan. O prihvatanju popravke odlučuju ponovna provera sanitizer-om i regresioni testovi, a ne objašnjenje modela.<sup>[[22]](#references)</sup>

## Bogatije povratne informacije kada edge coverage ne razlikuje različite putanje

Uobičajeni edge coverage ne može da razlikuje dva izvršavanja koja prolaze kroz isti helper iz različitih pozivalaca ili prolaze kroz različite kombinacije grana unutar funkcije. To je važno kod zajedničkih dekodera, protocol dispatcher-a i helper-a interpretera, gde **putanja** do ivice određuje aktivno stanje. Naivno praćenje svakog konteksta pozivanja je takođe rizično: coverage mapa i queue mogu enormno da porastu. Zato istraživanja fuzzing-a osetljivog na kontekst preporučuju da se dodatno preciziraju samo obećavajući konteksti, umesto da se ceo graf poziva tretira kao osetljiv na kontekst.<sup>[[14]](#references)</sup>

Novije verzije AFL++ obezbeđuju **Ball-Larus coverage putanja po funkciji** uz uobičajeni edge coverage. Dodeljuje feature svakoj acikličkoj putanji kroz funkciju; povratne ivice petlji se uklanjaju, pa ova povratna informacija razlikuje kombinacije grana, ali **ne i broj iteracija petlje**. Počnite sa blažim nivoom `1`, a zatim strože režime ograničite na sumnjiv kod parser-a ili mašine stanja jer broj putanja može eksponencijalno da raste.<sup>[[13]](#references)</sup>

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

**Smernice za kampanju:** oprezno primenjujte bogatije povratne informacije i pratite njihov trošak po mapi pokrivenosti i redu čekanja.<sup>[[13]](#references)[[14]](#references)</sup>

- Paralelno pokrenite običnu instancu sa pokrivenošću ivica; bogatije povratne informacije su korisne samo ako dodatni trošak po redu čekanja i mapi ne smanji broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da ograničite instrumentaciju putanja/pozivalaca kada velike biblioteke pune šablona ili generički pomoćni kod dominiraju mapom.
- Funkcije sa previše acikličnih putanja mogu se preskočiti u AFL++; upozorenja tokom kompilacije ukazuju na to da cilj zahteva allowlisting ili manje strog nivo.
- Pokrivenost pozivaoca + putanje podržava samo jednu dubinu pozivaoca. Nemojte je kombinovati sa dubljim kontekstnim stekovima.
- ID-jevi putanja mogu da se promene između glavnih verzija LLVM-a. Tokom kampanje koristite fiksiran toolchain i nemojte sinhronizovati korpuse zasnovane na PATH-u kao da su njihovi ID-jevi karakteristika stabilni između build-ova.
- Ove povratne informacije dopunjuju `CMPLOG`: praćenje poređenja rešava pitanje **koja vrednost prolazi kroz guard**, dok povratne informacije o putanji/pozivaocu čuvaju **koja ruta i kombinacija grana su dovele do nje**.

## Stateful fuzzing: sekvence su seed-ovi

Kod **protokola**, **autentifikovanih tokova rada** i **parsera u više faza**, zanimljiva jedinica često nije jedan blob, već **sekvenca poruka**. Spajanje celog transkripta u jednu datoteku i njegovo nasumično mutiranje obično je neefikasno, jer fuzzer podjednako mutira svaki korak, čak i kada samo kasnija poruka stiže do krhkog stanja.<sup>[[4]](#references)</sup>

Efikasniji obrazac je da se **sama sekvenca** tretira kao seed, a da se **uočljivo stanje** (kodovi odgovora, stanja protokola, faze parsera, vraćeni tipovi objekata) koristi kao dodatna povratna informacija.<sup>[[4]](#references)</sup>

- Održavajte **validne prefiksne poruke** nepromenjenim i usmerite mutacije na poruku koja **pokreće prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada sledeći korak zavisi od njih.
- Dajte prednost mutiranju/spajanju pojedinačnih poruka umesto mutiranju celog serijalizovanog transkripta kao neprozirnog blob-a.
- Ako protokol izlaže smislene kodove odgovora, koristite ih kao **jeftin oracle stanja** za davanje prioriteta sekvencama koje napreduju dublje.

Iz istog razloga vanilla fuzzing u stilu rada sa datotekama često propušta autentifikovane bagove, skrivene prelaze ili bagove parsera koji se javljaju „tek nakon rukovanja“: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing drajvera sa više klijenata

Visoka pokrivenost ivica i dalje može da propusti bagove IPC drajvera, jer pokrivenost ne opisuje **vlasništvo nad objektima, brojače referenci, poruke na čekanju, redosled čišćenja ni preplitanje niti**. Stranica [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) obrađuje model objekata drajvera; ovaj primer se fokusira na harness fuzzera. Android Binder je koristan model: nije dovoljno dostići i putanje za alokaciju i putanje za oslobađanje ako fuzzer ne može da natera više procesa da rade nad istim objektom kernela odgovarajućim redosledom.<sup>[[15]](#references)</sup>

#### Modelujte protokol, a ne izolovane `ioctl` bafere

Predstavite testni slučaj kao uređenu gramatiku **identiteta klijenta + operacije + strukturisanih argumenata**. Binder LKL fuzzer koristi protobuf i `libprotobuf-mutator`, sa jednim trajnim klijentom menadžera konteksta i dva obična klijenta. Semantički harness zatim čuva odnose koje bi nasumična mutacija bajtova uništila.<sup>[[15]](#references)</sup>

- Keširajte vrednosti koje vraćaju prethodne operacije. Na primer, `BC_FREE_BUFFER` mora ponovo da upotrebi pokazivač na bafer transakcije koji je vratila prethodna operacija `ioctl`.
- Generišite validne podrazumevane odgovore kako bi sinhrone transakcije mogle da se dovrše i kako bi kasnije operacije ostale dostižne.
- Odbacujte nemoguće prelaze, kao što su transakcije ka samom sebi ili više transakcija na čekanju ka istom cilju.
- Održavajte stanje inicijalizacije za pojedinačni primerak izvan resetovanja po ulazu. Binder dozvoljava samo jednu registraciju `BINDER_SET_CONTEXT_MGR` tokom jednog pokretanja sistema, pa bi ponovljeno uništavanje i ponovno kreiranje tog klijenta učinilo kasnije ulaze nevažećim.

Koristan obrazac za trku u životnom ciklusu jeste da jedan klijent prenese objekat, pokrene čišćenje niti ili procesa, a da istovremeno klijent primalac oslobodi bafer transakcije. U primeru CVE-2020-0423, prenos `BINDER_TYPE_WEAK_BINDER`, praćen trkom `BINDER_THREAD_EXIT` sa `BC_FREE_BUFFER`, mogao je da oslobodi ugrađeni `binder_work` dok ga je putanja čišćenja niti koja se gasila još koristila.<sup>[[15]](#references)</sup>

#### Ponovo uvedite kontrolisano preplitanje u userspace kernel

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) povezuje stvarni kod kernela u harness u userspace-u i izlaže njegov syscall interfejs kroz `lkl_syscall`. Tako je lako koordinisati protobuf stanje, pokrivenost i KASAN u jednom procesu. LKL obično izvršava syscall bez prekidanja drugom niti kernela. Za kampanje trka, ubacite tačke `schedule()` oko odabranih granica zaključavanja/otključavanja i životnog ciklusa, a zatim prepustite harness-u da nasumično bira sledećeg klijenta pri svakom ustupanju kontrole. Ove tačke postavljajte ciljano, jer svaka od njih umnožava prostor pretrage rasporeda. Randomizovani raspoređivač koji su opisali istraživači **nije** deo uzvodnog Binder fuzzera.<sup>[[15]](#references)</sup>

#### Izgradite i ponovite serijalizovane regresione seed-ove

Uzvodni harness fiksira kompatibilnu verziju `libprotobuf-mutator`, omogućava instrumentaciju za LKL fuzzing i KASAN pomoću `LKL_FUZZING=1`, a za Binder omogućava `CONFIG_MMU` opcijom `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nakon što pređete na namerno ranjivu reviziju ili primenite rollback zakrpe dokumentovane u upstream-u, serijalizovano početno stanje može da reprodukuje ceo prelaz stanja sa više klijenata, bez potrebe da ga ponovo sastavljate u ad hoc C proof of concept-u:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tretirajte rezultat KASAN use-after-free kao potvrdu da je seed stigao do ranjive putanje životnog ciklusa. To **ne** dokazuje postojanje kasnijih primitiva potrebnih za izvršavanje koda u kernelu ili eskalaciju privilegija.<sup>[[16]](#references)</sup>

## Trik za raznovrsnost na jednoj mašini (u stilu Jackalope)

Praktičan način da se kombinuju **generativna novina** i **ponovna upotreba pokrivenosti** jeste da se **kratkotrajni radnici ponovo pokreću** nad trajnim serverom. Svaki radnik počinje s praznim korpusom, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi koristeći objedinjeni korpus, ponovo se sinhronizuje, a zatim se gasi. Tako se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno iskorišćavanje akumulirane pokrivenosti.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (najpre novine, zatim ponovna upotreba).
- U režimu grammar fuzzing, **početna sinhronizacija servera je podrazumevano preskočena** (nije potrebno koristiti `-skip_initial_server_sync`).
- Optimalna vrednost `T` **zavisi od cilja**; najbolje rezultate obično daje promena nakon što worker pronađe većinu „lake“ pokrivenosti.

## Snapshot Fuzzing za ciljeve koje je teško pripremiti za testiranje

Kada kod koji želite da testirate postaje dostupan tek **nakon opsežne pripreme** (pokretanja VM-a, dovršavanja prijave, prijema paketa, parsiranja kontejnera, inicijalizacije servisa), korisna alternativa je **snapshot fuzzing**: snimite stanje spremnog procesa ili VM-a, ubacite svaki testni slučaj u ulaznu putanju cilja, izvršavajte do pada/vremenskog ograničenja, pa vratite snimak. Time se izbegava ponavljanje inicijalizacije ili prefiksa protokola, a pristup je koristan za **mrežne servise**, **firmware**, **površine napada nakon autentifikacije** i **ciljeve dostupne samo u binarnom obliku**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite cilj dok željeno stanje ne bude spremno.
2. U tom trenutku napravite snimak **memorije + registara**.
3. Za svaki testni slučaj upišite izmenjeni ulaz direktno u odgovarajući bafer gosta/procesa.
4. Izvršavajte do pada/vremenskog ograničenja/resetovanja.
5. Vratite snimak; za VM ciljeve, kada je podržano, vratite samo **izmenjene stranice**, pa ponovite postupak.

Postavite snimak što bliže prvom skupom koraku parsiranja/dispatch-a, na primer nakon tačke `recv`/`read` ili deserijalizacije paketa, i zabeležite ulazni bafer koji cilj koristi. Ovo sledi princip adaptivnog postavljanja: pomeranje snimka dublje u obradu ulaza da bi se izbeglo ponavljanje rada.<sup>[[11]](#references)</sup>

## Istraživanje race uslova Linux kernela pomoću MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) pretvara race uslove u Linux kernelu osetljive na tajming u ponovljive rasporede pristupa memoriji. Može automatski da nabroji **A-B-A** izvršavanja u dva konteksta ili da omogući analitičaru da nametne ograničenja redosleda putem terminalskog UI-ja/GUI-ja. Ovo je eksperimentalni istraživački alat, a ne kompletan concurrency fuzzer: trenutno zahteva LLVM 23+ i kernel sa zakrpama projekta; alati komandne linije podržavaju dve testne niti, a predloženi userspace fuzzing sloj nije implementiran.<sup>[[17]](#references)[[18]](#references)</sup>

### Prikupljanje komunikacionih tačaka između konteksta

Izgradite instrumentisani kernel sa KASAN outline callbacks i podrškom zakrpljenog KCOV-a za beleženje memorije. README projekta preporučuje i onemogućavanje sibling-call optimizacije, kako bi stekovi poziva ostali upotrebljivi.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline režim (`asan-instrumentation-with-call-threshold=0`) pretvara instrumentirane pristupe u pozive pomoćnih funkcija. MAccConc kernel zakrpe isključuju `asan-opt-same-temp` da se uzastopni pristupi ne bi spajali; isključite i optimizaciju `asan-opt-globals` kada trke nad globalnim promenljivama moraju biti vidljive. KCOV prenosi nastale zapise u userspace. Uporedite pristupe iz različitih konteksta izvršavanja i zadržite parove čiji se opsezi bajtova preklapaju i kod kojih bar jedna strana vrši upis; tretirajte `kfree()` kao upis kako bi i promene životnog veka postale kandidati.<sup>[[17]](#references)</sup>

Za rad koji se nastavlja izvan inicijalnog taska, kao što su obrada paketa ili RCU callback-ovi, podsistem mora da prosledi KCOV remote-coverage handle. Uzvodni remote KCOV je opcionalan i nije automatski dostupan za proizvoljan rad u pozadini, pa izostanak prosleđivanja može učiniti stvarnu interakciju nevidljivom.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifikujte isti dinamički pristup pri svakom pokretanju

Nemojte ponavljati izvršavanje nad konkretnom adresom heap-a, koja se može promeniti nakon svake alokacije, niti samo nad adresom instrukcije, koja je dvosmislena unutar pomoćnih funkcija kao što su `memcpy()` i `spin_lock()`. MAccConc koristi **trag steka proširen brojačima**: svaki okvir identifikuje pozvanu funkciju i broj njenog poziva unutar pozivaoca, a poslednji element identifikuje instrukciju pristupa memoriji. Zapisi ulaska u funkciju i izlaska iz nje iz SanitizerCoverage omogućavaju userspace-u da rekonstruiše ovaj dinamički identifikator, koji ostaje stabilan uprkos promenama adresa i nepovezanim promenama toka kontrole.<sup>[[17]](#references)</sup>

### Pretvorite parove kandidata u prinudne rasporede

Zakrpljeni ioctl `KCOV_SET_DI` povezuje identifikator pristupa proširen brojačima sa akcijom nad zajedničkim flag-om.<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Postavi flag *N* neposredno pre izabranog pristupa. |
| `DI_STACK_WAIT` | Pre izabranog pristupa, čekaj u petlji dok se flag *N* ne postavi ili ne istekne podešeno ograničenje. |
| `DI_STACK_WAKE_POST` | Postavi flag *N* neposredno nakon izabranog pristupa. |

Za delimično ograničenje **A-happens-before-B**, povežite `DI_STACK_WAKE_POST` sa A, a `DI_STACK_WAIT` sa B, koristeći isti flag. Za potpuno definisan raspored dva konteksta, započnite tako što je B blokiran, a zatim naložite A da probudi B i sačeka na prvoj tački prenosa; B izvršava obrnutu operaciju pri sledećem prenosu. Ovo funkcioniše poput determinističkog prebacivanja konteksta i koristi ga automatski A-B-A istraživač.<sup>[[17]](#references)</sup>

Minimalna kampanja podrazumeva kompajliranje test-slučaja sa četiri hook-a (`test_setup`, dve thread funkcije i `test_end`) kao shared library-ja, prikupljanje traga bez ograničenja, a zatim nabrajanje A-B-A kandidata ili dodavanje ručnih ograničenja oko sumnjivih pristupa.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Vremenska ograničenja tumačite odvojeno od uspešnih promena redosleda: traženi redosled možda nije moguć jer zaključavanje ili zavisnost pri inicijalizaciji/objavljivanju sprečava drugi kontekst da stigne do tačke ubacivanja. Imajte na umu i slepe tačke KASAN-a: direktni pristupi steku obično nisu obuhvaćeni, osim ako postoji mogućnost da budu van granica; globalne promenljive se izostavljaju uz podrazumevanu optimizaciju, a aktuelni kompajleri ne mogu istovremeno da emituju ASAN i TSAN hook-ove. Pored toga, prototip gubi KCOV bafer kada se guest sruši, zato obezbedite nezavisnu konzolu/oracle za detekciju rušenja.<sup>[[17]](#references)</sup>

Za buduće fuzzing vođen konkurentnošću, beležite sažetke pristupa memoriji po ulazu ili sistemskom pozivu, uparite operacije koje bi formirale tačke komunikacije između konteksta, a zatim istražujte samo te kombinacije. VM snimci stanja stabilizuju globalno stanje i adrese; bez snimaka stanja, metapodaci o mestu alokacije mogu da apstrahuju objekte između pokretanja. Ovo je predloženo proširenje, a ne funkcija aktuelnih MAccConc korisničkih alata.<sup>[[17]](#references)</sup>

## Introspekcija harness-a: rano otkrijte plitke fuzzere

Kada kampanja zastane, problem često nije mutator, već **harness**. Koristite **introspekciju dostižnosti/pokrivenosti** da biste pronašli funkcije koje su statički dostižne iz cilja fuzzing-a, ali su retko ili nikad dinamički pokrivene. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u cilj prekasno ili prerano.
- Korpusu semena nedostaje čitava grupa funkcionalnosti.
- Cilju je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a koji „radi sve“.

Ako koristite OSS-Fuzz / ClusterFuzz tokove rada, Fuzz Introspector može da uporedi statičku dostižnost sa pokrivenošću tokom izvršavanja i da generiše izveštaje na osnovu vremenski ograničenog izvršavanja ili javnog korpusa.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Koristite izveštaj da odlučite da li da dodate novi harness za netestiranu putanju parsera, proširite korpus za određenu funkcionalnost ili podelite monolitni harness na manje ulazne tačke.

## Izbor fuzzing ciljeva na osnovu grafa i trijaža mutacija

Ako već imate **nalaze statičke analize**, **mutacije koje su preživele testiranje mutacijama** i **izveštaje o pokrivenosti**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **graf poziva**, označite čvorove **ciklomatskom složenošću**, **dostižnošću iz entrypoint-a/nepoverljivog ulaza** i svim spoljnim nalazima, a zatim postavite pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostižne iz nepoverljivog ulaza?
- Koje mutacije koje su preživele testiranje nalaze se na putanjama od parsera/handlera do bezbednosno kritičnog koda?
- Koje funkcije predstavljaju arhitektonska uska grla sa neuobičajeno velikim **radijusom uticaja**?

Ovim se obično otkrivaju bolji fuzzing ciljevi nego kada se posmatra samo „najniža pokrivenost“. Parser/dekoder sa **visokom složenošću** i potvrđenom **dostižnošću spolja** bolji je kandidat za harness nego izolovani interni pomoćni kod sa slabom pokrivenošću, ali bez putanje kojom napadač može da utiče na njega.

### Praktični postupak trijaže

1. Napravite **graf koda** iz kodne baze i izdvojite metrike složenosti/grana za svaku funkciju.
2. Navedite **entrypoint-e** koji primaju ulaz pod kontrolom napadača: obrađivače zahteva, dekodere, uvoznike, parsere protokola, CLI/čitače datoteka.
3. Pokrenite **upite nad putanjama** od tih entrypoint-a do kandidatskih funkcija da biste odvojili dostižnu površinu za napad od mrtvog koda/koda dostupnog samo interno.
4. Dajte prioritet čvorovima koji objedinjuju:
   - visoku **ciklomatsku složenost**
   - potvrđenu **dostižnost iz nepoverljivog ulaza**
   - veliki **radijus uticaja** ili mnogo zavisnih funkcija nizvodno
   - potkrepljujuće dokaze, kao što su nalazi **SARIF**-a, beleške iz bezbednosne revizije ili mutacije koje su preživele testiranje
5. Najpre napišite fokusirane harness-e za čvorove sa najboljim rezultatom, posebno za **parser-e/kodeke** kao što su dekoderi za hex/Base64/IP/poruke.

### Mutacije koje su preživele: ekvivalentne ili upotrebljive

Testiranje mutacijama često daje bučnu listu mutacija koje su preživele. Pre nego što svaku takvu mutaciju proglasite bezbednosnim propustom, pomoću grafa proverite:

- Da li je izmenjena funkcija dostižna iz entrypoint-a pod kontrolom napadača?
- Da li su sve putanje poziva ograničene jačim invarijantama od izmenjene provere?
- Da li se čvor nalazi u mrtvom kodu, logici koja utiče samo na formatiranje ili putanji sa aritmetikom/parserom visokog uticaja?

Mutacije koje ostaju nedostižne ili su strukturno ograničene često su **ekvivalentni mutanti**. Mutacije koje ostaju **dostižne** i dotiču se **graničnih uslova**, **putanja prelivanja/prenosa** ili **bezbednosno kritične aritmetike/parsiranja** treba unaprediti u:

- nove fuzz harness-e
- direktne testove svojstava/invarijanti
- ciljane skupove vektora za granične slučajeve

### Povezivanje spoljnih nalaza sa grafom

Ako vaš SAST proces izvozi **SARIF**, preslikajte nalaze na čvorove grafa prema **datoteci + opsegu redova** i pomoću grafa proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **radijus uticaja** označene funkcije
- proverite da li se nalaz nalazi na nekoj putanji od entrypoint-a
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno kada odlučujete da li da uložite vreme u fuzzing određene funkcije: čvor koji je **dostižan**, **složen** i već ima **SAST nalaze** često je bolji cilj od čvora koji je samo složen, ali nema putanju dostupnu napadaču.

Primer postupka pomoću alata Trailmark.<sup>[[6]](#references)</sup>

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

Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite graf da izaberete fuzz ciljeve s najvećom očekivanom bezbednosnom vrednošću, a zatim na osnovu mutanata koji prežive utvrdite koje granice i invarijante vaš harness treba da testira.<sup>[[5]](#references)</sup>

## Go fuzzing sa gosentry: Snažniji mehanizam, tipizovani ulazi i diferencijalne provere

Ako Go cilj već ima native `testing.F` harness, praktičan način za nadogradnju jeste pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), fork-ovanog Go toolchain-a koji zadržava `go test -fuzz`, ali zamenjuje backend sa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Ovo je korisno kada se izvorni Go fuzzer zaglavi na **teškim poređenjima**, **tipiziranim ulazima** ili formatima koji zahtevaju mnogo parsiranja. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za početne vrednosti i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite pomoću gosentry `go` binarne datoteke umesto standardnog toolchain-a.
- Tretirajte rezultat kampanje kao uobičajeno fuzzing pokretanje vođeno pokrivenošću, ali uz LibAFL raspoređivanje/mutacije i bolje prateće detektore.

### Pretvorite tihe greške u fuzz nalaze

Čest problem u Go procenama jeste to što se opasno ponašanje često podrazumevano **ne završava padom**. Uz gosentry, nekoliko klasa stanja „loših, ali tihih“ možete pretvoriti u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da bi odabrane putanje za logovanje/greške izazivale pad (korisno za putanje koda u stilu `log.Fatal` koje bi inače samo zapisale poruku i nastavile dalje).
- `--catch-races=true` da bi se novootkriveni unosi iz reda ponovo pokrenuli pomoću Go race detector-a.
- `--catch-leaks=true` da bi se novi unosi iz reda ponovo pokrenuli pomoću `goleak` i da bi se zaustavilo izvršavanje pri otkrivanju curenja gorutina.
- LibAFL obrada zastoja, kako bi se **beskonačne petlje / veoma spori ulazi** zabeležili kao fuzz nalazi umesto da nestanu kao timeout-i.
- Podrazumevano ugrađene provere prekoračenja aritmetičkih vrednosti, uz opcione provere skraćivanja pomoću instrumentacije u stilu go-panikint.

Ovo je posebno korisno za ciljeve kod kojih je bezbednosni uticaj **greška parsera bez panike**, **greška u konkurentnosti** ili **zastoj koji omogućava samo DoS**, a ne oštećenje memorije.

### Fuzzing Go API-ja sa uvažavanjem struktura

Izvorni Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira koristi tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (strukture, slice-ove, nizove, pokazivače), uz istovremeno menjanje bajtova u njihovoj osnovi.<sup>[[7]](#references)[[8]](#references)</sup>

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

Koristite ovo kada bi izrada lažnog žičanog formata samo za fuzzing prikrila logičke greške kodom za parsiranje koji postoji samo u harness-u. Za kampanje diferencijalnog fuzzing-a ili fuzzing-a zasnovanog na gramatici, zadržite ulaz harness-a kao jedan `[]byte` ili `string` i obavite parsiranje unutar callback-a.

### Fuzzing zasnovan na gramatici za parser-e i protokolarne ulaze

Za parser-e, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** na vrhu LibAFL-a. Gramatika je JSON niz produkcionih pravila, a harness bi obično trebalo da prima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Napomene o metodologiji:

- Koristite grammar mode kada mutacije na nivou bajtova uglavnom ne prolaze rane provere sintakse.
- Ograničite gramatiku na **bezbednosno relevantan podskup** jezika/protokola umesto da modelujete celu specifikaciju.
- Koristite velike granične vrednosti u terminalima/neterminalima da biste testirali granice celih brojeva, dužina i mašina stanja.
- Grammar mode održava ulaze validnim prema gramatici, ali cilj i dalje prima **bajtove/stringove**, pa parsiranje i semantičke provere ostaju unutar koda koji je obuhvaćen harness-om.

### Diferencijalni fuzzing: upoređujte implementacije, ne samo padove

Dobar obrazac za Go ekosisteme je **diferencijalni fuzzing zasnovan na gramatici**: generišite validne strukturirane ulaze i prosledite ih dvama parserima, klijentima ili mehanizmima za upravljanje prelazima stanja.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacija izaziva paniku, dok druga ispravno odbija unos
- nepodudaranja u prihvatanju/odbacivanju unosa
- različita stabla parsiranja ili dekodirani objekti
- različite promene stanja, nonce vrednosti, salda ili koreni stanja

Ovo je praktičan način za pronalaženje **nepodudaranja konsenzusa**, **dvosmislenosti parsera** i **odstupanja između specifikacije i implementacije** koja čisto fuzz testiranje radi pronalaženja padova često ne otkriva.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponovo upotrebite korpus kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo pokrenite sačuvani korpus reda čekanja da biste generisali Go izveštaj o pokrivenosti, bez potrebe da ručno izvozite zaseban korpus.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` kako bi gosentry razrešio ispravno stanje keširane kampanje.



## References

- [1] [Fuzzing mutacionom gramatikom](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing protokola vođen pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Forkovali smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brzi greybox fuzzer za protokole sa stanjem koji koristi snimke stanja](https://arxiv.org/abs/2202.03643)
- [10] [Nema gramatike? Nema problema: Ka fuzzingu Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasan fuzzing uz adaptivne i promenljive snimke stanja](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentacija: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivni fuzzing osetljiv na kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Fuzzing Binder-a](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - dokumentacija za izgradnju i regresione semenske datoteke](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Istraživanje race condition-a u Linux kernelu pomoću kontrolisanih preplitanja pristupa memoriji](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrivenost koda za fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO sintaksa proširenih naziva datoteka](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec bezbednosno obaveštenje: CFITSIO, četvrti kvartal 2025.](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing proširene sintakse naziva datoteka CFITSIO: 16 ranjivosti bezbednosti memorije i trijaža uz pomoć Codex-a](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
