# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Pokrivenost vs. Semantika

Kod **mutational grammar fuzzing-a**, ulazi se menjaju tako da ostanu **gramatički ispravni**. U režimu vođenom pokrivenošću, kao seedovi za korpus čuvaju se samo uzorci koji ostvaruju **novu pokrivenost**. Kod **jezičkih ciljeva** (parseri, interpreteri, engine-i), ovim se mogu propustiti greške koje zahtevaju **semantičke lance/tokove podataka**, u kojima izlaz jedne konstrukcije postaje ulaz druge.<sup>[[1]](#references)</sup>

**Način otkaza:** fuzzer pronalazi seedove koji pojedinačno izvršavaju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani tok podataka**, pa se uzorak „bliži grešci” odbacuje jer ne donosi novu pokrivenost. Kada postoje **3+ zavisna koraka**, nasumično rekombinovanje postaje skupo, a povratne informacije o pokrivenosti ne usmeravaju pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** kod gramatika sa mnogo zavisnosti, razmotrite **kombinovanje mutacionih i generativnih faza** ili usmeravanje generisanja ka obrascima **ulančavanja funkcija** (ne samo ka pokrivenosti).<sup>[[1]](#references)</sup>

## Zamke u raznovrsnosti korpusa

Mutacija vođena pokrivenošću je **pohlepna**: uzorak koji donese novu pokrivenost odmah se čuva, često zadržavajući velike neizmenjene delove. Vremenom korpusi postaju **skoro identični duplikati** sa malom strukturnom raznovrsnošću. Agresivno smanjivanje može ukloniti koristan kontekst, pa je praktičan kompromis **smanjivanje uz uvažavanje gramatike** koje **staje kada se dostigne minimalni prag tokena** (smanjuje šum, ali zadržava dovoljno okolne strukture da bi mutacije i dalje bile korisne).<sup>[[1]](#references)</sup>

Praktično pravilo za korpus kod mutacionog fuzzing-a glasi: **dajte prednost malom skupu strukturno različitih seedova koji maksimalno povećavaju pokrivenost** u odnosu na veliku gomilu skoro identičnih duplikata. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni korpusi, crawling, zabeleženi saobraćaj, skupovi datoteka iz ekosistema ciljnog sistema).
- Izdvojite reprezentativne uzorke pomoću **smanjivanja korpusa na osnovu pokrivenosti**, umesto da zadržite svaki ispravan uzorak.
- Zadržite seedove **dovoljno malim** da bi mutacije pogađale smislena polja, umesto da većinu ciklusa troše na nebitne bajtove.
- Ponovo smanjite korpus nakon većih izmena harness-a/instrumentacije, jer se „najbolji” korpus menja kada se promeni dostupnost delova koda.

## Mutacije svesne poređenja za magične vrednosti

Čest razlog zbog kog fuzzer-i zapinju nisu sintaksa, već **stroga poređenja**: magični bajtovi, provere dužine, enum stringovi, kontrolne sume ili vrednosti za izbor parsera koje se proveravaju pomoću `memcmp`, switch tabela ili niza poređenja. Čiste nasumične mutacije troše cikluse pokušavajući da pogode ove vrednosti bajt po bajt.

Za ove ciljeve koristite **praćenje poređenja** (na primer, tokove rada u stilu AFL++ `CMPLOG` / Redqueen) kako bi fuzzer mogao da vidi operande neuspelih poređenja i usmeri mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>

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
- Kombinujte ovo sa **rečnicima** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali rečnik sa gramatičkim tokenima, imenima segmenata, glagolima i separatorima često je korisniji od ogromne generičke liste reči.
- Ako cilj obavlja mnogo uzastopnih provera, prvo rešite najranija poređenja „magijskih“ vrednosti, a zatim ponovo minimizujte dobijeni korpus kako bi kasnije faze počinjale od već ispravnih prefiksa.

## Fuzzing API-ja za datoteke koji skrivaju jezik za nazive datoteka

Parametar nazvan `filename`, `path` ili `URL` može biti ulazna tačka interpreter-a, a ne doslovno traženje datoteke. Na primer, CFITSIO Extended Filename Syntax (EFS) obrađuje selektore u uglastim zagradama, izraze za redove/piksele, izračunate kolone, histograme i transformacije pre nego što vrati otvoreni objekat; neki oblici takođe kreiraju privremene kopije. Tokom mapiranja površine napada, klasifikujte svaki API za otvaranje/uvoz kao **doslovnu putanju** ili **interpretiranu putanju**, a zatim fuzz-ujte produkcionu ulaznu tačku koju aplikacije zaista pozivaju.<sup>[[20]](#references)[[22]](#references)</sup>

Za rezultujuće primitive SSRF-a, kopiranja datoteka i rukovalaca protokolima — kao i bezbednije API-je za doslovne putanje — pogledajte [Mini-jezici za nazive datoteka kao primitive za SSRF/datoteke](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Držite pozadinski objekat odvojeno od programa koji se fuzz-uje

Kada se gramatika nalazi u sufiksu naziva datoteke, mutiranje samo bajtova referencirane datoteke ne obuhvata parser. Umesto toga, mali harness može da pročita jedan testcase kao string i prosledi ga API-ju za otvaranje koji interpretira sadržaj; kampanja za CFITSIO dosegla je većinu EFS parsera i evaluator-a pozivanjem funkcije `fits_open_file()` u režimu samo za čitanje. Neka važeće pozadinske datoteke budu dostupne odvojeno kako bi mutacije mogle da se usredsrede na jezik selektora/izraza, umesto da neprestano kvare osnovnu putanju.<sup>[[22]](#references)</sup>

Koristite seed-ove koji svaki dosežu drugu porodicu gramatike, a zatim izvedite kompaktan rečnik iz specifikacije i izvornog koda lexer-a/parsera. Ako se pokrivenost zaustavi dok ulazi stalno padaju u istu putanju sintaksne greške, sačuvajte važeće prefikse i dodajte separatore, operatore, ključne reči, nazive funkcija i reprezentativna imena polja, umesto da samo produžavate vreme nasumičnih mutacija.<sup>[[22]](#references)</sup>

Pokrenite harness sa rečnikom gramatike, na primer:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograničite neželjene efekte „read-only“ harness-a

Oznaka biblioteke „read-only“ ne garantuje testcase bez neželjenih efekata: jezik naziva datoteka može da prepiše ulaz, kreira izlazne datoteke ili materijalizuje privremene objekte. CFITSIO kampanja je u početku uništavala seed datoteke i ostavljala neočekivane datoteke širom filesystem-a, pa su bili potrebni čišćenje i izolacija.<sup>[[22]](#references)</sup>

- Svakom worker-u dodelite zaseban radni direktorijum koji se može odbaciti i privatni privremeni direktorijum.
- Izložite kopije kanonskih pomoćnih datoteka; nikada ne dozvolite da target izmeni jedinu kopiju corpus-a.
- Isključite pristup mreži, osim ako su udaljeni backend-i predviđeni target, i ograničite putanje za upis pomoću container-a, mount namespace-a ili ekvivalentnog sandbox-a.
- Resetujte direktorijum nakon svakog pokretanja ili grupe worker-a i neočekivane izmene filesystem-a tretirajte kao dodatne nalaze.

### Petlja crash-to-patch-to-fuzz

Grupišite crash-ove pre popravke da hiljade artefakata ne bi postale hiljade zadataka za patch. U CFITSIO proceni, AFLTriage je sveo početni skup crash-ova na nekoliko osnovnih uzroka; rezultujući savetodavni izveštaj prikazuje različite greške, uključujući netačne provere veličine odredišta, zastarele pokazivače nakon `realloc()`, aritmetičke greške i nebezbedne putanje čišćenja parser-a.<sup>[[21]](#references)[[22]](#references)</sup>

1. Svedite reprezentativni ulaz iz svakog klastera na minimum i reprodukujte problem pod AddressSanitizer-om.
2. Zabeležite tačan pristup koji je izazvao grešku, lokaciju u izvornom kodu, istoriju alokacija i oslobađanja memorije i stanje parser-a zbog kog invariant više nije važio.
3. Primenite jedan usko ograničen kandidat za patch i ponovo ga izgradite uz istu instrumentaciju za coverage i sanitizer.
4. Ponovo pokrenite originalni reproducer **i svaki ulaz iz njegovog klastera**; uključite i detekciju leak-ova, jer popravka bezbednosti memorije može da naruši vlasništvo nad memorijom na putanji greške.
5. Pokrenite funkcionalne testove sa stvarnim datotekama, a zatим nastavite iz akumuliranog queue-а (ili ponovo uvezite taj queue ako engine nakon izmene binarne datoteke zahteva nov izlazni direktorijum).
6. Ponavljajte postupak: uklanjanje prvog, površinskog crash-а često omogućava postojećim seed-ovima da stignu do dubljeg stanja parser-a.

LLM može da ubrza korak 2 i pripremi nacrt za korak 3 ako dobije ulaz koji izaziva crash, izveštaj sanitizer-a, harness i relevantni izvorni kod, ali njegov patch ostaje neproveren. O prihvatanju popravke odlučuju ponovna provera sanitizer-om i regresioni testovi, a ne objašnjenje modela.<sup>[[22]](#references)</sup>

## Bogatije povratne informacije kada edge coverage ne razlikuje različite putanje

Uobičajeni edge coverage ne može da razlikuje dva izvršavanja koja prolaze kroz isti helper iz različitih caller-a ili imaju različite kombinacije grana unutar funkcije. To je važno u deljenim decoder-ima, protocol dispatcher-ima i helper-ima interpreter-a, gde **putanja** do edge-a određuje aktivno stanje. Naivno praćenje svakog konteksta poziva takođe je rizično: mapa coverage-a i queue mogu naglo da porastu. Istraživanja context-sensitive fuzzing-a zato preporučuju da se dodatno preciziraju samo obećavajući konteksti, umesto da se ceo call graph tretira kao context-sensitive.<sup>[[14]](#references)</sup>

Novije verzije AFL++ pružaju **Ball-Larus per-function path coverage** pored uobičajenog edge coverage-a. Dodeljuje feature svakoj acikličnoj putanji kroz funkciju; povratne grane petlji se uklanjaju, pa ove povratne informacije razlikuju kombinacije grana, ali **ne i broj iteracija petlje**. Počnite sa opuštenim nivoom `1`, a zatim strože režime primenite samo na sumnjiv kod parser-a ili state machine-a, jer broj putanja može eksponencijalno da poraste.<sup>[[13]](#references)</sup>

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

**Smernice za kampanju:** oprezno primenjujte bogatije povratne informacije i pratite njihov trošak u mapi pokrivenosti/redovima.<sup>[[13]](#references)[[14]](#references)</sup>

- Paralelno pokrenite običnu instancu sa pokrivenošću grana; bogatije povratne informacije korisne su samo ako dodatni trošak reda/mape ne smanji broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da ograničite instrumentation putanja/pozivalaca kada velike biblioteke sa mnogo šablona ili generički pomoćni kod dominiraju mapom.
- Funkcije sa previše acikličnih putanja mogu da se preskoče u AFL++; upozorenja tokom kompilacije ukazuju na to da cilj treba staviti na allowlist ili koristiti manje strog nivo.
- Pokrivenost pozivalaca + putanja podržava samo jednu dubinu pozivalaca. Nemojte je kombinovati sa dubljim stekovima konteksta.
- ID-jevi putanja mogu da se menjaju između glavnih verzija LLVM-a. Tokom kampanje koristite isti toolchain i nemojte sinhronizovati korpuse zasnovane na PATH-u kao da su njihovi ID-jevi funkcija stabilni između različitih build-ova.
- Ove povratne informacije dopunjuju `CMPLOG`: praćenje poređenja rešava pitanje **koja vrednost prolazi kroz zaštitni uslov**, dok povratne informacije o putanjama/pozivaocima čuvaju **koja ruta i kombinacija grana su dovele do njega**.

## Stateful Fuzzing: sekvence su seed-ovi

Kod **protokola**, **autentifikovanih tokova rada** i **parsera u više faza**, zanimljiva jedinica često nije jedan blob, već **sekvenca poruka**. Spajanje čitavog transkripta u jednu datoteku i njegovo nasumično mutiranje obično je neefikasno jer fuzzer mutira svaki korak podjednako, čak i kada samo kasnija poruka doseže krhko stanje.<sup>[[4]](#references)</sup>

Efikasniji pristup je da se **sama sekvenca tretira kao seed**, a **uočljivo stanje** (kodovi odgovora, stanja protokola, faze parsera, tipovi vraćenih objekata) koristi kao dodatna povratna informacija.<sup>[[4]](#references)</sup>

- Održavajte **validne prefiksne poruke** neizmenjenim i usmerite mutacije na poruku koja pokreće **prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada naredni korak zavisi od njih.
- Dajte prednost mutiranju/spajanju pojedinačnih poruka umesto mutiranju celog serijalizovanog transkripta kao neprozirnog bloba.
- Ako protokol pruža smislene kodove odgovora, koristite ih kao **jeftin orakul stanja** da biste dali prednost sekvencama koje napreduju dublje.

Iz istog razloga vanilla fuzzing datoteka često propušta autentifikovane bagove, skrivene prelaze ili bagove parsera koji se javljaju „tek nakon rukovanja“: fuzzer mora da sačuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing drajvera sa više klijenata

Velika pokrivenost grana i dalje može da propusti bagove IPC drajvera jer pokrivenost ne opisuje **vlasništvo nad objektima, brojače referenci, poruke na čekanju, redosled čišćenja ili preplitanje niti**. Stranica [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) obrađuje model objekata drajvera; ovaj primer se fokusira na harness fuzzera. Android Binder je koristan model: dostizanje putanja za alokaciju i oslobađanje nije dovoljno ako fuzzer ne može da natera više procesa da operišu nad istim objektom kernela zahtevanym redosledom.<sup>[[15]](#references)</sup>

#### Modelujte protokol, a ne izolovane `ioctl` bafere

Predstavite testni slučaj kao uređenu gramatiku **identiteta klijenta + operacije + strukturisanih argumenata**. Binder LKL fuzzer koristi protobuf i `libprotobuf-mutator`, uz jedan persistentni klijent za upravljanje kontekstom i dva obična klijenta. Semantički harness zatim čuva odnose koje bi nasumično mutiranje bajtova uništilo.<sup>[[15]](#references)</sup>

- Keširajte vrednosti koje vraćaju prethodne operacije. Na primer, `BC_FREE_BUFFER` mora ponovo da upotrebi pokazivač na transakcioni bafer koji je vratio prethodni `ioctl`.
- Generišite validne podrazumevane odgovore kako bi sinhrone transakcije mogle da se završe, a kasnije operacije ostale dostupne.
- Odbacujte nemoguće prelaze, kao što su transakcije ka samom sebi ili više transakcija na čekanju prema istom cilju.
- Držite singleton stanje inicijalizacije van resetovanja po ulazu. Binder dozvoljava samo jednu registraciju `BINDER_SET_CONTEXT_MGR` po pokretanju sistema, pa bi stalno uništavanje i ponovno kreiranje tog klijenta učinilo kasnije ulaze nevažećim.

Korisni šablon za trku oko životnog veka jeste da jedan klijent prenese objekat, pokrene čišćenje niti ili procesa, a da istovremeno klijent primalac oslobodi transakcioni bafer. U primeru CVE-2020-0423, prenos `BINDER_TYPE_WEAK_BINDER`, a zatim trka između `BINDER_THREAD_EXIT` i `BC_FREE_BUFFER`, mogli su da oslobode ugrađeni `binder_work` dok ga je putanja za čišćenje niti koja se gasila i dalje koristila.<sup>[[15]](#references)</sup>

#### Ponovo uvedite kontrolisano preplitanje u kernel u userspace-u

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) povezuje stvarni kernel kod u harness u userspace-u i izlaže njegov syscall interfejs preko `lkl_syscall`. Tako se protobuf stanje, pokrivenost i KASAN lako koordiniraju u jednom procesu. Međutim, LKL obično izvršava syscall bez prekidanja od strane druge kernel niti. Za kampanje usmerene na trke, umetnite tačke `schedule()` oko odabranih granica zaključavanja/otključavanja i životnog veka, a zatim prepustite harness-u da nasumično bira sledećeg klijenta pri svakom ustupanju izvršavanja. Ove tačke postavljajte ciljano jer svaka od njih umnožava prostor za pretragu rasporeda. Nasumični raspoređivač koji su opisali istraživači **nije** deo upstream Binder fuzzera.<sup>[[15]](#references)</sup>

#### Izgradite i ponovo pustite serijalizovane seed-ove za regresiju

Upstream harness fiksira kompatibilnu verziju `libprotobuf-mutator`, uključuje instrumentation za LKL fuzzing i KASAN pomoću `LKL_FUZZING=1`, a za Binder uključuje `CONFIG_MMU` pomoću `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nakon preuzimanja namerno ranjive revizije ili primene rollback zakrpa dokumentovanih u upstream-u, serijalizovani seed može da reprodukuje ceo prelaz stanja sa više klijenata, bez njegove rekonstrukcije u ad hoc C proof of concept-u:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tretirajte nastali KASAN use-after-free kao potvrdu da je seed stigao do ranjive putanje životnog ciklusa. To **ne** dokazuje postojanje kasnijih primitiva potrebnih za izvršavanje koda u kernelu ili eskalaciju privilegija.<sup>[[16]](#references)</sup>

## Trik raznovrsnosti na jednoj mašini (u stilu Jackalope)

Praktičan način da se spoje **generativna novina** i **ponovno korišćenje pokrivenosti** jeste da se **kratkotrajni worker-i ponovo pokreću** nad persistent serverom. Svaki worker počinje sa praznim corpus-om, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi nad kombinovanim corpus-om, ponovo se sinhronizuje, a zatim se gasi. Tako se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno iskorišćavanje akumulirane pokrivenosti.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sekvencijalni radnici (primer petlje):**

<details>
<summary>Petlja za ponovno pokretanje Jackalope radnika</summary>

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
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo noviteti, kasnije ponovno korišćenje).
- U režimu grammar fuzzing, **početna sinhronizacija sa serverom se podrazumevano preskače** (nije potrebno `-skip_initial_server_sync`).
- Optimalna vrednost `T` zavisi od **cilja**; najbolje rezultate obično daje promena nakon što worker pronađe većinu lako dostupnog coverage-a.

## Snapshot Fuzzing za ciljeve koje je teško pripremiti za testiranje

Kada kod koji želite da testirate postaje dostupan tek **nakon dugotrajne pripreme** (pokretanja VM-a, dovršetka prijave, prijema paketa, parsiranja container-a, inicijalizacije servisa), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog procesa ili VM-a, ubacite svaki testni slučaj kroz putanju ulaza cilja, izvršavajte do pada/isteka vremena i vratite snapshot. Tako se izbegava ponavljanje inicijalizacije ili prefiksa protokola, a ovaj pristup je koristan za **mrežne servise**, **firmware**, **površine za napad nakon autentifikacije** i **ciljeve dostupne samo kao binarne datoteke**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite cilj dok željeno stanje ne bude spremno.
2. Napravite snapshot **memorije + registara** u tom trenutku.
3. Za svaki testni slučaj, upišite izmenjeni ulaz direktno u relevantni bafer gosta/procesa.
4. Izvršavajte do pada/isteka vremena/resetovanja.
5. Vratite snapshot; kod VM ciljeva, vratite samo **izmenjene stranice** ako je to podržano, pa ponovite.

Postavite snapshot što je moguće bliže prvom koraku parsiranja/dispatch-a koji zahteva mnogo resursa, na primer nakon tačke `recv`/`read` ili deserijalizacije paketa, i zabeležite ulazni bafer koji cilj koristi. Ovo prati princip adaptivnog postavljanja: pomeranje snapshota dublje u obradu ulaza kako bi se izbeglo ponavljanje posla.<sup>[[11]](#references)</sup>

## Istraživanje race uslova u Linux kernelu pomoću MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) pretvara race uslove u Linux kernelu osetljive na tajming u ponovljive rasporede pristupa memoriji. Može automatski da enumeriše izvršavanja **A-B-A** u dva konteksta ili da omogući analitičaru da zada ograničenja redosleda putem terminalskog UI-ja/GUI-ja. Ovo je eksperimentalni istraživački alat, a ne kompletan concurrency fuzzer: trenutno zahteva LLVM 23+ i kernel sa zakrpama iz projekta, alati komandne linije podržavaju dve testne niti, a predloženi userspace sloj za fuzzing nije implementiran.<sup>[[17]](#references)[[18]](#references)</sup>

### Prikupljanje tačaka komunikacije između konteksta

Izgradite instrumentirani kernel sa KASAN outline callback-ovima i zakrpljenom podrškom za KCOV memorijske zapise. README projekta takođe preporučuje onemogućavanje optimizacije sibling-call kako bi stack trace-ovi ostali upotrebljivi.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) pretvara instrumentirane pristupe u pozive pomoćnih funkcija. Zakrpe MAccConc kernela isključuju `asan-opt-same-temp` kako se uzastopni pristupi ne bi spajali; isključite i optimizaciju `asan-opt-globals` kada treba da budu vidljive trke nad globalnim promenljivama. KCOV prenosi dobijene zapise u userspace. Uporedite pristupe iz različitih konteksta izvršavanja i zadržite parove čiji se opsezi bajtova preklapaju i kod kojih bar jedna strana vrši upis; tretirajte `kfree()` kao upis kako bi i prelazi životnog veka bili kandidati.<sup>[[17]](#references)</sup>

Za rad koji se odvija van inicijalnog zadatka, kao što su obrada paketa ili RCU povratni pozivi, podsistem mora da prosledi KCOV remote-coverage handle. Uzvodni remote KCOV je opcionalan i nije automatski dostupan za proizvoljan rad u pozadini, pa izostanak prosleđivanja može učiniti stvarnu interakciju nevidljivom.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifikujte isti dinamički pristup pri svakom pokretanju

Nemojte ponavljati izvršavanje koristeći konkretnu adresu na heap-u, koja se može promeniti nakon svake alokacije, niti samo adresu instrukcije, koja je dvosmislena unutar pomoćnih funkcija kao što su `memcpy()` i `spin_lock()`. MAccConc koristi **trag steka obogaćen brojačima**: svaki okvir identifikuje funkciju koja se poziva i broj njenog pozivanja unutar pozivaoca, a poslednji element identifikuje instrukciju pristupa memoriji. Zapisi o ulasku/izlasku iz funkcije koje generiše SanitizerCoverage omogućavaju userspace-u da rekonstruiše ovaj dinamički identifikator, koji ostaje stabilan uprkos promenama adresa i nepovezanim šumovima u toku upravljanja.<sup>[[17]](#references)</sup>

### Pretvorite parove kandidata u prinudne rasporede

Zakrpani ioctl `KCOV_SET_DI` povezuje identifikator pristupa obogaćen brojačima sa radnjom nad deljenom zastavicom.<sup>[[17]](#references)</sup>

| Radnja | Semantika |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Postavite zastavicu *N* neposredno pre izabranog pristupa. |
| `DI_STACK_WAIT` | Pre izabranog pristupa, vrtite se dok se ne postavi zastavica *N* ili ne istekne podešeno ograničenje. |
| `DI_STACK_WAKE_POST` | Postavite zastavicu *N* neposredno nakon izabranog pristupa. |

Za delimično ograničenje **A-happens-before-B**, povežite `DI_STACK_WAKE_POST` sa A, a `DI_STACK_WAIT` sa B, koristeći istu zastavicu. Za potpuno definisan raspored sa dva konteksta, započnite tako što je B blokiran, zatim neka A probudi B i sačeka na prvoj tački prenosa; B na sledećem prenosu obavlja obrnutu operaciju. Ovo drugo funkcioniše kao determinističko prebacivanje konteksta i koristi ga automatski A-B-A explorer.<sup>[[17]](#references)</sup>

Minimalna kampanja je da četiri hook-a testnog slučaja (`test_setup`, dve funkcije niti i `test_end`) prevedete kao deljenu biblioteku, prikupite trag bez ograničenja, a zatim nabrojite A-B-A kandidate ili dodate ručna ograničenja oko sumnjivih pristupa.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeout tretirajte odvojeno od uspešnih promena redosleda: traženi redosled možda nije moguć jer zaključavanje ili zavisnost od inicijalizacije/objavljivanja sprečava drugi kontekst da stigne do tačke ubacivanja. Imajte na umu i KASAN-ove slepe tačke: direktni pristupi steku obično nisu obuhvaćeni hook-ovima osim ako postoji mogućnost da budu van granica, globalne promenljive se izostavljaju podrazumevanom optimizacijom, a trenutni kompajleri ne mogu istovremeno da generišu ASAN i TSAN hook-ove. Konačno, prototip gubi svoj KCOV bafer kada se guest sruši, zato sačuvajte nezavisnu crash konzolu/oracle.<sup>[[17]](#references)</sup>

Za buduće fuzzing usmereno na konkurentnost, zabeležite sažetke pristupa memoriji za svaki ulaz ili syscall, uparite operacije koje bi predstavljale tačke komunikacije između konteksta, a zatim istražujte samo te kombinacije. VM snapshot-ovi stabilizuju globalno stanje i adrese; bez snapshot-ova, metapodaci o mestima alokacije mogu da apstrahuju objekte između pokretanja. Ovo je predloženo proširenje, a ne funkcija trenutnih MAccConc userspace alata.<sup>[[17]](#references)</sup>

## Harness Introspection: Rano otkrijte površne fuzzere

Kada kampanja zastane, problem često nije u mutatoru, već u **harness-u**. Koristite **introspekciju dostižnosti/pokrivenosti** da pronađete funkcije koje su statički dostižne iz vaše fuzz mete, ali se retko ili nikad ne pokrivaju dinamički. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u metu prekasno ili prerano.
- Seed corpus ne sadrži celu porodicu funkcionalnosti.
- Meti je zaista potreban **drugi harness**, a ne jedan preveliki harness „koji radi sve“.

Ako koristite OSS-Fuzz / ClusterFuzz tokove rada, Fuzz Introspector može da uporedi statičku dostižnost sa pokrivenošću tokom izvršavanja i da generiše izveštaje na osnovu vremenski ograničenog pokretanja ili javnog corpus-a.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Koristite izveštaj da odlučite da li da dodate novi harness za putanju parsera koja nije testirana, proširite korpus za određenu funkciju ili podelite monolitni harness na manje ulazne tačke.

## Izbor fuzz ciljeva na osnovu grafa i trijaža mutacija

Ako već imate **nalaze statičke analize**, **preživele mutacije iz testiranja mutacijama** i **izveštaje o pokrivenosti**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **graf poziva**, označite čvorove **ciklomatskom složenošću**, **dostupnošću iz ulaznih tačaka/nepoverljivog ulaza** i svim spoljnim nalazima, a zatim postavljajte pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti su dostupne iz nepoverljivog ulaza?
- Koje preživele mutacije leže na putanjama od parsera/obrađivača do bezbednosno kritičnog koda?
- Koje funkcije su arhitektonska uska grla sa neuobičajeno velikim **blast radius**?

Ovo obično otkriva bolje fuzz ciljeve nego samo izbor funkcija sa „najnižom pokrivenošću“. Parser/dekoder sa **visokom složenošću** i potvrđenom **dostupnošću spolja** bolji je kandidat za harness nego izolovani interni pomoćni kod sa slabom pokrivenošću, ali bez putanje kojom bi napadač mogao da dođe do njega.

### Praktični postupak trijaže

1. Napravite **graf koda** iz baze koda i izdvojite metrike složenosti/grana za svaku funkciju.
2. Navedite **ulazne tačke** koje prihvataju podatke pod kontrolom napadača: obrađivače zahteva, dekodere, uvoznike, parserе protokola, CLI/čitače datoteka.
3. Pokрените **upite za putanje** od tih ulaznih tačaka do kandidatskih funkcija da biste odvojili dostupnu površinu napada od neaktivnog ili samo internog koda.
4. Dajte prioritet čvorovima koji objedinjuju:
   - visoku **ciklomatsku složenost**
   - potvrđenu **dostupnost iz nepoverljivog ulaza**
   - veliki **blast radius** ili mnogo zavisnih funkcija
   - potkrepljujuće dokaze, kao što su nalazi **SARIF**, beleške sa revizije ili preživele mutacije
5. Najpre napišite ciljane harness-e za čvorove sa najboljim rezultatima, naročito za **parserе/kodeke** kao što su dekoderi za hex/Base64/IP/poruke.

### Preživele mutacije: ekvivalentne ili iskoristive

Testiranje mutacijama često daje bučnu listu preživelih mutacija. Pre nego što svaku preživelu mutaciju proglasite bezbednosnim propustom, pomoću grafa proverite:

- Da li je izmenjena funkcija dostupna iz ulazne tačke pod kontrolom napadača?
- Da li su sve putanje poziva ograničene jačim invarijantama od one koju izmena proverava?
- Da li se čvor nalazi u neaktivnom kodu, logici koja utiče samo na formatiranje ili putanji za aritmetiku/parser sa velikim uticajem?

Preživele mutacije koje su i dalje nedostupne ili strukturno ograničene često su **ekvivalentni mutanti**. Preživele mutacije koje su i dalje **dostupne** i dotiču se **graničnih uslova**, **putanja prekoračenja/carry** ili **bezbednosno kritične aritmetike/parsiranja** treba unaprediti u:

- nove fuzz harness-e
- direktne testove svojstava/invarijanti
- ciljane vektore graničnih slučajeva

### Povežite spoljne nalaze sa grafom

Ako vaš SAST pipeline izvozi **SARIF**, mapirajte nalaze na čvorove grafa na osnovu **datoteke + opsega redova** i pomoću grafa proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **blast radius** označene funkcije
- proverite da li je nalaz na nekoj putanji od ulazne tačke
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno pri odlučivanju da li da vreme za fuzzing posvetite određenoj funkciji: čvor koji je **dostupan**, **složen** i već ima **SAST nalaze** često je bolja meta od čvora koji je samo složen, ali nema putanju dostupnu napadaču.

Primer postupka rada sa alatom Trailmark.<sup>[[6]](#references)</sup>

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

Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite graf da odaberete fuzz ciljeve s najvećom očekivanom bezbednosnom vrednošću, a zatim na osnovu preživelih mutacija utvrdite koje granice i invarijante vaš harness treba da optereti.<sup>[[5]](#references)</sup>

## Diferencijalni fuzzing kodiranja kriptografskih ključeva

Počnite od ispravnih serijalizovanih ključeva ili standardnih test vektora. Mutirajte kodirana polja, a da pritom ne narušite dužinu i strukturu potrebnu za pristup putanjama za uvoz i operacije, pa iste bajtove prosledite nezavisnim implementacijama. Uporedite prihvatanje i greške. Za nasumične potpise i šifrate potrebni su oracli za ispravnost, a ne poređenje bajt po bajt: proverite potpise ili uporedite zajedničke tajne dobijene kružnim tokom enkapsulacije i dekapsulacije. Test vektori potvrđuju usklađenost za poznate slučajeve; diferencijalno mutiranje ispituje neispravna kodiranja koja oni ne obuhvataju.<sup>[[23]](#references)[[26]](#references)</sup>

Za ove formate ključeva koristite oracla specifične za format:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Prošireni ključevi za potpisivanje ML-DSA:** izmenite upakovane koeficijente `s1` ili `s2` tako da budu izvan opsega `[-η, η]`, a da ključ i dalje može da se parsira. Proverite da li se pri uvozu ili potpisivanju ključ odbacuje i da li se eventualni dobijeni potpis može verifikovati. Samo razlike u prihvatanju ne predstavljaju kršenje standarda, jer FIPS 204 ne propisuje dodatne provere privatnog ključa. Pogledajte [mehanizam uslovnog curenja](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Parovi ključeva ML-KEM:** odvojite obavezne provere enkapsulacionog ključa i ulaza za dekapsulaciju od opcione provere konzistentnosti para (PCT) pri uvozu para. Izvršite enkapsulaciju javnim ključem, dekapsulaciju privatnim ključem i uporedite zajedničke tajne; nepodudaranje može da prekine šifrovanu komunikaciju čak i kada pojedinačni ključevi prođu ulazne provere. Proverite da li API validira ulaze tokom operacije ili putem zasebnog poziva; libcrux izlaže `validate_public_key(pk)` i `validate_private_key(sk, ct)`, ali te funkcije ne zamenjuju PCT.
- **Sirovi XMSS/XMSSMT ključevi:** testirajte serijalizovane kružne tokove ključeva za **potpisivanje i verifikaciju** kroz skupove parametara, a ne samo operacije nad ključevima u memoriji. XMSS i XMSSMT imaju zasebne četvorobajtne OID prostore, pa parser koji proverava samo OID i prvo pokušava XMSS može pogrešno klasifikovati XMSSMT ključ sa istim OID-om i odbiti uvoz. Opisani RustCrypto parser pokazuje problem interoperabilnosti/dostupnosti, a ne falsifikovanje potpisa.

## Go fuzzing uz gosentry: snažniji engine, tipizirani ulazi i diferencijalne provere

Ako Go cilj već ima izvorni harness `testing.F`, praktičan način za unapređenje jeste da pokrenete isti harness pomoću [gosentry](https://github.com/trailofbits/gosentry), forkovanog Go toolchain-a koji zadržava `go test -fuzz`, ali menja pozadinski engine u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This je korisno kada se native Go fuzzer zaglavi na **teškim poređenjima**, **tipiziranim ulazima** ili **formatima sa složenim parserima**. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za seed-ove i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite gosentry-jevim `go` binarnim fajlom umesto standardnog toolchain-a.
- Tretirajte dobijenu kampanju kao uobičajeno coverage-guided pokretanje, ali uz LibAFL scheduling/mutation i bolje prateće detektore.

### Pretvorite tihe greške u fuzz nalaze

Čest problem pri Go procenama jeste to što opasno ponašanje često podrazumevano **ne izaziva crash**. Uz gosentry, nekoliko kategorija „loših, ali tihih“ stanja možete pretvoriti u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da bi se odabrane putanje za logging/error ponašale kao crash-evi (korisno za putanje koda u stilu `log.Fatal` koje bi inače samo zapisale poruku i nastavile).
- `--catch-races=true` da bi se novootkrivene stavke reda čekanja ponovo pokrenule uz Go race detector.
- `--catch-leaks=true` da bi se nove stavke reda čekanja ponovo pokrenule uz `goleak` i zaustavile ako dođe do curenja gorutina.
- LibAFL obrada zaglavljivanja, koja zadržava **beskonačne petlje / veoma spore ulaze** kao fuzz nalaze umesto da ih odbaci kao timeout-e.
- Podrazumevano ugrađene provere aritmetičkog overflow-a, kao i opcione provere truncation-a kroz instrumentaciju u stilu go-panikint.

Ovo je naročito korisno za ciljeve kod kojih je bezbednosni uticaj **greška parsera bez panic-a**, **concurrency bug** ili **zaglavljivanje koje izaziva samo DoS**, a ne oštećenje memorije.

### Struct-aware fuzzing za tipizirane Go API-je

Native Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira obrađuje tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (struct-ove, slice-ove, nizove, pokazivače), uz istovremenu mutaciju osnovnih bajtova.<sup>[[7]](#references)[[8]](#references)</sup>

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

Koristite ovo kada bi pravljenje lažnog wire formata samo za fuzzing sakrilo logičke greške iza koda za parsiranje koji postoji samo u harness-u. Za diferencijalne kampanje ili kampanje zasnovane na gramatici, neka ulaz u harness bude jedan `[]byte` ili `string`, a parsiranje obavite unutar callback-a.

### Fuzzing zasnovan na gramatici za parsere i protokolarne ulaze

Za parsere, formate i ulazne jezike, gosentry može da pokrene **Nautilus grammar fuzzing** povrh LibAFL-a. Gramatika je JSON niz produkcionih pravila, a harness bi obično trebalo da prima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Beleške o metodologiji:

- Koristite režim gramatike kada većina mutacija na nivou bajtova ne prođe rane sintaksne provere.
- Ograničite gramatiku na **bezbednosno relevantan podskup** jezika/protokola, umesto da modelujete celu specifikaciju.
- Koristite velike granične vrednosti u terminalima/neterminalima da biste opteretili ivice celobrojnih vrednosti, dužina i mašina stanja.
- Režim gramatike održava ulaze gramatički ispravnim, ali cilj i dalje prima **bajtove/niske**, tako da parsiranje i semantičke provere ostaju unutar koda obuhvaćenog harnessom.

### Differential fuzzing: poređenje implementacija, ne samo padova

Snažan obrazac za Go ekosisteme je **grammar-based differential fuzzing**: generisanje važećih strukturiranih ulaza i prosleđivanje dvama parserima, klijentima ili mehanizmima za upravljanje prelazima stanja.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacija izaziva paniku, dok druga uredno odbija ulaz
- nepodudaranja prihvaćenih/odbijenih ulaza
- različita stabla parsiranja ili dekodirani objekti
- različiti prelazi stanja, nonce vrednosti, stanja računa ili koreni stanja

Ovo je praktičan način za otkrivanje **nepodudaranja konsenzusa**, **dvosmislenosti parsera** i **odstupanja između specifikacije i implementacije**, koja čisto fuzziranje usmereno na padove često ne otkriva.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponovo upotrebite corpus kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo pokrenite corpus sačuvanog reda čekanja da biste generisali Go izveštaj o pokrivenosti, bez ručnog izvoza zasebnog corpusa.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` kako bi gosentry pronašao odgovarajuće keširano stanje kampanje.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing mutacionom gramatikom](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing protokola vođen pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Forkovali smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brzi greybox fuzzer za stateful mrežne protokole koji koristi snimke stanja](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike? Nema problema: ka fuzzingu Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasan fuzzing uz adaptivne i promenljive snimke stanja](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [LLVM instrumentacija za AFL++: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivni fuzzing osetljiv na kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - fuzzing Binder-a](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - dokumentacija za build i regresione seed-ove](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Istraživanje uslova trke u Linux kernelu uz kontrolisano preplitanje pristupa memoriji](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrivenost koda za fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Proširena sintaksa imena datoteka za CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec savet: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing proširene sintakse imena datoteka za CFITSIO: 16 ranjivosti bezbednosti memorije i trijaža uz pomoć Codex-a](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Diferencijalni fuzzing za kriptografiju](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standard za mehanizam enkapsulacije ključeva zasnovan na modulnoj rešetki](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Greška u parsiranju XMSSMT OID-a - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stanje implementacija postkvantne kriptografije](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
