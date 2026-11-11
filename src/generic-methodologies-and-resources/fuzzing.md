# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Pokrivenost naspram semantike

Kod **mutational grammar fuzzing-a**, ulazi se menjaju tako da ostanu **gramatički validni**. U režimu vođenom pokrivenošću, kao početni uzorci korpusa čuvaju se samo primeri koji aktiviraju **novu pokrivenost**. Kod **jezičkih ciljeva** (parsera, interpretera, engine-a), ovim mogu da se propuste greške koje zahtevaju **semantičke lance/lančane tokove podataka**, gde izlaz jednog konstrukta postaje ulaz drugog.<sup>[[1]](#references)</sup>

**Način otkaza:** fuzzer pronalazi početne uzorke koji pojedinačno aktiviraju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani tok podataka**, pa se uzorak „bliži grešci“ odbacuje jer ne doprinosi pokrivenosti. Kada postoje **3 ili više zavisnih koraka**, nasumična rekombinacija postaje skupa, a povratne informacije o pokrivenosti ne usmeravaju pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** kod gramatika sa mnogo zavisnosti razmotrite **kombinovanje mutacionih i generativnih faza** ili usmeravanje generisanja ka obrascima **ulančavanja funkcija** (ne samo ka pokrivenosti).<sup>[[1]](#references)</sup>

## Zamke u raznovrsnosti korpusa

Mutacije vođene pokrivenošću su **pohlepne**: uzorak koji donosi novu pokrivenost odmah se čuva, a često zadržava i velike neizmenjene delove. Vremenom korpusi postaju **skoro duplikati** sa malom strukturnom raznovrsnošću. Agresivno smanjivanje može da ukloni koristan kontekst, pa je praktičan kompromis **smanjivanje uz uvažavanje gramatike**, koje **staje kada se dostigne minimalni prag tokena** (smanjuje šum, a zadržava dovoljno okolne strukture da bi uzorak i dalje bio pogodan za mutacije).<sup>[[1]](#references)</sup>

Praktično pravilo za korpus pri mutacionom fuzzing-u glasi: **dajte prednost malom skupu strukturno različitih početnih uzoraka koji maksimizuju pokrivenost** u odnosu na veliku gomilu skoro dupliranih uzoraka. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni korpusi, podaci prikupljeni crawling-om, snimljeni saobraćaj, skupovi datoteka iz ekosistema ciljnog sistema).
- Svedite ih na manji skup pomoću **smanjivanja korpusa zasnovanog na pokrivenosti**, umesto da zadržite svaki validan uzorak.
- Neka početni uzorci budu **dovoljno mali**, kako bi mutacije zahvatale značajna polja umesto da se većina iteracija troši na nebitne bajtove.
- Ponovo smanjite korpus nakon većih izmena harness-a/instrumentacije, jer se „najbolji“ korpus menja kada se promeni doseg koda.

## Mutacije koje uzimaju poređenja u obzir za magične vrednosti

Čest razlog zbog kog fuzzers prestaju da napreduju nisu sintaksne prepreke, već **stroga poređenja**: magični bajtovi, provere dužine, enum stringovi, kontrolne sume ili vrednosti za izbor parsera koje proveravaju `memcmp`, switch tabele ili nizovi poređenja. Čiste nasumične mutacije troše iteracije pokušavajući da pogode te vrednosti bajt po bajt.

Za takve ciljeve koristite **praćenje poređenja** (na primer, radne tokove u stilu AFL++ `CMPLOG` / Redqueen) kako bi fuzzer mogao da vidi operande neuspešnih poređenja i usmeri mutacije ka vrednostima koje ih zadovoljavaju.<sup>[[3]](#references)</sup>

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

- Ovo je posebno korisno kada cilj skriva složenu logiku iza **potpisa datoteka**, **glagola protokola**, **oznaka tipa** ili **bitova funkcionalnosti koji zavise od verzije**.
- Uparite ovo sa **rečnicima** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali rečnik sa gramatičkim tokenima, nazivima delova, glagolima i graničnicima često je vredniji od ogromne generičke liste reči.
- Ako cilj obavlja mnogo uzastopnih provera, prvo rešite najranija poređenja „magic” vrednosti, a zatim ponovo minimizujte dobijeni korpus kako bi kasnije faze počinjale od već validnih prefiksa.

## Fuzzing API-ja za datoteke koji skrivaju jezik naziva datoteka

Parametar nazvan `filename`, `path` ili `URL` može biti ulazna tačka za interpreter, a ne doslovno traženje datoteke. Na primer, CFITSIO Extended Filename Syntax (EFS) obrađuje selektore u uglastim zagradama, izraze za redove/piksele, izračunate kolone, histograme i transformacije pre nego što vrati otvoreni objekat; neki oblici takođe stvaraju privremene kopije. Tokom mapiranja površine napada, klasifikujte svaki open/import API kao **literal-path** ili **interpreted-path**, a zatim fuzz-ujte produkcionu ulaznu tačku koju aplikacije zaista pozivaju.<sup>[[20]](#references)[[22]](#references)</sup>

Za rezultujuće primitive SSRF, kopiranja datoteka i rukovaoce protokolima — kao i bezbednije API-je za literal-path — pogledajte [Mini-jezici naziva datoteka kao primitive za SSRF/datoteke](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Držite pozadinski objekat odvojeno od fuzz-ovanog programa

Kada se gramatika nalazi u sufiksu naziva datoteke, menjanje samo bajtova referencirane datoteke promašuje parser. Umesto toga, mali harness može da pročita jedan testcase kao string i prosledi ga API-ju za interpreted open; kampanja za CFITSIO dosegla je većinu EFS parsera i evaluatorâ pozivanjem funkcije `fits_open_file()` u režimu samo za čitanje. Validne pozadinske datoteke držite dostupnim odvojeno kako bi izmene bile usmerene na jezik selektora/izraza, umesto da stalno kvare osnovnu putanju.<sup>[[22]](#references)</sup>

Koristite seed-ove koji svaki dosežu različitu porodicu gramatike, a zatim napravite kompaktan rečnik na osnovu specifikacije i izvornog koda lexer/parser-a. Ako se pokrivenost zaustavi, dok ulazi stalno završavaju na istoj putanji sintaksne greške, sačuvajte validne prefikse i dodajte graničnike, operatore, ključne reči, nazive funkcija i reprezentativne nazive polja, umesto da samo povećavate vreme nasumičnih izmena.<sup>[[22]](#references)</sup>

Pokrenite harness sa gramatičkim rečnikom, na primer:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograničite sporedne efekte „read-only“ harness-a

Oznaka biblioteke za read-only ne garantuje da test case neće imati sporedne efekte: jezik naziva datoteka može da prepiše ulaz, kreira izlazne datoteke ili materijalizuje privremene objekte. CFITSIO kampanja je u početku uništavala seed datoteke i ostavljala neočekivane datoteke širom sistema datoteka, pa su bili neophodni čišćenje i izolacija.<sup>[[22]](#references)</sup>

- Dodelite svakom worker-u zaseban privremeni radni direktorijum i privatni privremeni direktorijum.
- Izložite kopije kanonskih datoteka koje služe kao osnova; nikada ne dozvolite da cilj menja jedinu kopiju korpusa.
- Onemogućite mrežni pristup, osim ako su udaljeni backend-i cilj testiranja, i ograničite putanje za upis pomoću kontejnera, mount namespace-a ili ekvivalentnog sandbox-a.
- Resetujte direktorijum nakon svakog izvršavanja ili grupe worker-a i tretirajte neočekivane promene sistema datoteka kao dodatne nalaze.

### Petlja od crash-a do patch-a pa do fuzz testiranja

Grupišite crash-eve pre popravke kako hiljade artefakata ne bi postale hiljade zadataka za patch. U proceni CFITSIO-a, AFLTriage je smanjio početni skup crash-eva na nekoliko osnovnih uzroka; nastali advisory prikazuje različite greške, uključujući netačne provere veličine odredišta, zastarele pokazivače nakon `realloc()`, aritmetičke greške i nesigurne putanje čišćenja parser-a.<sup>[[21]](#references)[[22]](#references)</sup>

1. Svedite reprezentativan ulaz za svaki klaster na minimum i reprodukujte problem uz AddressSanitizer.
2. Zabeležite tačan pristup koji je izazvao grešku, lokaciju u izvornom kodu, istoriju alokacije i oslobađanja memorije, kao i stanje parser-a zbog kog je invariant postao netačan.
3. Primените један уско усмерен кандидатски patch и поново изградите програм са истом инструментацијом за coverage и sanitizer.
4. Поново покрените оригинални репродуктор **и сваки улаз из његовог кластера**; укључите и детекцију цурења јер исправка безбедности меморије може да наруши власништво над ресурсима на путањи грешке.
5. Покрените функционалне тестове са стварним датотекама, па наставите од акумулираног реда (или поново увезите тај ред ако engine захтева свеж излазни директоријум након промене бинарног фајла).
6. Понављајте: уклањање првог плитког crash-а често омогућава постојећим seed-овима да дођу до дубљег стања parser-а.

LLM може да убрза корак 2 и припреми нацрт за корак 3 ако му се доставе улаз који изазива crash, извештај sanitizer-а, harness и релевантни изворни код, али његов patch остаје непоуздан. О томе да ли ће исправка бити прихваћена одлучују поновно покретање sanitizer-а и регресиони тестови — а не објашњење модела.<sup>[[22]](#references)</sup>

## Богатије повратне информације када покривеност ивица спаја различите путање

Уобичајена покривеност ивица не може да разликује два извршавања која пролазе кроз исти помоћни код из различитих позиваоца или изаберу различите комбинације грана унутар функције. То је важно у заједничким decoder-има, protocol dispatcher-има и interpreter helper-има, где **путања** до ивице одређује тренутно стање. Наивно праћење сваког контекста позива такође је опасно: мапа покривености и ред могу експлодирати. Истраживања контекстно осетљивог fuzzing-а зато препоручују прецизирање само обећавајућих контекста, уместо да се цео граф позива третира као контекстно осетљив.<sup>[[14]](#references)</sup>

Новије верзије AFL++ поред уобичајене покривености ивица нуде **Ball-Larus покривеност путања по функцији**. Она додељује feature свакој ацикличној путањи кроз функцију; повратне ивице петљи се уклањају, па ове повратне информације разликују комбинације грана, али **не и број итерација петље**. Почните са опуштеним нивоом `1`, а затим примените строже режиме само на сумњиви parser/state-machine код, јер број путања може експоненцијално да расте.<sup>[[13]](#references)</sup>

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

**Smernice za kampanju:** oprezno primenjujte bogatije povratne informacije i pratite njihovu cenu u coverage map-i/queue-u.<sup>[[13]](#references)[[14]](#references)</sup>

- Pokrenite paralelno običnu instancu sa edge coverage-om; bogatije povratne informacije su korisne samo ako dodatni trošak queue-a/map-e ne smanji broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da ograničite instrumentaciju path/caller-a kada velike biblioteke sa mnogo šablona ili generički pomoćni kod dominiraju map-om.
- Funkcije sa previše acikličnih putanja mogu da se preskoče u AFL++; upozorenja tokom kompajliranja ukazuju na to da cilj zahteva allowlisting ili manje strog nivo.
- Caller + path coverage podržava samo jednu dubinu caller-a. Nemojte ga kombinovati sa dubljim context stack-ovima.
- Path ID-jevi mogu da se promene između glavnih verzija LLVM-a. Tokom kampanje koristite nepromenjen toolchain i nemojte sinhronizovati korpuse zasnovane na PATH-u kao da su njihovi feature ID-jevi stabilni između različitih build-ova.
- Ove povratne informacije dopunjuju `CMPLOG`: praćenje poređenja rešava pitanje **koja vrednost prolazi guard**, dok path/caller feedback čuva **kojom rutom i kombinacijom grana se do nje stiglo**.

## Stateful Fuzzing: Sekvence su seed-ovi

Kod **protokola**, **autentifikovanih tokova rada** i **parsera u više faza**, zanimljiva jedinica često nije jedan blob, već **sekvenca poruka**. Spajanje celog transkripta u jednu datoteku i njegovo nasumično mutiranje obično je neefikasno, jer fuzzer podjednako mutira svaki korak, čak i kada samo kasnija poruka stiže do osetljivog stanja.<sup>[[4]](#references)</sup>

Efikasniji pristup je da se **sama sekvenca tretira kao seed**, a da se **uočljivo stanje** (kodovi odgovora, stanja protokola, faze parsera, vraćeni tipovi objekata) koristi kao dodatni feedback.<sup>[[4]](#references)</sup>

- Održavajte **validne poruke prefiksa** neizmenjenim i usmerite mutacije na poruku koja pokreće **prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server u prethodnim odgovorima kada sledeći korak zavisi od njih.
- Dajte prednost mutiranju/spajanju pojedinačnih poruka umesto mutiranju celog serijalizovanog transkripta kao neprozirnog bloba.
- Ako protokol izlaže smislene kodove odgovora, koristite ih kao **jeftin oracle stanja** da biste dali prednost sekvencama koje napreduju dublje.

Iz istog razloga se greške u autentifikaciji, skriveni prelazi ili greške parsera koje se javljaju „tek nakon handshake-a“ često ne otkriju običnim fuzzing-om datoteka: fuzzer mora da očuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing drajvera sa više klijenata

Visok edge coverage i dalje može da propusti greške IPC drajvera, jer coverage ne opisuje **vlasništvo nad objektima, broj referenci, poruke na čekanju, redosled čišćenja ni preplitanje niti**. Stranica [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) obrađuje model objekata drajvera; ovaj primer se fokusira na fuzzer harness. Android Binder je koristan primer: nije dovoljno stići i do putanja alokacije i oslobađanja ako fuzzer ne može da natera više procesa da rade nad istim kernel objektom u zahtevanom redosledu.<sup>[[15]](#references)</sup>

#### Modelujte protokol, a ne izolovane `ioctl` bafere

Predstavite test slučaj kao uređenu gramatiku **identitet klijenta + operacija + strukturisani argumenti**. Binder LKL fuzzer koristi protobuf i `libprotobuf-mutator`, sa jednim persistent context-manager klijentom i dva obična klijenta. Semantički harness zatim čuva odnose koje bi nasumično mutiranje bajtova uništilo.<sup>[[15]](#references)</sup>

- Keširajte vrednosti koje vraćaju ranije operacije. Na primer, `BC_FREE_BUFFER` mora ponovo da upotrebi pokazivač na transaction buffer koji je vratio prethodni `ioctl`.
- Generišite podrazumevane validne odgovore kako bi sinhrone transakcije mogle da se završe i kako bi kasnije operacije ostale dostižne.
- Odbacujte nemoguće prelaze, kao što su transakcije samom sebi ili više transakcija na čekanju ka istom odredištu.
- Držite singleton bootstrap stanje van resetovanja za svaki ulaz. Binder dozvoljava samo jednu registraciju `BINDER_SET_CONTEXT_MGR` tokom jednog pokretanja sistema, pa bi ponovljeno uništavanje i ponovno kreiranje tog klijenta učinilo kasnije ulaze nevalidnim.

Korisni obrazac za trku oko životnog veka jeste da jedan klijent prenese objekat, pokrene čišćenje niti ili procesa, a zatim istovremeno natera klijenta primaoca da oslobodi transaction buffer. U primeru CVE-2020-0423, prenos `BINDER_TYPE_WEAK_BINDER`, praćen trkom između `BINDER_THREAD_EXIT` i `BC_FREE_BUFFER`, mogao je da oslobodi ugrađeni `binder_work` dok ga je putanja čišćenja niti koja se gasila još koristila.<sup>[[15]](#references)</sup>

#### Vratite kontrolisano preplitanje u userspace kernel

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) povezuje stvarni kernel kod sa userspace harness-om i izlaže njegov syscall interfejs preko `lkl_syscall`. Tako je lako koordinisati protobuf stanje, coverage i KASAN u jednom procesu. Međutim, LKL obično izvršava syscall bez prekida od strane druge kernel niti. Za kampanje sa trkama, ubacite tačke `schedule()` oko odabranih granica zaključavanja/otključavanja i životnog veka, pa prepustite harness-u da nasumično izabere sledećeg klijenta pri svakom ustupanju kontrole. Ove tačke postavljajte ciljano, jer svaka od njih umnožava prostor za pretragu rasporeda. Randomizovani scheduler koji su opisali istraživači **nije** deo upstream Binder fuzzera.<sup>[[15]](#references)</sup>

#### Izgradite i ponovo pustite u rad serijalizovane regression seed-ove

Upstream harness fiksira kompatibilnu verziju `libprotobuf-mutator`, omogućava LKL fuzzing instrumentaciju i KASAN preko `LKL_FUZZING=1`, a Binder-u omogućava `CONFIG_MMU` pomoću `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nakon što preuzmete namerno ranjivu reviziju ili primenite rollback zakrpe dokumentovane upstream, serijalizovano početno stanje može da reprodukuje ceo prelaz stanja za više klijenata bez njegove rekonstrukcije u ad hoc C proof of concept:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tretirajte rezultat KASAN use-after-free kao potvrdu da je seed stigao do ranjive putanje životnog ciklusa. To **ne** dokazuje postojanje kasnijih primitiva potrebnih za izvršavanje koda u kernelu ili eskalaciju privilegija.<sup>[[16]](#references)</sup>

## Trik za raznovrsnost na jednoj mašini (u stilu Jackalope)

Praktičan način da se kombinuju **generativna novina** i **ponovna upotreba pokrivenosti** jeste da se pokreću kratkotrajni worker-i nad trajnim serverom. Svaki worker počinje sa praznim korpusom, sinhronizuje se nakon `T` sekundi, radi još `T` sekundi koristeći objedinjeni korpus, ponovo se sinhronizuje, a zatim se gasi. Tako se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno iskorišćavanje akumulirane pokrivenosti.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sekvencijalni workers (primer petlje):**

<details>
<summary>Jackalope petlja za ponovno pokretanje workera</summary>

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

- `-in empty` forsira **novi corpus** u svakoj generaciji.
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo noviteti, kasnije ponovna upotreba).
- U režimu grammar fuzzing, **početna sinhronizacija servera je podrazumevano preskočena** (nije potrebno `-skip_initial_server_sync`).
- Optimalna vrednost `T` zavisi od **cilja**; najbolje rezultate obično daje promena nakon što worker pronađe većinu „lake“ pokrivenosti.

## Snapshot Fuzzing za ciljeve koje je teško pripremiti

Kada kod koji želite da testirate postaje dostupan tek **nakon dugotrajne pripreme** (pokretanje VM-a, završetak prijave, prijem paketa, parsiranje kontejnera, inicijalizacija servisa), korisna alternativa je **snapshot fuzzing**: sačuvajte stanje spremnog procesa ili VM-a, ubacite svaki testni slučaj u ulaznu putanju cilja, izvršavajte do crash-a/isteka vremena, pa vratite snapshot. Tako se izbegava ponavljanje inicijalizacije ili prefiksa protokola. Ovaj pristup je koristan za **mrežne servise**, **firmware**, **površine napada nakon autentifikacije** i **ciljeve dostupne samo kao binarne datoteke**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Pokrenite cilj dok željeno stanje ne bude spremno.
2. U tom trenutku napravite snapshot **memorije + registara**.
3. Za svaki testni slučaj upišite izmenjeni ulaz direktno u odgovarajući bafer u guest-u/procesu.
4. Izvršavajte do crash-a/isteka vremena/resetovanja.
5. Vratite snapshot; za VM ciljeve, kada je podržano, vratite samo **izmenjene stranice**, pa ponovite.

Postavite snapshot što je moguće bliže prvom skupom koraku parsiranja/raspodele, na primer nakon tačke `recv`/`read` ili deserializacije paketa, i zabeležite ulazni bafer koji cilj koristi. Ovo sledi princip adaptivnog postavljanja: snapshot se pomera dublje u obradu ulaza kako bi se izbeglo ponavljanje posla.<sup>[[11]](#references)</sup>

### Inkrementalni snapshot-i za stanja protokola

Fiksni snapshot izbegava troškove pripreme, ali sam po sebi ne istražuje prelaze za koje je potrebno nekoliko ispravnih poruka. LibAFL-Qemu harness može da prati upise u polje stanja protokola i sačuva novi snapshot kada se stanje promeni. U [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) prati `tcpcb.t_state`, hešira stanje i zastavice odgovora radi uklanjanja duplikata snapshot-a i čuva izmenjene stranice u odnosu na roditeljski snapshot. Pre izmene sledeće strukturisane poruke vraća izabrani snapshot preko lanca roditelja. Testni slučaj čuva `SnapshotId` i generisane ulazne bajtove (`gen_bytes`); snapshot manager prati vezu s roditeljem koja je potrebna za replay.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu-ov `SnapshotModule` za user-mode čuva mapiranja i memoriju cilja, ali ne i CPU registre; po potrebi ih sačuvajte zasebno. Opisani manager podržava jedno korensko stablo snapshot-a i ne može da deli ID-eve snapshot-a između worker-a. Njegov multi-snapshot režim takođe ne može direktno ponovo da koristi QASAN shadow state. Za offline trijažu rekonstrušite lanac ulaza u zasebnom instrumentiranom procesu. Kada koristite `AsanHostModule` i `DrCovModule`, `fuzzer.evaluate_input` izvršava potrebne `pre_exec`/`post_exec` callback-ove; samo `qemu.run` ih ne izvršava.<sup>[[27]](#references)[[28]](#references)</sup>

### Otkrivanje logičkog čitanja van granica ring buffera

Čitanje izvan *broja važećih podataka* bafera može ostati unutar njegove host alokacije i proći neprimećeno običnom ASAN-u. Primer urgentnih podataka u [libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) takođe izaziva underflow neoznačenog broja bajtova. Ako je izvorni kod dostupan, instrumentacija za prelivanje celobrojnih vrednosti sa predznakom/bez predznaka može da otkrije tu sporednu posledicu; pre potiskivanja izveštaja razlikujte namerno prelivanje TCP sekvencijskih brojeva. Snažniji predloženi oracle jeste da se custom ring alokacija označi kao nedostupna, da se kao dostupni označe samo važeći opsezi dok njen interni alokator napreduje i da se oslobođeni opsezi ponovo označe kao nedostupni. LibAFL-Qemu izlaže ASAN poisoning API za ciljeve kod kojih je instrumentacija izvornog koda nepraktična.<sup>[[27]](#references)</sup>

## Istraživanje Linux kernel race uslova pomoću MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) pretvara race uslove u Linux kernelu osetljive na vremensko usklađivanje u ponovljive rasporede pristupa memoriji. Može automatski da enumeriše izvršavanja **A-B-A** u dva konteksta ili da omogući analitičaru da nametne ograničenja redosleda putem terminalnog UI-ja/GUI-ja. Ovo je eksperimentalni istraživački alat, a ne kompletan concurrency fuzzer: trenutno zahteva LLVM 23+ i kernel zakrpljen projektom, alati komandne linije podržavaju dve testne niti, a predloženi sloj za fuzzing u userspace-u nije implementiran.<sup>[[17]](#references)[[18]](#references)</sup>

### Prikupljanje tačaka komunikacije između konteksta

Izgradite instrumentirani kernel sa KASAN outline callback-ovima i zakrpljenom KCOV podrškom za beleženje memorije. README projekta takođe preporučuje isključivanje sibling-call optimizacije kako bi stekovi poziva ostali upotrebljivi.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN režim outline (`asan-instrumentation-with-call-threshold=0`) pretvara instrumentirane pristupe u pozive pomoćnih funkcija. MAccConc zakrpe kernela isključuju `asan-opt-same-temp` kako se uzastopni pristupi ne bi spajali; isključite i optimizaciju `asan-opt-globals` kada trke nad globalnim promenljivama moraju biti vidljive. KCOV prenosi dobijene zapise u userspace. Uporedite pristupe iz različitih konteksta izvršavanja i zadržite parove čiji se opsezi bajtova preklapaju i gde bar jedna strana vrši upis; tretirajte `kfree()` kao upis kako bi i promene životnog veka postale kandidati.<sup>[[17]](#references)</sup>

Za rad koji se nastavlja van početnog zadatka, kao što su obrada paketa ili RCU povratni pozivi, podsistem mora da prosledi KCOV remote-coverage handle. Upstream remote KCOV je opcionalan i nije automatski dostupan za proizvoljan rad u pozadini, pa izostanak prosleđivanja može učiniti stvarnu interakciju nevidljivom.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifikujte isti dinamički pristup pri svakom pokretanju

Nemojte ponavljati izvršavanje nad konkretnom adresom na hipu, koja se može promeniti nakon svake alokacije, niti se oslanjati samo na adresu instrukcije, koja je dvosmislena unutar pomoćnih funkcija kao što su `memcpy()` i `spin_lock()`. MAccConc koristi **stek-trag obogaćen brojačima**: svaki okvir identifikuje pozvanu funkciju i broj njenog pozivanja unutar pozivaoca, a poslednji element identifikuje instrukciju pristupa memoriji. Zapisi ulaska/izlaska u funkciju iz SanitizerCoverage omogućavaju userspace-u da rekonstruiše ovaj dinamički identifikator, koji ostaje stabilan uprkos promenama adresa i nepovezanom šumu u toku upravljanja.<sup>[[17]](#references)</sup>

### Pretvorite parove kandidata u nametnute rasporede

Zakrpljeni `KCOV_SET_DI` ioctl povezuje identifikator pristupa obogaćen brojačima sa radnjom nad zajedničkom zastavicom.<sup>[[17]](#references)</sup>

| Radnja | Semantika |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Postavite zastavicu *N* neposredno pre izabranog pristupa. |
| `DI_STACK_WAIT` | Pre izabranog pristupa, čekajte u petlji dok se ne postavi zastavica *N* ili ne istekne podešeno ograničenje. |
| `DI_STACK_WAKE_POST` | Postavite zastavicu *N* neposredno nakon izabranog pristupa. |

Za delimično ograničenje **A-se-dešava-pre-B**, povežite `DI_STACK_WAKE_POST` sa A, a `DI_STACK_WAIT` sa B, koristeći istu zastavicu. Za potpuno određen raspored dva konteksta, pokrenite B u blokiranom stanju, zatim neka A probudi B i sačeka na prvoj tački prenosa; B na sledećem prenosu obavlja obrnutu operaciju. Ovo drugo funkcioniše poput determinističkog prebacivanja konteksta i koristi ga automatski A-B-A explorer.<sup>[[17]](#references)</sup>

Minimalna kampanja podrazumeva kompajliranje testnog slučaja sa četiri hook-a (`test_setup`, dve funkcije niti i `test_end`) kao deljene biblioteke, prikupljanje traga bez ograničenja, a zatim nabrajanje A-B-A kandidata ili dodavanje ručnih ograničenja oko sumnjivih pristupa.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Razmatrajte timeout-e odvojeno od uspešnih promena redosleda: traženi redosled možda nije moguć zato što lock ili zavisnost od inicijalizacije/objavljivanja sprečava drugi kontekst da stigne do tačke ubrizgavanja. Imajte na umu i slepe tačke KASAN-a: direktni pristupi steku obično nisu obuhvaćeni hook-ovima, osim ako postoji mogućnost da su van granica; globalne promenljive se izostavljaju podrazumevanom optimizacijom, a aktuelni kompajleri ne mogu istovremeno da generišu ASAN i TSAN hook-ove. Konačno, prototip gubi svoj KCOV bafer kada se guest sruši, zato sačuvajte nezavisnu crash konzolu/oracle.<sup>[[17]](#references)</sup>

Za budući fuzzing vođen konkurentnošću, beležite sažetke pristupa memoriji za svaki ulaz ili sistemski poziv, uparujte operacije koje bi formirale komunikacione tačke između konteksta, a zatim istražujte samo te kombinacije. VM snapshot-i stabilizuju globalno stanje i adrese; bez snapshot-a, metapodaci o mestu alokacije mogu da apstrahuju objekte između pokretanja. Ovo je predloženo proširenje, a ne funkcija aktuelnih MAccConc userspace alata.<sup>[[17]](#references)</sup>

## Introspekcija harness-a: rano otkrijte plitke fuzzere

Kada kampanja zastane, problem često nije mutator, već **harness**. Koristite **introspekciju dostižnosti/pokrivenosti** da biste pronašli funkcije koje su statički dostižne iz vaše fuzz mete, ali se retko ili nikada ne pokrivaju dinamički. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u metu prekasno ili prerano.
- Seed corpus-u nedostaje čitava porodica funkcionalnosti.
- Meti je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a koji „radi sve“.

Ako koristite radne tokove u stilu OSS-Fuzz / ClusterFuzz, Fuzz Introspector može da uporedi statičku dostižnost sa pokrivenošću tokom izvršavanja i da generiše izveštaje na osnovu vremenski ograničenog pokretanja ili javnog korpusa.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Koristite izveštaj da odlučite da li da dodate novi harness za neproverenu putanju parsera, proširite korpus za određenu funkcionalnost ili podelite monolitni harness na manje ulazne tačke.

## Izbor fuzz targeta na osnovu grafa i trijaža mutacija

Ako već imate **nalaze statičke analize**, **preživele mutacije** i **izveštaje o pokrivenosti**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **graf poziva**, označite čvorove **ciklomatskom složenošću**, **dostupnošću iz ulaznih tačaka/nepoverljivog ulaza** i svim spoljnim nalazima, pa zatim postavljajte pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije velike složenosti su dostupne iz nepoverljivog ulaza?
- Koje preživele mutacije se nalaze na putanjama od parsera/obrađivača do bezbednosno kritičnog koda?
- Koje funkcije su arhitektonska uska grla s neuobičajeno velikim **blast radius**?

Ovim se obično otkrivaju bolji fuzz targeti nego pukim izborom funkcija sa „najnižom pokrivenošću“. Parser/dekoder **velike složenosti** za koji je potvrđeno da je **dostupan spolja** bolji je kandidat za harness nego izolovana interna pomoćna funkcija sa slabom pokrivenošću, ali bez putanje kojom bi napadač mogao da je dosegne.

### Praktični tok trijaže

1. Napravite **graf koda** iz baze koda i izdvojite metrike složenosti/grana za svaku funkciju.
2. Navedite **ulazne tačke** koje prihvataju ulaz pod kontrolom napadača: obrađivače zahteva, dekodere, uvoznike, parsere protokola, čitače CLI-ja/datoteka.
3. Pokrenite upite za putanje od tih ulaznih tačaka do kandidatskih funkcija da biste razdvojili dostupnu površinu za napad od neaktivnog koda ili koda dostupnog samo interno.
4. Dajte prednost čvorovima koji objedinjuju:
   - visoku **ciklomatsku složenost**
   - potvrđenu **dostupnost iz nepoverljivog ulaza**
   - veliki **blast radius** ili mnogo zavisnih funkcija
   - dodatne dokaze, kao što su nalazi u **SARIF**-u, beleške iz bezbednosne revizije ili preživele mutacije
5. Najpre napišite fokusirane harness-e za čvorove s najboljim rezultatima, naročito za **parser-e/kodeke** kao što su dekoderi za hex/Base64/IP/poruke.

### Preživele mutacije: ekvivalentne ili iskoristive

Testiranje mutacijama često daje bučnu listu preživelih mutacija. Pre nego što svaku preživelu mutaciju proglasite bezbednosnim propustom, pomoću grafa proverite sledeće:

- Da li je izmenjena funkcija dostupna iz ulazne tačke pod kontrolom napadača?
- Da li su sve putanje poziva ograničene jačim invarijantama od onih koje nameće izmenjena provera?
- Da li se čvor nalazi u neaktivnom kodu, logici koja služi samo za formatiranje ili putanji aritmetike/parsera s velikim uticajem?

Mutacije koje su i dalje nedostupne ili strukturno ograničene često su **ekvivalentni mutanti**. Mutacije koje su i dalje **dostupne** i utiču na **granične uslove**, **putanje overflow-a/prenosa** ili **bezbednosno kritičnu aritmetiku/parsiranje** treba unaprediti u:

- nove fuzz harness-e
- direktne testove svojstava/invarijanti
- ciljane vektore graničnih slučajeva

### Povezivanje spoljnih nalaza s grafom

Ako vaš SAST pipeline izvozi **SARIF**, mapirajte nalaze na čvorove grafa na osnovu **datoteke i opsega linija**, pa pomoću grafa proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **blast radius** označene funkcije
- proverite da li je nalaz na nekoj putanji od ulazne tačke
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno kada odlučujete da li da utrošite vreme na fuzzing određene funkcije: čvor koji je **dostupan**, **složen** i već ima **SAST nalaze** često je bolji target od čvora koji je samo složen, ali nema putanju dostupnu napadaču.

Primer toka rada uz Trailmark.<sup>[[6]](#references)</sup>

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

Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite graf da izaberete fuzz ciljeve s najvećom očekivanom bezbednosnom vrednošću, a zatim na osnovu mutacija koje prežive utvrdite koje granice i invarijante vaš harness treba da testira.<sup>[[5]](#references)</sup>

## Diferencijalni fuzzing kodiranja kriptografskih ključeva

Počnite od važećih serijalizovanih ključeva ili standardnih testnih vektora. Menjajte kodirana polja, ali sačuvajte dužinu i strukturu potrebne da bi se došlo do putanja za uvoz i operacije, a zatim pošaljite iste bajtove nezavisnim implementacijama. Uporedite prihvatanje i greške. Za nasumične potpise i šifroporuke potrebni su orakuli ispravnosti, a ne poređenje bajt po bajt: verifikujte potpise ili uporedite zajedničke tajne dobijene tokom ciklusa enkapsulacije/dekapsulacije. Testni vektori utvrđuju usklađenost za poznate slučajeve; diferencijalne mutacije ispituju neispravna kodiranja koja nisu obuhvaćena njima.<sup>[[23]](#references)[[26]](#references)</sup>

Za ove formate ključeva koristite orakule specifične za format:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Prošireni ML-DSA ključevi za potpisivanje:** izmenite upakovane koeficijente `s1` ili `s2` tako da budu izvan opsega `[-η, η]`, ali da ključ i dalje može da se parsira. Proverite da li uvoz ili potpisivanje odbijaju ključ i da li se neki dobijeni potpis može verifikovati. Sama razlika u prihvatanju ne predstavlja nužno kršenje standarda, jer FIPS 204 ne zahteva dodatne provere privatnih ključeva. Pogledajte [mehanizam uslovnog curenja](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Parovi ML-KEM ključeva:** razdvojte obavezne provere ključa za enkapsulaciju i ulaza za dekapsulaciju od opcione provere međusobne usklađenosti (PCT) uvezenog para. Enkapsulirajte pomoću javnog ključa, dekapsulirajte pomoću privatnog ključa i uporedite zajedničke tajne; nepoklapanje može da prekine šifrovanu komunikaciju čak i kada pojedinačni ključevi prođu provere ulaza. Proverite da li API validira ulaze tokom operacije ili putem zasebnog poziva; libcrux izlaže `validate_public_key(pk)` i `validate_private_key(sk, ct)`, ali oni ne zamenjuju PCT.
- **Sirovi XMSS/XMSSMT ključevi:** testirajte serijalizovane cikluse **potpisivanja i verifikacije** ključeva kroz skupove parametara, a ne samo operacije nad ključevima u memoriji. XMSS i XMSSMT imaju zasebne četvorobajtne prostore imena OID vrednosti, pa parser koji proverava samo OID i prvo pokušava XMSS može pogrešno klasifikovati XMSSMT ključ sa istom OID vrednošću i odbiti uvoz. Opisani RustCrypto parser pokazuje problem interoperabilnosti/dostupnosti, a ne falsifikovanje potpisa.

## Go fuzzing uz gosentry: jači engine, tipizovani ulazi i diferencijalne provere

Ako Go cilj već ima izvorni harness `testing.F`, praktičan način za nadogradnju jeste pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), račvanog Go lanca alata koji zadržava `go test -fuzz`, ali menja pozadinski engine u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Ovo je korisno kada se native Go fuzzer zaglavi na **teškim poređenjima**, **tipiziranim ulazima** ili **formatima zahtevnim za parsiranje**. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za seed-ove i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite gosentry-jevim `go` binarnim fajlom umesto standardnog toolchain-a.
- Tretirajte dobijenu kampanju kao uobičajeno coverage-guided pokretanje, ali uz LibAFL scheduling/mutation i bolje prateće detektore.

### Pretvorite tihe greške u fuzz nalaze

Čest problem pri Go procenama jeste to što se opasno ponašanje često podrazumevano **ne završava padom programa**. Pomoću gosentry-ja možete više klasa „loših, ali tihih“ stanja pretvoriti u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da bi izabrane putanje za logovanje/greške radile kao padovi programa (korisno za putanje koda u stilu `log.Fatal` koje bi inače samo zapisale log i nastavile).
- `--catch-races=true` da biste ponovo pokrenuli novootkrivene stavke reda čekanja uz Go race detector.
- `--catch-leaks=true` da biste ponovo pokrenuli nove stavke reda čekanja pomoću `goleak` i zaustavili se pri curenju gorutina.
- Obrada hang-ova u LibAFL-u čuva **beskonačne petlje / veoma spore ulaze** kao fuzz nalaze, umesto da ih odbaci kao timeoute.
- Provere aritmetičkog prekoračenja su podrazumevano ugrađene, uz opcione provere skraćivanja pomoću instrumentacije u stilu go-panikint.

Ovo je naročito korisno za ciljeve kod kojih je bezbednosni uticaj **greška parsera bez panike**, **greška konkurentnosti** ili **hang koji uzrokuje samo DoS**, a ne oštećenje memorije.

### Fuzzing tipiziranih Go API-ja svestan struktura

Native Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira obrađuje tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (strukture, slice-ove, nizove, pokazivače), uz istovremeno menjanje bajtova u pozadini.<sup>[[7]](#references)[[8]](#references)</sup>

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

Koristite ovo kada bi pravljenje lažnog wire formata samo za fuzzing sakrilo logičke greške iza koda za parsiranje koji postoji samo u harness-u. Za differential ili grammar-based kampanje, neka ulaz u harness bude jedan `[]byte` ili `string`, a zatim ga parsirajte unutar callback-a.

### Grammar-based fuzzing za parsere i protokolarne ulaze

Za parsere, formate i jezike ulaza, gosentry može da pokrene **Nautilus grammar fuzzing** povrh LibAFL-a. Gramatika je JSON niz produkcionih pravila, a harness bi obično trebalo da prima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Napomene o metodologiji:

- Koristite grammar mode kada mutacije na nivou bajtova uglavnom ne prođu rane provere sintakse.
- Usmerite gramatiku na **bezbednosno relevantan podskup** jezika/protokola, umesto da modelujete celu specifikaciju.
- Koristite velike granične vrednosti u terminalima/neterminalima da biste opteretili granice celih brojeva, dužina i mašina stanja.
- Grammar mode održava ulaze gramatički ispravnim, ali cilj i dalje prima **bajtove/nizove**, pa parsiranje i semantičke provere ostaju unutar koda koji se testira.

### Differential fuzzing: upoređujte implementacije, ne samo padove

Snažan obrazac za Go ekosisteme je **grammar-based differential fuzzing**: generišite važeće strukturirane ulaze i prosledite ih dvama parserima, klijentima ili mehanizmima za prelaze stanja.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacija izaziva panic, dok druga uredno odbija ulaz
- nepodudaranja u prihvatanju/odbijanju ulaza
- različita stabla parsiranja ili dekodirani objekti
- različiti prelazi stanja, nonce vrednosti, stanja računa ili koreni stanja

Ovo je praktičan način za pronalaženje **nepodudaranja konsenzusa**, **dvosmislenosti parsera** i **odstupanja između specifikacije i implementacije** koja čisto fuzz testiranje usmereno na padove često propušta.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponovo upotrebite korpus kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo pokrenite sačuvani korpus reda čekanja da biste generisali Go izveštaj o pokrivenosti, bez ručnog izvoza zasebnog korpusa.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` da bi gosentry pronašao odgovarajuće keširano stanje campaign-a.

## References

- [1] [Fuzzing mutacionom gramatikom](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++: Fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing protokola vođen pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alatki. Izmenili smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brzi greybox fuzzer za stateful mrežne protokole pomoću snapshot-ova](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: ka fuzzingu Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasan fuzzing uz adaptivne i promenljive snapshot-ove](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentacija: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivni context-sensitive fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - dokumentacija za build i regression seed-ove](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Istraživanje race condition-a u Linux kernelu pomoću kontrolisanog preplitanja pristupa memoriji](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrivenost koda za fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO sintaksa proširenih imena datoteka](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec savet: CFITSIO, četvrti kvartal 2025.](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing sintakse proširenih imena datoteka CFITSIO: 16 ranjivosti bezbednosti memorije i trijaža uz pomoć Codex-a](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Diferencijalni fuzzing za kriptografiju](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standard za mehanizam enkapsulacije ključeva zasnovan na modulnoj rešetki](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Greška u parsiranju XMSSMT OID-a - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stanje implementacija postkvantne kriptografije](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Kako smo pomoću snapshot-ova došli do CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
