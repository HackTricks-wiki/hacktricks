# Metodologija fuzzing-a

{{#include ../banners/hacktricks-training.md}}

## Mutaciono fuzzing gramatike: pokrivenost naspram semantike

Kod **mutacionog fuzzing-a gramatike**, ulazi se menjaju uz očuvanje **gramatičke ispravnosti**. U režimu vođenom pokrivenošću, kao seeds korpusa čuvaju se samo uzorci koji aktiviraju **novu pokrivenost**. Za **jezičke ciljeve** (parsere, interpretere, engine-e), ovim se mogu propustiti bagovi koji zahtevaju **semantičke lance / lance protoka podataka**, gde izlaz jedne konstrukcije postaje ulaz druge.<sup>[[1]](#references)</sup>

**Način otkaza:** fuzzer pronalazi seeds koji pojedinačno aktiviraju `document()` i `generate-id()` (ili slične primitive), ali **ne čuva ulančani tok podataka**, pa se uzorak „bliži bagu” odbacuje jer ne povećava pokrivenost. Kada postoje **3+ zavisna koraka**, nasumično rekombinovanje postaje skupo, a povratne informacije o pokrivenosti ne usmeravaju pretragu.<sup>[[1]](#references)</sup>

**Implikacija:** za gramatike sa mnogo zavisnosti razmotrite **kombinovanje mutacionih i generativnih faza** ili usmeravanje generisanja ka obrascima **ulančavanja funkcija** (ne samo ka pokrivenosti).<sup>[[1]](#references)</sup>

## Zamke raznovrsnosti korpusa

Mutacije vođene pokrivenošću su **pohlepne**: uzorak sa novom pokrivenošću odmah se čuva, često uz zadržavanje velikih neizmenjenih delova. Vremenom korpusi postaju **skoro identični duplikati** sa malom strukturnom raznovrsnošću. Agresivna minimizacija može ukloniti koristan kontekst, pa je praktičan kompromis **minimizacija koja uzima gramatiku u obzir** i **zaustavlja se nakon dostizanja minimalnog broja tokena** (uklanja šum, a zadržava dovoljno okolne strukture da bi mutacije i dalje bile korisne).<sup>[[1]](#references)</sup>

Praktično pravilo za korpus pri mutacionom fuzzing-u glasi: **dajte prednost malom skupu strukturno različitih seed-ova koji maksimizuju pokrivenost** u odnosu na veliku gomilu skoro identičnih duplikata. U praksi to obično podrazumeva sledeće.<sup>[[1]](#references)[[3]](#references)</sup>

- Počnite od **uzoraka iz stvarnog sveta** (javni korpusi, crawling, snimljen saobraćaj, skupovi datoteka iz ekosistema ciljnog sistema).
- Svedite ih na manji skup pomoću **minimizacije korpusa zasnovane na pokrivenosti**, umesto da zadržite svaki ispravan uzorak.
- Neka seeds budu **dovoljno mali** da mutacije pogađaju smislena polja, umesto da se većina ciklusa troši na nebitne bajtove.
- Ponovo pokrenite minimizaciju korpusa nakon većih izmena harness-a/instrumentacije, jer se „najbolji” korpus menja kada se promeni dostižnost koda.

## Veliki generisani programi i pristrasnost zbog vremenskih ograničenja

Pri fuzzing-u kompajlera i interpretera, ulaz možda mora da pređe **prag veličine generisanog koda**, umesto da dosegne novu granu parsera. U V8 [primeru pomeraja offset-a rukovaoca izuzecima](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size), ispravan testni slučaj morao je da premaši 256 MiB bytecode-a da bi skraćeni offset rukovaoca postao bitan. Ponovljene konstrukcije `yield*` mogle su da dostignu taj prag, ali kompajliranje testnog slučaja trajalo je nekoliko sekundi u debug build-u. Prednost malim ulazima i kratki vremenski limiti izvršavanja mogu da stave ovu klasu u nepovoljan položaj čak i kada je pokrivenost gramatike visoka. Pri proveri upakovanih offset-a ili drugih metapodataka osetljivih na dužinu, razmotrite pragove veličine i pravila za vremenska ograničenja odvojeno; ovaj savet za kampanju predstavlja zaključak izveden iz prijavljenog načina otkaza.<sup>[[29]](#references)</sup>

## Mutacije prilagođene poređenjima za magične vrednosti

Čest razlog zbog kog fuzzers prestanu da napreduju nisu sintaksa, već **stroga poređenja**: magični bajtovi, provere dužine, enum stringovi, kontrolne sume ili vrednosti za izbor parsera, zaštićene pomoću `memcmp`, switch tabela ili niza poređenja. Čiste nasumične mutacije rasipaju cikluse pokušavajući da pogode ove vrednosti bajt po bajt.

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

- Ovo je naročito korisno kada cilj skriva duboku logiku iza **potpisa datoteka**, **protocol verbs**, **type tags** ili **bitova funkcionalnosti koji zavise od verzije**.
- Kombinujte ovo sa **rečnicima** izdvojenim iz stvarnih uzoraka, specifikacija protokola ili debug logova. Mali rečnik sa gramatičkim tokenima, imenima chunk-ova, glagolima i delimiterima često vredi više od ogromne generičke liste reči.
- Ako cilj izvršava mnogo uzastopnih provera, prvo rešite najranija poređenja „magic“ vrednosti, a zatim ponovo minimizujte dobijeni korpus kako bi kasnije faze počinjale od već validnih prefiksa.

## Fuzzing API-ja za datoteke koji skrivaju jezik za nazive datoteka

Parametar nazvan `filename`, `path` ili `URL` može biti ulazna tačka za interpreter, a ne doslovno traženje datoteke. Na primer, CFITSIO Extended Filename Syntax (EFS) obrađuje selektore u uglastim zagradama, izraze za redove/piksele, izračunate kolone, histograme i transformacije pre nego što vrati otvoreni objekat; neki oblici prave i privremene kopije. Tokom mapiranja površine napada, klasifikujte svaki API za otvaranje/uvoz kao **doslovnu putanju** ili **interpretiranu putanju**, a zatim fuzz-ujte produkcionu ulaznu tačku koju aplikacije zaista pozivaju.<sup>[[20]](#references)[[22]](#references)</sup>

Za rezultujuće primitive za SSRF, kopiranje datoteka i rukovanje protokolima — kao i bezbednije API-je koji koriste doslovne putanje — pogledajte [Mini-jezici za nazive datoteka kao primitive za SSRF/datoteke](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Odvojite prateći objekat od programa koji se fuzz-uje

Kada se gramatika nalazi u sufiksu naziva datoteke, menjanje samo bajtova referencirane datoteke neće dosegnuti parser. Umesto toga, mali harness može da učita jedan testcase kao string i prosledi ga API-ju za interpretirano otvaranje; CFITSIO kampanja dosegla je većinu EFS parsera i evaluatora pozivanjem `fits_open_file()` u režimu samo za čitanje. Validne prateće datoteke držite odvojeno kako bi izmene mogle da se usredsrede na jezik selektora/izraza, umesto da stalno narušavaju osnovnu putanju.<sup>[[22]](#references)</sup>

Koristite seed-ove koji svaki dosežu drugu porodicu gramatike, a zatim napravite sažet rečnik na osnovu specifikacije i izvornog koda lexer-a/parsera. Ako se pokrivenost zaustavi, a ulazi stalno završavaju na istoj putanji sintaksne greške, sačuvajte validne prefikse i dodajte delimitere, operatore, ključne reči, nazive funkcija i reprezentativna imena polja, umesto da samo produžavate vreme nasumičnog menjanja.<sup>[[22]](#references)</sup>

Pokrenite harness sa rečnikom gramatike, na primer:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograničite sporedne efekte „read-only“ harness-a

Zastavica biblioteke „read-only“ ne garantuje testcase bez sporednih efekata: jezik naziva datoteka može da prepiše ulaz, napravi izlazne datoteke ili materijalizuje privremene objekte. CFITSIO kampanja je u početku uništavala seed datoteke i ostavljala neočekivane datoteke širom sistema datoteka, pa su čišćenje i izolacija bili neophodni.<sup>[[22]](#references)</sup>

- Dodelite svakom worker-u zaseban radni direktorijum za jednokratnu upotrebu i privatni privremeni direktorijum.
- Izložite kopije kanonskih pratećih datoteka; nikada ne dozvolite da target menja jedinu kopiju corpus-a.
- Onemogućite mrežni pristup osim ako su udaljeni backend-i predviđeni target, a putanje za upis ograničite pomoću container-a, mount namespace-a ili ekvivalentnog sandbox-a.
- Resetujte direktorijum nakon svakog izvršavanja ili grupe worker-a i tretirajte neočekivane promene sistema datoteka kao dodatne nalaze.

### Petlja od crash-a do patch-a do fuzzing-a

Grupišite crash-eve pre popravke da hiljade artefakata ne bi postale hiljade zadataka za patch. U CFITSIO proceni, AFLTriage je sveo početni skup crash-eva na nekoliko osnovnih uzroka; rezultujući savetodavni izveštaj prikazuje različite greške, uključujući neispravne provere veličine odredišta, zastarele pokazivače nakon `realloc()`, aritmetičke greške i nebezbedne putanje za čišćenje parser-a.<sup>[[21]](#references)[[22]](#references)</sup>

1. Svedite reprezentativan ulaz iz svake grupe na najmanju meru i ponovite reprodukciju uz AddressSanitizer.
2. Zabeležite tačan pristup koji izaziva grešku, lokaciju u izvornom kodu, istoriju alokacije i oslobađanja memorije i stanje parser-a zbog kog je narušen invariant.
3. Primeni jedan usko usmeren potencijalni patch i ponovo izgradite program uz istu instrumentaciju za pokrivenost i sanitizer.
4. Ponovo pokrenite originalni reproducer **i sve ulaze iz njegove grupe**; uključite i detekciju curenja jer popravka problema sa bezbednošću memorije može da naruši upravljanje resursima na putanji greške.
5. Pokrenite funkcionalne testove sa stvarnim datotekama, a zatim nastavite iz akumuliranog queue-a (ili ponovo uvezite taj queue ako engine zahteva nov izlazni direktorijum nakon promene binarne datoteke).
6. Ponavljajte postupak: uklanjanje prvog, plitkog crash-a često omogućava postojećim seed-ovima da stignu do dubljeg stanja parser-a.

LLM može da ubrza 2. korak i sastavi nacrt za 3. korak ako mu se dostave ulaz koji izaziva crash, izveštaj sanitizer-a, harness i relevantni izvorni kod, ali njegov patch se i dalje mora smatrati nepouzdanim. O tome da li će popravka biti prihvaćena odlučuju ponovljeno pokretanje uz sanitizer i regresioni testovi, a ne objašnjenje modela.<sup>[[22]](#references)</sup>

## Bogatije povratne informacije kada pokrivenost ivica ne razlikuje različite putanje

Uobičajena pokrivenost ivica ne može da razlikuje dva izvršavanja koja prolaze kroz isti helper iz različitih pozivalaca ili koriste različite kombinacije grana unutar funkcije. To je važno kod deljenih decoder-a, dispečera protokola i helper-a interpreter-a, gde **putanja** do ivice određuje aktivno stanje. Naivno praćenje svakog konteksta pozivanja takođe je rizično: mapa pokrivenosti i queue mogu naglo da porastu. Istraživanja fuzzing-a osetljivog na kontekst zato preporučuju preciziranje samo obećavajućih konteksta, umesto tretiranja celog grafa poziva kao osetljivog na kontekst.<sup>[[14]](#references)</sup>

Novije verzije AFL++ podržavaju **Ball-Larus pokrivenost putanja po funkciji** pored uobičajene pokrivenosti ivica. Ona dodeljuje feature svakoj acikličkoj putanji kroz funkciju; povratne ivice petlji se uklanjaju, tako da ove povratne informacije razlikuju kombinacije grana, ali **ne i broj iteracija petlje**. Počnite od opuštenog nivoa `1`, a zatim strože režime ograničite na sumnjiv kod parser-a i mašine stanja, jer broj putanja može eksponencijalno da raste.<sup>[[13]](#references)</sup>

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

**Smernice za kampanju:** oprezno primenjujte bogatije povratne informacije i pratite njihovu cenu u coverage-map/queue resursima.<sup>[[13]](#references)[[14]](#references)</sup>

- Paralelno pokrenite običnu instancu sa edge-coverage; bogatije povratne informacije su korisne samo ako dodatna cena za queue/map ne smanji broj izvršavanja u sekundi.
- Koristite `AFL_LLVM_ALLOWLIST` da biste ograničili path/caller instrumentaciju kada velike biblioteke sa mnogo šablona ili generički uslužni kod dominiraju mapom.
- Funkcije sa previše acikličnih putanja mogu da se preskoče u AFL++; upozorenja tokom kompilacije ukazuju na to da je za cilj potrebno allowlisting ili manje strog nivo.
- Caller + path coverage podržava samo jednu dubinu pozivaoca. Nemojte ga kombinovati sa dubljim context stackovima.
- ID-jevi putanja mogu da se menjaju između glavnih verzija LLVM-a. Tokom kampanje koristite fiksiran toolchain i nemojte sinhronizovati korpuse zasnovane na PATH-u kao da su njihovi ID-jevi funkcija stabilni između buildova.
- Ove povratne informacije dopunjuju `CMPLOG`: praćenje poređenja rešava pitanje **koja vrednost prolazi kroz guard**, dok path/caller povratne informacije čuvaju **koja ruta i kombinacija grana su dovele do nje**.

## Stateful Fuzzing: Sekvence su seedovi

Kod **protokola**, **autentifikovanih tokova rada** i **parsera u više faza**, zanimljiva jedinica često nije pojedinačni blob, već **sekvenca poruka**. Spajanje celog transkripta u jednu datoteku i njegovo nasumično mutiranje obično je neefikasno jer fuzzer podjednako mutira svaki korak, čak i kada samo kasnija poruka dostiže osetljivo stanje.<sup>[[4]](#references)</sup>

Efikasniji pristup je da se **sama sekvenca** tretira kao seed, a da se **uočljivo stanje** (kodovi odgovora, stanja protokola, faze parsera, tipovi vraćenih objekata) koristi kao dodatna povratna informacija.<sup>[[4]](#references)</sup>

- Zadržite **validne prefiksne poruke** nepromenjene i usmerite mutacije na poruku koja **pokreće prelaz**.
- Keširajte identifikatore i vrednosti koje generiše server iz prethodnih odgovora kada od njih zavisi sledeći korak.
- Dajte prednost mutiranju i spajanju pojedinačnih poruka umesto mutiranju celog serijalizovanog transkripta kao neprozirnog bloba.
- Ako protokol izlaže smislene kodove odgovora, koristite ih kao **jeftin oracle stanja** da biste dali prioritet sekvencama koje napreduju dublje.

Iz istog razloga vanilla fuzzing u stilu rada sa datotekama često ne otkriva autentifikovane bagove, skrivene prelaze ili bagove parsera koji se javljaju „tek nakon rukovanja“: fuzzer mora da sačuva **redosled, stanje i zavisnosti**, a ne samo strukturu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing drajvera sa više klijenata

Visoka edge coverage i dalje može da propusti bagove IPC drajvera jer coverage ne opisuje **vlasništvo nad objektima, brojače referenci, poruke na čekanju, redosled čišćenja ni preplitanje niti**. Stranica [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) obrađuje model objekata drajvera; ovaj primer se fokusira na harness fuzzera. Android Binder je koristan model: nije dovoljno dostići i putanje alokacije i oslobađanja ako fuzzer ne može da natera više procesa da rade nad istim objektom kernela propisanim redosledom.<sup>[[15]](#references)</sup>

#### Modelujte protokol, a ne izolovane `ioctl` baferе

Predstavite testni slučaj kao uređenu gramatiku **identitet klijenta + operacija + strukturisani argumenti**. Binder LKL fuzzer koristi protobuf i `libprotobuf-mutator`, uz jedan persistentni klijent menadžera konteksta i dva obična klijenta. Semantički harness zatim čuva relacije koje bi nasumično mutiranje bajtova uništilo.<sup>[[15]](#references)</sup>

- Keširajte vrednosti koje vrate prethodne operacije. Na primer, `BC_FREE_BUFFER` mora ponovo da koristi pokazivač na bafer transakcije koji je vratilo prethodno `ioctl` pozivanje.
- Generišite podrazumevane validne odgovore kako bi sinhrone transakcije mogle da se završe, a kasnije operacije ostale dostupne.
- Odbacujte nemoguće prelaze, kao što su transakcije samom sebi ili više transakcija na čekanju za isti cilj.
- Držite singleton bootstrap stanje van resetovanja za svaki ulaz. Binder dozvoljava samo jednu registraciju `BINDER_SET_CONTEXT_MGR` tokom jednog pokretanja sistema, pa bi stalno uništavanje i ponovno kreiranje tog klijenta učinilo kasnije ulaze nevažećim.

Korisni šablon za trku životnog ciklusa jeste da jedan klijent prenese objekat, pokrene čišćenje niti ili procesa, a da istovremeno klijent primalac oslobodi bafer transakcije. U primeru CVE-2020-0423, prenos `BINDER_TYPE_WEAK_BINDER` praćen trkom između `BINDER_THREAD_EXIT` i `BC_FREE_BUFFER` mogao je da oslobodi ugrađeni `binder_work` dok ga je putanja čišćenja niti koja se gasila još koristila.<sup>[[15]](#references)</sup>

#### Ponovno uvođenje kontrolisanog preplitanja u kernel u userspace-u

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) povezuje stvarni kod kernela sa harnessom u userspace-u i izlaže njegov syscall interfejs putem `lkl_syscall`. Tako se protobuf stanje, coverage i KASAN lako koordiniraju u jednom procesu. LKL obično izvršava syscall bez prekidanja druge niti kernela. Za kampanje trka zato umetnite tačke `schedule()` oko odabranih granica zaključavanja/otključavanja i životnog ciklusa, pa pustite harness da nasumično bira sledećeg klijenta pri svakom ustupanju izvršavanja. Pažljivo birajte ove tačke jer svaka povećava prostor pretrage raspoređivanja. Nasumični raspoređivač koji su opisali istraživači **nije** deo upstream Binder fuzzera.<sup>[[15]](#references)</sup>

#### Buildovanje i ponovno pokretanje serijalizovanih regresionih seedova

Upstream harness fiksira kompatibilnu verziju `libprotobuf-mutator`, uključuje LKL fuzzing instrumentaciju i KASAN pomoću `LKL_FUZZING=1`, a za Binder uključuje i `CONFIG_MMU` pomoću `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nakon preuzimanja namerno ranjive revizije ili primene rollback zakrpa dokumentovanih u upstream-u, serijalizovano seme može da reprodukuje ceo prelaz stanja sa više klijenata, bez rekonstrukcije u ad-hoc C proof of concept-u:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Tretirajte dobijeni KASAN use-after-free kao potvrdu da je seed stigao do ranjive putanje životnog ciklusa. To **ne** dokazuje postojanje kasnijih primitiva potrebnih za izvršavanje koda u kernelu ili eskalaciju privilegija.<sup>[[16]](#references)</sup>

## Trik raznovrsnosti na jednoj mašini (u stilu Jackalope)

Praktičan način da se spoje **generativna novost** i **ponovna upotreba pokrivenosti** jeste da se **kratkotrajni worker-i restartuju** nad persistent serverom. Svaki worker počinje s praznim corpus-om, sinhronizuje se nakon `T` sekundi, još `T` sekundi radi nad kombinovanim corpus-om, ponovo se sinhronizuje, a zatim se gasi. Tako se dobijaju **sveže strukture u svakoj generaciji**, uz istovremeno iskorišćavanje akumulirane pokrivenosti.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sekvencijalni radnici (primer petlje):**

<details>
<summary>Jackalope petlja za ponovno pokretanje radnika</summary>

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
- `-server_update_interval T` približno simulira **odloženu sinhronizaciju** (prvo novine, zatim ponovna upotreba).
- U režimu grammar fuzzing, **početna sinhronizacija sa serverom se podrazumevano preskače** (nema potrebe za `-skip_initial_server_sync`).
- Optimalna vrednost `T` **zavisi od cilja**; obično najbolje funkcioniše promena nakon što worker pronađe većinu „lake“ pokrivenosti.

## Snapshot Fuzzing za ciljeve koje je teško pripremiti za testiranje

Kada kod koji želite da testirate postane dostupan tek **nakon dugog pripremnog postupka** (pokretanja VM-a, dovršetka prijave, prijema paketa, parsiranja containera, inicijalizacije servisa), korisna alternativa je **snapshot fuzzing**: snimite stanje spremnog procesa ili VM-a, ubacite svaki test case u ulazni put cilja, izvršavajte do crash/timeout-а i vratite снимак. Тако се избегава понављање иницијализације или префикса протокола, па је овај приступ користан за **мрежне сервисе**, **firmware**, **attack surface након аутентификације** и **binary-only циљеве**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Покрените циљ док жељено стање не буде спремно.
2. У том тренутку направите snapshot **меморије и регистара**.
3. За сваки test case упишите мутирани улаз директно у одговарајући buffer госта/процеса.
4. Извршавајте до crash/timeout/reset-а.
5. Вратите snapshot; за VM циљеве вратите само **dirty pages** када је то подржано, па поновите поступак.

Поставите snapshot што ближе првом скупом кораку парсирања/диспечирања, на пример након `recv`/`read` или десеријализације пакета, и забележите улазни buffer који циљ користи. Ово следи принцип адаптивног позиционирања: померање snapshot-а дубље у обраду улаза како би се избегло понављање посла.<sup>[[11]](#references)</sup>

### Инкрементални snapshot-и за стања протокола

Фиксни snapshot избегава трошак припреме, али сам по себи не истражује прелазе који захтевају неколико исправних порука. LibAFL-Qemu harness може да прати уписе у поље стања протокола и сачува нови snapshot када се стање промени. У [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) прати се `tcpcb.t_state`, хеширају се стање и response flags ради уклањања дупликата snapshot-а, а dirty pages се чувају у односу на родитељски snapshot. Пре мутирања следеће структуриране поруке, враћа се изабрани snapshot преко ланца његових родитеља. Testcase чува `SnapshotId` и генерисане улазне бајтове (`gen_bytes`); snapshot manager прати однос са родитељем који је потребан за поновно извршавање.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu-ов user-mode `SnapshotModule` чува мапирања и меморију циља, али не и CPU регистре; по потреби их сачувајте одвојено. Описани manager подржава једно стабло root snapshot-а и не може да дели ID-ове snapshot-а између worker-а. Његов multi-snapshot режим такође не може директно поново да користи QASAN shadow state. За offline triage, реконструишите ланац улаза у засебном инструментованом процесу. Када користите `AsanHostModule` и `DrCovModule`, `fuzzer.evaluate_input` покреће потребне `pre_exec`/`post_exec` callback-ове; само `qemu.run` то не ради.<sup>[[27]](#references)[[28]](#references)</sup>

### Откривање логичких прекорачења при читању из ring buffer-а

Читање изван *броја важећих података* у buffer-у може остати унутар додељене меморије host-а и избећи уобичајени ASAN. Пример [libslirp urgent-data](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) такође изазива underflow непотписаног броја бајтова. Ако је изворни код доступан, инструментација за overflow целобројних вредности са знаком/без знака може да открије ту споредну последицу; пре него што потиснете извештаје, разликујте је од намерног обиласка TCP sequence number-а. Снажнији предложени oracle је да се poison-ује прилагођена ring алокација, да се unpoison-ују само важећи опсези како њен интерни allocator напредује и да се ослобођени опсези поново poison-ују. LibAFL-Qemu нуди ASAN poisoning API за циљеве код којих је инструментација изворног кода непрактична.<sup>[[27]](#references)</sup>

## Истраживање race услова у Linux kernel-у помоћу MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) претвара race услове у Linux kernel-у осетљиве на тајминг у поновљиве распореде приступа меморији. Може аутоматски да наброји **A-B-A** извршавања у два контекста или да омогући аналитичару да зада ограничења редоследа преко терминалног UI-ја/GUI-ја. Ово је експериментални истраживачки алат, а не комплетан concurrency fuzzer: тренутно захтева LLVM 23+ и kernel са закрпама пројекта, алати командне линије подржавају две test нити, а предложени userspace fuzzing слој није имплементиран.<sup>[[17]](#references)[[18]](#references)</sup>

### Прикупљање тачака комуникације између контекста

Изградите инструментовани kernel са KASAN outline callback-овима и подршком за меморијске записе у KCOV-у са закрпама. README пројекта такође препоручује онемогућавање sibling-call оптимизације како би стекови позива остали употребљиви.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) pretvara instrumentirane pristupe u pozive pomoćnih funkcija. MAccConc kernel zakrpe isključuju `asan-opt-same-temp` kako se uzastopni pristupi ne bi spajali; isključite i optimizaciju `asan-opt-globals` kada trke nad globalnim promenljivama moraju biti vidljive. KCOV prenosi nastale zapise u userspace. Uporedite pristupe iz različitih konteksta izvršavanja i zadržite parove čiji se opsezi bajtova preklapaju i gde bar jedna strana vrši upis; modelujte `kfree()` kao upis kako bi i promene životnog veka postale kandidati.<sup>[[17]](#references)</sup>

Za rad koji se nastavlja van početnog zadatka, kao što su obrada paketa ili RCU callback-ovi, podsistem mora da prosledi KCOV remote-coverage handle. Uzvodni remote KCOV je opcionalan i nije automatski dostupan za proizvoljan rad u pozadini, pa izostanak prosleđivanja može učiniti stvarnu interakciju nevidljivom.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifikujte isti dinamički pristup u svakom pokretanju

Nemojte ponavljati testiranje nad konkretnom heap adresom, koja se može promeniti posle svake alokacije, niti samo nad adresom instrukcije, koja je dvosmislena unutar pomoćnih funkcija kao što su `memcpy()` i `spin_lock()`. MAccConc koristi **stack trace proširen brojačima**: svaki okvir identifikuje callee i broj poziva unutar caller-a, a poslednji element identifikuje instrukciju za pristup memoriji. Zapisi ulaska/izlaska funkcija iz SanitizerCoverage omogućavaju userspace-u da rekonstruiše ovaj dinamički identifikator, koji ostaje stabilan pri promenama adresa i nepovezanoj buci u toku kontrole.<sup>[[17]](#references)</sup>

### Pretvorite parove kandidata u forsirane rasporede

Zakrpljeni `KCOV_SET_DI` ioctl povezuje identifikator pristupa proširen brojačima sa radnjom nad deljenom zastavicom.<sup>[[17]](#references)</sup>

| Radnja | Semantika |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Postavi zastavicu *N* neposredno pre izabranog pristupa. |
| `DI_STACK_WAIT` | Pre izabranog pristupa, čekaj u petlji dok se ne postavi zastavica *N* ili dok ne istekne podešeno ograničenje. |
| `DI_STACK_WAKE_POST` | Postavi zastavicu *N* neposredno posle izabranog pristupa. |

Za delimično ograničenje **A-happens-before-B**, povežite `DI_STACK_WAKE_POST` sa A, a `DI_STACK_WAIT` sa B koristeći istu zastavicu. Za potpuno definisan raspored dva konteksta, počnite tako što je B blokiran, zatim neka A probudi B i sačeka na prvoj tački prenosa; B izvršava obrnutu operaciju pri sledećem prenosu. Ovo funkcioniše kao determinističko prebacivanje konteksta i koristi ga automatski A-B-A explorer.<sup>[[17]](#references)</sup>

Minimalna kampanja podrazumeva kompajliranje testnog slučaja sa četiri hook-a (`test_setup`, dve thread funkcije i `test_end`) kao shared library-ja, prikupljanje traga bez ograničenja, a zatim nabrajanje A-B-A kandidata ili dodavanje ručnih ograničenja oko sumnjivih pristupa.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Tumačite timeout-e odvojeno od uspešnih promena redosleda: traženi redosled možda nije moguć jer lock ili zavisnost od inicijalizacije/objavljivanja sprečava drugi kontekst da stigne do tačke ubrizgavanja. Imajte na umu i slepe tačke KASAN-a: direktni pristupi steku obično se ne presreću, osim ako mogu biti van granica; globalne promenljive se izostavljaju pri podrazumevanoj optimizaciji, a trenutni kompajleri ne mogu istovremeno da emituju ASAN i TSAN hook-ove. Pored toga, prototip gubi KCOV bafer kada guest doživi panic, zato obezbedite nezavisnu crash konzolu/oracle.<sup>[[17]](#references)</sup>

Za buduće concurrency-guided fuzzing, beležite sažetke pristupa memoriji za svaki ulaz ili syscall, uparujte operacije koje bi formirale komunikacione tačke između konteksta, a zatim istražujte samo te kombinacije. VM snapshot-i stabilizuju globalno stanje i adrese; bez snapshot-a, metapodaci o mestima alokacije mogu da apstrahuju objekte između pokretanja. Ovo je predloženo proširenje, a ne funkcionalnost trenutnih MAccConc userspace alata.<sup>[[17]](#references)</sup>

## Introspekcija harness-a: Rano otkrijte nedovoljno obuhvatne fuzzere

Kada kampanja zastane, problem često nije mutator, već **harness**. Koristite **introspekciju dostižnosti/pokrivenosti** da biste pronašli funkcije koje su statički dostižne iz vaše fuzz mete, ali se retko ili nikada ne pokrivaju dinamički. Te funkcije obično ukazuju na jedan od tri problema.<sup>[[12]](#references)</sup>

- Harness ulazi u metu prekasno ili prerano.
- Seed corpus-u nedostaje cela porodica funkcionalnosti.
- Meti je zaista potreban **drugi harness**, umesto jednog prevelikog harness-a koji „radi sve“.

Ako koristite OSS-Fuzz / ClusterFuzz radne tokove, Fuzz Introspector može da uporedi statičku dostižnost sa pokrivenošću tokom izvršavanja i da generiše izveštaje na osnovu vremenski ograničenog izvršavanja ili javnog corpus-a.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Koristite izveštaj da odlučite da li da dodate novi harness za neproverenu putanju parsera, proširite korpus za određenu funkciju ili podelite monolitni harness na manje ulazne tačke.

## Izbor fuzzing meta i trijaža mutacija na osnovu grafa

Ako već imate **nalaze statičke analize**, **preživele mutante iz testiranja mutacijama** i **izveštaje o pokrivenosti**, nemojte ih trijažirati kao nezavisne liste. Najpre napravite **graf poziva**, označite čvorove **ciklomatskom složenošću**, **dostupnošću sa ulaznih tačaka/putanja do kojih može stići nepoverljiv ulaz** i svim spoljnim nalazima, a zatim postavljajte pitanja o grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Koje funkcije visoke složenosti mogu da se dosegnu iz nepoverljivog ulaza?
- Koji preživeli mutanti se nalaze na putanjama od parsera/obrađivača do bezbednosno kritičnog koda?
- Koje funkcije predstavljaju arhitektonska uska grla sa neuobičajeno velikim **poljem uticaja**?

Ovim se obično pronalaze bolje fuzzing mete nego oslanjanjem samo na „najnižu pokrivenost“. Parser/dekoder **visoke složenosti** do kog se dokazano može stići spolja bolja je meta za harness nego izolovan interni pomoćni program sa slabom pokrivenošću, ali bez putanje kojom bi napadač mogao da utiče na njega.

### Praktični tok trijaže

1. Napravite **graf koda** iz baze koda i izdvojte metrike složenosti/grana za svaku funkciju.
2. Navedite **ulazne tačke** koje prihvataju ulaz pod kontrolom napadača: obrađivače zahteva, dekodere, uvoznike, parser-e protokola, čitače CLI-ja/datoteka.
3. Pokrenite **upite putanja** od tih ulaznih tačaka do kandidata kako biste razdvojili dostupnu napadnu površinu od mrtvog koda ili koda dostupnog samo interno.
4. Dajte prednost čvorovima koji objedinjuju:
   - visoku **ciklomatsku složenost**
   - potvrđenu **dostupnost iz nepoverljivog ulaza**
   - veliko **polje uticaja** ili mnogo zavisnih elemenata nizvodno
   - potkrepljujuće dokaze, kao što su nalazi **SARIF**, beleške sa audita ili preživeli mutanti
5. Najpre napišite fokusirane harness-e za čvorove sa najboljim rezultatom, naročito za **parser-e/kodeke**, kao što su dekoderi hex/Base64/IP/poruka.

### Preživeli mutanti: ekvivalentni naspram onih na koje treba reagovati

Testiranje mutacijama često daje bučnu listu preživelih mutanata. Pre nego što svaki preživeli mutant proglasite bezbednosnim propustom, pomoću grafa proverite:

- Da li je izmenjena funkcija dostupna sa ulazne tačke pod kontrolom napadača?
- Da li su sve putanje poziva ograničene jačim invarijantama od one koju izmenjena provera treba da nametne?
- Da li se čvor nalazi u mrtvom kodu, logici koja služi samo za formatiranje ili putanji aritmetike/parsera sa velikim uticajem?

Mutanti koji ostanu nedostupni ili su strukturno ograničeni često su **ekvivalentni mutanti**. Preživele mutante koji ostanu **dostupni** i dotiču se **graničnih uslova**, **putanja prenosa/prekoračenja** ili **bezbednosno kritične aritmetike/parsiranja** treba unaprediti u:

- nove fuzzing harness-e
- direktne testove svojstava/invarijanti
- ciljane skupove vektora za rubne slučajeve

### Povežite spoljne nalaze sa grafom

Ako vaš SAST pipeline izvozi **SARIF**, preslikajte nalaze na čvorove grafa prema **datoteci i opsegu redova** i upotrebite graf da proširite procenu uticaja.<sup>[[6]](#references)</sup>

- izračunajte **polje uticaja** označene funkcije
- proverite da li se nalaz nalazi na nekoj putanji od ulazne tačke
- grupišite obližnje nalaze koji se svode na isto usko grlo

Ovo je korisno pri odlučivanju da li da uložite vreme u fuzzing određene funkcije: čvor koji je **dostupan**, **složen** i već ima **SAST nalaze** često je bolja meta od čvora koji je samo složen, ali do njega ne vodi putanja dostupna napadaču.

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

Važna metodologija je presek: **složenost x izloženost x uticaj**. Koristite grafikon da biste izabrali fuzz ciljeve sa najvećom očekivanom bezbednosnom vrednošću, a zatim pomoću mutacija koje prežive odredite koje granice i invarijante vaš harness treba da optereti.<sup>[[5]](#references)</sup>

## Diferencijalni fuzzing kodiranja kriptografskih ključeva

Počnite od važećih serijalizovanih ključeva ili standardnih testnih vektora. Mutirajte kodirana polja, a da pritom ne narušite dužinu i strukturu potrebnu da se dođe do putanja za uvoz i operacije, a zatim iste bajtove prosledite nezavisnim implementacijama. Uporedite prihvatanje i greške. Za randomizovane potpise i šifrate potrebni su oracle-i ispravnosti, a ne poređenje bajt po bajt: proverite potpise ili uporedite zajedničke tajne dobijene kružnim tokom enkapsulacije i dekapsulacije. Testni vektori potvrđuju usklađenost za poznate slučajeve; diferencijalne mutacije ispituju neispravna kodiranja koja nisu obuhvaćena njima.<sup>[[23]](#references)[[26]](#references)</sup>

Za ove formate ključeva koristite oracle-e specifične za format:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Prošireni ML-DSA ključevi za potpisivanje:** menjajte upakovane koeficijente `s1` ili `s2` tako da budu izvan opsega `[-η, η]`, a da ključ i dalje može da se parsira. Proverite da li ih uvoz ili potpisivanje odbijaju i da li se dobijeni potpis može verifikovati. Razlike u prihvatanju same po sebi ne predstavljaju kršenje standarda, jer FIPS 204 ne zahteva dodatne provere privatnog ključa. Pogledajte [uslovni mehanizam curenja](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM parovi ključeva:** odvojite obavezne provere ključa za enkapsulaciju i ulaznih podataka za dekapsulaciju od opcione provere konzistentnosti para (PCT) pri uvozu para. Enkapsulirajte pomoću javnog ključa, dekapsulirajte pomoću privatnog ključa i uporedite zajedničke tajne; nepodudaranje može da naruši šifrovanu komunikaciju čak i kada pojedinačni ključevi prođu ulazne provere. Proverite da li API validira ulaze tokom operacije ili zasebnim pozivom; libcrux nudi `validate_public_key(pk)` i `validate_private_key(sk, ct)`, koje ne zamenjuju PCT.
- **Sirovi XMSS/XMSSMT ključevi:** testirajte kružno serijalizovanje i deserijalizovanje ključeva za **potpisivanje i verifikaciju** u različitim skupovima parametara, a ne samo operacije nad ključevima u memoriji. XMSS i XMSSMT imaju odvojene četvorobajtne OID prostore imena, pa parser koji proverava samo OID i prvo pokušava XMSS može pogrešno da klasifikuje XMSSMT ključ sa istim OID-om i odbije uvoz. Prijavljeni RustCrypto parser pokazuje problem interoperabilnosti/dostupnosti, a ne falsifikovanje potpisa.

## Go fuzzing pomoću gosentry: snažniji mehanizam, tipizovani ulazi i diferencijalne provere

Ako Go cilj već ima izvorni `testing.F` harness, praktičan način nadogradnje jeste pokretanje istog harness-a pomoću [gosentry](https://github.com/trailofbits/gosentry), račvanja Go toolchain-a koje zadržava `go test -fuzz`, ali menja pozadinski mehanizam u **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Ovo je korisno kada se native Go fuzzer zaglavi na **teškim poređenjima**, **tipiziranim ulazima** ili formatima sa mnogo parsiranja. Metodologija ostaje ista:

- Nastavite da koristite `f.Add(...)` za semenske vrednosti i `f.Fuzz(...)` za callback.
- Ponovo koristite isti harness, ali ga pokrenite pomoću gosentry `go` binarnog fajla umesto standardnog toolchain-a.
- Tretirajte kampanju kao uobičajeno coverage-guided pokretanje, ali uz LibAFL scheduling/mutation i bolje prateće detektore.

### Pretvaranje neprimetnih grešaka u fuzz nalaze

Čest problem u Go procenama jeste to što opasno ponašanje često **ne izaziva** crash po podrazumevanim podešavanjima. Pomoću gosentry-ja možete da pretvorite nekoliko klasa „loših, ali neprimetnih“ stanja u nalaze.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` da bi izabrani logging/error putevi izazivali crash (korisno za putanje koda u stilu `log.Fatal` koje bi inače samo zapisale log i nastavile sa radom).
- `--catch-races=true` za ponovno pokretanje novootkrivenih unosa u queue-u pomoću Go race detector-a.
- `--catch-leaks=true` za ponovno pokretanje novih unosa u queue-u pomoću `goleak`-a i prekidanje pri otkrivanju curenja gorutina.
- LibAFL obradu zaglavljivanja da bi se **beskonačne petlje / veoma spori ulazi** zadržali kao fuzz nalazi, umesto da budu odbačeni kao timeout-i.
- Ugrađene provere aritmetičkog prekoračenja po podrazumevanim podešavanjima, uz opcione provere odsecanja pomoću instrumentacije u stilu go-panikint-a.

Ovo je posebno korisno za ciljeve kod kojih je bezbednosni uticaj **greška parsera bez panike**, **greška u konkurentnosti** ili **zaglavljivanje koje izaziva samo DoS**, a ne oštećenje memorije.

### Fuzzing svestan struktura za tipizirane Go API-je

Native Go fuzzing uglavnom očekuje skalare kao što su `[]byte`, `string` i brojevi. Ako kod koji se testira obrađuje tipizirane objekte, gosentry može direktno da fuzz-uje **složene vrednosti** (strukture, slice-ove, nizove, pokazivače), uz istovremeno mutiranje bajtova u pozadini.<sup>[[7]](#references)[[8]](#references)</sup>

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

Koristite ovo kada bi pravljenje lažnog wire formata samo za fuzzing sakrilo logičke greške iza parsiranja koje postoji samo u harness-u. Za differential ili grammar-based kampanje, neka ulaz u harness bude jedan `[]byte` ili `string`, a parsirajte ga unutar callback-a.

### Grammar-based fuzzing za parser-e i ulaze protokola

Za parser-e, formate i jezike ulaza, gosentry može da pokrene **Nautilus grammar fuzzing** uz LibAFL. Gramatika je JSON niz pravila produkcije, a harness bi obično trebalo da prima jedan argument tipa `[]byte` ili `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Beleške o metodologiji:

- Koristite grammar mode kada mutacije na nivou bajtova uglavnom ne prođu rane provere sintakse.
- Neka gramatika bude usmerena na **bezbednosno relevantan podskup** jezika/protokola, umesto da modeluje celu specifikaciju.
- Koristite velike granične vrednosti u terminalima/neterminalima da biste testirali ivice celih brojeva, dužina i mašina stanja.
- Grammar mode održava ulaze validnim prema gramatici, ali cilj i dalje prima **bajtove/niske**, tako da parsiranje i semantičke provere ostaju unutar koda nad kojim se vrši testiranje.

### Differential fuzzing: upoređujte implementacije, ne samo padove

Snažan obrazac za Go ekosisteme je **grammar-based differential fuzzing**: generišite validne strukturirane ulaze i prosledite ih dvama parserima, klijentima ili mehanizmima za prelaze stanja.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacija izazove paniku, dok druga uredno odbije ulaz
- neslaganja u prihvatanju/odbacivanju ulaza
- različita stabla parsiranja ili dekodirani objekti
- različiti prelazi stanja, nonce vrednosti, stanja na računima ili koreni stanja

Ovo je praktičan način za pronalaženje **neslaganja u konsenzusu**, **dvosmislenosti parsera** i **odstupanja između specifikacije i implementacije** koja čisto fuzziranje usmereno na padove često propušta.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponovo upotrebite korpus kampanje za izveštavanje o pokrivenosti

Nakon kampanje, ponovo pustite sačuvani korpus reda čekanja da biste generisali Go izveštaj o pokrivenosti, bez ručnog izvoza zasebnog korpusa.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Pokrenite komandu iz **istog paketa** i sa istim ciljem `-fuzz` kako bi gosentry razrešio odgovarajuće stanje keširane kampanje.

## References

- [1] [Fuzzing mutacionom gramatikom](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing detaljno](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pet godina kasnije: fuzzing protokola vođen pokrivenošću](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark pretvara kod u grafove](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzingu je nedostajala polovina alata. Forkovali smo toolchain da bismo to popravili.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Brzi greybox fuzzer za protokole sa stanjem, uz korišćenje snapshotova](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatike nema problema: ka fuzzingu Linux kernela bez opisa sistemskih poziva](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efikasan fuzzing uz adaptivne i promenljive snapshotove](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [LLVM instrumentacija za AFL++: pokrivenost putanja i pozivalaca](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prediktivni fuzzing osetljiv na kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - dokumentacija za build i regression seed-ove](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Istraživanje race condition-a u Linux kernelu pomoću kontrolisanih preplitanja pristupa memoriji](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrivenost koda za fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO sintaksa proširenih imena datoteka](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec savetodavno obaveštenje: CFITSIO, Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing proširene sintakse imena datoteka u CFITSIO: 16 ranjivosti u bezbednosti memorije i trijaža uz pomoć Codex-a](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Diferencijalni fuzzing za kriptografiju](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standard za mehanizam enkapsulacije ključeva zasnovan na modulnoj rešetki](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Greška u parsiranju XMSSMT OID-a - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stanje implementacija postkvantne kriptografije](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Kako smo pomoću snapshotova došli do CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzers protiv AI-ja: poređenje alata Fuzzilli i BigSleep na JavaScript engine-ima](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
