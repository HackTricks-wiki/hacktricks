# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Dekking teenoor semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl hulle **grammatikageldig** bly. In dekkinggestuurde modus word slegs monsters wat **nuwe dekking** oplewer as corpus-sade gestoor. Vir **taikteikens** (ontleders, interpreteerders, enjins) kan dit foute miskyk wat **semantiese/data-vloeikettings** vereis, waar die uitvoer van een konstruksie die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Faalmodus:** die fuzzer vind sade wat elk `document()` en `generate-id()` (of soortgelyke primitiewe) aktiveer, maar **nie die gekoppelde data-vloei behou nie**. Gevolglik word die monster wat “nader aan die fout” is, weggegooi omdat dit nie dekking byvoeg nie. Met **3+ afhanklike stappe** raak ewekansige herkombinasie duur, en dekkingterugvoer stuur nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** oorweeg vir grammatikas met baie afhanklikhede om mutasionele en generatiewe fases **hibried te maak**, of om generering te bevoordeel wat **function chaining**-patrone volg (nie net dekking nie).<sup>[[1]](#references)</sup>

## Slaggate met corpus-diversiteit

Dekkinggestuurde mutasie is **gierig**: ’n monster met nuwe dekking word onmiddellik gestoor en behou dikwels groot onveranderde gedeeltes. Met verloop van tyd word corpora **byna-duplikate** met min strukturele diversiteit. Agressiewe minimisering kan nuttige konteks verwyder, daarom is ’n praktiese kompromie **grammatikabewuste minimisering** wat **ná ’n minimum tokenlimiet ophou** (verminder geraas, maar behou genoeg omliggende struktuur om mutasievriendelik te bly).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel struktureel verskillende sade wat dekking maksimeer** bo ’n groot hoop byna-duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **werklike monsters** (openbare corpora, crawling, vasgelegde verkeer, lêerstelle uit die teikene-ekosisteem).
- Distilleer dit met **dekkinggebaseerde corpus-minimisering** eerder as om elke geldige monster te behou.
- Hou sade **klein genoeg** sodat mutasies betekenisvolle velde tref, eerder as om die meeste siklusse aan irrelevante grepe te bestee.
- Voer corpus-minimisering weer uit ná groot veranderinge aan die harness/instrumentering, omdat die “beste” corpus verander wanneer bereikbaarheid verander.

## Vergelykingsbewuste mutasie vir magiese waardes

’n Algemene rede waarom fuzzers ’n plato bereik, is nie sintaksis nie, maar **harde vergelykings**: magiese grepe, lengtekontroles, enum-stringe, kontrolesomme of ontleder-versendingswaardes wat deur `memcmp`, switch-tabelle of opeenvolgende vergelykings beskerm word. Suiwer ewekansige mutasie mors siklusse deur hierdie waardes greep vir greep te probeer raai.

Gebruik vir hierdie teikens **vergelykingsnasporing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-styl werkvloeie) sodat die fuzzer operande van mislukte vergelykings kan waarneem en mutasies kan stuur na waardes wat daaraan voldoen.<sup>[[3]](#references)</sup>

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

**Praktiese notas:**

- Dit is veral nuttig wanneer die teiken dieper logika agter **lêerhandtekeninge**, **protokolwerkwoorde**, **tipe-etikette** of **weergawe-afhanklike kenmerkbisse** versteek.
- Gebruik dit saam met **woordeboeke** wat uit werklike voorbeelde, protokolspesifikasies of ontfoutingslogboeke onttrek is. ’n Klein woordeboek met grammatikatekens, stukname, werkwoorde en skeidingstekens is dikwels meer waardevol as ’n massiewe generiese woordelys.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en verklein dan die resulterende corpus weer, sodat latere stadiums met reeds geldige voorvoegsels begin.

## Ryker terugvoer wanneer randdekking verskillende paaie laat saamsmelt

Normale randdekking kan nie onderskei tussen twee uitvoerings wat dieselfde helper via verskillende oproepers deurloop, of verskillende kombinasies vertakkings binne ’n funksie volg nie. Dit is belangrik in gedeelde dekodeerders, protokolverspreiders en interpreterhelpers, waar die **roete** na ’n rand bepaal watter toestand aktief is. Om elke oproepkonteks naïef na te spoor, is ook gevaarlik: die dekkingskaart en tou kan ontplof. Navorsing oor kontekssensitiewe fuzzing beveel daarom aan dat slegs belowende kontekste verfyn word, eerder as om die hele oproepgrafiek as kontekssensitief te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-bouweergawes bied **Ball-Larus-paddekkingsmeting per funksie** bykomend tot normale randdekking. Dit ken ’n kenmerk toe aan elke asikliese pad deur ’n funksie; terugkante van lusse word verwyder, dus onderskei hierdie terugvoer kombinasies van vertakkings, maar **nie die aantal lusiterasies nie**. Begin met die minder streng vlak `1`, en beperk dan strenger modusse tot verdagte ontleder-/toestandmasjienkode, omdat die aantal paaie eksponensieel kan groei.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Vir ’n helper wat vanaf baie sekuriteitsrelevante plekke aangeroep word, kan LTO-modus elke funksiepad met sy onmiddellike aanroepingsplek kombineer:<sup>[[13]](#references)</sup>

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

**Veldtogriglyne:** pas ryker terugvoer versigtig toe en monitor die koste daarvan vir die coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Laat ’n gewone edge-coverage-instansie parallel loop; ryker terugvoer is net nuttig as die ekstra queue/map-koste nie die aantal uitvoerings per sekonde vernietig nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om pad-/oproeper-instrumentasie te beperk wanneer groot biblioteke met baie templates of generiese nutskode die map oorheers.
- Funksies met buitensporig baie asikliese paaie kan deur AFL++ oorgeslaan word; waarskuwings tydens samestelling dui daarop dat die teiken ’n allowlist of ’n minder streng vlak nodig het.
- Caller + path coverage ondersteun net een oproeperdiepte. Moenie dit met dieper konteksstapels kombineer nie.
- Pad-ID’s kan tussen groot LLVM-weergawes verander. Hou die toolchain onveranderd vir ’n veldtog en moenie PATH-gebaseerde corpora sinkroniseer asof hul feature-ID’s stabiel tussen samestellings is nie.
- Hierdie terugvoer vul `CMPLOG` aan: vergelykingnasporing bepaal **watter waarde ’n guard slaag**, terwyl pad-/oproeper-terugvoer behou **watter roete en vertakkingskombinasie dit bereik het**.

## Stateful Fuzzing: Reekse is Seeds

Vir **protokolle**, **geïntegreerde werkvloeie** en **parsers met veelvuldige fases**, is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **boodskapreeks**. Om die hele transkripsie in een lêer aaneen te skakel en dit blindelings te muteer, is gewoonlik ondoeltreffend, omdat die fuzzer elke stap ewe veel muteer, selfs wanneer net die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Doeltreffender patroon is om die **reeks self as die seed** te behandel en **waarneembare toestand** (antwoordkodes, protokoltoestande, parserfases, teruggegeven objekttipes) as bykomende terugvoer te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige voorvoegselboodskappe** stabiel en fokus mutasies op die boodskap wat die **toestandsoorgang dryf**.
- Cache identifiseerders en bediener-gegenereerde waardes uit vorige antwoorde wanneer die volgende stap daarvan afhang.
- Verkies mutasie/splicing per boodskap bo die mutering van die hele geserialiseerde transkripsie as ’n ondeursigtige blob.
- As die protokol betekenisvolle antwoordkodes blootstel, gebruik hulle as ’n **goedkoop toestandsorakel** om reekse wat dieper vorder, voorkeur te gee.

Dit is dieselfde rede waarom geverifieerde foute, verborge oorgange of parserfoute wat “slegs ná die handdruk” voorkom, dikwels deur vanilla-lêerstyl-fuzzing gemis word: die fuzzer moet **volgorde, toestand en afhanklikhede** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

### Android Binder: multi-kliënt driver-fuzzing

Hoë edge coverage kan steeds IPC-driverfoute mis, omdat coverage nie **objekeienaarskap, verwysingtellings, hangende boodskappe, opruimingsvolgorde of draad-interleavings** beskryf nie. Die [Android Binder IPC-internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md)-bladsy dek die objekmodel van die driver; hierdie voorbeeld fokus op die fuzzer-harnas. Android Binder is ’n nuttige model: om beide die toewysings- en vrymaakpaaie te bereik, is nie genoeg as die fuzzer nie verskeie prosesse in die vereiste volgorde op dieselfde kernobjek kan laat werk nie.<sup>[[15]](#references)</sup>

#### Modelleer die protokol, nie geïsoleerde `ioctl`-buffers nie

Stel ’n toetsgeval voor as ’n geordende grammatika van **kliëntidentiteit + bewerking + gestruktureerde argumente**. Die Binder LKL-fuzzer gebruik protobuf en `libprotobuf-mutator`, met een aanhoudende konteksbestuurderkliënt en twee gewone kliënte. ’n Semantiese harnas behou dan die verwantskappe wat blinde greepmutasie sou vernietig.<sup>[[15]](#references)</sup>

- Cache waardes wat deur vorige bewerkings teruggegee is. Byvoorbeeld, `BC_FREE_BUFFER` moet ’n transaksiebufferwyser hergebruik wat deur ’n vorige `ioctl` teruggegee is.
- Genereer geldige verstekantwoorde sodat sinchrone transaksies kan voltooi en latere bewerkings bereikbaar bly.
- Verwerp onmoontlike oorgange, soos selftransaksies of veelvuldige hangende transaksies na dieselfde teiken.
- Hou enkelinstansie-opstarttoestand buite die terugstelling per invoer. Binder laat slegs een `BINDER_SET_CONTEXT_MGR`-registrasie per selflaai toe; die herhaaldelike vernietiging en herskepping van daardie kliënt sou dus latere invoere ongeldig maak.

’n Nuttige sjabloon vir ’n leeftydwedloop is om een kliënt ’n objek te laat oordra, draad- of prosesopruiming te begin, en die ontvangende kliënt terselfdertyd die transaksiebuffer te laat vrystel. In die CVE-2020-0423-voorbeeld kon ’n `BINDER_TYPE_WEAK_BINDER`-oordrag, gevolg deur `BINDER_THREAD_EXIT` wat met `BC_FREE_BUFFER` meeding, ’n ingebedde `binder_work` vrystel terwyl die uittredende draad se opruimingspad dit steeds gebruik het.<sup>[[15]](#references)</sup>

#### Stel beheerde interleavings weer in ’n gebruikersruimte-kern in

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) koppel die werklike kernkode in ’n gebruikersruimte-harnas en stel sy syscall-koppelvlak via `lkl_syscall` beskikbaar. Dit maak dit maklik om protobuf-toestand, coverage en KASAN in een proses te koördineer. LKL voer ’n syscall egter normaalweg uit sonder dat ’n ander kerndraad dit onderbreek. Voeg vir wedloopveldtogte `schedule()`-punte by rondom geselekteerde slot-/onts lok- en leeftydgrense, en laat die harnas dan by elke prysgawe willekeurig die volgende kliënt kies. Hou hierdie punte doelgerig, want elkeen vergroot die skeduleringsoekruimte. Die ewekansige skeduleerder wat die navorsers beskryf, is **nie** deel van die upstream Binder-fuzzer nie.<sup>[[15]](#references)</sup>

#### Bou en herhaal geserialiseerde regressie-seeds

Die upstream-harnas pen ’n versoenbare `libprotobuf-mutator`-weergawe vas, aktiveer LKL-fuzzing-instrumentasie en KASAN met `LKL_FUZZING=1`, en aktiveer `CONFIG_MMU` vir Binder met `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nadat jy ’n doelbewus kwesbare hersiening uitgecheck het of die rollback-patches toegepas het wat stroomop gedokumenteer is, kan ’n geserialiseerde saad die hele multi-kliënttoestandsoorgang reproduseer sonder om dit in ’n ad hoc C-bewys-van-konsep te rekonstrueer:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandel die gevolglike KASAN use-after-free as bevestiging dat die seed die kwesbare lewensduurpad bereik het. Dit demonstreer **nie** die latere primitives wat vir kernel code execution of privilege escalation nodig is nie.<sup>[[16]](#references)</sup>

## Enkelmasjien-diversiteitstruuk (Jackalope-styl)

’n Praktiese manier om **generatiewe nuutheid** met **hergebruik van dekking** te kombineer, is om **kortlewende werkers** teen ’n persistente bediener te herbegin. Elke werker begin met ’n leë corpus, sinkroniseer ná `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sinkroniseer weer en sluit dan af. Dit lewer **vars strukture in elke generasie** terwyl dit steeds opgehoopte dekking benut.<sup>[[1]](#references)[[2]](#references)</sup>

**Bediener:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Opeenvolgende werkers (voorbeeldlus):**

<details>
<summary>Jackalope-werker-herbeginlus</summary>

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

**Notas:**

- `-in empty` dwing ’n **vars corpus** af met elke generasie.
- `-server_update_interval T` benader **vertraagde sinkronisering** (eers nuwe invoer, later hergebruik).
- In grammar fuzzing-modus word **aanvanklike bedienersinkronisering by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Die optimale `T` is **teikenafhanklik**; dit werk gewoonlik die beste om oor te skakel nadat die worker die meeste “maklike” dekking gevind het.

## Snapshot Fuzzing Vir Teikens Wat Moeilik Is Om Te Harnas

Wanneer die kode wat jy wil toets eers bereikbaar word **ná ’n groot opstelkoste** (’n VM begin, ’n aanmelding voltooi, ’n pakkie ontvang, ’n container ontleed, ’n diens inisialiseer), is ’n nuttige alternatief **snapshot fuzzing**: neem ’n momentopname van die gereed proses- of VM-toestand, voer elke toetsgeval in via die teiken se invoerpad, voer uit tot ’n crash/timeout, en herstel die momentopname. Dit vermy dat inisialisering of protokolvoorvoegsels herhaal word en is nuttig vir **netwerkdienste**, **firmware**, **aanvaloppervlakke ná verifikasie**, en **teikens wat slegs uit binaries bestaan**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die teiken loop totdat die interessante toestand gereed is.
2. Neem op daardie punt ’n momentopname van **geheue + registers**.
3. Skryf vir elke toetsgeval die gemuteerde invoer direk na die relevante gas-/prosesbuffer.
4. Voer uit tot ’n crash/timeout/reset.
5. Herstel die momentopname; vir VM-teikens, herstel slegs die **gewysigde bladsye** indien dit ondersteun word, en herhaal dan.

Plaas die momentopname so na as wat prakties moontlik is aan die eerste duur ontleed-/verspreidingstap, soos ná ’n `recv`/`read` of punt waar pakkies gedeserialiseer word, en teken die invoerbuffer aan wat die teiken gebruik. Dit volg die beginsel van aanpasbare plasing: skuif die momentopname dieper in die invoerverwerking om herhaalde werk te vermy.<sup>[[11]](#references)</sup>

## Linux-kernrasverkenning Met MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) verander tydsensitiewe Linux-kernrasse in herhaalbare geheuetoegangskedules. Dit kan twee-konteks-**A-B-A**-uitvoerings outomaties opsom, of ’n ontleder toelaat om volgordebeperkings in ’n terminale UI/GUI op te lê. Dit is eksperimentele navorsingsgereedskap eerder as ’n volledige concurrency fuzzer: dit benodig tans LLVM 23+ en die projek se gepatchte kern, die opdragreëlnutsgoed ondersteun twee toetsdrade, en die voorgestelde fuzzing-laag in userspace is nie geïmplementeer nie.<sup>[[17]](#references)[[18]](#references)</sup>

### Versamel kommunikasiepunte tussen kontekste

Bou die geïnstrumenteerde kern met KASAN outline callbacks en die gepatchte KCOV-geheue-opnamesteun. Die projek se README beveel ook aan dat sibling-call-optimering gedeaktiveer word sodat oproepstapels bruikbaar bly.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN-outline mode (`asan-instrumentation-with-call-threshold=0`) omskep instrumented accesses in helper calls. Die MAccConc-kernellappies deaktiveer `asan-opt-same-temp` sodat opeenvolgende accesses nie saamgevoeg word nie; deaktiveer ook die `asan-opt-globals`-optimering wanneer races op globale veranderlikes sigbaar moet wees. KCOV dra die gevolglike rekords na userspace oor. Vergelyk accesses uit verskillende uitvoeringskontekste en behou pare waarvan die grepe-reekse oorvleuel en waar minstens een kant skryf; modelleer `kfree()` as ’n skryfaksie sodat leeftydsoorgange ook kandidate word.<sup>[[17]](#references)</sup>

Vir werk wat buite die taak wat dit begin het, voortgaan, soos pakkieverwerking of RCU-callbacks, moet die subsisteem ’n KCOV remote-coverage-handle deurgee. Upstream remote KCOV is opt-in en is nie outomaties vir willekeurige agtergrondwerk beskikbaar nie. As die handle nie deurgegee word nie, kan ’n werklike interaksie dus onsigbaar wees.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifiseer dieselfde dinamiese access tydens elke uitvoering

Moenie teen ’n konkrete heap-adres herspeel nie, want dit kan ná elke toekenning verander, of slegs teen ’n instruksie-adres nie, want dit is dubbelsinnig binne helpers soos `memcpy()` en `spin_lock()`. MAccConc gebruik ’n **count-augmented stack trace**: elke raamwerk identifiseer ’n callee plus die aanroepingtelling binne sy caller, en die laaste element identifiseer die memory-access-instruksie. SanitizerCoverage-funksie-inskrywing-/uittree-rekords laat userspace hierdie dinamiese identifiseerder rekonstrueer, wat stabiel bly ondanks adresveranderinge en onverwante beheer-vloeigeraas.<sup>[[17]](#references)</sup>

### Skakel kandidaatpare om in afgedwonge skedules

Die aangepaste `KCOV_SET_DI`-ioctl koppel ’n count-augmented access-identifiseerder aan ’n shared-flag-aksie.<sup>[[17]](#references)</sup>

| Aksie | Semantiek |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Stel vlag *N* onmiddellik voor die geselekteerde access. |
| `DI_STACK_WAIT` | Spin voor die geselekteerde access totdat vlag *N* gestel is of die opgestelde limiet verstryk. |
| `DI_STACK_WAKE_POST` | Stel vlag *N* onmiddellik ná die geselekteerde access. |

Vir ’n gedeeltelike **A-happens-before-B**-beperking, koppel `DI_STACK_WAKE_POST` aan A en `DI_STACK_WAIT` aan B met dieselfde vlag. Vir ’n volledig gespesifiseerde skedule met twee kontekste, begin B geblokkeer; laat A dan B wakker maak en wag by die eerste oordragpunt. B voer die omgekeerde bewerking by die volgende oordrag uit. Dit werk soos deterministiese kontekswisseling en is wat die outomatiese A-B-A-verkenner gebruik.<sup>[[17]](#references)</sup>

’n Minimale veldtog is om die toetssaak met vier hooks (`test_setup`, twee thread-funksies en `test_end`) as ’n gedeelde biblioteek te compileer, ’n onbeperkte spoor in te samel en dan A-B-A-kandidate te enumereer of handmatige beperkings rondom verdagte accesses by te voeg.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreteer time-outs apart van suksesvolle herordening: ’n versoekte volgorde kan onmoontlik wees omdat ’n slot- of inisialisering-/publikasie-afhanklikheid verhoed dat die tweede konteks sy inspuitingspunt bereik. Hou ook KASAN se blindekolle in gedagte: direkte stack-toegange word gewoonlik nie gehaak nie, tensy hulle buite die grense kan gaan; globals word met die verstekoptimering weggelaat; en huidige samestellers kan nie ASAN- en TSAN-hooks gelyktydig genereer nie. Laastens verloor die prototipe sy KCOV-buffer wanneer ’n guest paniekerig raak, so behou ’n onafhanklike crash-console/orakel.<sup>[[17]](#references)</sup>

Vir toekomstige concurrency-geleide fuzzing, teken geheue-toegangopsommings per invoer of syscall aan, koppel bewerkings wat kruiskonteks-kommunikasiepunte sou vorm, en verken dan slegs daardie kombinasies. VM-snapshots stabiliseer globale toestand en adresse; sonder snapshots kan metadata oor toewysingsplekke objekte oor lopies heen abstraheer. Dit is ’n voorgestelde uitbreiding, nie ’n kenmerk van die huidige MAccConc-userspace-gereedskap nie.<sup>[[17]](#references)</sup>

## Harness-introspeksie: Vind vlak fuzzers vroeg

Wanneer ’n veldtog vasval, lê die probleem dikwels nie by die **mutator** nie, maar by die **harness**. Gebruik **bereikbaarheids-/dekking-introspeksie** om funksies te vind wat staties vanaf jou fuzz-teiken bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die teiken te laat of te vroeg.
- Die saadkorpus mis ’n hele kenmerkgroep.
- Die teiken benodig eintlik ’n **tweede harness** in plaas van een oorgroot “doen-alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-styl werkvloeie gebruik, kan Fuzz Introspector statiese bereikbaarheid met looptyddekking vergelyk en verslae genereer op grond van ’n tydgebonde loop of openbare korpus.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Gebruik die verslag om te besluit of jy ’n nuwe harness moet byvoeg vir ’n parser-pad wat nie getoets is nie, die corpus vir ’n spesifieke kenmerk moet uitbrei, of ’n monolitiese harness in kleiner entry points moet verdeel.

## Grafiek-eerste seleksie van fuzz-teikens en mutasie-triage

As jy reeds **statiese-analise-bevindings**, **mutasietoetsing-oorlewendes** en **dekkingverslae** het, moenie hulle as afsonderlike lyste triageer nie. Bou eers ’n **oproepgrafiek**, annoteer nodes met **siklomatiese kompleksiteit**, **bereikbaarheid vanaf entry points/onvertroude invoer** en enige eksterne bevindings, en vra dan grafiekvrae.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is bereikbaar vanaf onvertroude invoer?
- Watter mutasie-oorlewendes lê op paaie van parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met buitengewoon groot **blast radius**?

Dit bring gewoonlik beter fuzz-teikens na vore as om net op die "laagste dekking" te fokus. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker kandidaat vir ’n harness as ’n geïsoleerde interne helper met swak dekking, maar sonder ’n pad wat deur ’n aanvaller beheer word.

### Praktiese triage-werkvloei

1. Bou ’n **kodegrafiek** van die kodebasis en haal kompleksiteits-/vertakkingsmaatstawwe per funksie uit.
2. Lys **entry points** wat invoer aanvaar wat deur ’n aanvaller beheer word: request handlers, decoders, importers, protocol parsers, CLI-/lêerlesers.
3. Voer **padnavrae** vanaf daardie entry points na kandidaatfunksies uit om bereikbare aanvaloppervlak van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodes wat die volgende kombineer:
   - hoë **siklomatiese kompleksiteit**
   - bevestigde **bereikbaarheid vanaf onvertroude invoer**
   - groot **blast radius** of baie afhanklike funksies stroomaf
   - ondersteunende bewyse soos **SARIF**-bevindings, ouditnotas of mutasie-oorlewendes
5. Skryf eerste gefokusde harnesses vir die nodes met die hoogste telling, veral vir **parsers/codecs** soos hex-/Base64-/IP-/boodskap-decoders.

### Mutasie-oorlewendes: ekwivalent teenoor uitvoerbaar

Mutasietoetsing lewer dikwels ’n raserige lys oorlewendes op. Voordat jy elke oorlewende as ’n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n entry point wat deur ’n aanvaller beheer word?
- Word alle oproeppaaie beperk deur sterker invariantes as die gemuteerde kontrole?
- Lê die node in dooie kode, formateringslogika alleen, of in ’n hoë-impak rekenkundige/parser-pad?

Oorlewendes wat onbereikbaar bly of struktureel beperk is, is dikwels **ekwivalente mutante**. Oorlewendes wat **bereikbaar** bly en **grenswaardes**, **oorloop-/oordragpaaie** of **sekuriteitskritieke rekenkunde/ontleding** raak, moet bevorder word tot:

- nuwe fuzz-harnesses
- direkte eienskap-/invarianttoetse
- geteikende randgevalvektore

### Korreleer eksterne bevindings met die grafiek

As jou SAST-pyplyn **SARIF** uitvoer, karteer bevindings op grafieknodes volgens **lêer + lynreeks** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kyk of die bevinding op enige pad vanaf ’n entry point voorkom
- groepeer nabygeleë bevindings wat na dieselfde knelpunt herlei kan word

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd aan ’n spesifieke funksie moet bestee: ’n node wat **bereikbaar** en **kompleks** is en reeds **SAST-treffers** het, is dikwels ’n beter teiken as ’n bloot komplekse node sonder ’n aanvallerpad.

Voorbeeldwerkvloei met Trailmark.<sup>[[6]](#references)</sup>

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

Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutasie-oorlewendes om te bepaal watter grense en invariantes jou harness moet stres.<sup>[[5]](#references)</sup>

## Go Fuzzing Met gosentry: Kragtiger Enjin, Getipeerde Insette, En Differensiële Kontroles

As ’n Go-teiken reeds ’n inheemse `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop, ’n gevurkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** omskakel.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Dit is nuttig wanneer die native Go fuzzer vashaak op **hard comparisons**, **typed inputs** of **parser-heavy formats**. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback te gebruik.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binary uit in plaas van die standaard toolchain.
- Hanteer die gevolglike campaign as ’n normale coverage-guided run, maar met LibAFL-scheduling/mutation en beter omliggende detectors.

### Verander stille foute in fuzz-bevindings

’n Herhalende probleem met Go-assessments is dat gevaarlike gedrag dikwels **nie** by verstek crash nie. Met gosentry kan jy verskeie klasse “sleg maar stil”-toestande in bevindings omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging/error-paaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte queue entries met die Go race detector weer af te speel.
- `--catch-leaks=true` om nuwe queue entries met `goleak` weer af te speel en by goroutine-leaks te stop.
- LibAFL-hanghantering om **infinite loops / baie stadige inputs** as fuzz-bevindings te behou, eerder as om hulle as timeouts te laat verdwyn.
- Ingeboude kontroles vir arithmetic overflow is by verstek aan, plus opsionele truncation-kontroles deur go-panikint-agtige instrumentation.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **panicless parser failure**, ’n **concurrency bug** of ’n hang wat net **DoS** veroorsaak, eerder as memory corruption, is.

### Struct-aware fuzzing vir getikte Go-API’s

Native Go-fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string` en getalle. As die kode wat getoets word getikte objects verbruik, kan gosentry **saamgestelde waardes** (structs, slices, arrays, pointers) direk fuzz, terwyl dit steeds bytes onderliggend muteer.<sup>[[7]](#references)[[8]](#references)</sup>

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

Gebruik dit wanneer ’n vals wire format wat net vir fuzzing gebou is, logika-foute agter parsing-kode wat net in die harness voorkom, sou verberg. Vir differential- of grammatika-gebaseerde veldtogte, hou die harness-invoer as ’n enkele `[]byte` of `string` en parseer dit eerder binne die callback.

### Grammatik-gebaseerde fuzzing vir parsers en protokolinsette

Vir parsers, formate en invoertale kan gosentry **Nautilus-grammatikafuzzing** bo-op LibAFL uitvoer. Die grammatika is ’n JSON-skikking van produksiereëls, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te neem.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodologienotas:

- Gebruik grammar mode wanneer byte-level mutations meestal tydens vroeë sintaksiskontroles doodloop.
- Hou die grammar gefokus op die **sekuriteitsrelevante deelversameling** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om heelgetal-, lengte- en toestandsmasjiengrense te beproef.
- Grammar mode hou invoere grammatika-geldig, maar die teiken ontvang steeds **bytes/strings**, dus bly ontleding en semantiese kontroles binne die kode wat deur die harness getoets word.

### Differential fuzzing: vergelyk implementasies, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde invoere en voer dit aan twee parsers, clients of toestandoorgang-enjins.<sup>[[7]](#references)[[8]](#references)</sup>

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

Behandel die volgende as bevindings:

- een implementering veroorsaak ’n panic terwyl die ander dit netjies afwys
- wanpassings tussen aanvaarde/verwerpte invoer
- verskillende parse-bome of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, saldo’s of toestandswortels

Dit is ’n praktiese manier om **konsensus-wanpassings**, **parser-dubbelsinnigheid** en **spesifikasie-teenoor-implementering-afwykings** te vind wat suiwer crash-fuzzing dikwels mis.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Hergebruik die veldtogkorpus vir dekkingverslagdoening

Speel ná ’n veldtog die gestoorde toukorpus weer af om ’n Go-dekkingsverslag te genereer sonder om ’n aparte korpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Voer die opdrag uit vanuit dieselfde pakket en met dieselfde `-fuzz`-teiken sodat gosentry die korrekte gekaste veldtogtoestand kan oplos.



## References

- [1] [Mutasionele grammatika-fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet vyf jaar later: Oor dekking-geleide protokol-fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel ontbreek. Ons het die toolchain gefork om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox-fuzzer vir toestandvolle netwerkprotokolle met behulp van snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Op pad na fuzzing van die Linux-kern sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentasie: pad- en oproeperdekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende konteksensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder-fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder-fuzzer - dokumentasie vir bou en regressiesade](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Verkenning van Linux-kern-rastoestande met beheerde geheuetoegang-interleavings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Kodedekking vir fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
