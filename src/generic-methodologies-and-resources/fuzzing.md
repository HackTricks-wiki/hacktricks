# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage teenoor Semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl hulle **grammatikageldig** bly. In coverage-guided-modus word slegs monsters wat **nuwe coverage** veroorsaak as corpus-seeds gestoor. Vir **taalteikens** (parsers, interpreteerders, engines) kan dit foute miskyk wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruk die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Mislukkingsmodus:** die fuzzer vind seeds wat afsonderlik `document()` en `generate-id()` (of soortgelyke primitiewe) uitoefen, maar **behou nie die gekoppelde dataflow nie**. Gevolglik word die monster wat “nader aan die fout” is weggegooi omdat dit nie coverage byvoeg nie. Met **3+ afhanklike stappe** raak lukrake herkombinasie duur, en coverage-terugvoer stuur nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** oorweeg vir grammatikas met baie afhanklikhede om mutasionele en generatiewe fases te **kombineer**, of om generering na **funksieketting**-patrone te stuur (nie net coverage nie).<sup>[[1]](#references)</sup>

## Slaggate met Corpus-diversiteit

Coverage-guided-mutasie is **gulsig**: ’n monster met nuwe coverage word onmiddellik gestoor en behou dikwels groot onveranderde dele. Met verloop van tyd word corpora **byna duplikate** met min strukturele diversiteit. Aggressiewe minimalisering kan nuttige konteks verwyder, dus is ’n praktiese kompromie **grammatikabewuste minimalisering** wat **ná ’n minimum token-drempel stop** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutasievriendelik te wees).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutasionele fuzzing is: **verkies ’n klein stel struktureel verskillende seeds wat coverage maksimeer** bo ’n groot hoop byna duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **werklike monsters** (openbare corpora, crawling, vasgelegde verkeer, lêerstelle uit die teikene-omgewing).
- Distilleer hulle met **coverage-gebaseerde corpus-minimalisering** eerder as om elke geldige monster te behou.
- Hou seeds **klein genoeg** sodat mutasies op betekenisvolle velde val, eerder as om die meeste siklusse aan irrelevante grepe te bestee.
- Voer corpus-minimalisering weer uit ná groot veranderinge aan die harness of instrumentering, want die “beste” corpus verander wanneer bereikbaarheid verander.

## Comparison-Aware Mutation vir Magic Values

’n Algemene rede waarom fuzzers plato bereik, is nie sintaksis nie, maar **harde vergelykings**: magiese grepe, lengte-kontroles, enum-stringe, kontrolesomme of parser-dispatch-waardes wat deur `memcmp`, switch-tabelle of opeenvolgende vergelykings beskerm word. Suiwer lukrake mutasie mors siklusse deur hierdie waardes greep vir greep te probeer raai.

Gebruik vir hierdie teikens **comparison tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-styl-werkvloeie), sodat die fuzzer operande van mislukte vergelykings kan waarneem en mutasies kan stuur na waardes wat daaraan voldoen.<sup>[[3]](#references)</sup>

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

- Dit is veral nuttig wanneer die teiken diep logika agter **lêerhandtekeninge**, **protokolwerkwoorde**, **tipeetikette** of **weergawe-afhanklike kenmerkbisse** versteek.
- Kombineer dit met **woordeboeke** wat uit werklike voorbeelde, protokolspesifikasies of ontfoutingslogboeke onttrek is. ’n Klein woordeboek met grammatika-tokens, stukname, werkwoorde en skeidingstekens is dikwels waardevoller as ’n massiewe generiese woordelys.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en minimaliseer dan die resulterende corpus weer sodat latere fases met reeds geldige voorvoegsels begin.

## Fuzzing van lêer-API’s wat ’n lêernaamtaal versteek

’n Parameter met die naam `filename`, `path` of `URL` kan ’n tolk se toegangspunt wees eerder as ’n letterlike lêeropsoek. CFITSIO Extended Filename Syntax (EFS) evalueer byvoorbeeld selektors tussen hakies, ry-/piekseluitdrukkings, berekende kolomme, histogramme en transformasies voordat dit die oopgemaakte objek teruggee; sommige vorme skep ook tydelike kopieë. Klassifiseer elke open-/invoer-API tydens die kartering van die aanvaloppervlak as **letterlike pad** of **geïnterpreteerde pad**, en fuzz die produksie-toegangspunt wat toepassings werklik aanroep.<sup>[[20]](#references)[[22]](#references)</sup>

Vir die gevolglike SSRF-, lêerkopieer- en protokolhanteerder-primitiewe — en veiliger API’s vir letterlike paaie — sien [Lêernaam-minitale as SSRF-/lêerprimitiewe](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Hou die ondersteunende objek apart van die program wat gefuzz word

Wanneer die grammatika in ’n lêernaamsuffiks voorkom, mis jy die parser as jy slegs die grepe van die lêer waarna verwys word, muteer. ’n Klein harnas kan eerder een toetsgeval as ’n string lees en dit aan die geïnterpreteerde open-API deurgee; die CFITSIO-veldtog het die meeste EFS-parsers en -evalueerders bereik deur `fits_open_file()` in leesalleenmodus aan te roep. Hou geldige ondersteunende lêers afsonderlik beskikbaar sodat mutasies op die selektor-/uitdrukkings-taal kan fokus, eerder as om voortdurend die basispad te beskadig.<sup>[[22]](#references)</sup>

Gebruik seeds wat elk ’n ander grammatikafamilie bereik, en lei dan ’n kompakte woordeboek uit sowel die spesifikasie as die lexer-/parser-bronkode af. As dekking plato bereik terwyl invoere herhaaldelik in dieselfde sintaksfoutpad misluk, behou geldige voorvoegsels en voeg skeidingstekens, operatore, sleutelwoorde, funksiename en verteenwoordigende veldname by, eerder as om bloot die tyd vir ewekansige mutasie te verleng.<sup>[[22]](#references)</sup>

Voer die harnas met die grammatikawoordeboek uit, byvoorbeeld:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Beperk newe-effekte van "read-only"-harnasse

’n read-only-biblioteekvlag waarborg nie ’n toetssaak sonder newe-effekte nie: die lêernaamtaal kan die invoer herskryf, uitvoerlêers skep of tydelike objekte materialiseer. Die CFITSIO-veldtog het aanvanklik saadlêers vernietig en onverwagte lêers oral op die lêerstelsel agtergelaat, dus was skoonmaak en isolasie nodig.<sup>[[22]](#references)</sup>

- Gee elke worker ’n weggooibare werkgids en ’n private tydelike gids.
- Stel kopieë van kanonieke rugsteunlêers beskikbaar; moenie ooit toelaat dat die teiken die enigste korpuskopie wysig nie.
- Deaktiveer netwerktoegang, tensy afgeleë backends die beoogde teiken is, en beperk skryfbare paaie met ’n container, mount namespace of soortgelyke sandbox.
- Stel die gids ná elke uitvoering of worker-bondel terug en behandel onverwagte lêerstelselveranderinge as bykomende bevindings.

### Crash-na-patch-na-fuzz-siklus

Groepeer crashes voordat jy dit herstel, sodat duisende artefakte nie duisende patch-take word nie. In die CFITSIO-assessering het AFLTriage die aanvanklike stel crashes tot ’n paar hoofoorsake verminder; die gevolglike advies toon duidelike foute, waaronder verkeerde kontroles van bestemmingsgroottes, verouderde pointers ná `realloc()`, rekenkundige foute en onveilige opruimpaaie in die parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimaliseer ’n verteenwoordigende invoer vir elke groep en reproduseer dit met AddressSanitizer.
2. Teken die presiese mislukte toegang, bronligging, toewysings-/vrymaakgeskiedenis en parsertoestand aan wat die invariant ongeldig gemaak het.
3. Pas een noukeurig afgebakende kandidaatpatch toe en bou weer met dieselfde coverage- en sanitizer-instrumentasie.
4. Speel die oorspronklike reproduseerder **en elke invoer in sy groep** weer af; aktiveer ook leak-detection, want ’n memory-safety-regstelling kan eienaarskap op ’n foutpad breek.
5. Voer funksionele toetse met werklike lêers uit, en hervat dan vanaf die opgehoopte queue (of voer daardie queue weer in as die engine ’n nuwe uitvoergids vereis nadat die binary verander het).
6. Herhaal: die verwydering van die eerste oppervlakkige crash laat bestaande sade dikwels toe om ’n dieper parsertoestand te bereik.

’n LLM kan stap 2 bespoedig en ’n konsep vir stap 3 opstel wanneer dit die crashende invoer, sanitizer-verslag, harnas en relevante bronkode ontvang, maar sy patch bly onbetroubaar. Die sanitizer-herhaling en regressiehekke—nie die model se verduideliking nie—bepaal of die regstelling aanvaar word.<sup>[[22]](#references)</sup>

## Ryker Terugvoer Wanneer Edge Coverage Verskillende Paaie Saamvoeg

Normale edge coverage kan nie twee uitvoerings onderskei wat deur dieselfde helper beweeg, maar verskillende callers gebruik of verskillende kombinasies van vertakkings binne ’n funksie volg nie. Dit maak saak in gedeelde decoders, protokol-dispatchers en interpreter-helpers, waar die **roete** na ’n edge die aktiewe toestand bepaal. Om elke calling context eenvoudig na te spoor is ook gevaarlik: die coverage map en queue kan geweldig groei. Navorsing oor context-sensitive fuzzing beveel dus aan om net belowende contexts te verfyn, eerder as om die hele call graph as context-sensitive te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-weergawes bied **Ball-Larus per-function path coverage** bykomend tot normale edge coverage. Dit ken ’n feature toe aan elke siklusvrye pad deur ’n funksie; loop-terugkante word verwyder, dus onderskei hierdie terugvoer kombinasies van vertakkings, maar **nie die aantal loop-iterasies nie**. Begin met die ontspanne vlak `1`, en beperk daarna strenger modusse tot verdagte parser-/state-machine-kode, want die aantal paaie kan eksponensieel groei.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Vir ’n helper wat vanaf baie sekuriteitsrelevante plekke aangeroep word, kan LTO-modus elke funksiepad met sy onmiddellike aanroeppunt kombineer:<sup>[[13]](#references)</sup>

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

**Veldtogriglyne:** pas ryker feedback versigtig toe en monitor die koste daarvan vir die coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Laat ’n gewone edge-coverage-instansie parallel loop; ryker feedback is net nuttig as die ekstra queue/map-koste nie die aantal uitvoerings per sekonde kelder nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om path/caller-instrumentasie te beperk wanneer groot biblioteke vol templates of generiese nutsprogramkode die map oorheers.
- Funksies met buitensporig baie akikliese paths kan deur AFL++ oorgeslaan word; waarskuwings tydens kompilasie dui daarop dat die teiken ’n allowlist of ’n minder streng vlak nodig het.
- Caller + path coverage ondersteun net een caller-diepte. Moenie dit met dieper context-stacks kombineer nie.
- Path-ID’s kan oor LLVM-hoofweergawes heen verander. Hou die toolchain vas tydens ’n veldtog, en moenie PATH-gebaseerde corpora sinchroniseer asof hul feature-ID’s stabiel oor builds heen is nie.
- Hierdie feedback vul `CMPLOG` aan: comparison tracing bepaal **watter waarde ’n guard laat slaag**, terwyl path/caller-feedback behou **watter roete en takkombinasie dit bereik het**.

## Stateful Fuzzing: Sequences Is Seeds

Vir **protokolle**, **gewaarmerkte workflows** en **parsers met verskeie fases** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **boodskapsequence**. Om die hele transkripsie in een lêer aaneen te las en dit blindelings te muteer, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel muteer, selfs wanneer net die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Doeltreffender patroon is om die **sequence self as die seed** te behandel en **waarneembare toestand** (antwoordkodes, protokoltoestande, parserfases, teruggestuurde objekttipes) as bykomende feedback te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige voorvoegselboodskappe** stabiel en fokus mutasies op die boodskap wat die **oorgang aandryf**.
- Kas identifiseerders en bediener-gegenereerde waardes uit vorige antwoorde wanneer die volgende stap daarvan afhang.
- Verkies mutasie/splitsing per boodskap bo die mutasie van die hele geserialiseerde transkripsie as ’n ondeursigtige blob.
- As die protokol betekenisvolle antwoordkodes blootstel, gebruik dit as ’n **goedkoop toestandsorakel** om sequences wat dieper vorder, voorrang te gee.

Dit is dieselfde rede waarom geverifieerde foute, versteekte oorgange of parserfoute wat “eers ná die handdruk” voorkom, dikwels deur gewone lêerstyl-fuzzing gemis word: die fuzzer moet **volgorde, toestand en afhanklikhede** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing van ’n drywer met verskeie kliënte

Hoë edge coverage kan steeds IPC-drywerfoute mis, want coverage beskryf nie **objekeienaarskap, verwysingstellings, boodskappe in afwagting, opruimvolgorde of draad-interleavings** nie. Die [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md)-bladsy beskryf die drywer se objekmodel; hierdie voorbeeld fokus op die fuzzer-harnas. Android Binder is ’n nuttige model: dit is nie genoeg om beide die toewysings- en vrymaakpaaie te bereik as die fuzzer nie verskeie prosesse in die vereiste volgorde op dieselfde kernobjek kan laat werk nie.<sup>[[15]](#references)</sup>

#### Modelleer die protokol, nie geïsoleerde `ioctl`-buffers nie

Stel ’n toetsgeval voor as ’n geordende grammatika van **kliëntidentiteit + bewerking + gestruktureerde argumente**. Die Binder LKL-fuzzer gebruik protobuf en `libprotobuf-mutator`, met een aanhoudende konteksbestuurderkliënt en twee gewone kliënte. ’n Semantiese harnas behou dan die verwantskappe wat blinde byte-mutasie sou vernietig.<sup>[[15]](#references)</sup>

- Kas waardes wat deur vorige bewerkings teruggestuur is. `BC_FREE_BUFFER` moet byvoorbeeld ’n transaksiebufferwyser hergebruik wat deur ’n vorige `ioctl` teruggestuur is.
- Genereer geldige verstekantwoorde sodat sinchrone transaksies kan voltooi en latere bewerkings bereikbaar bly.
- Verwerp onmoontlike oorgange, soos selftransaksies of verskeie transaksies in afwagting na dieselfde teiken.
- Hou enkelinstansie-inisialiseringstoestand buite die terugstelling per invoer. Binder laat net een `BINDER_SET_CONTEXT_MGR`-registrasie per selflaai toe; as dié kliënt herhaaldelik vernietig en herskep word, sal latere invoere ongeldig wees.

’n Nuttige sjabloon vir ’n lewensduur-rastoestand is om een kliënt ’n objek te laat oordra, die opruiming van ’n draad of proses te begin, en terselfdertyd die ontvangende kliënt die transaksiebuffer te laat vrystel. In die CVE-2020-0423-voorbeeld kon ’n `BINDER_TYPE_WEAK_BINDER`-oordrag, gevolg deur `BINDER_THREAD_EXIT` wat met `BC_FREE_BUFFER` meeding, ’n ingebedde `binder_work` vrymaak terwyl die opruimingspad van die draad wat besig was om te eindig dit steeds gebruik het.<sup>[[15]](#references)</sup>

#### Herstel beheerde interleavings in ’n gebruikersruimte-kern

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) koppel die werklike kernkode aan ’n gebruikersruimte-harnas en stel sy syscall-koppelvlak via `lkl_syscall` beskikbaar. Dit maak dit maklik om protobuf-toestand, coverage en KASAN in een proses te koördineer. LKL laat normaalweg ’n syscall loop sonder dat ’n ander kerndraad dit onderbreek. Voeg vir rasveldtogte `schedule()`-punte rondom geselekteerde grendel-/ontgrendel- en lewensduurrandpunte in, en laat die harnas dan die volgende kliënt lukraak by elke opbrengspunt kies. Hou hierdie punte doelgerig, want elkeen vergroot die soekruimte vir skedulering. Die gerandomiseerde skeduleerder wat deur die navorsers beskryf word, is **nie** deel van die stroomop Binder-fuzzer nie.<sup>[[15]](#references)</sup>

#### Bou en speel geserialiseerde regressie-seeds af

Die stroomop-harnas pen ’n versoenbare `libprotobuf-mutator`-weergawe vas, aktiveer LKL-fuzzing-instrumentasie en KASAN met `LKL_FUZZING=1`, en aktiveer `CONFIG_MMU` vir Binder met `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nadat jy ’n doelbewus kwesbare weergawe uitgecheck het of die rollback patches wat upstream gedokumenteer is, toegepas het, kan ’n serialized seed die volledige multi-client state transition reproduseer sonder om dit in ’n ad hoc C proof of concept te herkonstrueer:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandel die gevolglike KASAN use-after-free as bevestiging dat die seed die kwesbare lewensikluspad bereik het. Dit demonstreer **nie** die latere primitiewe wat nodig is vir kode-uitvoering in die kernel of voorregte-eskalasie nie.<sup>[[16]](#references)</sup>

## Diversiteitstruuk op ’n enkele masjien (Jackalope-styl)

’n Praktiese manier om **generatiewe nuwigheid** met **hergebruik van dekking** te kombineer, is om **kortstondige workers** teen ’n aanhoudende bediener te herbegin. Elke worker begin met ’n leë corpus, sinkroniseer ná `T` sekondes, loop nog `T` sekondes met die gekombineerde corpus, sinkroniseer weer en sluit dan af. Dit lewer **vars strukture met elke generasie**, terwyl opgehoopte dekking steeds benut word.<sup>[[1]](#references)[[2]](#references)</sup>

**Bediener:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Opeenvolgende workers (voorbeeldlus):**

<details>
<summary>Jackalope worker-herbeginlus</summary>

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

- `-in empty` dwing ’n **vars corpus** af vir elke generasie.
- `-server_update_interval T` benader **vertraagde sinkronisering** (eers nuutheid, hergebruik later).
- In grammar fuzzing mode word **aanvanklike bedienersinkronisering by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Die optimale `T` is **teikenafhanklik**; dit werk gewoonlik die beste om oor te skakel nadat die worker die meeste “maklike” coverage gevind het.

## Snapshot Fuzzing Vir Teikens Wat Moeilik Is Om Te Harness

Wanneer die kode wat jy wil toets eers **ná ’n groot opstellingskoste** bereikbaar word (’n VM begin, ’n login voltooi, ’n packet ontvang, ’n container parse, ’n diens inisialiseer), is **snapshot fuzzing** ’n nuttige alternatief: neem ’n snapshot van die gereed proses- of VM-toestand, voer elke toetsgeval in via die teiken se invoerpad, voer uit totdat dit crash/timeout, en herstel die snapshot. Dit voorkom dat inisialisering of protokolvoorvoegsels herhaal moet word en is nuttig vir **network services**, **firmware**, **post-auth attack surfaces** en **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die teiken loop totdat die interessante toestand gereed is.
2. Neem op daardie punt ’n snapshot van **geheue + registers**.
3. Skryf vir elke toetsgeval die gemuteerde invoer direk na die relevante guest-/prosesbuffer.
4. Voer uit totdat dit crash/timeout/reset.
5. Herstel die snapshot; vir VM-teikens, herstel slegs die **dirty pages** wanneer dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as prakties moontlik aan die eerste duur parse-/dispatch-stap, soos ná ’n `recv`/`read` of ’n punt waar packets gedeserialiseer word, en teken die invoerbuffer aan wat die teiken gebruik. Dit volg die beginsel van aanpasbare plasing: skuif die snapshot dieper in die invoerverwerking in om herhaling van werk te vermy.<sup>[[11]](#references)</sup>

## Verkenning Van Linux Kernel Races Met MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) omskep tydsberekeningsensitiewe Linux-kernel-races in herhaalbare geheuetoegangskedules. Dit kan twee-konteks **A-B-A**-uitvoerings outomaties opsom, of ’n ontleder toelaat om volgordebeperkings in ’n terminal UI/GUI op te lê. Dit is eksperimentele navorsingsnutsmiddels eerder as ’n volledige concurrency fuzzer: dit benodig tans LLVM 23+ en die projek se patched kernel, die command-line tools ondersteun twee test threads, en die voorgestelde userspace fuzzing-laag is nie geïmplementeer nie.<sup>[[17]](#references)[[18]](#references)</sup>

### Versamel kommunikasiepunte oor kontekste heen

Bou die instrumented kernel met KASAN outline callbacks en die patched KCOV memory-record-ondersteuning. Die projek se README beveel ook aan dat sibling-call optimization afgeskakel word sodat call stacks bruikbaar bly.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) omskep geïnstrumenteerde toegange in helper-oproepe. Die MAccConc-kernellappies deaktiveer `asan-opt-same-temp` sodat opeenvolgende toegange nie saamgevoeg word nie; deaktiveer ook die `asan-opt-globals`-optimalisering wanneer wedrenne op globale veranderlikes sigbaar moet wees. KCOV dra die gevolglike rekords na userspace. Vergelyk toegange uit verskillende uitvoeringskontekste en behou pare waarvan die greepgebiede oorvleuel en waar minstens een kant skryf; modelleer `kfree()` as ’n skryfaksie sodat lewensduur-oorgange ook kandidate word.<sup>[[17]](#references)</sup>

Vir werk wat buite die taak wat dit begin het, voortgaan, soos pakkieverwerking of RCU-terugroepe, moet die substelsel ’n KCOV remote-coverage-hanteerder oordra. Upstream remote KCOV is opsioneel en nie outomaties vir arbitrêre agtergrondwerk beskikbaar nie, dus kan ontbrekende oordrag ’n werklike interaksie onsigbaar maak.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifiseer dieselfde dinamiese toegang tydens elke lopie

Moenie ’n konkrete heap-adres herhaal nie, aangesien dit ná elke toekenning kan verander, of slegs ’n instruksie-adres gebruik nie, aangesien dit dubbelsinnig is binne helpers soos `memcpy()` en `spin_lock()`. MAccConc gebruik ’n **count-augmented stack trace**: elke raamwerk identifiseer ’n callee plus die aanroepingtelling binne sy caller, en die laaste element identifiseer die geheuetoegangs-instruksie. SanitizerCoverage-funksie-invoer-/uitvoerrekords laat userspace toe om hierdie dinamiese identifiseerder te rekonstrueer, wat stabiel bly ondanks adresveranderinge en onverwante beheervloeigeraas.<sup>[[17]](#references)</sup>

### Skakel kandidaatpare om na afgedwonge skedules

Die gelapte `KCOV_SET_DI`-ioctl koppel ’n toegangsidentifiseerder met bygevoegde telling aan ’n gedeelde-vlag-aksie.<sup>[[17]](#references)</sup>

| Aksie | Semantiek |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Stel vlag *N* onmiddellik voor die geselekteerde toegang. |
| `DI_STACK_WAIT` | Spin voor die geselekteerde toegang totdat vlag *N* gestel is of die opgestelde limiet verstryk. |
| `DI_STACK_WAKE_POST` | Stel vlag *N* onmiddellik ná die geselekteerde toegang. |

Vir ’n gedeeltelike **A-happens-before-B**-beperking, heg `DI_STACK_WAKE_POST` aan A en `DI_STACK_WAIT` aan B met dieselfde vlag. Vir ’n volledig gespesifiseerde tweekonteksskedule, begin B geblokkeer; laat A dan B wakker maak en wag by die eerste oordragpunt. B voer die omgekeerde bewerking by die volgende oordrag uit. Laasgenoemde werk soos deterministiese konteksskakeling en word deur die outomatiese A-B-A-verkenner gebruik.<sup>[[17]](#references)</sup>

’n Minimale veldtog behels dat die vier-haak-toetsgeval (`test_setup`, twee thread-funksies en `test_end`) as ’n gedeelde biblioteek saamgestel word, ’n onbeperkte spoor ingesamel word, en dan A-B-A-kandidate opgesom word of handmatige beperkings by verdagte toegange gevoeg word.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreteer time-outs apart van suksesvolle herrangskikkings: ’n versoekte volgorde kan onmoontlik wees omdat ’n lock of ’n initialiserings-/publikasie-afhanklikheid verhoed dat die tweede konteks sy injection point bereik. Hou ook KASAN se blinde kolle in gedagte: direkte stack-toegange word gewoonlik nie gehook nie, tensy dit buite perke kan wees; globals word met die verstekoptimalisering weggelaat; en huidige compilers kan nie ASAN- en TSAN-hooks gelyktydig genereer nie. Laastens verloor die prototipe sy KCOV-buffer wanneer ’n gasheer paniekerig raak, so behou ’n onafhanklike crash-konsole/orakel.<sup>[[17]](#references)</sup>

Vir toekomstige concurrency-guided fuzzing, teken geheuetoegangopsommings per invoer of syscall aan, koppel bewerkings wat cross-context-kommunikasiepunte sou vorm, en verken dan slegs daardie kombinasies. VM-snapshots stabiliseer globale toestand en adresse; sonder snapshots kan metadata oor allokasiewerwe objekte oor lopies heen abstraheer. Dit is ’n voorgestelde uitbreiding, nie ’n kenmerk van die huidige MAccConc-userspace-tools nie.<sup>[[17]](#references)</sup>

## Harness-introspeksie: Vind oppervlakkige fuzzers vroeg

Wanneer ’n veldtog stilstaan, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **bereikbaarheids-/coverage-introspeksie** om funksies te vind wat staties vanaf jou fuzz-teiken bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die teiken te laat of te vroeg.
- Die seed-corpus mis ’n hele kenmerkfamilie.
- Die teiken benodig eintlik ’n **tweede harness** in plaas van een oorgrootte “doen-alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-styl werkvloeie gebruik, kan Fuzz Introspector statiese bereikbaarheid met runtime-coverage vergelyk en verslae uit ’n tydgebonde lopie of openbare corpus genereer.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Gebruik die verslag om te besluit of jy ’n nuwe harness vir ’n ongetoetste parser-pad moet byvoeg, die corpus vir ’n spesifieke kenmerk moet uitbrei, of ’n monolitiese harness in kleiner entry points moet verdeel.

## Fuzz-teikenseleksie en mutasietriage met die grafiek eerste

As jy reeds bevindings van **statiese analise**, **oorlewendes van mutasietoetsing** en **dekkingsverslae** het, moenie hulle as afsonderlike lyste triageer nie. Bou eers ’n **oproepgrafiek**, annoteer nodusse met **siklomatiese kompleksiteit**, **bereikbaarheid vanaf entry points/onvertroude invoer** en enige eksterne bevindings, en stel dan vrae oor die grafiek.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is vanaf onbetroubare invoer bereikbaar?
- Watter mutasie-oorlewendes lê op paaie van parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met ’n buitengewoon groot **ontploffingsradius**?

Dit lewer gewoonlik beter fuzz-teikens op as om net die "laagste dekking" te kies. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker kandidaat vir ’n harness as ’n geïsoleerde interne helper met swak dekking, maar geen aanvallerbeheerde pad nie.

### Praktiese triage-werkvloei

1. Bou ’n **kodegrafiek** uit die kodebasis en haal kompleksiteits-/vertakkingsmetrieke per funksie uit.
2. Lys **entry points** wat aanvallerbeheerde invoer aanvaar: versoekhandlers, decoders, importers, protokolparsers, CLI-/lêerlesers.
3. Voer **padnavrae** vanaf daardie entry points na kandidaatfunksies uit om bereikbare aanvaloppervlak van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodusse wat die volgende kombineer:
   - hoë **siklomatiese kompleksiteit**
   - bevestigde **bereikbaarheid vanaf onbetroubare invoer**
   - groot **ontploffingsradius** of baie afhanklike stroomaf-funksies
   - stawende bewyse soos **SARIF**-bevindings, ouditnotas of mutasie-oorlewendes
5. Skryf eers gefokusde harnasse vir die nodusse met die hoogste telling, veral vir **parsers/codecs** soos hex/Base64/IP-/boodskapdecoders.

### Mutasie-oorlewendes: ekwivalent teenoor aksiebaar

Mutasietoetsing lewer dikwels ’n raserige lys oorlewendes op. Voordat jy elke oorlewende as ’n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie vanaf ’n aanvallerbeheerde entry point bereikbaar?
- Word alle oproeppaaie deur sterker invariants as die gemuteerde kontrole beperk?
- Lê die nodus in dooie kode, formatteringslogika alleen, of ’n hoë-impak-rekenkundige/parser-pad?

Oorlewendes wat onbereikbaar bly of struktureel beperk word, is dikwels **ekwivalente mutante**. Oorlewendes wat **bereikbaar** bly en **grensgevalle**, **oorloop-/oordragpaaie** of **sekuriteitskritieke rekenkundige/parserverwerking** raak, moet bevorder word tot:

- nuwe fuzz-harnasse
- direkte eienskap-/invarianttoetse
- geteikende randgevalvektore

### Korreleer eksterne bevindings met die grafiek

As jou SAST-pyplyn **SARIF** uitvoer, projekteer bevindings op grafieknodusse volgens **lêer + lynreeks** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **ontploffingsradius** van die gemerkte funksie
- kyk of die bevinding op enige pad vanaf ’n entry point lê
- groepeer nabygeleë bevindings wat by dieselfde knelpunt uitkom

Dit is nuttig wanneer jy besluit of jy fuzz-tyd aan ’n spesifieke funksie moet bestee: ’n nodus wat **bereikbaar** en **kompleks** is, en reeds **SAST-bevindings** het, is dikwels ’n beter teiken as ’n bloot komplekse nodus sonder ’n aanvallerpad.

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

Die belangrike metodologie is die snypunt: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutasie-oorlewendes om te bepaal watter grense en invariantes jou harness moet toets.<sup>[[5]](#references)</sup>

## Go-fuzzing met gosentry: Sterker enjin, getipeerde insette en differensiële kontroles

As ’n Go-teiken reeds ’n native `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) uit te voer, ’n gevurkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** omskakel.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Dit is nuttig wanneer die native Go-fuzzer vashaak op **moeilike vergelykings**, **getipeerde invoer** of **formaatte met baie parserwerk**. Die metodologie bly dieselfde:

- Gebruik steeds `f.Add(...)` vir sade en `f.Fuzz(...)` vir die callback.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binary in plaas van die standaardtoolchain uit.
- Behandel die resulterende veldtog as ’n normale coverage-guided run, maar met LibAFL-skedulering/mutasie en beter omliggende detectors.

### Verander stille foute in fuzz-bevindings

’n Herhalende probleem in Go-assesserings is dat gevaarlike gedrag dikwels **nie** by verstek ’n crash veroorsaak nie. Met gosentry kan jy verskeie klasse “slegte maar stille” toestande in bevindings omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging-/foutroetes soos crashes te laat optree (nuttig vir `log.Fatal`-agtige kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte touinskrywings met die Go race detector weer uit te voer.
- `--catch-leaks=true` om nuwe touinskrywings met `goleak` weer uit te voer en by goroutine-lekkasies te stop.
- LibAFL-hanghantering om **oneindige lusse / baie stadige invoer** as fuzz-bevindings te behou, eerder as om dit as time-outs te laat verdwyn.
- Ingeboude aritmetiese oorloopkontroles by verstek, plus opsionele afkappingskontroles deur instrumentasie in die styl van go-panikint.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **parserfout sonder ’n panic**, ’n **gelyktydigheidsfout** of ’n **hang wat slegs ’n DoS veroorsaak** is, eerder as geheuekorrupsie.

### Struct-bewuste fuzzing vir getipeerde Go-API’s

Native Go-fuzzing verwag hoofsaaklik skalare soos `[]byte`, `string` en getalle. As die kode wat getoets word getipeerde objekte verbruik, kan gosentry **saamgestelde waardes** (structs, slices, arrays, pointers) direk fuzz, terwyl dit steeds die onderliggende grepe muteer.<sup>[[7]](#references)[[8]](#references)</sup>

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

Gebruik dit wanneer die bou van ’n vals wire format net vir fuzzing logikafoute agter harness-only parsing code sou verberg. Vir differential- of grammar-based campaigns, hou die harness-invoer as ’n enkele `[]byte` of `string` en parseer dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokol-insette

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammatika is ’n JSON-skikking van produksiereëls, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te neem.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodologienotas:

- Gebruik grammar mode wanneer bytevlakmutasies meestal tydens vroeë sintakskontroles misluk.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om integer-, lengte- en toestandmasjiengrense te toets.
- Grammar mode hou insette grammar-geldig, maar die teiken ontvang steeds **bytes/strings**, dus bly ontleding en semantiese kontroles binne die geharnaste kode.

### Differential fuzzing: vergelyk implementerings, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde insette en voer dit aan twee parsers, clients of toestandsoorgang-enjins.<sup>[[7]](#references)[[8]](#references)</sup>

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

- een implementering veroorsaak ’n panic terwyl die ander die invoer netjies verwerp
- verskille in aanvaarde/verwerpte invoer
- verskillende ontleedbome of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, saldo’s of toestandswortels

Dit is ’n praktiese manier om **konsensusverskille**, **ontleder-ambiguïteit** en **spesifikasie-teenoor-implementering-afwykings** te vind wat suiwer crash fuzzing dikwels mis.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Hergebruik die veldtogkorpus vir dekkingverslagdoening

Speel ná ’n veldtog die gestoorde toukorpus weer af om ’n Go-dekkingsverslag te genereer sonder om ’n aparte korpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Voer die opdrag vanaf **dieselfde pakket** en met **dieselfde `-fuzz`-teiken** uit sodat gosentry die korrekte kasveldtogtoestand oplos.



## References

- [1] [Mutasionele grammar-fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet vyf jaar later: Oor dekkingsgeleide protokolfuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel gemis. Ons het die toolchain gevurk om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox-fuzzer vir stateful netwerkprotokolle met behulp van snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Op pad na fuzzing van die Linux-kern sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentasie: pad- en oproeperdekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende konteksensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder-fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder-fuzzer - dokumentasie vir bou en regressiesade](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Verkenning van wedrentoestande in die Linux-kern met beheerde geheuetoegang-vervlegtings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: kodebedekking vir fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Uitgebreide lêernaam-sintaksis](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-advies: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing van CFITSIO se uitgebreide lêernaam-sintaksis: 16 geheueveiligheidskwesbaarhede en Codex-ondersteunde triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
