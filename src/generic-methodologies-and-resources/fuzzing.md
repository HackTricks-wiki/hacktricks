# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Dekking teenoor semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl hulle **grammatika-geldig** bly. In coverage-guided modus word slegs voorbeelde wat **nuwe dekking** oplewer, as corpus seeds gestoor. Vir **taalteikens** (parsers, interpreters, engines) kan dit foute miskyk wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruksie die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Mislukkingsmodus:** die fuzzer vind seeds wat afsonderlik `document()` en `generate-id()` (of soortgelyke primitiewe) uitvoer, maar **behou nie die gekoppelde dataflow nie**. Gevolglik word die voorbeeld wat “nader aan die fout” is, weggegooi omdat dit nie dekking byvoeg nie. Met **3+ afhanklike stappe** word ewekansige herkombinasie duur, en coverage-feedback stuur nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** oorweeg vir grammatika’s met baie afhanklikhede om **mutational- en generative fases te kombineer** of generering te laat voorkeur gee aan **function chaining**-patrone (nie net dekking nie).<sup>[[1]](#references)</sup>

## Slaggate van corpus-diversiteit

Coverage-guided mutasie is **gulsig**: ’n voorbeeld met nuwe dekking word onmiddellik gestoor, en groot onveranderde streke bly dikwels behoue. Met verloop van tyd word corpora **byna-duplikate** met min strukturele diversiteit. Aggressiewe minimisering kan nuttige konteks verwyder, dus is **grammatika-bewuste minimisering** ’n praktiese kompromie: **hou op ná ’n minimum token-drempel** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutasievriendelik te wees).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel struktureel verskillende seeds wat dekking maksimeer** bo ’n groot hoop byna-duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **werklike voorbeelde** (openbare corpora, crawling, vasgelegde verkeer, lêerstelle uit die teikensisteem).
- Distilleer hulle met **coverage-gebaseerde corpus-minimisering** eerder as om elke geldige voorbeeld te behou.
- Hou seeds **klein genoeg** sodat mutasies op betekenisvolle velde val, eerder as om die meeste siklusse aan irrelevante grepe te bestee.
- Voer corpus-minimisering weer uit ná groot veranderinge aan die harness/instrumentasie, want die “beste” corpus verander wanneer bereikbaarheid verander.

## Vergelykingsbewuste mutasie vir Magic Values

’n Algemene rede waarom fuzzers vasval, is nie sintaksis nie, maar **harde vergelykings**: magic bytes, lengte-kontroles, enum-stringe, checksums of parser-dispatch-waardes wat deur `memcmp`, switch-tabelle of opeenvolgende vergelykings beskerm word. Suiwer ewekansige mutasie mors siklusse deur hierdie waardes greep vir greep te probeer raai.

Gebruik vir hierdie teikens **comparison tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-styl werkvloeie), sodat die fuzzer operande van mislukte vergelykings kan waarneem en mutasies kan stuur na waardes wat daaraan voldoen.<sup>[[3]](#references)</sup>

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

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags** of **version-dependent feature bits** versteek.
- Kombineer dit met **dictionaries** wat uit werklike voorbeelde, protokolspesifikasies of debug logs onttrek is. ’n Klein dictionary met grammatikatokens, chunk names, verbs en skeidingstekens is dikwels nuttiger as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en verklein dan die resulterende corpus weer sodat latere fases met reeds geldige voorvoegsels begin.

## Fuzzing van lêer-API’s wat ’n lêernaamtaal versteek

’n Parameter met die naam `filename`, `path` of `URL` kan ’n interpreter-ingangspunt wees eerder as ’n letterlike lêeropsoek. CFITSIO Extended Filename Syntax (EFS) evalueer byvoorbeeld selectors tussen vierkantige hakies, ry-/pixel-uitdrukkings, berekende kolomme, histograms en transformasies voordat die oopgemaakte objek teruggestuur word; sommige vorme skep ook tydelike kopieë. Klassifiseer elke open/import-API tydens kartering van die aanvalsvlak as **literal-path** of **interpreted-path**, en fuzz dan die produksie-ingangspunt wat toepassings werklik gebruik.<sup>[[20]](#references)[[22]](#references)</sup>

Sien [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs) vir die gevolglike SSRF-, lêerkopieer- en protocol-handler-primitiewe—en veiliger literal-path-API’s.<sup>[[20]](#references)</sup>

### Hou die ondersteunende objek apart van die program wat gefuzz word

Wanneer die grammatika in ’n lêernaamsuffiks voorkom, sal die parser gemis word as slegs die grepe van die lêer waarna verwys word, gemuteer word. ’n Klein harness kan eerder een testcase as ’n string lees en dit aan die interpreted open-API deurgee; die CFITSIO-veldtog het die meeste EFS-parsers en -evaluators bereik deur `fits_open_file()` in read-only mode aan te roep. Hou geldige ondersteunende lêers apart beskikbaar sodat mutasies op die selector-/uitdrukkings-taal kan fokus, eerder as om die basispad voortdurend te breek.<sup>[[22]](#references)</sup>

Gebruik seeds wat elk ’n ander grammatikafamilie bereik, en lei dan ’n kompakte dictionary af van sowel die spesifikasie as die lexer-/parser-bronkode. As coverage afplat terwyl invoere herhaaldelik in dieselfde syntax-error-pad misluk, behou geldige voorvoegsels en voeg skeidingstekens, operators, sleutelwoorde, funksiename en verteenwoordigende veldname by, eerder as om bloot die tyd vir ewekansige mutasies te verleng.<sup>[[22]](#references)</sup>

Voer die harness met die grammatikadictionary uit, byvoorbeeld:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Beperk newe-effekte van die "read-only"-harness

'n read-only-biblioteekvlag waarborg nie 'n newe-effekvrye toetsgeval nie: die lêernaamtaal kan die invoer herskryf, uitvoerlêers skep of tydelike objekte materialiseer. Die CFITSIO-veldtog het aanvanklik saadlêers vernietig en onverwagte lêers oor die lêerstelsel agtergelaat, dus was opruiming en isolasie nodig.<sup>[[22]](#references)</sup>

- Gee elke worker 'n weggooibare werkgids en private tydelike gids.
- Stel kopieë van kanonieke rugsteunlêers beskikbaar; moenie die teiken ooit die enigste kopie in die corpus laat verander nie.
- Deaktiveer netwerktoegang tensy afgeleë backends die beoogde teiken is, en beperk skryfbare paaie met 'n container, mount namespace of gelykwaardige sandbox.
- Stel die gids ná elke uitvoering of worker-bondel terug en behandel onverwagte lêerstelselveranderinge as bykomende bevindings.

### Crash-to-patch-to-fuzz-lus

Groepeer crashes voordat jy dit herstel, sodat duisende artefakte nie duisende patch-take word nie. In die CFITSIO-assessering het AFLTriage die aanvanklike crash-stel tot 'n paar hoofoorsake verminder; die gevolglike advies toon afsonderlike foute, insluitend verkeerde kontroles van bestemminggroottes, verouderde pointers ná `realloc()`, rekenkundige foute en onveilige parser-opruimingspaaie.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimaliseer 'n verteenwoordigende invoer vir elke groep en reproduseer dit onder AddressSanitizer.
2. Teken die presiese mislukte toegang, bronligging, allokeer-/vrymaakgeskiedenis en parser-toestand aan wat die invariant ongeldig gemaak het.
3. Pas een noukeurig afgebakende kandidaatpatch toe en bou weer met dieselfde dekking- en sanitizer-instrumentasie.
4. Speel die oorspronklike reproduseerder **en elke invoer in sy groep** weer af; aktiveer ook lekbespeuring, want 'n geheueveiligheidsoplossing kan eienaarskap op 'n foutpad breek.
5. Voer funksionele toetse met werklike lêers uit, en hervat dan vanaf die opgehoopte queue (of voer daardie queue weer in as die engine ná die verandering aan die binary 'n vars uitvoergids vereis).
6. Herhaal: as jy die eerste oppervlakkige crash verwyder, kan bestaande sade dikwels na 'n dieper parser-toestand vorder.

'n LLM kan stap 2 versnel en 'n konsep vir stap 3 opstel wanneer dit die crashende invoer, sanitizer-verslag, harness en relevante bron ontvang, maar sy patch bly onbetroubaar. Die sanitizer-herspeeltoets en regressiehekke—nie die model se verduideliking nie—bepaal of die herstel aanvaar word.<sup>[[22]](#references)</sup>

## Ryker terugvoer wanneer Edge Coverage verskillende paaie laat saamval

Normale edge coverage kan nie twee uitvoerings onderskei wat dieselfde helper deur verskillende callers deurloop of verskillende takkombinasies binne 'n funksie volg nie. Dit is belangrik in gedeelde decoders, protokolversenders en interpreter-helpers waar die **roete** na 'n edge die lewendige toestand bepaal. Om elke calling context op 'n naïewe manier na te spoor, is ook gevaarlik: die coverage map en queue kan ontplof. Navorsing oor konteksensitiewe fuzzing beveel dus aan om net belowende kontekste te verfyn, eerder as om die hele call graph as konteksensitief te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-weergawes bied **Ball-Larus-paddekking per funksie** bykomend tot normale edge coverage. Dit ken 'n kenmerk toe aan elke asikliese pad deur 'n funksie; loop-terugkante word verwyder, dus onderskei hierdie terugvoer takkombinasies, maar **nie die aantal lusiterasies nie**. Begin met die ontspanne vlak `1`, en beperk dan strenger modusse tot verdagte parser-/toestandmasjienkode, want die aantal paaie kan eksponensieel groei.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Vir 'n helper wat vanaf baie sekuriteitsrelevante plekke aangeroep word, kan LTO-modus elke funksiepad met sy onmiddellike aanroepplek kombineer:<sup>[[13]](#references)</sup>

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

- Laat ’n gewone edge-coverage-instansie parallel loop; ryker terugvoer is slegs nuttig as die ekstra queue/map-koste nie die aantal uitvoerings per sekonde verlaag nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om path/caller-instrumentasie te beperk wanneer groot biblioteke vol templates of generiese nutskode die map oorheers.
- Funksies met buitensporig baie asikliese paaie kan deur AFL++ oorgeslaan word; waarskuwings tydens samestelling dui daarop dat die teiken ’n allowlist of ’n minder streng vlak nodig het.
- Caller + path coverage ondersteun slegs een caller-diepte. Moenie dit met dieper context-stacks kombineer nie.
- Path-ID’s kan tussen LLVM-hoofweergawes verander. Hou die toolchain vir ’n veldtog onveranderd en moenie PATH-gebaseerde corpora sinkroniseer asof hul feature-ID’s stabiel oor builds heen is nie.
- Hierdie terugvoer vul `CMPLOG` aan: vergelykingnasporing bepaal **watter waarde ’n guard slaag**, terwyl path/caller-terugvoer behou **watter roete en takkombinasie dit bereik het**.

## Stateful Fuzzing: Sequences Is Seeds

Vir **protokolle**, **gewaarmerkte werkvloeie** en **parsers met verskeie fases** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **boodskapvolgorde**. Om die hele transkripsie in een lêer saam te voeg en dit blindelings te muteer, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel muteer, selfs wanneer net die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Doeltreffender patroon is om die **volgorde self as die seed** te behandel en **waarneembare toestand** (responskodes, protokoltoestande, parserfases, teruggestuurde objekttipes) as bykomende terugvoer te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige voorvoegselboodskappe** stabiel en fokus mutasies op die boodskap wat die **toestandsoorgang aandryf**.
- Kas identifiseerders en bediener-gegenereerde waardes uit vorige response wanneer die volgende stap daarvan afhang.
- Verkies mutasie/splitsing per boodskap bo die mutering van die hele geserialiseerde transkripsie as ’n ondeursigtige blob.
- As die protokol betekenisvolle responsekodes blootstel, gebruik hulle as ’n **goedkoop toestands-orakel** om voorkeur te gee aan volgordes wat verder vorder.

Dit is dieselfde rede waarom geverifieerde foute, versteekte oorgange of parserfoute wat “eers ná die handshake” voorkom, dikwels deur vanilla lêerstyl-fuzzing gemis word: die fuzzer moet **volgorde, toestand en afhanklikhede** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing van ’n multi-kliëntbestuurder

Hoë edge coverage kan steeds IPC-bestuurderfoute miskyk omdat coverage nie **objekeienaarskap, verwysingtellings, hangende boodskappe, opruimingsvolgorde of draadvervlegtings** beskryf nie. Die [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md)-bladsy behandel die bestuurder se objekmodel; hierdie voorbeeld fokus op die fuzzer-harnas. Android Binder is ’n nuttige model: dit is nie genoeg om beide die allokeer- en vrymaakpaaie te bereik as die fuzzer nie verskeie prosesse dieselfde kernobjek in die vereiste volgorde kan laat gebruik nie.<sup>[[15]](#references)</sup>

#### Modelleer die protokol, nie afsonderlike `ioctl`-buffers nie

Stel ’n toetsgeval voor as ’n geordende grammatika van **kliëntidentiteit + bewerking + gestruktureerde argumente**. Die Binder LKL-fuzzer gebruik protobuf en `libprotobuf-mutator`, met een aanhoudende konteksbestuurder-kliënt en twee gewone kliënte. ’n Semantiese harnas behou dan die verwantskappe wat blinde grepmutasie sou vernietig.<sup>[[15]](#references)</sup>

- Kas waardes wat deur vroeëre bewerkings teruggestuur is. Byvoorbeeld, `BC_FREE_BUFFER` moet ’n transaksiebufferwyser hergebruik wat deur ’n vorige `ioctl` teruggestuur is.
- Genereer geldige verstekantwoorde sodat sinchrone transaksies kan voltooi en latere bewerkings bereikbaar bly.
- Verwerp onmoontlike oorgange, soos selftransaksies of verskeie hangende transaksies na dieselfde teiken.
- Hou singleton-opstarttoestand buite die terugstelling per invoer. Binder laat slegs een `BINDER_SET_CONTEXT_MGR`-registrasie per selflaai toe; as daardie kliënt herhaaldelik vernietig en herskep word, sal latere invoere dus ongeldig wees.

’n Nuttige sjabloon vir ’n lewensduurtoestandwedloop is om een kliënt ’n objek te laat oordra, draad- of prosesopruiming te begin en die ontvangende kliënt terselfdertyd die transaksiebuffer te laat vrystel. In die CVE-2020-0423-voorbeeld kon ’n `BINDER_TYPE_WEAK_BINDER`-oordrag, gevolg deur `BINDER_THREAD_EXIT` wat met `BC_FREE_BUFFER` toestandwedloop, ’n ingebedde `binder_work` vrystel terwyl die opruimingspad van die thread wat besig was om uit te tree dit steeds gebruik het.<sup>[[15]](#references)</sup>

#### Bring beheerde vervlegtings terug in ’n gebruikersruimte-kern

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) koppel die werklike kernkode in ’n gebruikersruimte-harnas en stel sy syscall-koppelvlak via `lkl_syscall` bloot. Dit maak dit maklik om protobuf-toestand, coverage en KASAN in een proses te koördineer. LKL laat egter normaalweg nie toe dat ’n ander kernthread ’n syscall onderbreek nie. Voeg vir toestandswedloopveldtogte `schedule()`-punte by rondom geselekteerde grendel-/ontgrendel- en lewensduurgrense, en laat die harnas by elke onderbreking lukraak die volgende kliënt kies. Hou hierdie punte doelgerig, want elkeen vergroot die skeduleringsoekruimte. Die ewekansige skeduleerder wat die navorsers beskryf, is **nie** deel van die stroomop Binder-fuzzer nie.<sup>[[15]](#references)</sup>

#### Bou en speel geserialiseerde regressie-seeds weer af

Die stroomop-harnas pen ’n versoenbare `libprotobuf-mutator` vas, aktiveer LKL-fuzzing-instrumentasie en KASAN met `LKL_FUZZING=1`, en aktiveer `CONFIG_MMU` vir Binder met `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nadat jy ’n doelbewus kwesbare weergawe uitgecheck het of die rollback-patches wat stroomop gedokumenteer is, toegepas het, kan ’n geserialiseerde seed die hele multi-kliënt-toestandsoorgang reproduseer sonder om dit in ’n ad hoc C-bewys van konsep te rekonstrueer:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandel die gevolglike KASAN use-after-free as bevestiging dat die seed die kwesbare lewensduurpad bereik het. Dit bewys **nie** dat die latere primitiewe bereik is wat nodig is vir kernel code execution of privilege escalation nie.<sup>[[16]](#references)</sup>

## Enkelmasjien-diversiteitstruuk (Jackalope-styl)

’n Praktiese manier om **generatiewe nuutheid** met **hergebruik van coverage** te kombineer, is om **kortlewende werkers te herbegin** teen ’n aanhoudende bediener. Elke werker begin met ’n leë corpus, sinkroniseer ná `T` sekondes, loop nog `T` sekondes met die gekombineerde corpus, sinkroniseer weer en sluit dan af. Dit lewer **vars strukture met elke generasie**, terwyl dit steeds opgehoopte coverage benut.<sup>[[1]](#references)[[2]](#references)</sup>

**Bediener:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Opeenvolgende werkers (voorbeeldlus):**

<details>
<summary>Jackalope-werker se herbeginlus</summary>

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

- `-in empty` dwing ’n **vars corpus** af by elke generasie.
- `-server_update_interval T` benader **vertraagde sync** (eers nuwigheid, later hergebruik).
- In grammar fuzzing-modus word **aanvanklike server-sync by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Die optimale `T` is **teikenafhanklik**; dit werk gewoonlik die beste om oor te skakel nadat die worker die meeste “maklike” coverage gevind het.

## Snapshot Fuzzing Vir Teikens Wat Moeilik Is Om Te Harness

Wanneer die kode wat jy wil toets eers **ná ’n groot opstellingskoste** bereikbaar word (’n VM selflaai, ’n aanmelding voltooi, ’n packet ontvang, ’n container ontleed, ’n diens inisialiseer), is **snapshot fuzzing** ’n nuttige alternatief: neem die gereed proses- of VM-toestand vas, voer elke toetsgeval in die teiken se invoerpad in, voer uit totdat dit crash/timeout, en herstel die snapshot. Dit vermy die herhaling van inisialisering of protokolvoorvoegsels en is nuttig vir **network services**, **firmware**, **post-auth-aanvalsoppervlakke** en **binary-only-teikens**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die teiken loop totdat die interessante toestand gereed is.
2. Neem op daardie punt ’n snapshot van **geheue + registers**.
3. Skryf vir elke toetsgeval die gemuteerde invoer direk na die relevante guest-/prosesbuffer.
4. Voer uit totdat daar ’n crash/timeout/reset is.
5. Herstel die snapshot; herstel vir VM-teikens slegs die **dirty pages** waar dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as prakties moontlik aan die eerste duur parse-/dispatch-stap, soos ná ’n `recv`/`read` of packet-deserialiseringspunt, en teken die invoerbuffer aan wat deur die teiken gebruik word. Dit volg die beginsel van aanpasbare plasing: skuif die snapshot dieper in die invoerverwerking om herhaalde werk te vermy.<sup>[[11]](#references)</sup>

## Linux Kernel Race-verkenning Met MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) omskep tydsberekeningsensitiewe Linux-kernel-races in herhaalbare geheuetoegangskedules. Dit kan twee-konteks- **A-B-A**-uitvoerings outomaties enumereer, of ’n ontleder toelaat om volgordebeperkings in ’n terminale UI/GUI op te lê. Dit is eksperimentele navorsingsgereedskap eerder as ’n volledige concurrency fuzzer: dit benodig tans LLVM 23+ en die projek se gepatchte kernel, die command-line-gereedskap ondersteun twee toetsdrade, en die voorgestelde userspace-fuzzinglaag is nie geïmplementeer nie.<sup>[[17]](#references)[[18]](#references)</sup>

### Versamel kommunikasiepunte tussen kontekste

Bou die geïnstrumenteerde kernel met KASAN-outline-callbacks en die gepatchte KCOV-geheue-opnamesteun. Die projek se README beveel ook aan om sibling-call-optimalisering te deaktiveer sodat call stacks bruikbaar bly.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) omskep geïnstrumenteerde toegangspunte in helper-oproepe. Die MAccConc-kernpleisters deaktiveer `asan-opt-same-temp` sodat opeenvolgende toegangspunte nie saamgevoeg word nie; deaktiveer ook die `asan-opt-globals`-optimering wanneer rasse op globale veranderlikes sigbaar moet wees. KCOV dra die gevolglike rekords na userspace oor. Vergelyk toegangspunte uit verskillende uitvoeringskontekste en behou pare waarvan die greep van grepe oorvleuel en waar minstens een kant skryf; modelleer `kfree()` as ’n skryfbewerking sodat lewensduuroorgange ook kandidate word.<sup>[[17]](#references)</sup>

Vir werk wat buite die aanvangstaak plaasvind, soos pakkieverwerking of RCU-terugroepe, moet die substelsel ’n KCOV remote-coverage-hanteerder oordra. Upstream remote KCOV is opsioneel en is nie outomaties vir arbitrêre agtergrondwerk beskikbaar nie; ontbrekende oordrag kan dus ’n werklike interaksie onsigbaar maak.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifiseer dieselfde dinamiese toegangspunt in elke lopie

Moenie ’n konkrete heap-adres, wat ná elke toekenning kan verander, as teiken vir herhaling gebruik nie, of net ’n instruksie-adres, wat dubbelsinnig is binne helpers soos `memcpy()` en `spin_lock()` nie. MAccConc gebruik ’n **telverrykte stapelspoor**: elke raamwerk identifiseer ’n callee plus die aanroepingtelling binne sy caller, en die laaste element identifiseer die geheuetoegangsinstruksie. SanitizerCoverage-funksie-invoer-/uitvoerrekords laat userspace toe om hierdie dinamiese identifiseerder te rekonstrueer, wat stabiel bly ondanks adresveranderings en onverwante beheer-vloeigeruis.<sup>[[17]](#references)</sup>

### Skakel kandidaatpare om na geforseerde skedules

Die gelapte `KCOV_SET_DI` ioctl koppel ’n telverrykte toegangspunt-identifiseerder aan ’n gedeelde-vlag-aksie.<sup>[[17]](#references)</sup>

| Aksie | Semantiek |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Stel vlag *N* onmiddellik voor die geselekteerde toegangspunt. |
| `DI_STACK_WAIT` | Spin voor die geselekteerde toegangspunt totdat vlag *N* gestel is of die gekonfigureerde limiet verstryk. |
| `DI_STACK_WAKE_POST` | Stel vlag *N* onmiddellik ná die geselekteerde toegangspunt. |

Vir ’n gedeeltelike **A-happens-before-B**-beperking, heg `DI_STACK_WAKE_POST` aan A en `DI_STACK_WAIT` aan B, met dieselfde vlag. Vir ’n volledig gespesifiseerde tweekonteksskedule, begin B geblokkeer; laat A dan B wakker maak en wag by die eerste oordragpunt; B voer die omgekeerde bewerking by die volgende oordragpunt uit. Laasgenoemde werk soos deterministiese konteksskakeling en is wat die outomatiese A-B-A-verkenner gebruik.<sup>[[17]](#references)</sup>

’n Minimale toetsveldtog is om die vier-haaktoetsgeval (`test_setup`, twee draadfunksies en `test_end`) as ’n gedeelde biblioteek te bou, ’n onbeperkte spoor in te samel en dan A-B-A-kandidate te enumereer of handmatige beperkings rondom verdagte toegangspunte by te voeg.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreteer time-outs apart van suksesvolle herordening: ’n aangevraagde volgorde kan onmoontlik wees omdat ’n slot- of initialiserings-/publikasie-afhanklikheid die tweede konteks verhoed om sy inspuitingspunt te bereik. Hou ook KASAN se blinde kolle in gedagte: direkte stapeltoegange word gewoonlik nie gemonitor nie, tensy hulle buite die grense kan wees; globale veranderlikes word met die verstekoptimering weggelaat; en huidige samestellers kan nie ASAN- en TSAN-hooks gelyktydig genereer nie. Laastens verloor die prototipe sy KCOV-buffer wanneer ’n gasmasjien paniekerig raak, dus moet jy ’n onafhanklike ongelukskonsole/orakel behou.<sup>[[17]](#references)</sup>

Vir toekomstige gelyktydigheidsgeleide fuzzing, teken geheuetoegangopsommings per invoer of per syscall aan, koppel bewerkings wat kruiskonteks-kommunikasiepunte sou vorm, en verken dan slegs daardie kombinasies. VM-kiekies stabiliseer globale toestand en adresse; sonder kiekies kan metadata van toewysingspunte voorwerpe oor uitvoerings heen abstrakteer. Dit is ’n voorgestelde uitbreiding, nie ’n kenmerk van die huidige MAccConc-gebruikersruimtenutsmiddels nie.<sup>[[17]](#references)</sup>

## Harness-introspeksie: Vind oppervlakkige fuzzers vroeg

Wanneer ’n veldtog stilstaan, lê die probleem dikwels nie by die mutator nie, maar by die **harness**. Gebruik **bereikbaarheids-/dekkingsintrospeksie** om funksies te vind wat staties vanaf jou fuzz-teiken bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die teiken te laat of te vroeg.
- Die saadkorpus ontbreek ’n hele kenmerkfamilie.
- Die teiken benodig eintlik ’n **tweede harness** in plaas van een oorgrootte “doen alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-agtige werkvloeie gebruik, kan Fuzz Introspector statiese bereikbaarheid met looptyddekking vergelyk en verslae uit ’n tydbeperkte lopie of openbare korpus genereer.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Gebruik die verslag om te besluit of jy ’n nuwe harness vir ’n ongetoetste parser-pad moet byvoeg, die corpus vir ’n spesifieke funksie moet uitbrei, of ’n monolitiese harness in kleiner entry points moet verdeel.

## Fuzz-teikenseleksie en mutasie-triage met die graaf eerste

As jy reeds **statiese-analise-bevindinge**, **mutasietoetsing-oorlewendes** en **dekkingsverslae** het, moenie hulle as onafhanklike lyste triageer nie. Stel eers ’n **call graph** op, annoteer nodusse met **siklomatiese kompleksiteit**, **entrypoint/bereikbaarheid vanaf onbetroubare invoer** en enige eksterne bevindinge, en stel dan vrae oor die graaf.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter hoë-kompleksiteitsfunksies is bereikbaar vanaf onbetroubare invoer?
- Watter mutasie-oorlewendes lê op paaie vanaf parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met ’n buitengewoon groot **blast radius**?

Dit bring gewoonlik beter fuzz-teikens na vore as om net die “laagste dekking” te kies. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker kandidaat vir ’n harness as ’n geïsoleerde interne helper met swak dekking, maar sonder ’n aanvallerbeheerbare pad.

### Praktiese triage-werkvloei

1. Stel ’n **kodegraaf** van die kodebasis op en haal kompleksiteits-/vertakkingsmaatstawwe per funksie uit.
2. Lys **entrypoints** wat aanvallerbeheerbare invoer aanvaar: request handlers, decoders, importers, protokolparsers, CLI-/lêerlesers.
3. Voer **padnavrae** vanaf daardie entrypoints na kandidaatfunksies uit om bereikbare aanvalsoppervlak van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodusse wat die volgende kombineer:
   - hoë **siklomatiese kompleksiteit**
   - bevestigde **bereikbaarheid vanaf onbetroubare invoer**
   - groot **blast radius** of baie afhanklike nodusse stroomaf
   - stawende bewyse soos **SARIF**-bevindinge, ouditnotas of mutasie-oorlewendes
5. Skryf eerste gefokusde harnesses vir die nodusse met die hoogste telling, veral vir **parsers/codecs** soos hex/Base64/IP/boodskap-decoders.

### Mutasie-oorlewendes: ekwivalent teenoor uitvoerbaar

Mutasietoetsing lewer dikwels ’n raserige lys oorlewendes op. Voordat jy elke oorlewende as ’n sekuriteitsgaping beskou, gebruik die graaf om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n aanvallerbeheerbare entrypoint?
- Word alle oproeppaaie deur sterker invariants as die gemuteerde kontrole beperk?
- Lê die nodus in dooie kode, formateringslogika alleen, of in ’n hoë-impak-rekenkundige/parser-pad?

Oorlewendes wat onbereikbaar bly of struktureel beperk word, is dikwels **ekwivalente mutante**. Oorlewendes wat **bereikbaar** bly en **grensgevalle**, **oorloop-/oordragpaaie** of **sekuriteitskritieke rekenkunde/parsing** raak, moet bevorder word tot:

- nuwe fuzz-harnesses
- direkte eienskap-/invarianttoetse
- geteikende randgeval-vektore

### Korreleer eksterne bevindinge met die graaf

As jou SAST-pyplyn **SARIF** uitvoer, karteer bevindinge na graafnodusse volgens **lêer + lynreeks** en gebruik die graaf om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kyk of die bevinding op enige pad vanaf ’n entrypoint lê
- groepeer nabygeleë bevindinge wat by dieselfde knelpunt uitkom

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd aan ’n spesifieke funksie moet bestee: ’n nodus wat **bereikbaar**, **kompleks** is en reeds **SAST-treffers** het, is dikwels ’n beter teiken as ’n bloot komplekse nodus sonder ’n aanvallerpad.

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

Die belangrike metodologie is die oorvleueling: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik mutasies wat oorleef om te bepaal watter grense en invariants jou harness moet beproef.<sup>[[5]](#references)</sup>

## Differensiële fuzzing van kriptografiese sleutelkoderings

Begin met geldige geserialiseerde sleutels of standaardtoetsvektore. Verander geënkodeerde velde sonder om die lengte en struktuur te breek wat nodig is om invoer- en bewerkingspaaie te bereik, en stuur dan dieselfde grepe na onafhanklike implementerings. Vergelyk die aanvaarding en foute. Gerandomiseerde handtekeninge en syferteks vereis korrektheidsorakels, nie ’n greep-vir-greep-vergelyking nie: verifieer handtekeninge of vergelyk die gedeelde geheime ná ’n inkapselings-/ontkapselingsrondte. Toetsvektore bevestig konformiteit vir bekende gevalle; differensiële mutasie toets misvormde koderings wat nie daardeur gedek word nie.<sup>[[23]](#references)[[26]](#references)</sup>

Gebruik formaatspesifieke orakels vir hierdie sleutelformate:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA-uitgebreide ondertekeningsleutels:** verander gepakte `s1`- of `s2`-koëffisiënte sodat hulle buite `[-η, η]` val, maar die sleutel steeds ontleedbaar bly. Kyk of invoer of ondertekening dit verwerp en of enige gevolglike handtekening geverifieer word. Verskille in aanvaarding alleen is nie standaardoortredings nie, omdat FIPS 204 nie bykomende kontroles op private sleutels vereis nie. Sien die [voorwaardelike leakage-meganisme](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM-sleutelpaar:** onderskei die vereiste kontroles vir inkapselingsleutels en ontkapselingsinvoer van die opsionele paargewyse-konsekwentheidstoets (PCT) op ’n ingevoerde paar. Inkapsuleer met die publieke sleutel, ontkapsuleer met die private sleutel en vergelyk die gedeelde geheime; ’n wanverhouding kan geënkripteerde kommunikasie breek, selfs wanneer individuele sleutels die invoerkontroles slaag. Kyk of die API invoer tydens die bewerking of deur ’n afsonderlike oproep valideer; libcrux stel `validate_public_key(pk)` en `validate_private_key(sk, ct)` bloot, maar dié vervang nie ’n PCT nie.
- **XMSS/XMSSMT-rou sleutels:** toets rondreise van geserialiseerde **ondertekenings- en verifikasiesleutels** oor parameterstelle, nie net bewerkings met sleutels in geheue nie. XMSS en XMSSMT het afsonderlike viergreep-OID-naamruimtes, dus kan ’n OID-ontleder wat eers XMSS probeer, ’n XMSSMT-sleutel met ’n botsende OID verkeerd klassifiseer en invoer verwerp. Die gerapporteerde RustCrypto-ontleder illustreer ’n interoperabiliteits-/beskikbaarheidsfout, nie ’n vervalsing van ’n handtekening nie.

## Go Fuzzing met gosentry: Kragtiger enjin, getipeerde invoer en differensiële kontroles

As ’n Go-teiken reeds ’n inheemse `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop, ’n gevurkte Go-toolchain wat `go test -fuzz` behou, maar die backend met **LibAFL** vervang.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Dit is nuttig wanneer die native Go-fuzzer vashaak by **harde vergelykings**, **getipeerde invoere** of **parser-swaar formate**. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir sade en `f.Fuzz(...)` vir die terugroepfunksie te gebruik.
- Hergebruik dieselfde harnas, maar voer dit met gosentry se `go`-binêre in plaas van die standaard toolchain uit.
- Behandel die resulterende veldtog as ’n normale coverage-guided run, maar met LibAFL-skedulering/mutasie en beter omringende detectors.

### Verander stil mislukkings in fuzz-bevindings

’n Herhalende probleem in Go-assesserings is dat gevaarlike gedrag dikwels by verstek **nie** ’n crash veroorsaak nie. Met gosentry kan jy verskeie klasse “sleg maar stil”-toestande in bevindings omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging-/foutpaaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte tou-inskrywings met die Go-race detector weer uit te voer.
- `--catch-leaks=true` om nuwe tou-inskrywings met `goleak` weer uit te voer en te stop wanneer daar goroutine-lekke is.
- LibAFL se hang-verwerking om **oneindige lusse / baie stadige invoere** as fuzz-bevindings te behou, eerder as om hulle as timeouts te laat verdwyn.
- Ingeboude rekenkundige oorloopkontroles by verstek, plus opsionele afkappingskontroles deur instrumentasie in die styl van go-panikint.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **parser-fout sonder ’n panic**, ’n **concurrency-fout** of ’n **hang wat slegs DoS veroorsaak** is, eerder as geheuekorrupsie.

### Struct-aware fuzzing vir getipeerde Go-API's

Native Go-fuzzing verwag hoofsaaklik skalare soos `[]byte`, `string` en getalle. As die kode wat getoets word getipeerde objekte verbruik, kan gosentry **saamgestelde waardes** direk fuzz (structs, slices, arrays, pointers), terwyl dit steeds die onderliggende grepe muteer.<sup>[[7]](#references)[[8]](#references)</sup>

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

Gebruik dit wanneer die bou van ’n vals wire format net vir fuzzing logikafoute agter parsingkode wat net in die harness voorkom, sou verberg. Hou vir differential- of grammar-based-veldtogte die harness-invoer as ’n enkele `[]byte` of `string` en parse dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokolinvoer

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammar is ’n JSON-skikking van produksiereëls, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te gebruik.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodologienotas:

- Gebruik grammar mode wanneer byte-level mutations meestal tydens vroeë sintakskontroles faal.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om integer-, lengte- en toestandsmasjiengrense te toets.
- Grammar mode verseker dat insette grammar-valid bly, maar die teiken ontvang steeds **bytes/strings**, dus vind parsing en semantiese kontroles steeds binne die kode onder toets plaas.

### Differential fuzzing: vergelyk implementasies, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde insette en voer dit aan twee parsers, clients of toestandoorgang-enjins.<sup>[[7]](#references)[[8]](#references)</sup>

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

Beskou die volgende as bevindings:

- een implementering panics terwyl die ander die invoer netjies verwerp
- teenstrydighede tussen aanvaarde en verwerpte invoer
- verskillende parse-bome of gedekodeerde objek­te
- uiteenlopende toestandsoorgange, nonces, saldo’s of toestandwortels

Dit is ’n praktiese manier om **konsensusteenstrydighede**, **parser-dubbelsinnigheid** en **spesifikasie-teenoor-implementering-afwykings** te vind wat suiwer crash-fuzzing dikwels mis.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Hergebruik die veldtogkorpus vir dekkingsverslagdoening

Speel ná ’n veldtog die gestoorde toukorpus weer af om ’n Go-dekkingsverslag te genereer sonder om ’n aparte korpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Voer die opdrag uit dieselfde pakket uit en met dieselfde `-fuzz`-teiken sodat gosentry die korrekte gekaste veldtogtoestand oplos.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Mutasionele grammatikafuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet vyf jaar later: Oor dekking-geleide protokolfuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel ontbreek. Ons het die toolchain gevurk om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox-fuzzer vir toestandvolle netwerkprotokolle met behulp van momentopnames](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Na fuzzing van die Linux-kern sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare momentopnames](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentasie: pad- en oproeperdekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende kontekssensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder-fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder-fuzzer - dokumentasie vir bou en regressiesade](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Verkenning van Linux-kern-rastoestande met beheerde geheuetoegangsvervlegtings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: kode-dekking vir fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO-uitgebreide lêernaamsintaksis](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-advies: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing van CFITSIO-uitgebreide lêernaamsintaksis: 16 geheueveiligheidskwesbaarhede en Codex-ondersteunde triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differensiële fuzzing vir kriptografie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standaard vir sleutelinkapsuleringsmeganismes gebaseer op modulêre roosters](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT-OID-ontledingsfout - RustCrypto-kwessie #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stand van post-kwantum-kriptografie-implementerings](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
