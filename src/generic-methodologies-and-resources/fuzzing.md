# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl hulle **grammatikaal geldig** bly. In coverage-guided-modus word slegs samples wat **nuwe coverage** aktiveer as corpus-seeds gestoor. Vir **taikteikens** (parsers, interpreters, engines) kan dit foute miskyk wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruk die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Faalmodus:** die fuzzer vind seeds wat elk afsonderlik `document()` en `generate-id()` (of soortgelyke primitiewe) aktiveer, maar **nie die gekoppelde dataflow behou nie**. Gevolglik word die sample wat “nader aan die fout” is, weggegooi omdat dit nie coverage byvoeg nie. Met **3+ afhanklike stappe** word ewekansige herkombinering duur, en coverage-terugvoer lei nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** oorweeg vir grammatikas met baie afhanklikhede om **mutational- en generative-fases te kombineer**, of om generering te laat voorkeur gee aan patrone met **funksieketting** (nie net coverage nie).<sup>[[1]](#references)</sup>

## Slaggate met Corpus-diversiteit

Coverage-guided-mutasie is **gierig**: ’n sample wat nuwe coverage oplewer, word onmiddellik gestoor en behou dikwels groot, onveranderde dele. Met verloop van tyd word corpora **byna-duplikate** met min strukturele diversiteit. Aggressiewe minimalisering kan nuttige konteks verwyder. ’n Praktiese kompromie is dus **grammatika-bewuste minimalisering** wat **ná ’n minimum token-drempel stop** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutasievriendelik te wees).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel struktureel verskillende seeds wat coverage maksimeer** bo ’n groot hoop byna-duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **werklike samples** (openbare corpora, crawling, vasgelegde verkeer, lêerstelle uit die teiken-ekosisteem).
- Distilleer hulle met **coverage-gebaseerde corpus-minimalisering** eerder as om elke geldige sample te behou.
- Hou seeds **klein genoeg** sodat mutasies op betekenisvolle velde beland, eerder as om die meeste siklusse op irrelevante grepe te mors.
- Voer corpus-minimalisering weer uit ná groot veranderinge aan die harness of instrumentation, omdat die “beste” corpus verander wanneer reachability verander.

## Comparison-Aware Mutation vir Magic Values

’n Algemene rede waarom fuzzers ’n plato bereik, is nie sintaksis nie, maar **harde vergelykings**: magic bytes, lengte-kontroles, enum-stringe, checksums of parser-dispatch-waardes wat deur `memcmp`, switch-tabelle of opeenvolgende vergelykings beskerm word. Suiwer ewekansige mutasie mors siklusse deur hierdie waardes byte vir byte te probeer raai.

Gebruik vir hierdie teikens **comparison tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-styl-werkvloeie) sodat die fuzzer operande van mislukte vergelykings kan waarneem en mutasies kan stuur na waardes wat daaraan voldoen.<sup>[[3]](#references)</sup>

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

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags** of **version-dependent feature bits** verberg.
- Gebruik dit saam met **dictionaries** wat uit werklike voorbeelde, protocol-spesifikasies of debug logs onttrek is. ’n Klein dictionary met grammatika-tokens, chunk-name, verbs en skeidingstekens is dikwels nuttiger as ’n massiewe generiese woordelys.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en verklein dan die resulterende corpus weer, sodat latere stadiums met reeds geldige voorvoegsels begin.

## Ryker terugvoer wanneer Edge Coverage verskillende paaie laat saamval

Normale edge coverage kan nie twee uitvoerings onderskei wat deur dieselfde helper via verskillende callers gaan, of verskillende kombinasies van vertakkings binne ’n funksie volg nie. Dit is belangrik in gedeelde decoders, protocol dispatchers en interpreter-helpers waar die **roete** na ’n edge die aktiewe toestand bepaal. Om elke calling context op ’n naïewe manier na te spoor, is ook gevaarlik: die coverage map en queue kan geweldig groei. Navorsing oor context-sensitive fuzzing beveel dus aan dat slegs belowende contexts verfyn word, eerder as om die hele call graph as context-sensitive te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-weergawes bied **Ball-Larus per-function path coverage** bykomend tot normale edge coverage. Dit ken ’n kenmerk toe aan elke siklusvrye pad deur ’n funksie; loop back-edges word verwyder, dus onderskei hierdie terugvoer kombinasies van vertakkings, maar **nie die aantal loop-iterasies nie**. Begin met die toegeeflike vlak `1`, en beperk dan strenger modusse tot verdagte parser-/state-machine-kode, omdat die aantal paaie eksponensieel kan groei.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Vir ’n helper wat vanaf baie sekuriteitsrelevante plekke aangeroep word, kan LTO-modus elke funksiepad met sy onmiddellike aanroepplek kombineer:<sup>[[13]](#references)</sup>

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

**Veldtogriglyne:** pas ryker terugvoer konserwatief toe en hou die dekkingkaart-/queue-koste dop.<sup>[[13]](#references)[[14]](#references)</sup>

- Laat ’n gewone edge-dekking-instansie parallel loop; ryker terugvoer is net nuttig as die ekstra queue-/map-koste nie die aantal uitvoerings per sekonde drasties verlaag nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om pad-/caller-instrumentasie te beperk wanneer groot biblioteke vol templates of generiese nutsprogramkode die map oorheers.
- Funksies met buitensporig baie asikliese paaie kan deur AFL++ oorgeslaan word; waarskuwings tydens samestelling dui daarop dat die teiken allowlisting of ’n minder streng vlak nodig het.
- Caller- plus paddekking ondersteun net een caller-diepte. Moenie dit met dieper konteksstapels kombineer nie.
- Pad-ID’s kan tussen LLVM-hoofweergawes verander. Hou die toolchain vas vir ’n veldtog en sinkroniseer nie PATH-gebaseerde korpora asof hul kenmerk-ID’s stabiel oor builds heen is nie.
- Hierdie terugvoer komplementeer `CMPLOG`: vergelykingnasporing bepaal **watter waarde ’n guard slaag**, terwyl pad-/caller-terugvoer behou **watter roete- en takkombinasie dit bereik het**.

## Toestandbehoudende Fuzzing: Opeenvolgings is sade

Vir **protokolle**, **geïdentifiseerde werkvloeie** en **meerfaseparsers** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **boodskapopeenvolging**. Om die hele transkripsie in een lêer saam te voeg en dit blindelings te muteer, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel muteer, selfs wanneer net die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Doeltreffender patroon is om die **opeenvolging self as die saad** te behandel en **waarneembare toestand** (reaksiekodes, protokoltoestande, parserfases, teruggestuurde objekttipes) as bykomende terugvoer te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige voorvoegselboodskappe** stabiel en fokus mutasies op die boodskap wat die **oorgang dryf**.
- Kas identifiseerders en bedienergegenereerde waardes uit vorige reaksies wanneer die volgende stap daarvan afhang.
- Verkies mutasie/splitsing per boodskap bo die mutering van die hele geserialiseerde transkripsie as ’n ondeursigtige blob.
- As die protokol betekenisvolle reaksiekodes blootstel, gebruik dit as ’n **goedkoop toestandsorakel** om voorkeur te gee aan opeenvolgings wat dieper vorder.

Dit is dieselfde rede waarom geverifieerde foute, versteekte oorgange of parserfoute wat “slegs ná die handdruk” voorkom, dikwels deur gewone lêerstyl-fuzzing gemis word: die fuzzer moet **volgorde, toestand en afhanklikhede** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

### Android Binder: multi-kliëntbestuurder-fuzzing

Hoë edge-dekking kan steeds IPC-bestuurderfoute mis omdat dekking nie **objekeienaarskap, verwysingtellings, hangende boodskappe, opruimvolgorde of draadvervlegtings** beskryf nie. Die bladsy oor [Android Binder IPC-internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) bespreek die bestuurder se objekmodel; hierdie voorbeeld fokus op die fuzzer-harnas. Android Binder is ’n nuttige model: dit is nie genoeg om beide die toekennings- en vrymaakpaaie te bereik as die fuzzer nie verskeie prosesse in die vereiste volgorde op dieselfde kernobjek kan laat werk nie.<sup>[[15]](#references)</sup>

#### Modelleer die protokol, nie afsonderlike `ioctl`-buffers nie

Stel ’n toetsgeval voor as ’n geordende grammatika van **kliëntidentiteit + bewerking + gestruktureerde argumente**. Die Binder LKL-fuzzer gebruik protobuf en `libprotobuf-mutator`, met een permanente konteksbestuurderkliënt en twee gewone kliënte. ’n Semantiese harnas behou dan die verwantskappe wat blinde byte-mutasie sou vernietig.<sup>[[15]](#references)</sup>

- Kas waardes wat deur vroeëre bewerkings teruggestuur word. Byvoorbeeld, `BC_FREE_BUFFER` moet ’n transaksiebufferwyser hergebruik wat deur ’n vorige `ioctl` teruggestuur is.
- Genereer geldige verstekantwoorde sodat sinchrone transaksies kan voltooi en latere bewerkings bereikbaar bly.
- Verwerp onmoontlike oorgange soos selftransaksies of verskeie hangende transaksies na dieselfde teiken.
- Hou singleton-oplaaistatus buite die terugstelling per invoer. Binder laat slegs een `BINDER_SET_CONTEXT_MGR`-registrasie per selflaai toe, dus sou dit latere invoere ongeldig maak om daardie kliënt herhaaldelik te vernietig en te herskep.

’n Nuttige sjabloon vir ’n lewensduurwedloop is om een kliënt ’n objek te laat oordra, draad- of prosesopruiming te begin en terselfdertyd die ontvangende kliënt die transaksiebuffer te laat vrystel. In die CVE-2020-0423-voorbeeld kon ’n `BINDER_TYPE_WEAK_BINDER`-oordrag gevolg deur `BINDER_THREAD_EXIT`, wat met `BC_FREE_BUFFER` gewedywer het, ’n ingebedde `binder_work` vrymaak terwyl die uitgaande draad se opruimpad dit steeds gebruik het.<sup>[[15]](#references)</sup>

#### Herstel beheerde vervlegtings in ’n userspace-kern

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) koppel die werklike kernkode in ’n userspace-harnas en stel sy syscall-koppelvlak deur `lkl_syscall` beskikbaar. Dit maak dit maklik om protobuf-toestand, dekking en KASAN in een proses te koördineer. LKL voer normaalweg ’n syscall uit sonder dat ’n ander kerndraad dit onderbreek. Voeg vir wedloopveldtogte `schedule()`-punte rondom geselekteerde sluit-/ontsluit- en lewensduurgrense in, en laat die harnas by elke toegewing willekeurig die volgende kliënt kies. Hou hierdie punte geteiken, want elkeen vergroot die skeduleringssoekruimte. Die ewekansige skeduleerder wat deur die navorsers beskryf word, is **nie** deel van die stroomop Binder-fuzzer nie.<sup>[[15]](#references)</sup>

#### Bou en speel geserialiseerde regressiesade weer af

Die stroomop-harnas pen ’n versoenbare `libprotobuf-mutator`-weergawe vas, aktiveer LKL-fuzzing-instrumentasie en KASAN met `LKL_FUZZING=1`, en aktiveer `CONFIG_MMU` vir Binder met `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nadat ’n doelbewus kwesbare weergawe uitgecheck is of die rollback patches wat stroomop gedokumenteer is, toegepas is, kan ’n geserialiseerde saad die volledige toestandoorgang met veelvuldige kliënte reproduseer sonder dat dit in ’n ad hoc C-bewys van konsep gerekonstrueer hoef te word:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandel die resulterende KASAN use-after-free as bevestiging dat die seed die kwesbare leeftydpad bereik het. Dit demonstreer **nie** die latere primitives wat nodig is vir kernel code execution of privilege escalation nie.<sup>[[16]](#references)</sup>

## Enkelmasjien-diversiteitstruuk (Jackalope-styl)

’n Praktiese manier om **generative novelty** met **coverage reuse** te kombineer, is om **kortlewende workers** teen ’n persistente server te herbegin. Elke worker begin met ’n leë corpus, sinkroniseer ná `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sinkroniseer weer en sluit dan af. Dit lewer **vars strukture met elke generasie**, terwyl dit steeds opgehoopte coverage benut.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

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

- `-in empty` dwing ’n **nuwe corpus** vir elke generasie af.
- `-server_update_interval T` benader **vertraagde sync** (eers nuutheid, hergebruik later).
- In grammar fuzzing mode word **aanvanklike server sync by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Die optimale `T` is **teikenafhanklik**; dit werk gewoonlik die beste om oor te skakel nadat die worker die meeste “maklike” coverage gevind het.

## Snapshot Fuzzing Vir Teikens Wat Moeilik Is Om Te Harness

Wanneer die kode wat jy wil toets eers **ná ’n groot opstellingskoste** bereikbaar word (’n VM selflaai, ’n aanmelding voltooi, ’n packet ontvang, ’n container ontleed, ’n diens inisialiseer), is **snapshot fuzzing** ’n nuttige alternatief: neem ’n momentopname van die gereedstaande proses- of VM-toestand, voer elke toetsgeval in die teiken se invoerpad in, voer uit totdat ’n crash/timeout plaasvind, en herstel die momentopname. Dit vermy die herhaling van inisialisering of protokolvoorvoegsels en is nuttig vir **network services**, **firmware**, **post-auth attack surfaces** en **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die teiken loop totdat die interessante toestand gereed is.
2. Neem op daardie punt ’n momentopname van **memory + registers**.
3. Skryf vir elke toetsgeval die gemuteerde invoer direk na die relevante guest/process-buffer.
4. Voer uit totdat ’n crash/timeout/reset plaasvind.
5. Herstel die momentopname; vir VM-teikens, herstel slegs die **dirty pages** wanneer dit ondersteun word, en herhaal dan.

Plaas die momentopname so na as prakties moontlik aan die eerste duur parse/dispatch-stap, byvoorbeeld ná ’n `recv`/`read` of packet-deserialiseringspunt, en teken die invoerbuffer aan wat die teiken gebruik. Dit volg die beginsel van aanpasbare plasing: skuif die momentopname dieper in invoerverwerking om herhaalde werk te vermy.<sup>[[11]](#references)</sup>

## Harness Introspection: Vind Vlak Fuzzers Vroeg

Wanneer ’n veldtog vasval, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **reachability/coverage-introspeksie** om funksies te vind wat staties bereikbaar is vanaf jou fuzz-teiken, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die teiken te laat of te vroeg.
- Die seed corpus bevat nie ’n hele kenmerkgroep nie.
- Die teiken het werklik ’n **tweede harness** nodig in plaas van een oorgrootte “doen alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-styl werkvloeie gebruik, kan Fuzz Introspector statiese bereikbaarheid met runtime coverage vergelyk en verslae genereer vanaf ’n tydgebonde lopie of openbare corpus.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Gebruik die verslag om te besluit of ’n nuwe harness vir ’n ongetoetste parser-pad bygevoeg moet word, die corpus vir ’n spesifieke kenmerk uitgebrei moet word, of ’n monolitiese harness in kleiner toegangspunte verdeel moet word.

## Grafiek-Eerste Keuse Van Fuzz-Teikens En Mutasie-Triage

As jy reeds **statiese-analise-bevindings**, **mutasietoetsing-oorlewendes** en **dekkingverslae** het, moenie hulle as onafhanklike lyste triage nie. Bou eers ’n **oproepgrafiek**, annoteer nodusse met **siklomatiese kompleksiteit**, **bereikbaarheid vanaf toegangspunte/ongeloofwaardige invoer** en enige eksterne bevindings, en stel dan grafiekvrae.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is bereikbaar vanaf ongeloofwaardige invoer?
- Watter mutasie-oorlewendes lê op paaie van parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met ’n buitengewoon groot **blast radius**?

Dit bring gewoonlik beter fuzz-teikens na vore as om bloot die "laagste dekking" te kies. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker kandidaat vir ’n harness as ’n geïsoleerde interne helper met swak dekking maar geen aanvallerbeheerde pad nie.

### Praktiese triage-werkvloei

1. Bou ’n **kodegrafiek** uit die kodebasis en onttrek kompleksiteit-/vertakkingsmaatstawwe per funksie.
2. Lys **toegangspunte** wat aanvallerbeheerde invoer aanvaar: request handlers, decoders, importers, protokol-parsers, CLI-/lêerlesers.
3. Voer **padnavrae** vanaf daardie toegangspunte na kandidaatfunksies uit om bereikbaar aanvalsoppervlak van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodusse wat die volgende kombineer:
   - hoë **siklomatiese kompleksiteit**
   - bevestigde **bereikbaarheid vanaf ongeloofwaardige invoer**
   - groot **blast radius** of baie afhanklike nodusse stroomaf
   - stawende bewyse soos **SARIF**-bevindings, ouditnotas of mutasie-oorlewendes
5. Skryf eerste gefokusde harnesses vir die nodusse met die hoogste telling, veral vir **parsers/codecs** soos hex-/Base64-/IP-/boodskapdecoders.

### Mutasie-oorlewendes: ekwivalent teenoor uitvoerbaar

Mutasietoetsing lewer dikwels ’n raserige lys oorlewendes op. Voordat jy elke oorlewende as ’n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n aanvallerbeheerde toegangspunt?
- Word alle oproeppaaie deur sterker invariansies as die gemuteerde kontrole beperk?
- Lê die nodus in dooie kode, slegs-formateringslogika of ’n hoë-impak rekenkundige/parser-pad?

Oorlewendes wat onbereikbaar bly of struktureel beperk word, is dikwels **ekwivalente mutante**. Oorlewendes wat **bereikbaar** bly en **grensgevalle**, **oorloop-/oordragpaaie** of **sekuriteitskritieke rekenkunde/parsingslogika** raak, moet bevorder word tot:

- nuwe fuzz-harnesses
- direkte eienskap-/invariansietoetse
- geteikende randgeval-vektore

### Korreleer eksterne bevindings met die grafiek

As jou SAST-pyplyn **SARIF** uitvoer, karteer bevindings op grafieknodusse volgens **lêer + reëlreeks** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kyk of die bevinding op enige pad vanaf ’n toegangspunt lê
- groepeer nabygeleë bevindings wat by dieselfde knelpunt uitkom

Dit is nuttig wanneer jy besluit of jy fuzz-tyd aan ’n spesifieke funksie moet bestee: ’n nodus wat **bereikbaar** en **kompleks** is, en reeds **SAST-treffers** het, is dikwels ’n beter teiken as ’n bloot komplekse nodus sonder ’n aanvallerpad.

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

Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz targets met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutation survivors om te bepaal watter grense en invariants jou harness moet stres.<sup>[[5]](#references)</sup>

## Go Fuzzing met gosentry: Sterker Enjin, Getipeerde Insette, En Differensiële Kontroles

As ’n Go-teiken reeds ’n inheemse `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop, ’n geforkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** omskakel.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Dit is nuttig wanneer die inheemse Go-fuzzer vashaak by **harde vergelykings**, **getipeerde invoere** of **parser-swaar formate**. Die metodologie bly dieselfde:

- Gebruik steeds `f.Add(...)` vir sade en `f.Fuzz(...)` vir die terugroepfunksie.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binêre uit in plaas van die standaard-toolchain.
- Behandel die veldtog wat hieruit voortkom as ’n normale dekkinggestuurde lopie, maar met LibAFL-skedulering/-mutasie en beter omliggende detectors.

### Verander stil mislukkings in fuzz-bevindinge

’n Herhalende probleem in Go-sekuriteitsevaluerings is dat gevaarlike gedrag dikwels **nie** by verstek ineenstortings veroorsaak nie. Met gosentry kan jy verskeie klasse van “sleg maar stil” toestande in bevindinge omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om te verseker dat geselekteerde log-/foutpaaie soos ineenstortings optree (nuttig vir `log.Fatal`-styl kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte tou-inskrywings met die Go-rassedetector te herspeel.
- `--catch-leaks=true` om nuwe tou-inskrywings met `goleak` te herspeel en te stop wanneer daar goroutine-leaks voorkom.
- LibAFL-hanghantering om **oneindige lusse / baie stadige invoere** as fuzz-bevindinge te behou, eerder as om hulle as time-outs te laat verdwyn.
- Ingeboude rekenkundige oorloopkontroles is by verstek geaktiveer, plus opsionele afkappingkontroles deur instrumentasie in go-panikint-styl.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **parserfout sonder ’n panic**, ’n **gelyktydigheidsfout** of ’n **hang wat slegs ’n DoS veroorsaak** is, eerder as geheuekorrupsie.

### Struktuurbewuste fuzzing vir getipeerde Go-API’s

Inheemse Go-fuzzing verwag hoofsaaklik skalare soos `[]byte`, `string` en getalle. As die kode wat getoets word getipeerde objekte verbruik, kan gosentry **saamgestelde waardes** direk fuzz (strukture, snye, skikkings, wysers) terwyl dit steeds die onderliggende bytes muteer.<sup>[[7]](#references)[[8]](#references)</sup>

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

Gebruik dit wanneer die bou van ’n vals wire-formaat net vir fuzzing logikafoute agter parsing-kode wat net in die harness voorkom, sou versteek. Hou vir differential- of grammar-based-veldtogte die harness-invoer as ’n enkele `[]byte` of `string` en parseer dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokol-invoer

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammar is ’n JSON-skikking van production rules, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te neem.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodologienotas:

- Gebruik grammar mode wanneer bytevlakmutasies meestal tydens vroeë syntaxkontroles strand.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminale/nonterminale om integer-, lengte- en state-masjiengrense te stres.
- Grammar mode hou insette grammar-valid, maar die teiken ontvang steeds **bytes/strings**, dus bly parsing en semantiese kontroles binne die harnessed code.

### Differential fuzzing: vergelyk implementerings, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde insette en voer dit aan twee parsers, kliënte of state-transition-enjins.<sup>[[7]](#references)[[8]](#references)</sup>

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

- een implementering panics terwyl die ander die invoer netjies verwerp
- teenstrydighede oor watter invoer aanvaar of verwerp word
- verskillende parse-bome of gedekodeerde voorwerpe
- uiteenlopende toestandsoorgange, nonces, saldo’s of toestandswortels

Dit is ’n praktiese manier om **konsensusteenstrydighede**, **parser-ambiguïteit** en **afwykings tussen die spesifikasie en implementering** te vind, wat suiwer crash-fuzzing dikwels miskyk.

### Hergebruik die veldtogkorpus vir dekkingverslagdoening

Speel ná ’n veldtog die gestoorde toukorpus weer af om ’n Go-dekkingsverslag te genereer, sonder om ’n afsonderlike korpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Voer die opdrag uit vanaf dieselfde pakket en met dieselfde `-fuzz`-teiken sodat gosentry die korrekte kasveldtogtoestand kan vind.



## References

- [1] [Mutasionele grammatika-fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Vyf jaar later: Oor dekkinggeleide protokol-fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark omskep kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel gemis. Ons het die toolchain gevurk om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox-fuzzer vir toestandsvolle netwerkprotokolle met behulp van snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Op pad na fuzzing van die Linux-kern sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentering: pad- en caller-dekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende kontekssensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder-fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - bou- en regressie-seed-dokumentasie](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
