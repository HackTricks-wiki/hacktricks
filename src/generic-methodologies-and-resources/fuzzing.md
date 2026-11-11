# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutasionele grammar-fuzzing: dekking vs. semantiek

In **mutasionele grammar-fuzzing** word invoere gemuteer terwyl hulle **grammar-valid** bly. In coverage-guided-modus word slegs monsters wat **nuwe dekking** aktiveer as corpus-seeds gestoor. Vir **taikteikens** (parsers, interpreters, engines) kan dit foute mis wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruk die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Faalmodus:** die fuzzer vind seeds wat afsonderlik `document()` en `generate-id()` (of soortgelyke primitiewe) toets, maar **nie die gekoppelde dataflow behou nie**. Gevolglik word die monster wat “nader aan die fout” is, weggegooi omdat dit nie dekking byvoeg nie. Met **3+ afhanklike stappe** word ewekansige herkombinasie duur, en coverage-terugvoer stuur nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** oorweeg vir grammars met baie afhanklikhede om **mutasionele en generatiewe fases te kombineer**, of om generering te laat voorkeur gee aan **funksiekettingspatrone** (nie net dekking nie).<sup>[[1]](#references)</sup>

## Slaggate met corpus-diversiteit

Coverage-guided-mutasie is **gierig**: ’n monster met nuwe dekking word onmiddellik gestoor, en behou dikwels groot onveranderde dele. Met verloop van tyd word corpora **byna-duplikate** met min strukturele diversiteit. Aggressiewe minimalisering kan nuttige konteks verwyder, dus is **grammar-bewuste minimalisering** ’n praktiese kompromie: **stop sodra ’n minimum token-drempel bereik is** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutasies te ondersteun).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutasionele fuzzing is: **verkies ’n klein stel struktureel verskillende seeds wat dekking maksimeer** bo ’n groot hoop byna-duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **werklike monsters** (openbare corpora, crawling, vasgelegde verkeer, lêerstelle uit die teiken-ekosisteem).
- Distilleer hulle met **dekking-gebaseerde corpus-minimalisering** eerder as om elke geldige monster te behou.
- Hou seeds **klein genoeg** sodat mutasies betekenisvolle velde tref, eerder as om die meeste siklusse aan irrelevante grepe te bestee.
- Voer corpus-minimalisering weer uit ná groot veranderinge aan die harness of instrumentering, want die “beste” corpus verander wanneer bereikbaarheid verander.

## Groot gegenereerde programme en timeout-vooroordeel

Vir compiler- en interpreter-fuzzing moet ’n invoer moontlik ’n **drempel vir die grootte van gegenereerde kode** oorskry, eerder as ’n nuwe parser-vertakking te bereik. In die V8-[voorbeeld met exception-handler-offsets](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size) moes ’n geldige toetsgeval meer as 256 MiB bytecode bevat voordat die afgekapte handler-offset saak gemaak het. Herhaalde `yield*`-konstrukte kon daardie grens bereik, maar dit het sekondes geneem om die toetsgeval op ’n debug-build te compileer. Voorkeure vir klein invoere en kort execution-timeouts kan hierdie klas benadeel, selfs wanneer grammar-dekking hoog is. Oorweeg drempels vir grootte en timeout-beleid afsonderlik wanneer packed offsets of ander lengte-afhanklike metadata geoudit word; hierdie advies vir die veldtog is ’n afleiding uit die gerapporteerde faalmodus.<sup>[[29]](#references)</sup>

## Vergelykingsbewuste mutasie vir magic values

’n Algemene rede waarom fuzzers vashaak, is nie sintaksis nie, maar **harde vergelykings**: magic bytes, lengte-kontroles, enum-strings, checksums of parser-dispatch-waardes wat deur `memcmp`, switch-tabelle of opeenvolgende vergelykings beskerm word. Suiwer ewekansige mutasie mors siklusse deur hierdie waardes byte vir byte te probeer raai.

Gebruik vir hierdie teikens **vergelyking-tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-styl werkvloeie), sodat die fuzzer operande van mislukte vergelykings kan waarneem en mutasies kan stuur na waardes wat daaraan voldoen.<sup>[[3]](#references)</sup>

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
- Kombineer dit met **dictionaries** wat uit werklike voorbeelde, protocol-spesifikasies of debug logs onttrek is. ’n Klein dictionary met grammar-tokens, chunk-name, verbs en skeidingstekens is dikwels meer waardevol as ’n massiewe generiese woordelys.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en minimaliseer dan die resulterende corpus weer, sodat latere fases met reeds geldige voorvoegsels begin.

## Fuzzing van lêer-API’s wat ’n lêernaamtaal versteek

’n Parameter met die naam `filename`, `path` of `URL` kan ’n interpreter-ingangspunt wees eerder as ’n letterlike lêeropsoek. CFITSIO Extended Filename Syntax (EFS) evalueer byvoorbeeld selectors tussen hakies, ry-/pixel-uitdrukkings, berekende kolomme, histogramme en transformasies voordat die oopgemaakte objek teruggegee word; sommige vorme skep ook tydelike kopieë. Klassifiseer elke open-/import-API tydens aanvalsvlak-kartering as **literal-path** of **interpreted-path**, en fuzz die produksie-ingangspunt wat toepassings werklik aanroep.<sup>[[20]](#references)[[22]](#references)</sup>

Vir die gevolglike SSRF-, lêerkopie- en protocol-handler-primitives—en veiliger literal-path-API’s—sien [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Hou die onderliggende objek apart van die program wat gefuzz word

Wanneer die grammar in ’n lêernaamagtervoegsel voorkom, mis die parser as jy net die bytes van die verwysde lêer muteer. ’n Klein harness kan eerder een testcase as ’n string lees en dit aan die interpreted open-API deurgee; die CFITSIO-veldtog het die meeste EFS-parsers en -evaluators bereik deur `fits_open_file()` in leesalleenmodus aan te roep. Hou geldige onderliggende lêers apart beskikbaar, sodat mutasies op die selector-/expression-taal kan fokus eerder as om voortdurend die basispad te beskadig.<sup>[[22]](#references)</sup>

Gebruik seeds wat elk ’n ander grammar-familie bereik, en stel dan ’n kompakte dictionary saam uit sowel die spesifikasie as die lexer-/parser-bronkode. As coverage ’n plato bereik terwyl insette herhaaldelik in dieselfde syntax-error-pad misluk, behou geldige voorvoegsels en voeg skeidingstekens, operators, keywords, funksiename en verteenwoordigende veldname by, eerder as om net die tyd vir ewekansige mutasies te verleng.<sup>[[22]](#references)</sup>

Laat die harness met die grammar-dictionary loop, byvoorbeeld:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Beperk newe-effekte van die "read-only"-harnas

’n Read-only-biblioteekvlag waarborg nie ’n toetssaak sonder newe-effekte nie: die lêernaamtaal kan die invoer herskryf, uitvoerlêers skep of tydelike voorwerpe materialiseer. Die CFITSIO-veldtog het aanvanklik seed-lêers vernietig en onverwagte lêers deur die lêerstelsel agtergelaat, daarom was skoonmaak en isolasie nodig.<sup>[[22]](#references)</sup>

- Gee elke worker ’n weggooibare werkgids en ’n private tydelike gids.
- Stel kopieë van kanonieke rugsteunlêers beskikbaar; moet nooit toelaat dat die teiken die enigste kopie van die corpus verander nie.
- Deaktiveer netwerktoegang, tensy afgeleë backends die beoogde teiken is, en beperk skryfbare paaie met ’n container, mount namespace of ekwivalente sandbox.
- Stel die gids terug ná elke uitvoering of worker-bondel, en behandel onverwagte lêerstelselveranderinge as bykomende bevindings.

### Crash-na-patch-na-fuzz-lus

Groepeer crashes voordat jy herstelwerk doen, sodat duisende artefakte nie duisende patch-take word nie. In die CFITSIO-assessering het AFLTriage die aanvanklike crash-stel tot ’n paar hoofoorsake verminder; die daaropvolgende advies beskryf verskillende foute, insluitend verkeerde kontroles van bestemmingsgroottes, verouderde wysers ná `realloc()`, rekenkundige foute en onveilige parser-opruimingspaaie.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimaliseer ’n verteenwoordigende invoer vir elke groep en reproduseer dit met AddressSanitizer.
2. Teken die presiese foutiewe toegang, bronligging, geskiedenis van toekenning/vrystelling en parser-toestand aan wat die invariant ongeldig gemaak het.
3. Pas een noukeurig afgebakende kandidaat-patch toe en bou weer met dieselfde dekking- en sanitizer-instrumentasie.
4. Speel die oorspronklike reproduseerder **en elke invoer in sy groep** weer af; aktiveer ook lekopsporing, want ’n geheueveiligheidsherstel kan eienaarskap op ’n foutpad breek.
5. Voer funksionele toetse met werklike lêers uit, en hervat dan vanaf die opgehoopte tou (of voer daardie tou weer in as die engine ’n nuwe uitvoergids ná ’n verandering aan die binary vereis).
6. Herhaal: deur die eerste oppervlakkige crash te verwyder, kan bestaande seeds dikwels verder vorder tot ’n dieper parser-toestand.

’n LLM kan stap 2 bespoedig en ’n konsep vir stap 3 opstel wanneer dit die crashende invoer, sanitizer-verslag, harnas en relevante bronkode ontvang, maar sy patch bly onbetroubaar. Die sanitizer-herhaling en regressiehekke—nie die model se verduideliking nie—bepaal of die herstel aanvaar word.<sup>[[22]](#references)</sup>

## Ryker terugvoer wanneer edge coverage verskillende paaie saamvoeg

Gewone edge coverage kan nie twee uitvoerings onderskei wat dieselfde helper via verskillende oproepers deurloop, of verskillende kombinasies van vertakkings binne ’n funksie volg nie. Dit maak saak in gedeelde decoders, protokolverspreiders en interpreter-helpers waar die **roete** na ’n edge die aktiewe toestand bepaal. Om elke oproepkonteks naïef na te spoor is ook gevaarlik: die dekkingskaart en tou kan ontplof. Navorsing oor konteksensitiewe fuzzing beveel daarom aan dat slegs belowende kontekste verfyn word, eerder as om die hele oproepgrafiek as konteksensitief te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-weergawes bied **Ball-Larus-paddekking per funksie** bykomend tot gewone edge coverage. Dit ken ’n kenmerk toe aan elke asikliese pad deur ’n funksie; terugkante van lusse word verwyder, dus onderskei hierdie terugvoer kombinasies van vertakkings, maar **nie die aantal lusiterasies nie**. Begin met die ontspanne vlak `1`, en pas dan strenger modusse slegs toe op verdagte parser-/toestandsmasjienkode, want die aantal paaie kan eksponensieel groei.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Vir 'n hulpfunksie wat vanaf baie sekuriteitsrelevante plekke aangeroep word, kan LTO-modus elke funksiepad met sy onmiddellike aanroepingsplek kombineer:<sup>[[13]](#references)</sup>

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

**Veldtogleiding:** pas ryker terugvoer versigtig toe en monitor die koste daarvan vir die coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Laat ’n gewone edge-coverage-instansie parallel loop; ryker terugvoer is net nuttig as die ekstra queue/map-koste nie die aantal uitvoerings per sekonde verlaag nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om path/caller-instrumentasie te beperk wanneer groot biblioteke met baie templates of generiese nutskode die map oorheers.
- Funksies met buitensporig baie asikliese paaie kan deur AFL++ oorgeslaan word; waarskuwings tydens samestelling dui daarop dat die teiken allowlisting of ’n minder streng vlak nodig het.
- Caller + path coverage ondersteun net een caller-diepte. Moenie dit met dieper konteksstapels kombineer nie.
- Path-ID’s kan tussen groot LLVM-weergawes verander. Hou die toolchain vir ’n veldtog vas en sinkroniseer nie PATH-gebaseerde corpora asof hul feature-ID’s stabiel tussen builds is nie.
- Hierdie terugvoer vul `CMPLOG` aan: vergelykingnasporing bepaal **watter waarde ’n guard slaag**, terwyl path/caller-terugvoer bewaar **watter roete en vertakkingskombinasie dit bereik het**.

## Toestandafhanklike Fuzzing: Sequences Is Seeds

Vir **protokolle**, **gewaarmerkte werkvloeie** en **parsers met verskeie fases** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **boodskapsequence**. Om die hele transkripsie in een lêer saam te voeg en dit blindelings te muteer, is gewoonlik ondoeltreffend, want die fuzzer muteer elke stap ewe veel, selfs wanneer net die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Meer doeltreffende patroon is om die **sequence self as die seed** te behandel en **waarneembare toestand** (antwoordkodes, protokoltoestande, parserfases, teruggegewe objeksoorte) as bykomende terugvoer te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige voorvoegselboodskappe** stabiel en fokus mutasies op die boodskap wat die **toestandsoorgang dryf**.
- Kas identifiseerders en bedienergegenereerde waardes uit vorige antwoorde wanneer die volgende stap daarvan afhanklik is.
- Verkies mutasie/splitsing per boodskap bo die mutasie van die hele geserialiseerde transkripsie as ’n ondeursigtige blob.
- As die protokol betekenisvolle antwoordkodes blootstel, gebruik dit as ’n **goedkoop toestandsorakel** om voorkeur te gee aan sequences wat dieper vorder.

Dit is dieselfde rede waarom geverifieerde foute, versteekte oorgange of parserfoute wat “eers ná die handdruk” voorkom, dikwels deur gewone lêerstyl-fuzzing gemis word: die fuzzer moet **volgorde, toestand en afhanklikhede** bewaar, nie net struktuur nie.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing van ’n multi-client-bestuurder

Hoë edge coverage kan steeds IPC-bestuurderfoute mis, want coverage beskryf nie **objekeienaarskap, verwysingtellings, hangende boodskappe, opruimingsvolgorde of draadinterleavings** nie. Die bladsy oor [Android Binder IPC-internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) dek die bestuurder se objekmodel; hierdie voorbeeld fokus op die fuzzer-harnas. Android Binder is ’n nuttige model: om beide die toekennings- en vrymaakpaaie te bereik, is nie genoeg as die fuzzer nie verskeie prosesse in die vereiste volgorde op dieselfde kernel-objek kan laat werk nie.<sup>[[15]](#references)</sup>

#### Modelleer die protokol, nie afsonderlike `ioctl`-buffers nie

Stel ’n toetsgeval voor as ’n geordende grammatika van **kliëntidentiteit + bewerking + gestruktureerde argumente**. Die Binder LKL-fuzzer gebruik protobuf en `libprotobuf-mutator`, met een aanhoudende konteksbestuurder-kliënt en twee gewone kliënte. ’n Semantiese harnas behou dan die verwantskappe wat blinde bytemutasie sou vernietig.<sup>[[15]](#references)</sup>

- Kas waardes wat deur vroeëre bewerkings teruggegee word. `BC_FREE_BUFFER` moet byvoorbeeld ’n transaksiebufferwyser hergebruik wat deur ’n vorige `ioctl` teruggegee is.
- Genereer geldige verstekantwoorde sodat sinchrone transaksies kan voltooi en latere bewerkings bereikbaar bly.
- Verwerp onmoontlike oorgange, soos selftransaksies of verskeie hangende transaksies na dieselfde teiken.
- Hou enkelvoudige selflaaitoestand buite die terugstelling per invoer. Binder laat net een `BINDER_SET_CONTEXT_MGR`-registrasie per selflaai toe, dus sou dit latere invoere ongeldig maak om daardie kliënt herhaaldelik te vernietig en te herskep.

’n Nuttige sjabloon vir ’n leeftydrenloop is om een kliënt ’n objek te laat oordra, draad- of prosesopruiming te begin, en terselfdertyd die ontvangende kliënt die transaksiebuffer te laat vrystel. In die CVE-2020-0423-voorbeeld kon ’n `BINDER_TYPE_WEAK_BINDER`-oordrag, gevolg deur `BINDER_THREAD_EXIT` wat met `BC_FREE_BUFFER` meeding, ’n ingebedde `binder_work` vrymaak terwyl die opruimingspad van die uittredende draad dit nog gebruik het.<sup>[[15]](#references)</sup>

#### Herstel beheerde interleavings in ’n userspace-kernel

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) koppel die werklike kernelkode aan ’n userspace-harnas en stel sy syscall-koppelvlak via `lkl_syscall` beskikbaar. Dit maak protobuf-toestand, coverage en KASAN maklik om in een proses te koördineer. LKL voer normaalweg ’n syscall uit sonder dat ’n ander kerneldraad dit onderbreek. Voeg vir renloopveldtogte `schedule()`-punte rondom geselekteerde sluit-/ontsluit- en leeftydgrense in, en laat die harnas dan by elke oorhandiging lukraak die volgende kliënt kies. Hou hierdie punte doelgerig, want elkeen vergroot die skeduleringssoekruimte. Die ewekansige skeduleerder wat deur die navorsers beskryf word, is **nie** deel van die stroomop Binder-fuzzer nie.<sup>[[15]](#references)</sup>

#### Bou en herspeel geserialiseerde regressie-seeds

Die stroomop-harnas pen ’n versoenbare `libprotobuf-mutator`-weergawe vas, aktiveer LKL-fuzzing-instrumentasie en KASAN met `LKL_FUZZING=1`, en aktiveer `CONFIG_MMU` vir Binder met `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nadat jy ’n doelbewus kwesbare weergawe uitgecheck het of die rollback patches toegepas het wat stroomop gedokumenteer is, kan ’n geserialiseerde seed die volledige multi-client-toestandsoorgang reproduseer sonder om dit in ’n ad hoc C proof of concept te rekonstrueer:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandel die KASAN use-after-free wat hieruit voortkom as bevestiging dat die seed die kwesbare lewensduurpad bereik het. Dit demonstreer **nie** die latere primitives wat nodig is vir kode-uitvoering in die kernel of privilege escalation nie.<sup>[[16]](#references)</sup>

## Diversiteitstruuk op een masjien (Jackalope-styl)

’n Praktiese manier om **generatiewe nuwigheid** met **hergebruik van coverage** te kombineer, is om **kortstondige workers** teen ’n persistente bediener te herbegin. Elke worker begin met ’n leë corpus, sinkroniseer ná `T` sekondes, loop nog `T` sekondes met die gekombineerde corpus, sinkroniseer weer en sluit dan af. Dit lewer **vars strukture met elke generasie**, terwyl dit steeds opgehoopte coverage benut.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` dwing ’n **vars corpus** af met elke generering.
- `-server_update_interval T` benader **vertraagde sync** (eers nuutheid, later hergebruik).
- In grammar fuzzing-modus word **aanvanklike serversync by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Die optimale `T` is **teikenafhanklik**; dit werk gewoonlik die beste om oor te skakel nadat die worker die meeste “maklike” coverage gevind het.

## Snapshot Fuzzing vir teikens wat moeilik is om te harness

Wanneer die kode wat jy wil toets eers bereikbaar word **ná ’n groot opstelkoste** (’n VM selflaai, ’n aanmelding voltooi, ’n pakkie ontvang, ’n container ontleed of ’n diens inisialiseer), is **snapshot fuzzing** ’n nuttige alternatief: neem die gereed-proses- of VM-toestand vas, voer elke toetsgeval in die teiken se invoerpad in, voer uit totdat ’n crash/timeout plaasvind en herstel die snapshot. Dit voorkom dat inisialisering of protokolvoorvoegsels herhaal moet word, en is nuttig vir **netwerkdienste**, **firmware**, **aanvaloppervlakke ná verifikasie** en **slegs-binêre teikens**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die teiken loop totdat die interessante toestand gereed is.
2. Neem **geheue + registers** op daardie punt as ’n snapshot.
3. Skryf vir elke toetsgeval die gemuteerde invoer direk na die relevante gasheer-/prosesbuffer.
4. Voer uit totdat ’n crash/timeout/reset plaasvind.
5. Herstel die snapshot; vir VM-teikens, herstel slegs die **dirty pages** wanneer dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as wat prakties moontlik is aan die eerste duur ontleed-/versendingstap, soos ná ’n `recv`/`read` of ’n punt waar pakkies gedeserialiseer word, en teken die invoerbuffer aan wat die teiken gebruik. Dit volg die beginsel van aanpasbare plasing: skuif die snapshot dieper in die invoerverwerking in om herhaalde werk te vermy.<sup>[[11]](#references)</sup>

### Inkrementele snapshots vir protokoltoestande

’n Vaste snapshot vermy opstelkoste, maar verken nie vanself oorgange wat verskeie geldige boodskappe vereis nie. ’n LibAFL-Qemu-harness kan skrywes na ’n protokoltoestandveld dophou en ’n nuwe snapshot stoor wanneer die toestand verander. In die [libslirp TCP-harness](https://github.com/quarkslab/slirp_snapshots_stateful) hou dit `tcpcb.t_state` dop, hash dit die toestand en responsvlae om duplikaatsnapshots te voorkom, en stoor dirty pages relatief tot ’n ouersnapshot. Voordat die volgende gestruktureerde boodskap gemuteer word, herstel dit die geselekteerde snapshot via sy ouerketting. Die toetsgeval bevat ’n `SnapshotId` en gegenereerde invoergrepe (`gen_bytes`); die snapshotbestuurder hou die ouerverwantskap by wat vir terugspeel nodig is.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu se gebruikersmodus-`SnapshotModule` stoor mappings en teikengeheue, maar nie CPU-registers nie; bewaar dit afsonderlik wanneer nodig. Die beskryfde bestuurder ondersteun een wortelsnapshotboom en kan nie snapshot-ID’s tussen workers deel nie. Sy multi-snapshot-modus kan ook nie QASAN-shadow state direk hergebruik nie. Vir vanlyn triage, rekonstrueer die invoerketting in ’n afsonderlike geïnstrumenteerde proses. Wanneer `AsanHostModule` en `DrCovModule` gebruik word, voer `fuzzer.evaluate_input` die vereiste `pre_exec`/`post_exec`-callbacks uit; `qemu.run` alleen doen dit nie.<sup>[[27]](#references)[[28]](#references)</sup>

### Bespeur logiese oorlesings van ringbuffers

’n Lees buite ’n buffer se *geldige-datatelling* kan binne sy gasheertoekenning bly en gewone ASAN ontduik. Die [libslirp-voorbeeld met urgent data](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) laat ook ’n unsigned grepetelling onderloop. Wanneer bronkode beskikbaar is, kan instrumentasie vir signed/unsigned integer-oorloop daardie newe-effek bespeur; onderskei doelbewuste TCP-volgnommeromvou voordat verslae onderdruk word. ’n Sterker voorgestelde oracle is om die pasgemaakte ringtoekenning te poison, slegs geldige reekse te unpoison soos die interne allocator vorder, en vrygestelde reekse weer te poison. LibAFL-Qemu bied ’n ASAN-poisoning-API vir teikens waar broninstrumentasie onprakties is.<sup>[[27]](#references)</sup>

## Verkenning van Linux-kernelaanwedywings met MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) verander tydsensitiewe Linux-kernelaanwedywings in herhaalbare geheuetoegangskedules. Dit kan twee-konteks-**A-B-A**-uitvoerings outomaties opsom, of ’n ontleder toelaat om volgordebeperkings in ’n terminale UI/GUI af te dwing. Dit is eksperimentele navorsingsnutsmiddels, nie ’n volledige concurrency fuzzer nie: tans vereis dit LLVM 23+ en die projek se gepatchte kernel, die opdragreëlnutsmiddels ondersteun twee toetsdrade, en die voorgestelde fuzzing-laag vir gebruikersruimte is nie geïmplementeer nie.<sup>[[17]](#references)[[18]](#references)</sup>

### Versamel kommunikasiepunte tussen kontekste

Bou die geïnstrumenteerde kernel met KASAN outline-callbacks en die gepatchte KCOV-geheuerekordondersteuning. Die projek se README beveel ook aan om sibling-call-optimalisering te deaktiveer sodat oproepstapels bruikbaar bly.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) omskep geïstrumenteerde toegangspunte in helper calls. Die MAccConc-kernelpatches deaktiveer `asan-opt-same-temp` sodat opeenvolgende toegangspunte nie saamgevoeg word nie; deaktiveer ook die `asan-opt-globals`-optimering wanneer rasse op globale veranderlikes sigbaar moet wees. KCOV dra die resulterende rekords na userspace oor. Vergelyk toegangspunte uit verskillende uitvoeringskontekste en behou pare waarvan die grepe-omvang oorvleuel en waar minstens een kant skryf; modelleer `kfree()` as ’n skrywing sodat lewensduur-oorgange ook kandidate word.<sup>[[17]](#references)</sup>

Vir werk wat buite die inisierende taak voortgaan, soos pakkieverwerking of RCU-terugroepe, moet die substelsel ’n KCOV remote-coverage handle oordra. Upstream remote KCOV is opt-in en is nie outomaties beskikbaar vir arbitrêre agtergrondwerk nie, dus kan ontbrekende oordrag ’n werklike interaksie onsigbaar maak.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifiseer dieselfde dinamiese toegangspunt by elke uitvoering

Moenie herhaal met ’n konkrete heap-adres nie, aangesien dit ná elke toekenning kan verander, of net met ’n instruksie-adres nie, aangesien dit dubbelsinnig is binne helpers soos `memcpy()` en `spin_lock()`. MAccConc gebruik ’n **count-augmented stack trace**: elke raam identifiseer ’n callee plus die aanroepingtelling binne sy caller, en die laaste element identifiseer die geheuetoegangsinstruksie. SanitizerCoverage-funksie-intree-/uittree-rekords stel userspace in staat om hierdie dinamiese identifiseerder te rekonstrueer, wat stabiel bly ondanks adresveranderinge en onverwante beheer-vloei-geraas.<sup>[[17]](#references)</sup>

### Skakel kandidaatpare om in afgedwonge skedules

Die gelapte `KCOV_SET_DI` ioctl koppel ’n count-augmented toegangspuntidentifiseerder aan ’n shared-flag-aksie.<sup>[[17]](#references)</sup>

| Aksie | Semantiek |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Stel vlag *N* onmiddellik voor die gekose toegangspunt. |
| `DI_STACK_WAIT` | Spin voor die gekose toegangspunt totdat vlag *N* gestel is of die ingestelde limiet verstryk. |
| `DI_STACK_WAKE_POST` | Stel vlag *N* onmiddellik ná die gekose toegangspunt. |

Vir ’n gedeeltelike **A-happens-before-B**-beperking, koppel `DI_STACK_WAKE_POST` aan A en `DI_STACK_WAIT` aan B met dieselfde vlag. Vir ’n volledig gespesifiseerde tweekonteksskedule, begin B geblokkeer, laat A dan B wakker maak en wag by die eerste oordragpunt; B voer die omgekeerde handeling by die volgende oordrag uit. Laasgenoemde tree op soos deterministiese kontekswisseling en is wat die outomatiese A-B-A-verkenner gebruik.<sup>[[17]](#references)</sup>

’n Minimale veldtog is om die viertakhaak-toetsgeval (`test_setup`, twee thread-funksies en `test_end`) as ’n gedeelde biblioteek te kompileer, ’n onbeperkte spoor in te samel en dan A-B-A-kandidate te lys of handmatige beperkings rondom verdagte toegangspunte by te voeg.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreteer time-outs apart van suksesvolle herrangskikkings: ’n aangevraagde volgorde kan onmoontlik wees omdat ’n lock of ’n afhanklikheid van initialisering/publisering verhoed dat die tweede konteks sy injection point bereik. Hou ook KASAN se blinde kolle in gedagte: direkte stack-toegange word gewoonlik nie gehook nie, tensy hulle moontlik buite die grense val; globals word met die verstekoptimering weggelaat; en huidige kompileerders kan nie ASAN- en TSAN-hooks gelyktydig genereer nie. Laastens verloor die prototipe sy KCOV-buffer wanneer ’n gasheer paniekerig raak, dus moet jy ’n onafhanklike crashkonsole/orakel behou.<sup>[[17]](#references)</sup>

Vir toekomstige concurrency-begeleide fuzzing, teken geheuetoegangopsommings per invoer of per syscall aan, koppel bewerkings wat kommunikasiepunte tussen kontekste sou vorm, en verken dan slegs daardie kombinasies. VM-snapshots stabiliseer globale toestand en adresse; sonder snapshots kan metadata oor allokasieliggings voorwerpe oor lopies heen abstraheer. Dit is ’n voorgestelde uitbreiding, nie ’n kenmerk van die huidige MAccConc-userspace-gereedskap nie.<sup>[[17]](#references)</sup>

## Harness-introspeksie: Vind vlak fuzzers vroeg

Wanneer ’n veldtog stilstaan, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **introspeksie van bereikbaarheid/dekking** om funksies te vind wat staties vanaf jou fuzz-teiken bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die teiken te laat of te vroeg.
- Die saadkorpus mis ’n hele kenmerkgroep.
- Die teiken het werklik ’n **tweede harness** nodig in plaas van een oorgroot “doen-alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-styl werkvloeie gebruik, kan Fuzz Introspector statiese bereikbaarheid met looptyddekking vergelyk en verslae uit ’n tydbeperkte lopie of openbare korpus genereer.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Gebruik die verslag om te besluit of ’n nuwe harness vir ’n ongetoetste parser-pad bygevoeg moet word, die corpus vir ’n spesifieke kenmerk uitgebrei moet word, of ’n monolitiese harness in kleiner toegangspunte verdeel moet word.

## Fuzz-teikenseleksie met die grafiek eerste en mutasie-triage

As jy reeds **statiese-analise-bevindinge**, **mutasietoetsing-oorlewendes** en **dekkingsverslae** het, moenie hulle as afsonderlike lyste triageer nie. Bou eers ’n **oproepgrafiek**, annoteer nodusse met **siklomatiese kompleksiteit**, **bereikbaarheid vanaf toegangspunte/onbetroubare insette** en enige eksterne bevindinge, en stel dan grafiekverwante vrae.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is bereikbaar vanaf onbetroubare insette?
- Watter mutasie-oorlewendes lê op paaie van parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met ’n buitengewoon groot **ontploffingsradius**?

Dit lewer gewoonlik beter fuzz-teikens op as bloot “laagste dekking”. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker kandidaat vir ’n harness as ’n geïsoleerde interne helper met swak dekking, maar sonder ’n aanvallerbeheerde pad.

### Praktiese triage-werkvloei

1. Bou ’n **kodegrafiek** uit die kodebasis en haal kompleksiteits-/vertakkingsmaatstawwe per funksie uit.
2. Lys **toegangspunte** wat aanvallerbeheerde insette aanvaar: versoekhandlers, decoders, invoerders, protokolparsers, CLI-/lêerlesers.
3. Voer **padnavrae** vanaf daardie toegangspunte na kandidaatfunksies uit om bereikbare aanvalsoppervlak van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodusse wat die volgende kombineer:
   - hoë **siklomatiese kompleksiteit**
   - bevestigde **bereikbaarheid vanaf onbetroubare insette**
   - groot **ontploffingsradius** of baie afhanklike nodusse stroomaf
   - stawende bewyse soos **SARIF**-bevindinge, ouditnotas of mutasie-oorlewendes
5. Skryf eerste gefokusde harnesses vir die nodusse met die hoogste telling, veral **parsers/codecs** soos hex-/Base64-/IP-/boodskapdecoders.

### Mutasie-oorlewendes: ekwivalent teenoor uitvoerbaar

Mutasietoetsing lewer dikwels ’n raserige lys oorlewendes op. Voordat jy elke oorlewende as ’n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n aanvallerbeheerde toegangspunt?
- Word alle oproeppaaie deur sterker invariantes as die gemuteerde kontrole beperk?
- Lê die nodus in dooie kode, slegs in formateringslogika, of in ’n hoë-impak rekenkundige/parser-pad?

Oorlewendes wat onbereikbaar bly of struktureel beperk word, is dikwels **ekwivalente mutante**. Oorlewendes wat **bereikbaar** bly en **grensgevalle**, **oorloop-/oordragpaaie** of **sekuriteitskritieke rekenkunde/parsing** raak, moet bevorder word na:

- nuwe fuzz-harnesses
- direkte property-/invarianttoetse
- doelgerigte grensgevalvektore

### Korreleer eksterne bevindinge met die grafiek

As jou SAST-pyplyn **SARIF** uitvoer, karteer bevindinge op grafieknodusse volgens **lêer + lynreeks** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **ontploffingsradius** van die gemerkte funksie
- kyk of die bevinding op enige pad vanaf ’n toegangspunt lê
- groepeer nabygeleë bevindinge wat op dieselfde knelpunt uitkom

Dit is nuttig wanneer jy besluit of jy fuzz-tyd aan ’n spesifieke funksie moet bestee: ’n nodus wat **bereikbaar**, **kompleks** is en reeds **SAST-treffers** het, is dikwels ’n beter teiken as ’n bloot komplekse nodus sonder ’n aanvallerpad.

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

Die belangrike metodologie is die kruising van: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutasie-oorlewendes om te bepaal watter grense en invariantia jou harness moet stres.<sup>[[5]](#references)</sup>

## Differensiële fuzzing van kriptografiese sleutelkoderings

Begin met geldige geserialiseerde sleutels of standaardtoetsvektore. Mutateer geënkodeerde velde sonder om die lengte en struktuur te breek wat nodig is om die invoer- en bewerkingspaaie te bereik, en dien dan dieselfde grepe by onafhanklike implementerings in. Vergelyk aanvaarding en foute. Gerandomiseerde handtekeninge en syferskrifte benodig korrektheidsorakels, nie byte-vir-byte-vergelyking nie: verifieer handtekeninge of vergelyk die gedeelde geheime van ’n inkapselings-/ontkapselingsrondrit. Toetsvektore stel konformiteit vir bekende gevalle vas; differensiële mutasie toets misvormde enkoderings wat verder strek as dié gevalle.<sup>[[23]](#references)[[26]](#references)</sup>

Gebruik formaatafhanklike orakels vir hierdie sleutelformate:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA-uitgebreide ondertekeningsleutels:** verander gepakte `s1`- of `s2`-koëffisiënte sodat hulle buite `[-η, η]` val, terwyl die sleutel ontleedbaar bly. Kyk of invoer of ondertekening dit verwerp en of enige gevolglike handtekening geverifieer word. Verskille in aanvaarding alleen is nie standaardoortredings nie, want FIPS 204 vereis nie bykomende privatesleutelnasien nie. Sien die [meganisme vir voorwaardelike lek](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM-sleutelpare:** onderskei die vereiste kontroles van die inkapselingsleutel en ontkapselingsinvoer van die opsionele paargewyse konsekwentheidskontrole (PCT) op ’n ingevoerde paar. Inkapsuleer met die publieke sleutel, ontkapsuleer met die private sleutel en vergelyk die gedeelde geheime; ’n wanpassing kan geënkripteerde kommunikasie breek, selfs wanneer individuele sleutels die invoerkontroles slaag. Kyk of die API insette tydens die bewerking of met ’n afsonderlike oproep valideer; libcrux stel `validate_public_key(pk)` en `validate_private_key(sk, ct)` beskikbaar, maar dié vervang nie ’n PCT nie.
- **XMSS/XMSSMT-rou sleutels:** toets rondritte van geserialiseerde **ondertekenings- en verifikasiesleutels** oor parameterstelle, nie net bewerkings met sleutels in die geheue nie. XMSS en XMSSMT het afsonderlike viergreep-OID-naamruimtes, dus kan ’n OID-alleen-ontleder wat XMSS eerste probeer, ’n XMSSMT-sleutel met ’n botsende OID verkeerd klassifiseer en invoer verwerp. Die gerapporteerde RustCrypto-ontleder illustreer ’n interoperabiliteits-/beskikbaarheidsfout, nie ’n vervalsing van ’n handtekening nie.

## Go-fuzzing met gosentry: sterker enjin, getipeerde insette en differensiële kontroles

As ’n Go-teiken reeds ’n inheemse `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop, ’n gevurkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** omskakel.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This is nuttig wanneer die native Go-fuzzer vashaak by **moeilike vergelykings**, **getipeerde invoere** of **parser-swaar formate**. Die metodologie bly dieselfde:

- Gebruik steeds `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binary uit in plaas van die standaard toolchain.
- Behandel die resulterende veldtog as ’n normale coverage-guided run, maar met LibAFL-skedulering/mutasie en beter omringende detectors.

### Verander stille mislukkings in fuzz-bevindinge

’n Terugkerende probleem in Go-assesserings is dat gevaarlike gedrag dikwels nie by verstek ’n crash veroorsaak nie. Met gosentry kan jy verskeie klasse “sleg maar stil”-toestande in bevindinge omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging-/error-paaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte touinskrywings met die Go race detector te herspeel.
- `--catch-leaks=true` om nuwe touinskrywings met `goleak` te herspeel en by goroutine-lekkasies te stop.
- LibAFL se hang-hantering om **oneindige lusse / baie stadige invoere** as fuzz-bevindinge te behou, eerder as om dit as timeouts te laat verdwyn.
- Ingeboude rekenkundige oorloopkontroles by verstek, plus opsionele afkappingskontroles deur go-panikint-styl-instrumentasie.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **parser-mislukking sonder ’n panic**, ’n **concurrency-bug** of ’n **hang wat net DoS veroorsaak** is, eerder as geheuekorrupsie.

### Struct-aware fuzzing vir getipeerde Go-API’s

Native Go-fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string` en getalle. As die kode wat getoets word getipeerde objekte verbruik, kan gosentry **saamgestelde waardes** direk fuzz (structs, slices, arrays, pointers), terwyl bytes steeds onderliggend gemuteer word.<sup>[[7]](#references)[[8]](#references)</sup>

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

Gebruik dit wanneer die bou van ’n vals wire format net vir fuzzing logikafoute agter parsing-kode wat net in die harness gebruik word, sou versteek. Hou vir differential- of grammatika-gebaseerde veldtogte die harness-invoer as ’n enkele `[]byte` of `string`, en parse dit eerder binne die callback.

### Grammatika-gebaseerde fuzzing vir parsers en protokol-invoer

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammatika is ’n JSON-skikking van produksiereëls, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te neem.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodologienotas:

- Gebruik grammar mode wanneer byte-vlak-mutasies meestal tydens vroeë sintakskontroles faal.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om integer-, lengte- en toestandsmasjiengrense te toets.
- Grammar mode hou die insette grammar-geldig, maar die teiken ontvang steeds **bytes/strings**, dus bly ontleding en semantiese kontroles binne die geharnaste code.

### Differensiële fuzzing: vergelyk implementasies, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-gebaseerde differensiële fuzzing**: genereer geldige gestruktureerde insette en voer dit aan twee parsers, clients of toestandoorgang-enjins.<sup>[[7]](#references)[[8]](#references)</sup>

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

Behandel die volgende as bevindinge:

- een implementering veroorsaak ’n panic terwyl die ander dit netjies afwys
- verskille in aanvaarbare/afgekeurde invoer
- verskillende parse-bome of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, balances of state roots

Dit is ’n praktiese manier om **konsensuswanpassings**, **parser-dubbelsinnigheid** en **afwykings tussen spesifikasie en implementering** te vind wat suiwer crash-fuzzing dikwels mis.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Hergebruik die veldtogkorpus vir dekkingsverslagdoening

Speel ná ’n veldtog die gestoorde toukorpus weer af om ’n Go-dekkingsverslag te genereer sonder om ’n aparte korpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Voer die opdrag uit vanuit dieselfde pakket en met dieselfde `-fuzz`-teiken sodat gosentry die korrekte kasveldtogtoestand oplos.

## References

- [1] [Mutasionele grammatikafuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet vyf jaar later: Oor protokolfuzzing gelei deur dekking](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel ontbreek. Ons het die toolchain gefork om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox-fuzzer vir stateful-netwerkprotokolle wat snapshots gebruik](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Na fuzzing van die Linux-kern sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentasie: pad- en oproeperdekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende konteksensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security-blog - Binder-fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder-fuzzer - dokumentasie vir bou en regressie-seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Verkenning van Linux-kernrastoestande met beheerde geheuetoegang-interleavings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Kodedekking vir fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO-uitgebreide lêernaamsintaksis](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-advies: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing van CFITSIO se uitgebreide lêernaamsintaksis: 16 geheueveiligheidskwesbaarhede en Codex-ondersteunde triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differensiële fuzzing vir kriptografie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standaard vir ’n sleutelinkapselingsmeganisme gebaseer op ’n module-rooster](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID-ontledingsfout - RustCrypto-kwessie #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stand van implementerings van post-kwantumkriptografie](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Hoe snapshotting ons tot CVE-2026-9539 gelei het](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzers teenoor KI: Vergelyking van Fuzzilli en BigSleep op JavaScript-enjins](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
