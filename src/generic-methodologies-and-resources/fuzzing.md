# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage teenoor semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl hulle **grammatikaal geldig** bly. In coverage-guided-modus word slegs monsters wat **nuwe coverage** veroorsaak as corpus-sade gestoor. Vir **taikteikens** (parsers, interpreters, enjins) kan dit foute miskyk wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruk die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Mislukkingsmodus:** die fuzzer vind sade wat afsonderlik `document()` en `generate-id()` (of soortgelyke primitives) uitvoer, maar **nie die gekoppelde dataflow behou nie**. Daarom word die monster wat “nader aan die fout” is, weggegooi omdat dit nie coverage byvoeg nie. Met **3+ afhanklike stappe** word lukrake herkombinering duur, en coverage-terugvoer lei nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** oorweeg vir grammatikas met baie afhanklikhede om **mutational en generative fases te kombineer**, of om generering na **function-chaining-patrone** te stuur (nie net na coverage nie).<sup>[[1]](#references)</sup>

## Slaggate met corpus-diversiteit

Coverage-guided-mutasie is **gulsig**: ’n monster met nuwe coverage word onmiddellik gestoor, en behou dikwels groot onveranderde dele. Met verloop van tyd word corpora **byna-duplikate** met min strukturele diversiteit. Aggressiewe minimalisering kan nuttige konteks verwyder, dus is ’n praktiese kompromie **grammatika-bewuste minimalisering** wat **ná ’n minimum token-drempel stop** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutasievriendelik te wees).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel struktureel verskillende sade wat coverage maksimeer** bo ’n groot hoop byna-duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **monsters uit die werklike wêreld** (openbare corpora, crawling, vasgelegde verkeer, lêerstelle uit die teiken-ekosisteem).
- Distilleer dit met **coverage-gebaseerde corpus-minimalisering** eerder as om elke geldige monster te behou.
- Hou sade **klein genoeg** sodat mutasies op betekenisvolle velde land, eerder as om die meeste siklusse aan irrelevante grepe te bestee.
- Voer corpus-minimalisering weer uit ná groot harness-/instrumentasieveranderinge, want die “beste” corpus verander wanneer reachability verander.

## Vergelykingsbewuste mutasie vir magiese waardes

’n Algemene rede waarom fuzzers ’n plato bereik, is nie sintaksis nie, maar **harde vergelykings**: magiese grepe, lengtekontroles, enum-stringe, kontrolesomme of parser-dispatch-waardes wat deur `memcmp`, switch-tabelle of opeenvolgende vergelykings beskerm word. Suiwer lukrake mutasie mors siklusse deur hierdie waardes greep vir greep te probeer raai.

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

- Dit is veral nuttig wanneer die teiken diep logika agter **lêerhandtekeninge**, **protokolwerkwoorde**, **tipe-etikette** of **weergaweafhanklike kenmerkbisse** wegsteek.
- Gebruik dit saam met **woordeboeke** wat uit werklike voorbeelde, protokolspesifikasies of ontfoutingslogboeke verkry is. ’n Klein woordeboek met grammatikatokens, blokname, werkwoorde en skeidingstekens is dikwels waardevoller as ’n massiewe generiese woordelys.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en verklein dan die resulterende korpus weer, sodat latere fases vanaf reeds geldige voorvoegsels begin.

## Fuzzing van lêer-API’s wat ’n lêernaamtaal versteek

’n Parameter met die naam `filename`, `path` of `URL` kan ’n toegangspunt tot ’n interpreter wees, eerder as ’n letterlike lêeropsoek. CFITSIO Extended Filename Syntax (EFS) evalueer byvoorbeeld selektors tussen vierkantige hakies, ry-/pikseleks­presies, berekende kolomme, histogramme en transformasies voordat dit die oopgemaakte objek teruggee; sommige vorme skep ook tydelike kopieë. Klassifiseer tydens kartering van die aanvalsvlak elke open-/import-API as **literal-path** of **interpreted-path**, en fuzz dan die produksie-ingangspunt wat toepassings werklik aanroep.<sup>[[20]](#references)[[22]](#references)</sup>

Vir die gevolglike SSRF-, lêerkopieer- en protocol-handler-primitiewe—en veiliger literal-path-API’s—sien [Mini-tale vir lêername as SSRF-/lêerprimitiewe](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Hou die ondersteunende objek apart van die program wat gefuzz word

Wanneer die grammatika in ’n lêernaam-agtervoegsel voorkom, mis die parser as jy net die grepe van die verwysde lêer wysig. ’n Klein harness kan eerder een toetsgeval as ’n string lees en dit aan die interpreted open-API deurgee; die CFITSIO-veldtog het die meeste EFS-parsers en -evalueerders bereik deur `fits_open_file()` in leesalleenmodus aan te roep. Hou geldige ondersteunende lêers afsonderlik beskikbaar, sodat wysigings op die selektor-/uitdrukkings­taal kan fokus, eerder as om voortdurend die basispad te breek.<sup>[[22]](#references)</sup>

Gebruik saadwaardes wat elk ’n ander grammatika-familie bereik, en lei dan ’n kompakte woordeboek af uit sowel die spesifikasie as die lexer-/parserbron. As dekking stagneer terwyl invoere herhaaldelik in dieselfde sintaksisfoutpad misluk, behou geldige voorvoegsels en voeg skeidingstekens, operatore, sleutelwoorde, funksiename en verteenwoordigende veldname by, eerder as om net die tyd vir ewekansige wysigings te verleng.<sup>[[22]](#references)</sup>

Voer die harness met die grammatikawoordeboek uit, byvoorbeeld:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Beperk newe-effekte van ’n "read-only" harness

’n Read-only-biblioteekvlag waarborg nie ’n toetsgeval sonder newe-effekte nie: die lêernaamtaal kan die invoer herskryf, uitvoerlêers skep of tydelike objekte materialiseer. Die CFITSIO-veldtog het aanvanklik saadlêers vernietig en onverwagte lêers oor die lêerstelsel versprei, daarom was opruiming en isolasie nodig.<sup>[[22]](#references)</sup>

- Gee elke worker ’n weggooibare werkgids en privaat tydelike gids.
- Stel kopieë van kanonieke ondersteuningslêers beskikbaar; moenie die teiken ooit die enigste kopie in die corpus laat verander nie.
- Deaktiveer netwerktoegang tensy afgeleë backends die beoogde teiken is, en beperk skryfbare paaie met ’n container, mount namespace of soortgelyke sandbox.
- Stel die gids ná elke uitvoering of worker-bondel terug en beskou onverwagte lêerstelselveranderings as bykomende bevindings.

### Crash-na-patch-na-fuzz-lus

Groepeer crashes voordat jy herstelwerk doen, sodat duisende artefakte nie duisende patch-take word nie. In die CFITSIO-assessering het AFLTriage die aanvanklike stel crashes tot ’n paar hoofoorsake verminder; die gevolglike advies toon duidelike foute, waaronder verkeerde kontroles van bestemmingsgroottes, verouderde pointers ná `realloc()`, rekenkundige foute en onveilige opruimpaaie in die parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimeer ’n verteenwoordigende invoer vir elke groep en reproduseer dit met AddressSanitizer.
2. Teken die presiese foutiewe toegang, bronligging, geskiedenis van toewysing/vrystelling en parsertoestand aan wat die invariant ongeldig gemaak het.
3. Pas een noukeurig afgebakende kandidaat-patch toe en bou weer met dieselfde coverage- en sanitizer-instrumentasie.
4. Speel die oorspronklike reproduseerder **en elke invoer in sy groep** weer af; aktiveer ook leak-detection, want ’n geheueveiligheidsregstelling kan eienaarskap op ’n foutpad verbreek.
5. Voer funksionele toetse met werklike lêers uit, en hervat dan vanaf die opgehoopte tou (of voer daardie tou weer in as die engine ’n vars uitvoergids ná veranderinge aan die binary vereis).
6. Herhaal: deur die eerste oppervlakkige crash te verwyder, kan bestaande sade dikwels tot ’n dieper parsertoestand vorder.

’n LLM kan stap 2 bespoedig en ’n konsep vir stap 3 opstel wanneer dit die crashende invoer, sanitizer-verslag, harness en relevante bronkode ontvang, maar sy patch bly onvertroubaar. Die sanitizer-herhaling en regressiepoorte—nie die model se verduideliking nie—bepaal of die herstel aanvaar word.<sup>[[22]](#references)</sup>

## Ryker terugvoer wanneer Edge Coverage verskillende paaie saamsmelt

Normale edge coverage kan nie twee uitvoerings onderskei wat deur dieselfde helper via verskillende callers beweeg of verskillende kombinasies van vertakkings binne ’n funksie neem nie. Dit maak saak in gedeelde decoders, protokolversenders en interpreter-helpers waar die **roete** na ’n edge die aktiewe toestand bepaal. Om elke oproepkonteks naïef na te spoor is ook gevaarlik: die coverage-map en tou kan geweldig uitbrei. Navorsing oor konteksbewuste fuzzing beveel dus aan om slegs belowende kontekste te verfyn, eerder as om die hele oproepgrafiek as konteksbewus te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-weergawes bied **Ball-Larus-paddekking per funksie** bykomend tot normale edge coverage. Dit ken ’n kenmerk aan elke asikliese pad deur ’n funksie toe; terugkante van lusse word verwyder, dus onderskei hierdie terugvoer kombinasies van vertakkings, maar **nie die aantal lusiterasies nie**. Begin met die ontspanne vlak `1`, en beperk strenger modusse dan tot verdagte parser-/toestandmasjienkode, omdat die aantal paaie eksponensieel kan groei.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Vir ’n helper wat vanaf baie sekuriteitsrelevante plekke geroep word, kan LTO-modus elke funksiepad met sy onmiddellike call site kombineer:<sup>[[13]](#references)</sup>

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

**Veldtogriglyne:** pas ryker terugvoer konserwatief toe en monitor die koste daarvan vir die coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Laat ’n gewone edge-coverage-instansie parallel loop; ryker terugvoer is slegs nuttig as die ekstra queue/map-koste nie die aantal uitvoerings per sekonde drasties verminder nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om path/caller-instrumentering te beperk wanneer groot biblioteke met baie templates of generiese nutskode die map oorheers.
- Funksies met buitensporig baie asikliese paths kan deur AFL++ oorgeslaan word; waarskuwings tydens samestelling is ’n aanduiding dat die teiken allowlisting of ’n minder streng vlak nodig het.
- Caller + path coverage ondersteun slegs een caller-diepte. Moenie dit met dieper context-stacks kombineer nie.
- Path-ID’s kan tussen groot LLVM-weergawes verander. Hou die toolchain konstant gedurende ’n veldtog en moenie PATH-gebaseerde korpora sinkroniseer asof hul feature-ID’s stabiel oor builds heen is nie.
- Hierdie terugvoer vul `CMPLOG` aan: comparison-tracing bepaal **watter waarde ’n guard slaag**, terwyl path/caller-terugvoer behou **watter roete en vertakkingskombinasie dit bereik het**.

## Stateful Fuzzing: Sequences Is Seeds

Vir **protokolle**, **gewaarmerkte werkvloeie** en **meerfase-parsers** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **message sequence**. Om die hele transkripsie in een lêer saam te voeg en dit blindelings te muteer, is gewoonlik ondoeltreffend, omdat die fuzzer elke stap ewe veel muteer, selfs wanneer slegs die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Doeltreffender patroon is om die **sequence self as die seed** te behandel en **waarneembare toestand** (antwoordkodes, protokoltoestande, parserfases, teruggestuurde objekttipes) as bykomende terugvoer te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige voorvoegselboodskappe** stabiel en fokus mutasies op die boodskap wat die **toestandsoorgang aandryf**.
- Kas identifiseerders en bediener-gegenereerde waardes uit vorige antwoorde wanneer die volgende stap daarvan afhanklik is.
- Verkies mutasie/splicing per boodskap bo mutasie van die hele geserialiseerde transkripsie as ’n ondeursigtige blob.
- As die protokol betekenisvolle antwoordkodes blootstel, gebruik hulle as ’n **goedkoop toestandsorakel** om voorkeur te gee aan sequences wat verder vorder.

Dit is dieselfde rede waarom geverifieerde foute, versteekte oorgange of parserfoute wat “eers ná die handdruk” voorkom, dikwels deur vanilla-lêerstyl-fuzzing gemis word: die fuzzer moet **volgorde, toestand en afhanklikhede** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Hoë edge coverage kan steeds IPC-driver-foute mis omdat coverage nie **objekeienaarskap, verwysingtellings, hangende boodskappe, opruimvolgorde of thread-interleavings** beskryf nie. Die [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md)-bladsy behandel die bestuurder se objekmodel; hierdie voorbeeld fokus op die fuzzer-harnas. Android Binder is ’n nuttige model: dit is nie genoeg om beide die toewysings- en vrymaakpaaie te bereik as die fuzzer nie verskeie prosesse in die vereiste volgorde op dieselfde kernel-objek kan laat werk nie.<sup>[[15]](#references)</sup>

#### Model the protocol, not isolated `ioctl` buffers

Stel ’n toetsgeval voor as ’n geordende grammatika van **kliëntidentiteit + bewerking + gestruktureerde argumente**. Die Binder LKL-fuzzer gebruik protobuf en `libprotobuf-mutator`, met een aanhoudende konteksbestuurderkliënt en twee gewone kliënte. ’n Semantiese harnas behou dan die verwantskappe wat blinde greepmutasie sou vernietig.<sup>[[15]](#references)</sup>

- Kas waardes wat deur vorige bewerkings teruggestuur is. Byvoorbeeld, `BC_FREE_BUFFER` moet ’n transaksiebufferwyser hergebruik wat deur ’n vorige `ioctl` teruggestuur is.
- Genereer geldige verstekantwoorde sodat sinchroniese transaksies kan voltooi en latere bewerkings bereikbaar bly.
- Verwerp onmoontlike oorgange soos selftransaksies of verskeie hangende transaksies na dieselfde teiken.
- Hou enkelinstansie-opstarttoestand buite die terugstelling per inset. Binder laat slegs een `BINDER_SET_CONTEXT_MGR`-registrasie per selflaai toe, dus sou die herhaaldelike vernietiging en herskepping van daardie kliënt latere insette ongeldig maak.

’n Nuttige sjabloon vir ’n lewensduurwedloop is om een kliënt ’n objek te laat oordra, draad- of prosesopruiming te begin, en die ontvangende kliënt terselfdertyd die transaksiebuffer te laat vrystel. In die CVE-2020-0423-voorbeeld kon ’n `BINDER_TYPE_WEAK_BINDER`-oordrag, gevolg deur ’n wedloop tussen `BINDER_THREAD_EXIT` en `BC_FREE_BUFFER`, ’n ingebedde `binder_work` vrystel terwyl die uitgaande draad se opruimpad dit steeds gebruik het.<sup>[[15]](#references)</sup>

#### Reintroduce controlled interleavings in a userspace kernel

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) skakel die werklike kernel-kode in ’n gebruikersruimte-harnas in en stel sy syscall-koppelvlak via `lkl_syscall` bloot. Dit maak dit maklik om protobuf-toestand, coverage en KASAN in een proses te koördineer. LKL laat normaalweg egter nie toe dat ’n ander kernel-draad ’n syscall onderbreek nie. Vir wedloopveldtogte, voeg `schedule()`-punte by rondom geselekteerde grendel-/ontgrendel- en lewensduurgrense, en laat die harnas dan lukraak die volgende kliënt by elke skeduleringspunt kies. Hou hierdie punte doelgerig, want elkeen vermenigvuldig die skeduleringssoekruimte. Die gerandomiseerde skeduleerder wat die navorsers beskryf, is **nie** deel van die stroomop-Binder-fuzzer nie.<sup>[[15]](#references)</sup>

#### Build and replay serialized regression seeds

Die stroomop-harnas pen ’n versoenbare `libprotobuf-mutator`-weergawe vas, aktiveer LKL-fuzzing-instrumentering en KASAN met `LKL_FUZZING=1`, en aktiveer `CONFIG_MMU` vir Binder met `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nadat jy ’n doelbewus kwesbare weergawe uitgecheck het of die terugrolpleisters toegepas het wat stroomop gedokumenteer is, kan ’n geserialiseerde saad die hele toestandsoorgang tussen verskeie kliënte reproduseer sonder om dit in ’n ad hoc C-bewys-van-konsep te rekonstrueer:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandel die resulterende KASAN use-after-free as bevestiging dat die seed die kwesbare lifetime-pad bereik het. Dit demonstreer **nie** die latere primitives wat nodig is vir kernel code execution of privilege escalation nie.<sup>[[16]](#references)</sup>

## Diversiteitstruuk op ’n enkele masjien (Jackalope-styl)

’n Praktiese manier om **generatiewe nuutheid** met **hergebruik van dekking** te kombineer, is om **kortlewende workers** teen ’n persistente server te herbegin. Elke worker begin met ’n leë corpus, sinkroniseer ná `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sinkroniseer weer en sluit dan af. Dit lewer **vars strukture met elke generasie**, terwyl opgehoopte dekking steeds benut word.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` dwing ’n **vars corpus** vir elke generering af.
- `-server_update_interval T` benader **vertraagde sync** (eers nuwigheid, later hergebruik).
- In grammar fuzzing-modus word **aanvanklike server-sync by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Die optimale `T` is **teikenafhanklik**; dit werk gewoonlik die beste om oor te skakel nadat die worker die meeste “maklike” coverage gevind het.

## Snapshot Fuzzing Vir Teikens Wat Moeilik Is Om Te Harness

Wanneer die kode wat jy wil toets eers bereikbaar word **ná ’n groot opstelkoste** (’n VM selflaai, ’n aanmelding voltooi, ’n packet ontvang, ’n container ontleed of ’n diens inisialiseer), is **snapshot fuzzing** ’n nuttige alternatief: neem ’n snapshot van die gereed proses- of VM-toestand, voer elke testcase in via die teiken se invoerpad, voer uit totdat ’n crash/timeout voorkom, en herstel die snapshot. Dit vermy die herhaling van inisialisering of protokolvoorvoegsels en is nuttig vir **netwerkdienste**, **firmware**, **aanvaloppervlakke ná verifikasie** en **slegs-binêre teikens**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die teiken loop totdat die interessante toestand gereed is.
2. Neem op daardie punt ’n snapshot van **geheue + registers**.
3. Skryf vir elke testcase die gemuteerde invoer direk na die toepaslike gasheer-/prosesbuffer.
4. Voer uit totdat ’n crash/timeout/reset voorkom.
5. Herstel die snapshot; vir VM-teikens, herstel slegs die **dirty pages** waar dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as prakties moontlik aan die eerste duur parse-/dispatch-stap, byvoorbeeld ná ’n `recv`/`read` of ’n punt waar packets gedeserialiseer word, en teken die invoerbuffer aan wat die teiken gebruik. Dit volg die beginsel van aanpasbare plasing: skuif die snapshot dieper in die invoerverwerking in om herhaling van werk te vermy.<sup>[[11]](#references)</sup>

### Inkrementele snapshots vir protokoltoestande

’n Vaste snapshot vermy opstelkoste, maar verken nie op sigself oorgange wat verskeie geldige boodskappe vereis nie. ’n LibAFL-Qemu-harness kan skrywes na ’n protokoltoestandveld dophou en ’n nuwe snapshot stoor wanneer die toestand verander. In die [libslirp TCP-harness](https://github.com/quarkslab/slirp_snapshots_stateful) hou dit `tcpcb.t_state` dop, hash dit die toestand en antwoordvlae om snapshots te dedupliseer, en stoor dit dirty pages relatief tot ’n ouer. Voordat die volgende gestruktureerde boodskap gemuteer word, herstel dit die geselekteerde snapshot deur die ouerketting. Die testcase hou ’n `SnapshotId` en gegenereerde invoergrepe (`gen_bytes`) by; die snapshotbestuurder hou die ouerverwantskap by wat vir herhaling nodig is.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu se user-mode `SnapshotModule` stoor mappings en teikengeheue, maar nie CPU-registers nie; bewaar dit afsonderlik waar nodig. Die beskryfde bestuurder ondersteun een wortelsnapshotboom en kan nie snapshot-ID’s tussen workers deel nie. Sy multi-snapshot-modus kan ook nie QASAN-shadowtoestand direk hergebruik nie. Vir vanlyn triage, rekonstrueer die invoerketting in ’n afsonderlike geïnstrumenteerde proses. Wanneer `AsanHostModule` en `DrCovModule` gebruik word, voer `fuzzer.evaluate_input` die vereiste `pre_exec`/`post_exec`-terugroepe uit; `qemu.run` alleen doen dit nie.<sup>[[27]](#references)[[28]](#references)</sup>

### Bespeur logiese oorlesings van ringbuffers

’n Lees buite ’n buffer se *geldige datatelling* kan binne sy gasheertoewysing bly en gewone ASAN ontglip. Die [libslirp-voorbeeld met urgent data](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) onderloop ook ’n ongetekende greeptelling. As die bron beskikbaar is, kan instrumentasie vir oorloop van getekende/ontekende heelgetalle daardie newe-effek opspoor; onderskei doelbewuste TCP-volgnommer-omloop voordat verslae onderdruk word. ’n Sterker voorgestelde oracle is om die pasgemaakte ringtoewysing te vergiftig, slegs geldige reekse te ontvergiftig soos die interne allocator vorder, en vrygestelde reekse weer te vergiftig. LibAFL-Qemu stel ’n ASAN-vergiftigings-API beskikbaar vir teikens waar broninstrumentasie onprakties is.<sup>[[27]](#references)</sup>

## Linux Kernel Race-verkenning Met MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) verander tydsensitiewe Linux-kernel-races in herhaalbare geheuetoegangskedules. Dit kan twee-konteks-**A-B-A**-uitvoerings outomaties opsom, of ’n ontleder toelaat om volgordebeperkings in ’n terminale UI/GUI op te lê. Dit is eksperimentele navorsingshulpmiddel eerder as ’n volledige concurrency-fuzzer: dit vereis tans LLVM 23+ en die projek se gepatchte kernel, die command-line-gereedskap ondersteun twee toetsdrade, en die voorgestelde fuzzing-laag vir userspace is nie geïmplementeer nie.<sup>[[17]](#references)[[18]](#references)</sup>

### Versamel kommunikasiepunte tussen kontekste

Bou die geïnstrumenteerde kernel met KASAN-outline-terugroepe en die gepatchte KCOV-geheuerekordondersteuning. Die projek se README beveel ook aan dat sibling-call-optimering afgeskakel word sodat oproepstapels bruikbaar bly.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN-outlinemodus (`asan-instrumentation-with-call-threshold=0`) omskep geïnstrumenteerde toegangspunte in helper-oproepe. Die MAccConc-kernpleisters deaktiveer `asan-opt-same-temp` sodat opeenvolgende toegangspunte nie saamgevoeg word nie; deaktiveer ook die `asan-opt-globals`-optimalisering wanneer globale-veranderlike-resies sigbaar moet wees. KCOV stuur die resulterende rekords na gebruikersruimte. Vergelyk toegangspunte uit verskillende uitvoeringskontekste en behou pare waarvan die greepreekse oorvleuel en waar minstens een kant skryf; modelleer `kfree()` as ’n skryfhandeling sodat lewensduur-oorgange ook kandidate word.<sup>[[17]](#references)</sup>

Vir werk wat buite die aanvangstaak plaasvind, soos pakkieverwerking of RCU-terugroepe, moet die substelsel ’n KCOV-afgeleëdekkinghandvatsel deurgee. Stroomop se afgeleë KCOV is opsioneel en is nie outomaties vir willekeurige agtergrondwerk beskikbaar nie, dus kan ontbrekende deurgee ’n werklike interaksie onsigbaar maak.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifiseer dieselfde dinamiese toegang by elke uitvoering

Moenie ’n herhaling op ’n konkrete heap-adres uitvoer nie, aangesien dit ná elke toekenning kan verander, of net op ’n instruksie-adres nie, aangesien dit dubbelsinnig is binne helpers soos `memcpy()` en `spin_lock()`. MAccConc gebruik ’n **telverrykte stapelspoor**: elke raam identifiseer ’n callee plus die aanroeptelling binne sy caller, en die laaste element identifiseer die geheuetoegangsinstruksie. SanitizerCoverage-funksie-inskrywing-/uittreerekords stel gebruikersruimte in staat om hierdie dinamiese identifiseerder te rekonstrueer, wat stabiel bly ondanks adresveranderinge en onverwante beheervloei-geraas.<sup>[[17]](#references)</sup>

### Skakel kandidaatpare om in afgedwonge skedules

Die gelapte `KCOV_SET_DI`-ioctl koppel ’n telverrykte toegangsidentifiseerder aan ’n gedeelde-vlag-aksie.<sup>[[17]](#references)</sup>

| Aksie | Semantiek |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Stel vlag *N* onmiddellik voor die geselekteerde toegang in. |
| `DI_STACK_WAIT` | Wag voor die geselekteerde toegang deur te spin totdat vlag *N* ingestel is of die gekonfigureerde limiet verstryk. |
| `DI_STACK_WAKE_POST` | Stel vlag *N* onmiddellik ná die geselekteerde toegang in. |

Vir ’n gedeeltelike **A-happens-before-B**-beperking, koppel `DI_STACK_WAKE_POST` aan A en `DI_STACK_WAIT` aan B met dieselfde vlag. Vir ’n volledig gespesifiseerde skedule met twee kontekste, begin B geblokkeer; laat A dan B wakker maak en wag by die eerste oordragpunt. B voer die omgekeerde bewerking by die volgende oordrag uit. Dit tree op soos deterministiese konteksskakeling en is wat die outomatiese A-B-A-verkenner gebruik.<sup>[[17]](#references)</sup>

’n Minimale veldtog is om die vier-haaktoetsgeval (`test_setup`, twee draadd funksies en `test_end`) as ’n gedeelde biblioteek te kompileer, ’n onbeperkte spoor te versamel en dan A-B-A-kandidate op te som of handmatige beperkings rondom verdagte toegangspunte by te voeg.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreteer time-outs apart van suksesvolle herrangskikkings: ’n aangevraagde volgorde kan onmoontlik wees omdat ’n slot- of ’n initialiserings-/publiseringsafhanklikheid die tweede konteks verhinder om sy inspuitingspunt te bereik. Hou ook KASAN se blinde kolle in gedagte: direkte stapeltoegange word gewoonlik nie gehook nie, tensy hulle moontlik buite die grense val; globale veranderlikes word met die verstekoptimering weggelaat; en huidige samestellers kan nie ASAN- en TSAN-hooks gelyktydig genereer nie. Laastens verloor die prototipe sy KCOV-buffer wanneer ’n gaspaniek plaasvind, dus moet jy ’n onafhanklike crash-konsole/orakel behou.<sup>[[17]](#references)</sup>

Vir toekomstige concurrency-guided fuzzing, teken geheuetoegangopsommings per invoer of syscall aan, koppel bewerkings wat kruis-konteks-kommunikasiepunte sou vorm, en verken dan slegs daardie kombinasies. VM-snapshots stabiliseer globale toestand en adresse; sonder snapshots kan metadata van allokasiepunte voorwerpe oor lopies heen abstraheer. Dit is ’n voorgestelde uitbreiding, nie ’n kenmerk van die huidige MAccConc-userspace-gereedskap nie.<sup>[[17]](#references)</sup>

## Harness-introspeksie: Vind vlak fuzzers vroeg

Wanneer ’n veldtog stagneer, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **bereikbaarheids-/dekkingsintrospeksie** om funksies te vind wat staties vanaf jou fuzz-teiken bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness bereik die teiken te laat of te vroeg.
- Die saadkorpus bevat nie ’n hele kenmerkgroep nie.
- Die teiken benodig eintlik ’n **tweede harness** in plaas van een oorgroot “doen-alles”-harness.

As jy OSS-Fuzz- / ClusterFuzz-styl-werkvloeie gebruik, kan Fuzz Introspector statiese bereikbaarheid met looptyddeking vergelyk en verslae genereer vanaf ’n tydgebonde lopie of ’n publieke korpus.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Gebruik die verslag om te besluit of jy ’n nuwe harness vir ’n ongetoetste parser-pad moet byvoeg, die corpus vir ’n spesifieke kenmerk moet uitbrei, of ’n monolitiese harness in kleiner toegangspunte moet verdeel.

## Grafiek-eerste keuse van fuzz-teikens en mutasie-triage

As jy reeds **statiese-ontledingsbevindinge**, **mutasietoetsing-oorlewendes** en **dekkingsverslae** het, moenie hulle as afsonderlike lyste triageer nie. Bou eers ’n **oproepgrafiek**, annoteer nodusse met **siklomatiese kompleksiteit**, **bereikbaarheid vanaf toegangspunte/onbetroubare invoer** en enige eksterne bevindinge, en stel dan vrae oor die grafiek.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is bereikbaar vanaf onbetroubare invoer?
- Watter mutasie-oorlewendes lê op paaie van parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met ’n buitengewoon groot **blast radius**?

Dit lewer gewoonlik beter fuzz-teikens op as om net die "laagste dekking" te kies. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker kandidaat vir ’n harness as ’n geïsoleerde interne helper met swak dekking, maar sonder ’n pad wat deur ’n aanvaller beheer word.

### Praktiese triage-werkvloei

1. Bou ’n **kodegrafiek** uit die kodebasis en onttrek kompleksiteit-/vertakkingsmetrieke per funksie.
2. Lys **toegangspunte** wat invoer aanvaar wat deur ’n aanvaller beheer word: versoekhandlers, decoders, importers, protokolparsers, CLI-/lêerlesers.
3. Voer **padnavrae** vanaf daardie toegangspunte na kandidaatfunksies uit om bereikbare aanvaloppervlak van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodusse wat die volgende kombineer:
   - hoë **siklomatiese kompleksiteit**
   - bevestigde **bereikbaarheid vanaf onbetroubare invoer**
   - groot **blast radius** of baie afhanklikes stroomaf
   - stawende bewyse soos **SARIF**-bevindinge, ouditnotas of mutasie-oorlewendes
5. Skryf eers gefokusde harnesses vir die nodusse met die hoogste telling, veral **parsers/codecs** soos hex/Base64/IP/boodskapdecoders.

### Mutasie-oorlewendes: ekwivalent teenoor bruikbaar

Mutasietoetsing lewer dikwels ’n raserige lys oorlewendes op. Voordat jy elke oorlewende as ’n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n toegangspunt wat deur ’n aanvaller beheer word?
- Word alle oproeppaaie deur sterker invariantes as die gemuteerde kontrole beperk?
- Lê die nodus in dooie kode, formateringslogika alleen, of ’n hoë-impak rekenkundige/parser-pad?

Oorlewendes wat onbereikbaar bly of struktureel beperk word, is dikwels **ekwivalente mutante**. Oorlewendes wat **bereikbaar** bly en **grensgevalle**, **oorloop-/oordragpaaie** of **sekuriteitskritieke rekenkunde/parsing** raak, moet bevorder word tot:

- nuwe fuzz-harnesses
- direkte eienskap-/invariantoetse
- geteikende randgevalvektore

### Korreleer eksterne bevindinge met die grafiek

As jou SAST-pyplyn **SARIF** uitvoer, karteer bevindinge volgens **lêer + lynreeks** op grafieknodusse en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kyk of die bevinding op enige pad vanaf ’n toegangspunt lê
- groepeer nabygeleë bevindinge wat na dieselfde knelpunt herlei kan word

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

Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik mutasie-oorlewendes om te bepaal watter grense en invariantes jou harness moet stres.<sup>[[5]](#references)</sup>

## Differensiële fuzzing van kriptografiese sleutel-enkoderings

Begin met geldige geserialiseerde sleutels of standaardtoetsvektore. Verander geënkodeerde velde sonder om die lengte en struktuur te beskadig wat nodig is om die invoer- en bewerkingspaaie te bereik, en dien dan dieselfde grepe by onafhanklike implementasies in. Vergelyk aanvaarding en foute. Gerandomiseerde handtekeninge en syferteks vereis korrektheidsorakels, nie ’n greep-vir-greep-vergelyking nie: verifieer handtekeninge of vergelyk die gedeelde geheime van ’n inkapseling-/ontkapselingsrondte. Toetsvektore bevestig voldoening vir bekende gevalle; differensiële mutasie toets wanvormde enkoderings buite daardie gevalle.<sup>[[23]](#references)[[26]](#references)</sup>

Gebruik formaatspesifieke orakels vir hierdie sleutel-formate:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA-uitgebreide ondertekeningsleutels:** verander gepakte `s1`- of `s2`-koëffisiënte sodat hulle buite `[-η, η]` val, terwyl die sleutel ontleedbaar bly. Kontroleer of invoer of ondertekening dit verwerp en of enige gevolglike handtekening verifieer. Verskille in aanvaarding alleen is nie standaardoortredings nie, omdat FIPS 204 nie bykomende kontroles op private sleutels vereis nie. Sien die [voorwaardelike lekmeganisme](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM-sleutelpaar:** onderskei die vereiste kontroles op die inkapselingsleutel en ontkapselingsinvoer van die opsionele parewyse-konsekwentheidskontrole (PCT) op ’n ingevoerde paar. Inkapsuleer met die publieke sleutel, ontkapsuleer met die private sleutel en vergelyk die gedeelde geheime; ’n wanpassing kan geënkripteerde kommunikasie breek, selfs wanneer individuele sleutels die invoerkontroles slaag. Kontroleer of die API insette tydens die bewerking of deur ’n afsonderlike oproep valideer; libcrux stel `validate_public_key(pk)` en `validate_private_key(sk, ct)` beskikbaar, maar dit vervang nie ’n PCT nie.
- **XMSS/XMSSMT-rou sleutels:** toets rondreise vir geserialiseerde **ondertekenings- en verifikasie**sleutels oor parameterstelle heen, nie net bewerkings met sleutels in die geheue nie. XMSS en XMSSMT het afsonderlike OID-naamruimtes van vier grepe, so ’n OID-ontleder wat eers XMSS probeer, kan ’n botsende XMSSMT-sleutel verkeerd klassifiseer en die invoer daarvan verwerp. Die gerapporteerde RustCrypto-ontleder illustreer ’n interoperabiliteits-/beskikbaarheidsfout, nie ’n vervalsing van ’n handtekening nie.

## Go-fuzzing met gosentry: sterker enjin, getipeerde insette en differensiële kontroles

As ’n Go-teiken reeds ’n inheemse `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop, ’n gevurkte Go-gereedskapstel wat `go test -fuzz` behou, maar die backend na **LibAFL** omskakel.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Dit is nuttig wanneer die inheemse Go-fuzzer vashaak op **moeilike vergelykings**, **getikte invoere** of **parser-swaar formate**. Die metodologie bly dieselfde:

- Gebruik steeds `f.Add(...)` vir saadwaardes en `f.Fuzz(...)` vir die callback.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binêre lêer uit in plaas van die standaard-toolchain.
- Behandel die veldtog wat hieruit volg as ’n gewone dekkinggeleide lopie, maar met LibAFL-skedulering/-mutasie en beter omliggende detektors.

### Verander stille mislukkings in fuzz-bevindings

’n Herhalende probleem in Go-assesserings is dat gevaarlike gedrag dikwels nie by verstek ’n crash veroorsaak nie. Met gosentry kan jy verskeie klasse “slegte maar stille” toestande in bevindinge omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging-/foutpaaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte tou-inskrywings met die Go race detector weer af te speel.
- `--catch-leaks=true` om nuwe tou-inskrywings met `goleak` weer af te speel en by goroutine-lekkasies te stop.
- LibAFL-hanghantering om **oneindige lusse / baie stadige invoere** as fuzz-bevindings te behou, eerder as om dit as tydverstreke te laat verdwyn.
- Ingeboude rekenkundige oorloopkontroles by verstek, plus opsionele afkappingskontroles deur go-panikint-styl-instrumentasie.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **parser-mislukking sonder ’n panic**, ’n **gelyktydigheidsfout** of ’n **hang wat slegs ’n DoS veroorsaak** is, eerder as geheuekorrupsie.

### Struct-bewuste fuzzing vir getikte Go-API's

Inheemse Go-fuzzing verwag hoofsaaklik skalare soos `[]byte`, `string` en getalle. As die kode wat getoets word getikte objekte verbruik, kan gosentry saamgestelde waardes (structs, slices, arrays, pointers) direk fuzz, terwyl dit steeds die onderliggende bytes muteer.<sup>[[7]](#references)[[8]](#references)</sup>

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

Gebruik dit wanneer die bou van ’n vals wire format net vir fuzzing logikafoute agter parsing-kode wat slegs in die harness voorkom, sou verberg. Vir differential- of grammatika-gebaseerde veldtogte, hou die harness-invoer as ’n enkele `[]byte` of `string` en parseer eerder binne die callback.

### Grammatika-gebaseerde fuzzing vir parsers en protokolinvoer

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammatika is ’n JSON-skikking van produksiereëls, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te neem.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodologienotas:

- Gebruik grammar mode wanneer bytevlak-mutasies meestal tydens vroeë sintakskontroles faal.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om integer-, lengte- en staatsmasjienrande te stres.
- Grammar mode hou insette grammar-geldig, maar die teiken ontvang steeds **bytes/strings**, dus bly ontleding en semantiese kontroles binne die geharnaste kode.

### Differential fuzzing: vergelyk implementerings, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-gebaseerde differential fuzzing**: genereer geldige gestruktureerde insette en voer hulle aan twee parsers, kliënte of staats-oorgangsenjins.<sup>[[7]](#references)[[8]](#references)</sup>

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

Hanteer die volgende as bevindings:

- een implementering panikeer terwyl die ander die invoer netjies verwerp
- verskille in watter invoer aanvaar of verwerp word
- verskillende parse-bome of gedekodeerde objekte
- uiteenlopende toestandoorgange, nonces, saldo’s of toestandswortels

Dit is ’n praktiese manier om **konsensusverskille**, **parser-dubbelsinnigheid** en **afwykings tussen spesifikasie en implementering** te vind wat suiwer crash fuzzing dikwels mis.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Hergebruik die veldtogkorpus vir dekkingverslagdoening

Speel ná ’n veldtog die gestoorde toukorpus weer af om ’n Go-dekkingsverslag te genereer sonder om ’n aparte korpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Voer die opdrag vanuit dieselfde pakket uit en met dieselfde `-fuzz`-teiken sodat gosentry die korrekte gekaste veldtogtoestand vind.

## References

- [1] [Mutasionele grammatika-fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Vyf jaar later: Oor dekkinggeleide protokol-fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel ontbreek. Ons het die toolchain gevurk om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 'n Vinnige greybox-fuzzer vir toestandvolle netwerkprotokolle met behulp van snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Op pad na fuzzing van die Linux-kernel sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentering: pad- en oproeperdekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende konteksensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder-fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder-fuzzer - bou- en regressie-seed-dokumentasie](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Verkenning van Linux-kernel-rastoestande met beheerde geheuetoegangvervlegtings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: kodebedekking vir fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO-uitgebreide lêernaamsintaksis](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-advies: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing van CFITSIO-uitgebreide lêernaamsintaksis: 16 geheuevailigheidskwesbaarhede en Codex-ondersteunde triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differensiële fuzzing vir kriptografie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standaard vir 'n sleutelinkapselingsmeganisme gebaseer op module-roosters](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT-OID-ontleedfout - RustCrypto-kwessie #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stand van sake met implementerings van post-kwantumkriptografie](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Hoe snapshotting ons na CVE-2026-9539 gelei het](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
