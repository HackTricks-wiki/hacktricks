# Mbinu ya Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, ingizo hubadilishwa huku likibaki **halali kisarufi**. Katika hali ya coverage-guided, sampuli zinazosababisha **coverage mpya** pekee ndizo huhifadhiwa kama mbegu za corpus. Kwa **malengo ya lugha** (parsers, interpreters, engines), hili linaweza kukosa hitilafu zinazohitaji **minyororo ya semantic/dataflow**, ambapo matokeo ya construct moja huwa ingizo la nyingine.<sup>[[1]](#references)</sup>

**Hali ya kushindwa:** fuzzer hupata mbegu zinazotekeleza kila moja `document()` na `generate-id()` (au primitive zinazofanana), lakini **haihifadhi dataflow iliyounganishwa**, hivyo sampuli iliyo “karibu zaidi na hitilafu” hutupwa kwa sababu haiongezi coverage. Kwa **hatua tegemezi 3 au zaidi**, kuunganisha upya kwa nasibu huwa ghali na feedback ya coverage haielekezi utafutaji.<sup>[[1]](#references)</sup>

**Athari:** kwa grammars zenye utegemezi mwingi, zingatia **kuunganisha awamu za mutational na generative** au kuelekeza generation kwenye mifumo ya **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Changamoto za Utofauti wa Corpus

Mutational inayochochewa na coverage ni **ya pupa**: sampuli yenye coverage mpya huhifadhiwa mara moja, na mara nyingi hubakiza sehemu kubwa zisizobadilika. Baada ya muda, corpora huwa na **nakala zinazokaribiana** na utofauti mdogo wa kimuundo. Minimization kali inaweza kuondoa muktadha muhimu, kwa hiyo suluhu ya vitendo ni **grammar-aware minimization** inayosimama baada ya kufikia **kiwango cha chini cha tokeni** (kupunguza kelele huku ikihifadhi muundo wa kutosha ili mutations ziendelee kuwa na manufaa).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya mbegu zenye miundo tofauti zinazoongeza coverage** badala ya rundo kubwa la nakala zinazokaribiana. Kwa kawaida, hili humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **sampuli za ulimwengu halisi** (corpora za umma, crawling, trafiki iliyorekodiwa, seti za faili kutoka kwenye mfumo wa target).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sampuli halali.
- Hifadhi mbegu **ndogo vya kutosha** ili mutations ziguse sehemu zenye maana badala ya kutumia muda mwingi kwenye byte zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora zaidi” hubadilika reachability inapobadilika.

## Mutation Inayozingatia Ulinganisho kwa Thamani za Magic

Sababu ya kawaida inayofanya fuzzers kufikia kikomo si sintaksia bali ni **ulinganisho mgumu**: magic bytes, ukaguzi wa urefu, maandishi ya enum, checksums, au thamani za parser dispatch zinazolindwa na `memcmp`, switch tables, au ulinganisho mfululizo. Mutation ya nasibu pekee hupoteza muda kujaribu kubahatisha thamani hizi byte baada ya byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano, workflows za AFL++ `CMPLOG` / Redqueen) ili fuzzer iweze kuona operands za ulinganisho ulioshindwa na kuelekeza mutations kwenye thamani zinazotimiza masharti hayo.<sup>[[3]](#references)</sup>

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

**Vidokezi vya vitendo:**

- Hii ni muhimu hasa pale target inapoweka mantiki ya ndani zaidi nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iunganishe na **dictionaries** zilizotolewa kutoka kwa sampuli halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, chunk names, verbs, na delimiters mara nyingi huwa na manufaa zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa target hufanya ukaguzi mwingi mfululizo, tatua kwanza ulinganishaji wa mapema zaidi wa “magic”, kisha punguza tena corpus inayotokana na hapo ili hatua zinazofuata zianze na prefixes ambazo tayari ni halali.

## Maoni Tajiri Zaidi Wakati Edge Coverage Inapounganisha Njia Tofauti

Edge coverage ya kawaida haiwezi kutofautisha executions mbili zinazopita kwenye helper ileile kupitia callers tofauti au kuchukua mchanganyiko tofauti wa branches ndani ya function. Hili ni muhimu katika shared decoders, protocol dispatchers, na interpreter helpers ambapo **njia** ya kufikia edge huamua hali iliyo hai. Kufuatilia kila calling context bila mpango pia ni hatari: coverage map na queue zinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zenye matumaini pekee badala ya kuchukulia call graph nzima kuwa context-sensitive.<sup>[[14]](#references)</sup>

Build za hivi karibuni za AFL++ hutoa **Ball-Larus per-function path coverage** pamoja na edge coverage ya kawaida. Hii huweka feature kwa kila njia isiyo na mizunguko kupitia function; loop back-edges huondolewa, kwa hiyo maoni haya hutofautisha mchanganyiko wa branches lakini **si idadi ya marudio ya loop**. Anza na kiwango kilicholegezwa cha `1`, kisha weka hali kali zaidi kwenye parser/state-machine code inayotia shaka, kwa sababu idadi ya njia inaweza kukua kwa kasi ya kielelezo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Kwa helper inayoitwa kutoka sehemu nyingi zinazohusiana na usalama, hali ya LTO inaweza kuunganisha njia ya kila function na call site yake ya moja kwa moja:<sup>[[13]](#references)</sup>

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

**Mwongozo wa kampeni:** tumia feedback yenye maelezo zaidi kwa tahadhari na ufuatilie gharama yake kwa coverage map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage sambamba; feedback yenye maelezo zaidi ina manufaa tu ikiwa gharama ya ziada ya queue/map haitapunguza executions per second.
- Tumia `AFL_LLVM_ALLOWLIST` kuwekea mipaka instrumentation ya path/caller wakati libraries kubwa zenye templates nyingi au generic utility code zinapotawala map.
- Functions zenye acyclic paths nyingi kupita kiasi zinaweza kurukwa na AFL++; warnings wakati wa compilation ni dalili kwamba target inahitaji allowlisting au kiwango kisicho kali sana.
- Caller + path coverage inaunga mkono kina kimoja tu cha caller. Usiichanganye na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya matoleo makuu ya LLVM. Tumia toolchain ileile katika kampeni nzima na usisawazishe corpora zinazotegemea PATH kana kwamba feature IDs zake ni thabiti kati ya builds.
- Feedback hii hukamilishana na `CMPLOG`: ufuatiliaji wa comparisons hutatua **ni thamani gani inapita guard**, ilhali feedback ya path/caller huhifadhi **ni njia gani na mchanganyiko gani wa branches ulioifikisha hapo**.

## Stateful Fuzzing: Mfuatano Ni Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, kitu cha kuvutia mara nyingi si blob moja bali ni **mfuatano wa messages**. Kuunganisha transcript nzima kwenye faili moja na kuibadilisha bila mpango kwa kawaida hakufai, kwa sababu fuzzer hubadilisha kila hatua kwa kiwango sawa, hata pale ambapo ni message ya baadaye tu inayofikia hali dhaifu.<sup>[[4]](#references)</sup>

Mbinu yenye ufanisi zaidi ni kuichukulia **sequence yenyewe kama seed** na kutumia **hali inayoonekana** (response codes, protocol states, parser phases, aina za objects zinazorudishwa) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Hifadhi **valid prefix messages** bila mabadiliko mengi na lenga mutations kwenye message inayoendesha **transition**.
- Hifadhi identifiers na thamani zinazozalishwa na server kutoka kwenye responses za awali pale ambapo hatua inayofuata inazihitaji.
- Pendelea mutation/splicing kwa kila message badala ya kubadilisha transcript nzima iliyoserialishwa kana kwamba ni blob isiyo na muundo.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **state oracle** ya gharama ndogo ili kuyapa kipaumbele ma sequences yanayofika hatua za ndani zaidi.

Hii ndiyo sababu hiyo hiyo inayofanya bugs zilizothibitishwa kwa authentication, transitions zilizofichwa, au parser bugs zinazotokea “baada tu ya handshake” zikosekanwe mara nyingi na file-style fuzzing ya kawaida: fuzzer lazima ihifadhi **mpangilio, hali na dependencies**, si muundo tu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing ya driver ya clients wengi

Edge coverage ya juu bado inaweza kukosa bugs za IPC driver kwa sababu coverage haielezi **umiliki wa objects, reference counts, messages zinazosubiri, mpangilio wa usafishaji, au interleavings za threads**. Ukurasa wa [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) unaeleza object model ya driver; mfano huu unalenga fuzzer harness. Android Binder ni mfano mzuri: kufikia njia za allocation na free zote mbili hakutoshi ikiwa fuzzer haiwezi kufanya processes nyingi zifanye kazi kwenye kernel object ileile kwa mpangilio unaohitajika.<sup>[[15]](#references)</sup>

#### Modeli ya protocol, si buffers za `ioctl` zilizotengwa

Wakilisha test case kama grammar iliyopangwa ya **utambulisho wa client + operesheni + arguments zenye muundo**. Binder LKL fuzzer hutumia protobuf na `libprotobuf-mutator`, ikiwa na client mmoja endelevu wa context-manager na clients wawili wa kawaida. Kisha semantic harness huhifadhi mahusiano ambayo mutation ya bytes bila mpango ingeharibu.<sup>[[15]](#references)</sup>

- Hifadhi thamani zilizorejeshwa na operations za awali. Kwa mfano, `BC_FREE_BUFFER` lazima itumie tena pointer ya transaction-buffer iliyorejeshwa na `ioctl` ya awali.
- Tengeneza replies chaguomsingi halali ili transactions za synchronous zikamilike na operations za baadaye ziweze kufikiwa.
- Kataa transitions zisizowezekana kama vile self-transactions au transactions nyingi zinazosubiri kwa target ileile.
- Weka hali ya singleton bootstrap nje ya reset ya kila input. Binder huruhusu usajili mmoja tu wa `BINDER_SET_CONTEXT_MGR` kwa kila boot, kwa hiyo kuharibu na kuunda upya client huyo mara kwa mara kungefanya inputs za baadaye zisiwe halali.

Kiolezo kizuri cha lifetime-race ni kufanya client mmoja ahamishe object, kuanzisha usafishaji wa thread au process, na wakati huohuo kufanya client inayopokea i-release transaction buffer. Katika mfano wa CVE-2020-0423, uhamisho wa `BINDER_TYPE_WEAK_BINDER` uliofuatwa na `BINDER_THREAD_EXIT` ikigongana na `BC_FREE_BUFFER` ungeweza kufree `binder_work` iliyopachikwa wakati cleanup path ya thread inayotoka bado inaitumia.<sup>[[15]](#references)</sup>

#### Kurejesha interleavings zinazodhibitiwa kwenye kernel ya userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) huunganisha code halisi ya kernel kwenye userspace harness na kufichua syscall interface yake kupitia `lkl_syscall`. Hii hurahisisha kuratibu protobuf state, coverage na KASAN ndani ya process moja. Hata hivyo, LKL kwa kawaida huendesha syscall bila kernel thread nyingine kuikatiza. Kwa kampeni za race, weka sehemu za `schedule()` karibu na mipaka maalum ya lock/unlock na lifetime, kisha iache harness ichague kwa nasibu client inayofuata katika kila yield. Lenga sehemu hizi kwa uangalifu kwa sababu kila moja huongeza mara nyingi ukubwa wa scheduling search space. Randomized scheduler iliyoelezwa na watafiti **si** sehemu ya Binder fuzzer ya upstream.<sup>[[15]](#references)</sup>

#### Build na replay ya serialized regression seeds

Harness ya upstream hufunga toleo linalooana la `libprotobuf-mutator`, huwasha LKL fuzzing instrumentation na KASAN kwa `LKL_FUZZING=1`, na huwasha `CONFIG_MMU` kwa Binder kwa kutumia `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Baada ya kuangalia revision iliyoachwa ikiwa hatarishi kimakusudi au kutumia rollback patches zilizoandikwa kwenye upstream, seed iliyoserialishwa inaweza kurudia mabadiliko yote ya hali ya clients wengi bila kuyaunda upya katika proof of concept ya C ya dharura:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Chukulia KASAN use-after-free iliyopatikana kama uthibitisho kwamba seed ilifikia njia ya lifetime iliyo hatarini. Hii **haithibitishi** primitives za baadaye zinazohitajika kwa ajili ya kutekeleza code ya kernel au kupandisha privilege.<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **uvumbuzi unaozalishwa** na **matumizi upya ya coverage** ni **kuanzisha upya workers wa muda mfupi** dhidi ya server inayoendelea kufanya kazi. Kila worker huanza na corpus tupu, husawazisha baada ya sekunde `T`, huendesha kwa sekunde nyingine `T` kwa kutumia corpus iliyounganishwa, husawazisha tena, kisha hutoka. Hii huzalisha **miundo mipya katika kila kizazi** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers wa mfuatano (mfano wa loop):**

<details>
<summary>Loop ya kuwasha upya worker wa Jackalope</summary>

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

**Maelezo:**

- `-in empty` hulazimisha **corpus mpya** katika kila kizazi.
- `-server_update_interval T` hukaribia **usawazishaji uliocheleweshwa** (ugunduzi wa vipya kwanza, utumiaji upya baadaye).
- Katika hali ya grammar fuzzing, **usawazishaji wa awali wa server hurukwa kwa chaguomsingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora zaidi **hutegemea target**; kubadilisha baada ya worker kupata sehemu kubwa ya coverage “rahisi” kwa kawaida hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Targets Ngumu Kuweka Kwenye Harness

Wakati code unayotaka kupima inafikiwa tu **baada ya gharama kubwa ya usanidi** (kuwasha VM, kukamilisha login, kupokea packet, kuchanganua container, kuanzisha service), mbadala muhimu ni **snapshot fuzzing**: kunasa hali ya process au VM iliyo tayari, kuingiza kila test case kwenye njia ya ingizo ya target, kutekeleza hadi crash/timeout, kisha kurejesha snapshot. Hii huepusha kurudia uanzishaji au viambishi awali vya protocol, na ni muhimu kwa **network services**, **firmware**, **attack surfaces za baada ya uthibitishaji**, na **targets za binary-only**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayokuvutia iwe tayari.
2. Piga snapshot ya **memory + registers** wakati huo.
3. Kwa kila test case, andika ingizo lililobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Tekeleza hadi crash/timeout/reset.
5. Rejesha snapshot; kwa targets za VM, rejesha **dirty pages** pekee inapoungwa mkono, kisha urudie.

Weka snapshot karibu kadiri inavyowezekana na hatua ya kwanza ya gharama kubwa ya kuchanganua/kusambaza, kama vile baada ya `recv`/`read` au sehemu ya uondoaji wa mfuatano wa packet, na rekodi input buffer inayotumiwa na target. Hii hufuata kanuni ya uwekaji unaobadilika: kuhamisha snapshot ndani zaidi ya uchakataji wa ingizo ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Uchunguzi wa Harness: Tambua Fuzzers Zisizoingia Kina Mapema

Kampeni inapokwama, mara nyingi tatizo si mutator bali ni **harness**. Tumia **uchunguzi wa reachability/coverage** kutafuta functions zinazoweza kufikiwa kistatik kutoka kwenye fuzz target yako lakini ambazo hufunikwa mara chache au hazifunikwi kamwe kwa njia ya runtime. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness huingia kwenye target ikiwa imechelewa sana au mapema sana.
- Seed corpus haina familia nzima ya vipengele.
- Target inahitaji **harness ya pili** badala ya harness moja kubwa mno ya “kufanya kila kitu”.

Ukitumia mifumo ya kazi ya aina ya OSS-Fuzz / ClusterFuzz, Fuzz Introspector inaweza kulinganisha reachability ya kistatik na runtime coverage na kutengeneza ripoti kutoka kwa run yenye muda maalum au corpus ya umma.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Tumia ripoti kuamua ikiwa uongeze harness mpya kwa parser path ambayo haijajaribiwa, upanue corpus kwa kipengele fulani, au ugawanye harness kubwa moja kuwa entry point ndogo zaidi.

## Uteuzi wa Fuzz Target kwa Kuanza na Graph na Triage ya Mutation

Ikiwa tayari una **matokeo ya static analysis**, **mutant walionusurika kwenye mutation testing**, na **ripoti za coverage**, usizichambue kama orodha zisizohusiana. Tengeneza **call graph** kwanza, weka kwenye nodes maelezo ya **cyclomatic complexity**, **ufikikaji kutoka entrypoint/input isiyoaminika**, na matokeo yoyote ya nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinazoweza kufikiwa kutoka kwenye input isiyoaminika?
- Ni mutant gani walionusurika walio kwenye njia kutoka kwa parsers/handlers hadi kwenye code muhimu kwa usalama?
- Ni functions zipi ni sehemu muhimu za usanifu zenye **blast radius** kubwa isivyo kawaida?

Kwa kawaida, hili hubainisha fuzz targets bora zaidi kuliko kuangalia "coverage ya chini zaidi" pekee. Parser/decoder yenye **complexity kubwa** na **ufikikaji wa nje uliothibitishwa** ni mgombea bora zaidi wa harness kuliko internal helper isiyohusiana, yenye coverage dhaifu lakini isiyo na njia inayodhibitiwa na mshambulizi.

### Mchakato wa vitendo wa triage

1. Tengeneza **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branch kwa kila function.
2. Orodhesha **entrypoints** zinazopokea input inayodhibitiwa na mshambulizi: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Tekeleza **path queries** kutoka kwa entrypoints hadi kwenye functions zinazoweza kuchaguliwa ili kutenganisha attack surface inayoweza kufikiwa na code iliyokufa/ya ndani pekee.
4. Zipe kipaumbele nodes zinazochanganya:
   - **cyclomatic complexity** kubwa
   - **ufikikaji kutoka input isiyoaminika** uliothibitishwa
   - **blast radius** kubwa au dependents wengi wa chini
   - ushahidi unaounga mkono kama matokeo ya **SARIF**, maelezo ya ukaguzi, au mutant walionusurika
5. Andika harness maalum kwa nodes zenye alama bora zaidi kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutant walionusurika: equivalent au actionable

Mutation testing mara nyingi hutoa orodha yenye kelele ya mutant walionusurika. Kabla ya kuchukulia kila mmoja kama pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka kwenye entrypoint inayodhibitiwa na mshambulizi?
- Je, njia zote za kuita function zimewekewa vigezo thabiti zaidi kuliko ukaguzi uliobadilishwa?
- Je, node hiyo iko kwenye code iliyokufa, logic ya uumbizaji pekee, au njia yenye athari kubwa ya arithmetic/parser?

Mutant wanaobaki bila kufikika au waliozuiliwa kimuundo mara nyingi ni **equivalent mutants**. Mutant wanaobaki **wanaoweza kufikiwa** na kugusa **boundary conditions**, **overflow/carry paths**, au **arithmetic/parsing muhimu kwa usalama** wanapaswa kupewa kipaumbele na kuongezwa kwenye:

- harness mpya za fuzz
- majaribio ya moja kwa moja ya property/invariant
- vectors maalum za edge case

### Linganisha matokeo ya nje na graph

Ikiwa pipeline yako ya SAST inatoa **SARIF**, weka matokeo kwenye nodes za graph kwa kutumia **file + line range**, kisha tumia graph kupanua wigo wa athari.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya function iliyoalamishwa
- angalia ikiwa matokeo yako kwenye njia yoyote kutoka kwa entrypoint
- panga matokeo ya karibu ambayo yanaelekeza kwenye choke point moja

Hii ni muhimu unapoamua kama utatumia muda wa fuzzing kwenye function fulani: node **inayoweza kufikiwa**, **changamano**, na tayari yenye **matokeo ya SAST** mara nyingi ni target bora kuliko node changamano tu isiyo na njia ya mshambulizi.

Mfano wa workflow ukitumia Trailmark.<sup>[[6]](#references)</sup>

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

Mbinu muhimu ni makutano ya: **utata x uwezekano wa kufikiwa x athari**. Tumia grafu kuchagua malengo ya fuzz yenye thamani kubwa zaidi ya usalama inayotarajiwa, kisha tumia mutation survivors kubaini mipaka na invariants ambazo harness yako inapaswa kujaribu kwa ukali.<sup>[[5]](#references)</sup>

## Fuzzing ya Go kwa gosentry: Injini Imara Zaidi, Ingizo Zenye Aina, na Ukaguzi Linganishi

Ikiwa target ya Go tayari ina harness ya asili ya `testing.F`, njia ya vitendo ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), Go toolchain iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Hii ni muhimu wakati Go fuzzer ya asili inakwama kwenye **ulinganishi mgumu**, **inputs zenye aina maalum**, au **miundo inayotegemea sana parser**. Mbinu hubaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia campaign inayotokana na hilo kama run ya kawaida inayoongozwa na coverage, lakini yenye scheduling/mutation ya LibAFL na detectors za ziada zilizo bora zaidi.

### Geuza hitilafu zisizoonekana kuwa matokeo ya fuzzing

Tatizo linalojirudia katika tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa chaguo-msingi. Kwa gosentry, unaweza kubadilisha aina kadhaa za hali “mbaya lakini zisizoonekana” kuwa findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili njia teule za logging/error zitende kama crashes (inafaa kwa njia za msimbo za aina ya `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kurudia entries mpya zilizogunduliwa kwenye queue kwa kutumia Go race detector.
- `--catch-leaks=true` ili kurudia entries mpya kwenye queue kwa kutumia `goleak` na kusimama kunapovuja goroutine.
- Ushughulikiaji wa hang wa LibAFL ili kuhifadhi **loops zisizo na kikomo / inputs zinazoendelea polepole sana** kama findings za fuzzing badala ya kuziacha zipotee kama timeouts.
- Ukaguzi wa arithmetic overflow uliojengewa ndani kwa chaguo-msingi, pamoja na ukaguzi wa hiari wa truncation kupitia instrumentation ya mtindo wa go-panikint.

Hili ni muhimu hasa kwa targets ambazo athari ya kiusalama ni **hitilafu ya parser isiyosababisha panic**, **hitilafu ya concurrency**, au **hang inayosababisha DoS pekee**, badala ya uharibifu wa memory.

### Fuzzing inayozingatia struct kwa API za Go zenye aina maalum

Go fuzzing ya asili hutarajia hasa scalars kama `[]byte`, `string`, na nambari. Ikiwa msimbo unaojaribiwa hutumia objects zenye aina maalum, gosentry inaweza kufuzz **values changamano** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kufanya mutation ya bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>

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

Tumia hili unapounda wire format bandia kwa ajili ya fuzzing pekee, kwani parsing code inayotumika kwenye harness pekee inaweza kuficha hitilafu za logic. Kwa kampeni za differential au grammar-based, weka input ya harness kama `[]byte` au `string` moja, kisha ufanye parsing ndani ya callback.

### Grammar-based fuzzing kwa parser na input za protocol

Kwa parser, format na lugha za input, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni safu ya JSON yenye production rules, na kwa kawaida harness inapaswa kuchukua argument moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Maelezo kuhusu mbinu:

- Tumia grammar mode wakati mutations za byte-level mara nyingi hushindwa kwenye ukaguzi wa awali wa sintaksia.
- Elekeza grammar kwenye **sehemu ndogo ya lugha/protocol inayohusika na usalama** badala ya kuiga specification nzima.
- Tumia thamani kubwa za mipaka kwenye terminals/nonterminals ili kujaribu mipaka ya integer, urefu na state machine.
- Grammar mode huhakikisha inputs zinazingatia grammar, lakini target bado hupokea **bytes/strings**, kwa hiyo uchanganuzi na ukaguzi wa kisemantiki hubaki ndani ya code inayotumika na harness.

### Differential fuzzing: linganisha implementations, si crashes tu

Mbinu bora kwa mifumo ya Go ni **grammar-based differential fuzzing**: tengeneza inputs halali na zenye muundo, kisha uzitumie kwa parsers, clients au engines mbili za state-transition.<sup>[[7]](#references)[[8]](#references)</sup>

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

Chukulia yafuatayo kuwa ni matokeo:

- implementation moja inapata panic huku nyingine ikikataa kwa usahihi
- kutolingana kwa ingizo linalokubaliwa/kukataliwa
- parse trees au decoded objects tofauti
- state transitions, nonces, balances, au state roots zinazotofautiana

Hii ni njia ya vitendo ya kupata **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo mara nyingi hazigunduliki kwa crash fuzzing pekee.

### Tumia tena campaign corpus kwa kuripoti coverage

Baada ya campaign, cheza tena corpus ya queue iliyohifadhiwa ili kutengeneza ripoti ya Go coverage bila kuhamisha corpus tofauti mwenyewe.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Tekeleza amri kutoka kwenye package hiyo hiyo na utumie target ile ile ya -fuzz ili gosentry itambue hali sahihi ya kampeni iliyohifadhiwa kwenye cache.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing kwa Kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Miaka Mitano Baadaye: Kuhusu Protocol Fuzzing Inayoongozwa na Coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hubadilisha code kuwa grafu](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya zana. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Greybox Fuzzer ya Haraka kwa Stateful Network Protocols kwa kutumia Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Bila Grammar, Hakuna Tatizo: Kuelekea Kufuzz Linux Kernel bila Maelezo ya System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing Bora kwa kutumia Snapshots Zinazobadilika na Kubadilishwa Kulingana na Hali](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: coverage ya njia na caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing ya Muktadha Inayotabiri](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - nyaraka za build na regression-seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
