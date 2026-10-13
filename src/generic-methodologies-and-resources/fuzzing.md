# Mbinu ya Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **halali kisarufi**. Katika hali inayoongozwa na coverage, ni sampuli zinazosababisha **coverage mpya** pekee zinazohifadhiwa kama corpus seeds. Kwa **malengo ya lugha** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **minyororo ya semantic/dataflow** ambapo matokeo ya construct moja huwa input ya nyingine.<sup>[[1]](#references)</sup>

**Hali ya kushindwa:** fuzzer hupata seeds zinazojaribu `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haidumishi dataflow iliyounganishwa**, kwa hiyo sampuli “iliyo karibu zaidi na bug” hutupwa kwa sababu haiongezi coverage. Kwa **hatua tegemezi 3 au zaidi**, kuchanganya upya kwa nasibu huwa ghali, na mrejesho wa coverage hauongozi utafutaji.<sup>[[1]](#references)</sup>

**Athari:** kwa grammars zenye utegemezi mwingi, fikiria **kuunganisha awamu za mutational na generative** au kuelekeza generation zaidi kwenye mifumo ya **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Mitego ya Utofauti wa Corpus

Mutation inayoongozwa na coverage ni **greedy**: sampuli yenye coverage mpya huhifadhiwa mara moja, na mara nyingi hubakiza sehemu kubwa ambazo hazijabadilika. Kadiri muda unavyopita, corpora huwa **nakala zinazokaribiana** zenye utofauti mdogo wa kimuundo. Minimization kali inaweza kuondoa muktadha muhimu, kwa hiyo suluhu ya kati inayofaa ni **grammar-aware minimization** ambayo **husimama baada ya kufikia kiwango cha chini cha tokeni** (kupunguza kelele huku ikihifadhi muundo wa kutosha unaorahisisha mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye miundo tofauti zinazoongeza coverage** badala ya rundo kubwa la nakala zinazokaribiana. Kwa kawaida, hii humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **sampuli za matumizi halisi** (corpora za umma, crawling, traffic iliyonaswa, seti za faili kutoka kwenye ecosystem ya target).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sampuli halali.
- Hifadhi seeds **ndogo vya kutosha** ili mutations zilenge fields zenye maana badala ya kutumia muda mwingi kwenye bytes zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa kwenye harness/instrumentation, kwa sababu corpus “bora zaidi” hubadilika reachability inapobadilika.

## Mutation Inayozingatia Ulinganishaji kwa Magic Values

Sababu ya kawaida inayofanya fuzzers kukwama si syntax bali ni **ulinganishaji mkali**: magic bytes, ukaguzi wa urefu, enum strings, checksums, au thamani za parser dispatch zinazolindwa na `memcmp`, switch tables, au mfululizo wa ulinganishaji. Mutation ya nasibu pekee hupoteza muda ikijaribu kubashiri thamani hizi byte baada ya byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano, workflows za AFL++ `CMPLOG` / Redqueen) ili fuzzer iweze kuona operands kutoka kwenye ulinganishaji ulioshindwa na kuelekeza mutations kwenye thamani zinazotimiza masharti hayo.<sup>[[3]](#references)</sup>

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

**Maelezo ya vitendo:**

- Hii ni muhimu sana wakati target inaweka mantiki ya ndani nyuma ya **saini za faili**, **vitenzi vya protocol**, **lebo za aina**, au **bit za vipengele vinavyotegemea toleo**.
- Iunganishe na **dictionaries** zilizotolewa kutoka kwa sampuli halisi, specs za protocol, au logi za utatuzi. Dictionary ndogo yenye tokeni za sarufi, majina ya chunk, vitenzi na vitenganishi mara nyingi huwa na manufaa zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa target hufanya ukaguzi mwingi unaofuatana, suluhisha kwanza ulinganishaji wa mapema zaidi wa “magic”, kisha punguza tena corpus inayotokana nao ili hatua zinazofuata zianze na prefixes ambazo tayari ni halali.

## Fuzzing API za Faili Zinazoficha Lugha ya Majina ya Faili

Kigezo kinachoitwa `filename`, `path`, au `URL` kinaweza kuwa sehemu ya kuingilia ya interpreter badala ya utafutaji wa faili halisi. Kwa mfano, CFITSIO Extended Filename Syntax (EFS) hutathmini selectors zilizo ndani ya mabano, expressions za safu/safu ya pikseli, safu zilizokokotolewa, histograms na transformations kabla ya kurudisha object iliyofunguliwa; baadhi ya miundo pia huunda nakala za muda. Unapochora ramani ya attack surface, ainisha kila API ya kufungua/kuingiza kama **literal-path** au **interpreted-path**, kisha fanya fuzzing kwenye sehemu ya kuingilia ya production ambayo programu hutumia hasa.<sup>[[20]](#references)[[22]](#references)</sup>

Kwa primitives zinazotokana na SSRF, kunakili faili na protocol handlers—pamoja na API salama zaidi za literal-path—tazama [Lugha ndogo za majina ya faili kama primitives za SSRF/faili](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Weka object ya msingi tofauti na programu inayofanyiwa fuzzing

Sarufi inapokuwa ndani ya kiambishi tamati cha jina la faili, kubadilisha tu byte za faili husika hakutafikia parser. Badala yake, harness ndogo inaweza kusoma testcase moja kama string na kuipitisha kwa API ya kufungua iliyointerpretwa; kampeni ya CFITSIO ilifikia parser na evaluator nyingi za EFS kwa kuita `fits_open_file()` katika hali ya kusoma pekee. Weka faili halali za msingi zikipatikana kando ili mutations zielekezwe kwenye lugha ya selector/expression badala ya kuharibu mara kwa mara path ya msingi.<sup>[[22]](#references)</sup>

Tumia seeds ambazo kila moja hufikia familia tofauti ya sarufi, kisha tengeneza dictionary fupi kutoka kwenye spec na source ya lexer/parser. Ikiwa coverage itafikia kikomo huku inputs zikishindwa mara kwa mara kwenye njia ileile ya syntax-error, hifadhi prefixes halali na uongeze delimiters, operators, keywords, majina ya function na majina wakilishi ya field badala ya kuongeza tu muda wa random mutation.<sup>[[22]](#references)</sup>

Endesha harness kwa kutumia dictionary ya sarufi, kwa mfano:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Zuia athari za pembeni za harness ya "read-only"

Bendera ya library ya read-only haihakikishi kuwa testcase haina athari za pembeni: lugha ya majina ya faili inaweza kuandika upya ingizo, kuunda faili za matokeo, au kutengeneza vitu vya muda. Kampeni ya CFITSIO mwanzoni iliharibu seed files na kuacha faili zisizotarajiwa katika mfumo mzima wa faili, hivyo usafishaji na utengaji vilihitajika.<sup>[[22]](#references)</sup>

- Mpe kila worker working directory inayoweza kutupwa na temporary directory ya faragha.
- Toa nakala za backing files za msingi; usiruhusu target ibadilishe nakala pekee ya corpus.
- Zima ufikiaji wa mtandao isipokuwa backends za mbali ndizo zinazolengwa, na zuia njia zinazoweza kuandikika kwa kutumia container, mount namespace, au sandbox sawa.
- Weka upya directory baada ya kila execution au kundi la worker na uchukulie mabadiliko yasiyotarajiwa ya mfumo wa faili kama findings za ziada.

### Mzunguko wa crash-to-patch-to-fuzz

Panga crashes katika makundi kabla ya kurekebisha ili maelfu ya artifacts yasigeuke kuwa maelfu ya kazi za patch. Katika tathmini ya CFITSIO, AFLTriage ilipunguza seti ya awali ya crashes hadi sababu chache za msingi; advisory iliyotokana nayo inaonyesha hitilafu tofauti, zikiwemo ukaguzi usio sahihi wa ukubwa wa destination, pointers zilizopitwa na wakati baada ya `realloc()`, hitilafu za hesabu, na njia zisizo salama za kusafisha parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Punguza ingizo wakilishi kwa kila kundi na uzalishe tatizo hilo tena kwa kutumia AddressSanitizer.
2. Rekodi ufikiaji halisi ulioshindwa, eneo kwenye source, historia ya allocation/free, na hali ya parser iliyosababisha invariant kuwa si kweli.
3. Tumia patch moja yenye wigo finyu na ujenge upya kwa kutumia instrumentation ileile ya coverage na sanitizer.
4. Cheza tena reproducer ya awali **na kila ingizo katika kundi lake**; pia washa ugunduzi wa leak kwa sababu marekebisho ya memory-safety yanaweza kuvunja umiliki wa kumbukumbu kwenye njia ya hitilafu.
5. Endesha majaribio ya utendaji kwa kutumia faili halisi, kisha endelea kutoka kwenye queue iliyokusanywa (au ingiza queue hiyo tena ikiwa engine inahitaji output directory mpya baada ya binary kubadilika).
6. Rudia: kuondoa crash ya kwanza ya juu juu mara nyingi huruhusu seeds zilizopo kufikia hali ya ndani zaidi ya parser.

LLM inaweza kuharakisha hatua ya 2 na kuandaa rasimu ya hatua ya 3 ikipewa ingizo lililosababisha crash, ripoti ya sanitizer, harness, na source husika, lakini patch yake bado haiaminiki. Replay ya sanitizer na vigezo vya regression—si maelezo ya model—ndivyo vinavyoamua kama marekebisho yatakubaliwa.<sup>[[22]](#references)</sup>

## Feedback Tajiri Zaidi Edge Coverage Inapounganisha Njia Tofauti

Edge coverage ya kawaida haiwezi kutofautisha executions mbili zinazopitia helper ileile kupitia callers tofauti au zinazochukua mchanganyiko tofauti wa branches ndani ya function. Hili ni muhimu katika shared decoders, protocol dispatchers, na interpreter helpers ambamo **njia** ya kufikia edge huamua hali iliyo hai. Kufuatilia kila calling context kwa njia ya moja kwa moja pia ni hatari: coverage map na queue vinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zinazoonekana kuwa na matumaini pekee badala ya kuchukulia call graph nzima kuwa context-sensitive.<sup>[[14]](#references)</sup>

Build za hivi majuzi za AFL++ hutoa **Ball-Larus per-function path coverage** pamoja na edge coverage ya kawaida. Huipa kila njia isiyo na mizunguko ndani ya function kipengele chake; loop back-edges huondolewa, kwa hiyo feedback hii hutofautisha mchanganyiko wa branches lakini **si idadi ya marudio ya loop**. Anza na level `1` isiyo kali sana, kisha tumia modes kali zaidi kwa upeo mdogo kwenye msimbo wa parser/state-machine unaotia shaka, kwa sababu idadi ya njia inaweza kukua kwa kasi ya kielelezo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Kwa helper inayoitwa kutoka sehemu nyingi zinazohusika na usalama, hali ya LTO inaweza kuunganisha kila njia ya function na call site yake ya moja kwa moja:<sup>[[13]](#references)</sup>

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

**Mwongozo wa kampeni:** tumia feedback yenye maelezo zaidi kwa uangalifu na ufuatilie gharama yake kwenye coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage sambamba; feedback yenye maelezo zaidi inafaa tu ikiwa gharama ya ziada ya queue/map haiharibu idadi ya executions kwa sekunde.
- Tumia `AFL_LLVM_ALLOWLIST` kuweka kikomo cha path/caller instrumentation pale ambapo libraries kubwa zenye templates nyingi au code ya matumizi ya jumla zinatawala map.
- Kazi zenye acyclic paths nyingi kupita kiasi zinaweza kurukwa na AFL++; maonyo wakati wa compilation ni ishara kwamba target inahitaji allowlisting au kiwango kisicho kali sana.
- Caller + path coverage inasaidia kina kimoja tu cha caller. Usichanganye na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya matoleo makuu ya LLVM. Dumisha toolchain ileile kwa kampeni nzima na usisawazishe corpora za PATH kana kwamba feature IDs zake ni thabiti kati ya builds.
- Feedback hii inakamilisha `CMPLOG`: ufuatiliaji wa comparisons hutatua **ni thamani gani inayopita guard**, ilhali feedback ya path/caller huhifadhi **ni njia gani na mchanganyiko gani wa branches ulioifikisha hapo**.

## Fuzzing yenye hali: Mifuatano ni Seeds

Kwa **protocols**, **workflows zinazohitaji uthibitishaji**, na **parsers za hatua nyingi**, kitu cha kuvutia mara nyingi si blob moja bali **mfuatano wa messages**. Kuunganisha transcript nzima kwenye faili moja na kuibadilisha bila mpangilio kwa kawaida hakufai, kwa sababu fuzzer hubadilisha kila hatua kwa kiwango sawa, hata pale ambapo message ya baadaye pekee ndiyo inayofikia hali dhaifu.<sup>[[4]](#references)</sup>

Mbinu bora zaidi ni kuchukulia **mfuatano wenyewe kama seed** na kutumia **hali inayoonekana** (response codes, protocol states, parser phases, aina za objects zinazorudishwa) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Hifadhi messages halali za mwanzo bila kuzibadilisha na lenga mabadiliko kwenye message **inayoendesha mabadiliko ya hali**.
- Hifadhi identifiers na thamani zinazozalishwa na server kutoka kwenye responses zilizotangulia, pale hatua inayofuata inapozitegemea.
- Pendelea mutation/splicing ya kila message kivyake badala ya kubadilisha transcript nzima iliyoserialishwa kama blob isiyoeleweka.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **oracle ya hali ya gharama nafuu** ili kuzipa kipaumbele sequences zinazoendelea zaidi.

Hii ndiyo sababu ileile inayofanya bugs zinazohitaji uthibitishaji, mabadiliko ya hali yaliyofichwa, au bugs za parser zinazotokea “baada tu ya handshake” mara nyingi zikosekane na fuzzing ya kawaida ya mtindo wa faili: fuzzer lazima ihifadhi **mpangilio, hali, na utegemezi**, si muundo tu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing ya driver yenye clients wengi

Coverage kubwa ya edges bado inaweza kukosa bugs za IPC-driver kwa sababu coverage haielezi **umiliki wa objects, reference counts, messages zinazosubiri, mpangilio wa cleanup, au jinsi threads zinavyopishana**. Ukurasa wa [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) unaeleza muundo wa objects wa driver; mfano huu unaangazia harness ya fuzzer. Android Binder ni mfano mzuri: kufikia njia za allocation na free hakutoshi ikiwa fuzzer haiwezi kusababisha processes nyingi kufanya kazi kwenye kernel object ileile kwa mpangilio unaohitajika.<sup>[[15]](#references)</sup>

#### Modeli protocol, si buffers za `ioctl` zilizotengwa

Wakilisha test case kama grammar iliyopangwa ya **utambulisho wa client + operesheni + arguments zenye muundo**. Binder LKL fuzzer hutumia protobuf na `libprotobuf-mutator`, ikiwa na client mmoja wa context-manager inayodumu na clients wawili wa kawaida. Kisha harness ya kisemantiki huhifadhi mahusiano ambayo mutation ya byte bila mpangilio ingeharibu.<sup>[[15]](#references)</sup>

- Hifadhi thamani zinazorudishwa na operesheni za awali. Kwa mfano, `BC_FREE_BUFFER` lazima itumie tena pointer ya transaction-buffer iliyorudishwa na `ioctl` iliyotangulia.
- Tengeneza replies halali za msingi ili transactions za synchronous ziweze kukamilika na operesheni za baadaye zibaki kufikika.
- Kataa mabadiliko ya hali yasiyowezekana, kama vile transactions za client kujielekezea yenyewe au transactions nyingi zinazosubiri kwa target ileile.
- Hifadhi hali ya singleton ya bootstrap nje ya reset ya kila input. Binder huruhusu registration moja tu ya `BINDER_SET_CONTEXT_MGR` kwa kila boot, hivyo kuendelea kuharibu na kuunda upya client hiyo kungefanya inputs za baadaye zisihalali.

Muundo wa race ya lifetime unaofaa ni kufanya client mmoja ihamishe object, kuanzisha cleanup ya thread au process, na kwa wakati huohuo kufanya client inayopokea iachilie transaction buffer. Katika mfano wa CVE-2020-0423, uhamishaji wa `BINDER_TYPE_WEAK_BINDER` ukifuatiwa na `BINDER_THREAD_EXIT` unaotokea wakati mmoja na `BC_FREE_BUFFER` ungeweza kuachilia `binder_work` iliyopachikwa, huku njia ya cleanup ya thread inayotoka ikiwa bado inaitumia.<sup>[[15]](#references)</sup>

#### Rejesha interleavings zinazodhibitiwa kwenye kernel ya userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) huunganisha code halisi ya kernel kwenye harness ya userspace na kufichua syscall interface yake kupitia `lkl_syscall`. Hii hurahisisha kuratibu protobuf state, coverage, na KASAN katika process moja. Hata hivyo, LKL kwa kawaida huendesha syscall bila thread nyingine ya kernel kuikatiza. Kwa kampeni za race, weka sehemu za `schedule()` karibu na mipaka iliyochaguliwa ya lock/unlock na lifetime, kisha uruhusu harness ichague client inayofuata bila mpangilio kila inapofikia yield. Weka sehemu hizi mahususi, kwa sababu kila moja huongeza mara nyingi nafasi ya utafutaji wa scheduling. Randomized scheduler iliyoelezwa na watafiti **si sehemu ya Binder fuzzer ya upstream**.<sup>[[15]](#references)</sup>

#### Jenga na urudie seeds za regression zilizoserialishwa

Harness ya upstream hufunga toleo linalooana la `libprotobuf-mutator`, huwasha instrumentation ya LKL fuzzing na KASAN kwa kutumia `LKL_FUZZING=1`, na huwasha `CONFIG_MMU` kwa Binder kwa kutumia `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Baada ya kuangalia toleo lililo hatarini kimakusudi au kutumia patches za rollback zilizoelezwa upstream, seed iliyoserialishwa inaweza kurudia mabadiliko yote ya hali ya multi-client bila kuyaunda upya katika proof of concept ya C iliyotengenezwa kwa dharura:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Chukulia use-after-free ya KASAN iliyotokana na hili kuwa uthibitisho kwamba seed ilifika kwenye njia hatarishi ya lifetime. Haionyeshi primitives za baadaye zinazohitajika kwa ajili ya utekelezaji wa code ya kernel au privilege escalation.<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **generative novelty** na **coverage reuse** ni **kuanzisha upya workers wanaodumu kwa muda mfupi** dhidi ya server inayoendelea kufanya kazi. Kila worker huanza na corpus tupu, husawazisha baada ya sekunde `T`, huendesha tena kwa sekunde nyingine `T` kwa kutumia corpus iliyounganishwa, husawazisha tena, kisha hutoka. Hii huzalisha **miundo mipya katika kila kizazi** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` hulazimisha **fresh corpus** katika kila kizazi.
- `-server_update_interval T` hukadiria **delayed sync** (ubunifu kwanza, kutumia tena baadaye).
- Katika hali ya grammar fuzzing, **initial server sync hurukwa kwa chaguomsingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadilisha baada ya worker kupata sehemu kubwa ya coverage “rahisi” kwa kawaida hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Targets Ngumu Kuandaa

Wakati code unayotaka kujaribu inapofikiwa tu **baada ya gharama kubwa ya usanidi** (kuwasha VM, kukamilisha kuingia, kupokea packet, kuchanganua container, kuanzisha service), njia mbadala muhimu ni **snapshot fuzzing**: hifadhi hali ya mchakato au VM iliyo tayari, ingiza kila test case kwenye njia ya input ya target, endesha hadi crash/timeout, kisha rejesha snapshot. Hii huepusha kurudia uanzishaji au viambishi awali vya protocol na ni muhimu kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayokuvutia iwe tayari.
2. Hifadhi snapshot ya **memory + registers** wakati huo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Endesha hadi crash/timeout/reset.
5. Rejesha snapshot; kwa targets za VM, rejesha **dirty pages** pekee inapoungwa mkono, kisha urudie.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya parse/dispatch, kama vile baada ya `recv`/`read` au sehemu ya packet-deserialization, na rekodi input buffer inayotumiwa na target. Hii hufuata kanuni ya uwekaji unaobadilika kwa kuhamisha snapshot ndani zaidi ya uchakataji wa input ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Kuchunguza Linux Kernel Race Kwa MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) hubadilisha Linux-kernel races zinazotegemea muda kuwa ratiba za ufikiaji wa memory zinazoweza kurudiwa. Inaweza kuorodhesha kiotomatiki utekelezaji wa **A-B-A** wa contexts mbili au kumruhusu mchambuzi kuweka vikwazo vya mpangilio kupitia terminal UI/GUI. Hiki ni kifaa cha majaribio ya utafiti, si concurrency fuzzer kamili: kwa sasa kinahitaji LLVM 23+ na kernel ya mradi iliyofanyiwa marekebisho, zana za command-line zinaunga mkono test threads mbili, na safu inayopendekezwa ya userspace fuzzing haijatekelezwa.<sup>[[17]](#references)[[18]](#references)</sup>

### Kukusanya sehemu za mawasiliano kati ya contexts

Jenga kernel yenye instrumentation kwa kutumia KASAN outline callbacks na msaada wa patched KCOV wa kurekodi memory. README ya mradi pia inapendekeza kuzima sibling-call optimization ili call stacks zibaki zinafaa kutumika.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) hubadilisha accesses zilizowekewa instrumentation kuwa miito ya helper. Patches za kernel za MAccConc huzima `asan-opt-same-temp` ili accesses zinazofuatana zisiunganishwe; pia zima optimization ya `asan-opt-globals` wakati races za global variables zinapaswa kuonekana. KCOV hupeleka rekodi zinazotokana na hilo kwa userspace. Linganisha accesses kutoka execution contexts tofauti na uhifadhi jozi ambazo byte ranges zake zinaingiliana na angalau upande mmoja unaandika; chukulia `kfree()` kama write ili mabadiliko ya lifetime pia yawe candidates.<sup>[[17]](#references)</sup>

Kwa kazi inayotoka nje ya task iliyoianzisha, kama packet processing au RCU callbacks, subsystem lazima isambaze handle ya KCOV remote-coverage. Remote KCOV ya upstream ni opt-in na haipatikani kiotomatiki kwa kazi yoyote ya background, kwa hiyo kukosa usambazaji kunaweza kufanya interaction halisi isionekane.<sup>[[17]](#references)[[19]](#references)</sup>

### Tambua access ileile ya dynamic katika kila run

Usirudie jaribio kwa kutumia anwani mahususi ya heap, ambayo inaweza kubadilika baada ya kila allocation, au anwani ya instruction pekee, ambayo ina utata ndani ya helpers kama `memcpy()` na `spin_lock()`. MAccConc hutumia **count-augmented stack trace**: kila frame hutambua callee pamoja na idadi ya mara ilipoitwa ndani ya caller wake, na kipengele cha mwisho hutambua instruction ya memory-access. Rekodi za kuingia na kutoka kwenye function za SanitizerCoverage huruhusu userspace kujenga identifier hii ya dynamic, ambayo hubaki thabiti licha ya mabadiliko ya anwani na kelele zisizohusiana za control flow.<sup>[[17]](#references)</sup>

### Geuza jozi za candidates kuwa schedules za lazima

Ioctl iliyorekebishwa ya `KCOV_SET_DI` huhusisha identifier ya access ya count-augmented na kitendo cha shared-flag.<sup>[[17]](#references)</sup>

| Kitendo | Maana |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Weka flag *N* mara moja kabla ya access iliyochaguliwa. |
| `DI_STACK_WAIT` | Kabla ya access iliyochaguliwa, subiri kwa kuzunguka hadi flag *N* iwekwe au kikomo kilichosanidiwa kiishe. |
| `DI_STACK_WAKE_POST` | Weka flag *N* mara moja baada ya access iliyochaguliwa. |

Kwa sharti la sehemu la **A-hutokea-kabla-ya-B**, ambatisha `DI_STACK_WAKE_POST` kwa A na `DI_STACK_WAIT` kwa B ukitumia flag ileile. Kwa schedule iliyobainishwa kikamilifu ya contexts mbili, anza B ikiwa imezuiwa, kisha A imwamshie B na isubiri kwenye sehemu ya kwanza ya uhamisho; B hufanya operesheni ya kinyume kwenye uhamisho unaofuata. Hii hufanya kazi kama kubadilisha context kwa njia ya deterministic na ndiyo inayotumiwa na A-B-A explorer ya kiotomatiki.<sup>[[17]](#references)</sup>

Campaign ndogo ni kukompile test case ya hooks nne (`test_setup`, functions mbili za thread, na `test_end`) kama shared library, kukusanya trace isiyo na vizuizi, kisha kuorodhesha candidates za A-B-A au kuongeza constraints za mkono kuzunguka accesses zinazotia shaka.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Tafsiri timeouts kando na reorderings zilizofanikiwa: mpangilio ulioombwa huenda usiwezekane kwa sababu lock au utegemezi wa initialization/publication unazuia context ya pili kufika kwenye sehemu yake ya injection. Pia zingatia maeneo ambayo KASAN haioni: ufikiaji wa stack moja kwa moja kwa kawaida hauwekewi hooks isipokuwa unaweza kuwa nje ya mipaka, globals huachwa kwa optimization ya chaguo-msingi, na compilers za sasa haziwezi kutoa hooks za ASAN na TSAN kwa wakati mmoja. Mwisho, prototype hupoteza buffer yake ya KCOV guest inapopata panic, kwa hiyo hifadhi crash console/oracle huru.<sup>[[17]](#references)</sup>

Kwa fuzzing ya baadaye inayoongozwa na concurrency, hifadhi muhtasari wa ufikiaji wa memory kwa kila input au syscall, unganisha operations ambazo zinaweza kuunda sehemu za mawasiliano kati ya contexts, kisha chunguza michanganyiko hiyo pekee. VM snapshots hutuliza global state na anwani; bila snapshots, metadata ya allocation-site inaweza kutumika kuwakilisha objects katika runs tofauti. Hili ni pendekezo la upanuzi, si kipengele cha tools za sasa za MAccConc za userspace.<sup>[[17]](#references)</sup>

## Uchunguzi wa Harness: Tambua Fuzzers Zisizofika Mbali Mapema

Campaign inapokwama, mara nyingi tatizo si mutator bali **harness**. Tumia **uchunguzi wa reachability/coverage** kutambua functions zinazoweza kufikiwa kistatiki kutoka kwenye fuzz target yako lakini ambazo hazifunikwi kamwe au hufunikwa mara chache wakati wa utekelezaji. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness huingia kwenye target kwa kuchelewa sana au mapema sana.
- Seed corpus haina familia nzima ya feature.
- Target inahitaji **harness ya pili** badala ya harness moja kubwa ya “kufanya kila kitu”.

Ukitumia workflows za mtindo wa OSS-Fuzz / ClusterFuzz, Fuzz Introspector inaweza kulinganisha reachability ya kistatiki na coverage ya runtime na kutoa ripoti kutokana na run yenye muda maalum au public corpus.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Tumia ripoti kuamua iwapo uongeze harness mpya kwa njia ya parser ambayo haijajaribiwa, upanue corpus kwa kipengele maalum, au ugawanye harness kubwa moja kuwa entry point ndogo zaidi.

## Uteuzi wa Fuzz Target kwa Graph Kwanza na Triage ya Mutation

Ikiwa tayari una **matokeo ya static analysis**, **mutation-testing survivors**, na **ripoti za coverage**, usizifanyie triage kama orodha zinazojitegemea. Anza kwa kujenga **call graph**, weka kwenye nodes maelezo ya **cyclomatic complexity**, **ufikikaji kutoka entrypoint/input isiyoaminika**, na matokeo yoyote ya nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinazofikika kutoka kwa input isiyoaminika?
- Ni mutation survivors zipi zilizo kwenye njia kutoka kwa parsers/handlers hadi kwenye code muhimu kwa usalama?
- Ni functions zipi ambazo ni choke point za usanifu na zina **blast radius** kubwa isiyo ya kawaida?

Kwa kawaida, hii hufichua fuzz target bora kuliko kuzingatia tu “coverage ya chini zaidi.” Parser/decoder yenye **complexity kubwa** na **ufikikaji wa nje uliothibitishwa** ni mgombea bora wa harness kuliko helper ya ndani iliyojitenga yenye coverage dhaifu lakini isiyo na njia inayodhibitiwa na mshambulizi.

### Mchakato wa vitendo wa triage

1. Jenga **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branch kwa kila function.
2. Orodhesha **entrypoint** zinazopokea input inayodhibitiwa na mshambulizi: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Tumia **path queries** kutoka kwenye entrypoint hizo hadi kwa functions zinazoweza kuchaguliwa ili kutofautisha attack surface inayofikika na code iliyokufa/ya ndani pekee.
4. Weka kipaumbele kwa nodes zinazochanganya:
   - **cyclomatic complexity** kubwa
   - **ufikikaji uliothibitishwa kutoka kwenye input isiyoaminika**
   - **blast radius** kubwa au dependents wengi wa chini
   - ushahidi unaounga mkono, kama matokeo ya **SARIF**, madokezo ya audit, au mutation survivors
5. Andika harness maalum kwa nodes zenye alama bora kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: sawa au zinazohitaji hatua

Mutation testing mara nyingi hutoa orodha ya survivors yenye kelele nyingi. Kabla ya kuchukulia kila survivor kama pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inafikika kutoka kwenye entrypoint inayodhibitiwa na mshambulizi?
- Je, njia zote za mwito zinawekewa masharti na invariants imara zaidi kuliko ukaguzi uliobadilishwa?
- Je, node iko kwenye code iliyokufa, logic ya uumbizaji pekee, au njia ya arithmetic/parser yenye athari kubwa?

Survivors ambazo bado hazifikiki au zimewekewa masharti kimuundo mara nyingi ni **equivalent mutants**. Survivors ambazo zinaendelea **kufikika** na kugusa **boundary conditions**, **overflow/carry paths**, au **arithmetic/parsing muhimu kwa usalama** zinapaswa kupewa kipaumbele na kuingizwa kwenye:

- fuzz harnesses mpya
- majaribio ya moja kwa moja ya property/invariant
- vectors maalum za edge case

### Linganisha matokeo ya nje kwenye graph

Ikiwa pipeline yako ya SAST inatoa **SARIF**, weka matokeo kwenye nodes za graph kwa kutumia **file + line range** na utumie graph kupanua tathmini ya athari.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya function iliyowekwa alama
- hakikisha kama matokeo yako kwenye njia yoyote kutoka kwa entrypoint
- panga matokeo ya karibu yanayoelekeza kwenye choke point ileile

Hii husaidia unapoamua kama utumie muda wa fuzzing kwenye function maalum: node ambayo **inafikika**, ina **complexity kubwa**, na tayari ina **matokeo ya SAST** mara nyingi ni target bora kuliko node yenye complexity kubwa tu lakini isiyo na njia ya mshambulizi.

Mfano wa mchakato kwa kutumia Trailmark.<sup>[[6]](#references)</sup>

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

Mbinu muhimu ni makutano ya: **utata x kiwango cha kufichuliwa x athari**. Tumia grafu kuchagua malengo ya fuzzing yenye thamani kubwa zaidi ya usalama inayotarajiwa, kisha tumia mabadiliko yaliyosalia kuamua ni mipaka na invariants zipi harness yako inapaswa kujaribu.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Injini Yenye Nguvu Zaidi, Ingizo Zenye Aina Maalum, Na Ukaguzi Linganishi

Ikiwa lengo la Go tayari lina harness asilia ya `testing.F`, njia ya vitendo ya kuboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), toolchain ya Go iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Hii ni muhimu wakati Go fuzzer ya asili inakwama kwenye **hard comparisons**, **typed inputs**, au miundo inayotegemea sana parser. Mbinu hubaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia campaign inayotokana nayo kama run ya kawaida inayoongozwa na coverage, lakini ikiwa na scheduling/mutation ya LibAFL na detectors bora zaidi zinazoizunguka.

### Geuza hitilafu zisizoonekana kuwa matokeo ya fuzzing

Tatizo linalojirudia kwenye tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa chaguomsingi. Kwa gosentry, unaweza kubadilisha aina kadhaa za hali “mbaya lakini zisizoonekana” kuwa findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili njia maalum za logging/error zifanye kazi kama crashes (inafaa kwa njia za msimbo za aina ya `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kujaribu tena entries mpya zilizogunduliwa kwenye queue kwa kutumia Go race detector.
- `--catch-leaks=true` ili kujaribu tena entries mpya kwenye queue kwa kutumia `goleak` na kusimamisha kazi kukitokea goroutine leaks.
- Ushughulikiaji wa hang wa LibAFL ili kuhifadhi **infinite loops / inputs zinazoenda polepole sana** kama matokeo ya fuzzing badala ya kuziacha zipotee kama timeouts.
- Ukaguzi wa built-in wa arithmetic overflow kwa chaguomsingi, pamoja na ukaguzi wa hiari wa truncation kupitia instrumentation ya mtindo wa go-panikint.

Hili lina thamani hasa kwa targets ambazo athari ya usalama ni **hitilafu ya parser isiyosababisha panic**, **hitilafu ya concurrency**, au **hang inayosababisha DoS pekee**, badala ya corruption ya memory.

### Fuzzing inayozingatia struct kwa Go APIs zenye aina maalum

Go fuzzing ya asili hutarajia hasa scalars kama `[]byte`, `string`, na nambari. Ikiwa msimbo unaojaribiwa hutumia objects zenye aina maalum, gosentry inaweza kufuzz **composite values** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kubadilisha bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>

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

Kutumia hii unapounda wire format bandia kwa ajili ya fuzzing tu kungeficha hitilafu za logic nyuma ya msimbo wa parsing unaotumika kwenye harness pekee. Kwa kampeni za differential au grammar-based, weka ingizo la harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Fuzzing inayotegemea grammar kwa parser na ingizo za protocol

Kwa parser, format na lugha za ingizo, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni array ya JSON ya production rules, na kwa kawaida harness inapaswa kupokea argument moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Maelezo ya mbinu:

- Tumia grammar mode wakati byte-level mutations nyingi hukwama kwenye ukaguzi wa awali wa sintaksia.
- Weka grammar ilenge **sehemu ndogo ya lugha/protokali inayohusiana na usalama** badala ya kuiga vipimo vyote.
- Tumia thamani kubwa za mipaka kwenye terminals/nonterminals ili kuchunguza mipaka ya integer, urefu na mashine ya hali.
- Grammar mode huhakikisha inputs zinatii grammar, lakini target bado hupokea **bytes/strings**, kwa hivyo uchanganuzi na ukaguzi wa kisemantiki bado hufanyika ndani ya msimbo unaoendeshwa na harness.

### Differential fuzzing: linganisha utekelezaji, si crash pekee

Mbinu yenye nguvu katika mifumo ikolojia ya Go ni **grammar-based differential fuzzing**: tengeneza inputs halali na zenye muundo, kisha uzitumie kwenye parsers, clients au state-transition engines mbili.<sup>[[7]](#references)[[8]](#references)</sup>

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

Chukulia yafuatayo kuwa matokeo:

- implementation moja inapata panic huku nyingine ikikataa kwa usafi
- kutolingana kwa input zinazokubaliwa/kukataliwa
- parse trees au objects zilizodecodeiwa zinatofautiana
- state transitions, nonces, balances au state roots zinatofautiana

Hii ni njia ya vitendo ya kupata **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo mara nyingi hazigunduliki kwa crash fuzzing pekee.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tumia tena corpus ya kampeni kwa kuripoti coverage

Baada ya kampeni, rudia corpus ya queue iliyohifadhiwa ili kutengeneza ripoti ya Go coverage bila kuhamisha corpus tofauti kwa mikono.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Tekeleza amri kutoka **package ileile** na kwa target ileile ya `-fuzz` ili gosentry ipate hali sahihi ya kampeni iliyohifadhiwa kwenye cache.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++: Fuzzing kwa undani](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet baada ya miaka mitano: Kuhusu Fuzzing ya itifaki inayoongozwa na coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hubadilisha msimbo kuwa grafu](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya zana. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer ya haraka ya greybox kwa itifaki za mtandao zenye hali kwa kutumia snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna grammar, hakuna tatizo: Kuelekea kufuzz Linux kernel bila maelezo ya system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing yenye ufanisi kwa kutumia snapshots zinazobadilika na kuzoea hali](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: coverage ya njia na caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing inayotabiri na kuzingatia muktadha](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blogu ya Android Offensive Security - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - nyaraka za build na regression seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kuchunguza race condition za Linux kernel kwa kupanga kwa udhibiti mwingiliano wa ufikiaji wa kumbukumbu](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: coverage ya msimbo kwa ajili ya fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaksia ya jina la faili lililopanuliwa la CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Ushauri wa Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Kufuzz sintaksia ya jina la faili lililopanuliwa la CFITSIO: Udhaifu 16 wa usalama wa kumbukumbu na uchambuzi wa awali uliosaidiwa na Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
