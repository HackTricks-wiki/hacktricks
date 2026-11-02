# Mbinu ya Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **grammar-valid**. Katika hali inayoongozwa na coverage, sampuli zinazosababisha **coverage mpya** pekee ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains**, ambapo output ya construct moja inakuwa input ya nyingine.<sup>[[1]](#references)</sup>

**Hali ya kushindwa:** fuzzer hupata seeds zinazotumia `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haihifadhi dataflow iliyounganishwa**. Kwa hiyo, sampuli iliyo “karibu zaidi na bug” hutupwa kwa sababu haiongezi coverage. Kwa **hatua 3 au zaidi zinazotegemeana**, kuchanganya upya kwa nasibu kunakuwa ghali, na feedback ya coverage haiongozi utafutaji.<sup>[[1]](#references)</sup>

**Athari:** kwa grammars zinazotegemea sana, zingatia **kuunganisha awamu za mutational na generative** au kuelekeza generation kwenye mifumo ya **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Mitego ya Corpus Diversity

Mutation inayoongozwa na coverage ni **greedy**: sampuli yenye coverage mpya huhifadhiwa mara moja, mara nyingi ikiwa na sehemu kubwa zisizobadilika. Baada ya muda, corpora huwa na **near-duplicates** zenye utofauti mdogo wa kimuundo. Minimization kali inaweza kuondoa context yenye manufaa, kwa hiyo suluhu ya vitendo ni **grammar-aware minimization** inayosimama baada ya kufikia kiwango cha chini cha tokeni (kupunguza kelele huku ikihifadhi muundo wa kutosha unaofaa kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye miundo tofauti inayoongeza coverage** badala ya rundo kubwa la near-duplicates. Kwa vitendo, hili kwa kawaida humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **sampuli za ulimwengu halisi** (public corpora, crawling, traffic iliyorekodiwa, seti za mafaili kutoka kwenye mazingira ya target).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sampuli halali.
- Weka seeds **ndogo vya kutosha** ili mutations zilenge fields zenye maana badala ya kutumia mizunguko mingi kwenye bytes zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation kwa Magic Values

Sababu ya kawaida ya fuzzers kufikia kikomo si syntax bali **hard comparisons**: magic bytes, ukaguzi wa urefu, enum strings, checksums, au thamani za parser dispatch zinazodhibitiwa na `memcmp`, switch tables, au comparisons zinazofuatana. Mutation ya nasibu pekee hupoteza mizunguko ikijaribu kukisia thamani hizi byte moja baada ya nyingine.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano, workflows za AFL++ `CMPLOG` / Redqueen) ili fuzzer iweze kuona operands kutoka kwenye comparisons zilizoshindwa na kuelekeza mutations kwenye thamani zinazokidhi masharti hayo.<sup>[[3]](#references)</sup>

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

- Hii ni muhimu hasa pale ambapo lengwa huficha mantiki ya ndani nyuma ya **saini za faili**, **vitenzi vya protocol**, **lebo za aina**, au **biti za vipengele zinazotegemea toleo**.
- Iunganishe na **kamusi** zilizotolewa kutoka kwa sampuli halisi, specs za protocol, au logs za utatuzi. Kamusi ndogo yenye tokeni za sarufi, majina ya vipande, vitenzi, na vitenganishi mara nyingi huwa na thamani zaidi kuliko orodha kubwa ya maneno ya jumla.
- Ikiwa lengwa hufanya ukaguzi mwingi mfululizo, suluhisha ulinganisho wa mapema zaidi wa “magic” kwanza, kisha punguza corpus inayotokana tena ili hatua zinazofuata zianze na viambishi awali ambavyo tayari ni halali.

## Kufuzz API za Faili Zinazoficha Lugha ya Majina ya Faili

Kigezo kinachoitwa `filename`, `path`, au `URL` kinaweza kuwa sehemu ya kuingilia kwa interpreter badala ya utafutaji halisi wa faili. Kwa mfano, CFITSIO Extended Filename Syntax (EFS) hutathmini viteuzi vilivyo ndani ya mabano, misemo ya safu/s pikseli, safu wima zilizokokotolewa, histogramu, na mabadiliko kabla ya kurudisha object iliyofunguliwa; baadhi ya miundo pia huunda nakala za muda. Unapopanga ramani ya attack surface, ainisha kila API ya kufungua/kuingiza kama **literal-path** au **interpreted-path**, kisha fuzz sehemu ya kuingilia ya production ambayo programu hutumia kwa hakika.<sup>[[20]](#references)[[22]](#references)</sup>

Kwa primitives za SSRF, kunakili faili, na vishikio vya protocol vinavyotokana na hili—na API salama zaidi za literal-path—tazama [Lugha ndogo za majina ya faili kama primitives za SSRF/faili](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Weka object ya msingi tofauti na programu inayofuzzwa

Sarufi inapokuwa ndani ya kiambishi tamati cha jina la faili, kubadilisha tu baiti za faili inayorejelewa hakugusi parser. Badala yake, harness ndogo inaweza kusoma testcase moja kama string na kuipitisha kwa API ya kufungua iliyotafsiriwa; kampeni ya CFITSIO ilifikia parser na evaluator nyingi za EFS kwa kuita `fits_open_file()` katika hali ya kusoma pekee. Weka faili halali za msingi zikiwa tayari zinapatikana kando ili mabadiliko yalenge lugha ya kiteuzi/msemo badala ya kuendelea kuharibu njia ya msingi.<sup>[[22]](#references)</sup>

Tumia seeds ambazo kila moja hufikia familia tofauti ya sarufi, kisha tengeneza kamusi fupi kutoka kwa spec na msimbo wa lexer/parser. Ikiwa coverage itakwama huku ingizo zikirudia kushindwa katika njia ileile ya kosa la sintaksia, hifadhi viambishi awali halali na uongeze vitenganishi, waendeshaji, maneno muhimu, majina ya function, na majina wakilishi ya sehemu badala ya kuongeza tu muda wa mabadiliko ya nasibu.<sup>[[22]](#references)</sup>

Endesha harness kwa kutumia kamusi ya sarufi, kwa mfano:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Zuia athari za pembeni za harness ya "read-only"

Bendera ya library ya read-only haihakikishi kuwa testcase haitasababisha athari za pembeni: lugha ya majina ya faili inaweza kuandika upya ingizo, kuunda faili za matokeo, au kuunda objects za muda. Kampeni ya CFITSIO iliharibu faili za seed mwanzoni na kuacha faili zisizotarajiwa kwenye filesystem, kwa hiyo usafishaji na utengaji vilihitajika.<sup>[[22]](#references)</sup>

- Mpe kila worker working directory ya muda na temporary directory yake binafsi.
- Toa nakala za faili za msingi zilizo canonical; usiache target ibadilishe nakala pekee ya corpus.
- Zima ufikiaji wa network isipokuwa backends za remote ndizo zinazolengwa, na zuia njia zinazoweza kuandikwa kwa kutumia container, mount namespace, au sandbox inayolingana.
- Rudisha directory katika hali ya awali baada ya kila execution au kundi la worker, na chukulia mabadiliko yasiyotarajiwa ya filesystem kuwa findings za ziada.

### Mzunguko wa crash-to-patch-to-fuzz

Panga crashes katika makundi kabla ya kuzirekebisha ili maelfu ya artifacts zisisababishe maelfu ya kazi za patch. Katika tathmini ya CFITSIO, AFLTriage ilipunguza seti ya awali ya crashes hadi root causes chache; advisory iliyotokana nayo inaonyesha hitilafu tofauti, zikiwemo ukaguzi usio sahihi wa ukubwa wa destination, pointers zilizopitwa na wakati baada ya `realloc()`, hitilafu za hesabu, na njia zisizo salama za kusafisha parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Punguza ingizo wakilishi kwa kila kundi na lirudie chini ya AddressSanitizer.
2. Rekodi access halisi iliyoshindwa, eneo kwenye source, historia ya allocation/free, na hali ya parser iliyosababisha invariant kuvunjika.
3. Tekeleza candidate patch yenye wigo mwembamba na ujenge upya kwa instrumentation ileile ya coverage na sanitizer.
4. Rudia reproducer ya awali **na kila ingizo katika kundi lake**; pia washa ugunduzi wa leak kwa sababu marekebisho ya memory-safety yanaweza kuvuruga umiliki wa kumbukumbu kwenye error path.
5. Endesha functional tests kwa kutumia faili halisi, kisha endelea kutoka kwenye queue iliyokusanywa (au ingiza queue hiyo tena ikiwa engine inahitaji output directory mpya baada ya binary kubadilika).
6. Rudia: kuondoa crash ya kwanza ya juu juu mara nyingi huruhusu seeds zilizopo kufikia hali ya ndani zaidi ya parser.

LLM inaweza kuharakisha hatua ya 2 na kuandaa rasimu ya hatua ya 3 ikipewa ingizo lililosababisha crash, ripoti ya sanitizer, harness, na source husika, lakini patch yake bado haiaminiki. Uamuzi wa kukubali marekebisho hutegemea marudio ya sanitizer na vigezo vya regression—si maelezo ya model.<sup>[[22]](#references)</sup>

## Maoni Tajiri Zaidi Wakati Edge Coverage Inapounganisha Njia Tofauti

Edge coverage ya kawaida haiwezi kutofautisha executions mbili zinazopitia helper ileile kutoka kwa callers tofauti, au zinazochukua michanganyiko tofauti ya branches ndani ya function. Hili ni muhimu katika shared decoders, protocol dispatchers, na interpreter helpers ambamo **njia** ya kufikia edge huamua hali iliyopo wakati huo. Kufuatilia kila calling context bila mpango pia ni hatari: coverage map na queue zinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zenye matumaini pekee badala ya kuchukulia call graph nzima kuwa context-sensitive.<sup>[[14]](#references)</sup>

Build za hivi karibuni za AFL++ zina **Ball-Larus per-function path coverage** pamoja na edge coverage ya kawaida. Huweka feature kwa kila njia isiyo na mizunguko kupitia function; loop back-edges huondolewa, kwa hiyo feedback hii hutofautisha michanganyiko ya branches lakini **haitofautishi idadi ya marudio ya loop**. Anza na level iliyolegezwa ya `1`, kisha weka modes kali zaidi kwenye parser/state-machine code inayotiliwa shaka, kwa sababu idadi ya paths inaweza kukua kwa kasi ya kielelezo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Kwa function saidizi inayoitwa kutoka maeneo mengi yanayohusiana na usalama, hali ya LTO inaweza kuunganisha kila njia ya function na call site yake ya moja kwa moja:<sup>[[13]](#references)</sup>

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

**Mwongozo wa campaign:** tumia feedback yenye utajiri zaidi kwa tahadhari na ufuatilie gharama yake kwa coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage sambamba; feedback yenye utajiri zaidi ina manufaa tu ikiwa gharama ya ziada ya queue/map haiharibu idadi ya executions kwa sekunde.
- Tumia `AFL_LLVM_ALLOWLIST` kuzuia instrumentation ya path/caller wakati libraries kubwa zenye templates nyingi au code ya matumizi ya jumla zinapotawala map.
- AFL++ inaweza kuruka functions zenye njia nyingi mno zisizo na mizunguko; warnings wakati wa compilation ni dalili kwamba target inahitaji allowlisting au kiwango kisicho kali sana.
- Caller + path coverage hutumia kina kimoja tu cha caller. Usiichanganye na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya matoleo makuu ya LLVM. Dumisha toolchain ileile wakati wa campaign na usisawazishe corpora zinazotegemea PATH kana kwamba feature IDs zake ni thabiti katika builds tofauti.
- Feedback hii inakamilisha `CMPLOG`: ufuatiliaji wa comparisons hutatua **ni value gani inapita guard**, ilhali feedback ya path/caller huhifadhi **ni route gani na mchanganyiko gani wa branches ulioifikisha hapo**.

## Stateful Fuzzing: Mifuatano Ni Seeds

Kwa **protocols**, **authenticated workflows**, na **parsers za hatua nyingi**, kitengo cha kuvutia mara nyingi si blob moja bali ni **mfuatano wa messages**. Kuunganisha transcript nzima kwenye faili moja na kuibadilisha bila mpango kwa kawaida si njia bora, kwa sababu fuzzer hubadilisha kila hatua kwa kiwango sawa, hata ikiwa message ya baadaye pekee ndiyo inayofikia state dhaifu.<sup>[[4]](#references)</sup>

Mbinu yenye ufanisi zaidi ni kuichukulia **sequence yenyewe kama seed** na kutumia **state inayoweza kuonekana** (response codes, protocol states, parser phases, aina za objects zilizorejeshwa) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Weka **messages halali za prefix** bila kubadilika na elekeza mutations kwenye message inayoendesha **transition**.
- Hifadhi identifiers na values zinazozalishwa na server kutoka kwa majibu yaliyotangulia wakati hatua inayofuata inazitegemea.
- Pendelea mutation/splicing kwa kila message badala ya kubadilisha transcript nzima iliyoserialishwa kama blob isiyoeleweka.
- Ikiwa protocol hutoa response codes zenye maana, zitumie kama **state oracle ya gharama nafuu** ili kuzipa kipaumbele sequences zinazoendelea zaidi.

Hii ndiyo sababu authenticated bugs, transitions zilizofichwa, au bugs za parser zinazotokea “baada tu ya handshake” mara nyingi hukosekana kwenye vanilla file-style fuzzing: fuzzer lazima ihifadhi **mpangilio, state, na dependencies**, si muundo pekee.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing ya driver kwa clients wengi

Edge coverage ya juu bado inaweza kukosa bugs za IPC-driver kwa sababu coverage haielezi **umiliki wa objects, reference counts, messages zinazosubiri, mpangilio wa cleanup, au thread interleavings**. Ukurasa wa [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) unaeleza object model ya driver; mfano huu unaangazia fuzzer harness. Android Binder ni mfano mzuri: kufikia njia za allocation na free hakutoshi ikiwa fuzzer haiwezi kufanya processes nyingi zitumie kernel object ileile kwa mpangilio unaohitajika.<sup>[[15]](#references)</sup>

#### Modeli protocol, si buffers za `ioctl` zilizotengwa

Wakilisha test case kama grammar yenye mpangilio ya **utambulisho wa client + operation + arguments zenye muundo**. Binder LKL fuzzer hutumia protobuf na `libprotobuf-mutator`, ikiwa na client moja endelevu ya context-manager na clients wawili wa kawaida. Kisha semantic harness huhifadhi mahusiano ambayo mutation ya bytes bila mpango ingeharibu.<sup>[[15]](#references)</sup>

- Hifadhi values zilizorejeshwa na operations za awali. Kwa mfano, `BC_FREE_BUFFER` lazima itumie tena pointer ya transaction-buffer iliyorejeshwa na `ioctl` ya awali.
- Tengeneza majibu chaguomsingi halali ili synchronous transactions zikamilike na operations za baadaye ziweze kufikiwa.
- Kataa transitions zisizowezekana kama self-transactions au transactions nyingi zinazosubiri kwa target moja.
- Weka singleton bootstrap state nje ya reset ya kila input. Binder inaruhusu usajili mmoja tu wa `BINDER_SET_CONTEXT_MGR` kwa kila boot, kwa hiyo kuharibu na kuunda upya client huyo kila mara kungefanya inputs za baadaye zisiwe halali.

Muundo mzuri wa lifetime-race ni kufanya client mmoja ahamishe object, kuanzisha cleanup ya thread au process, kisha kwa wakati mmoja kufanya client inayopokea iachilie transaction buffer. Katika mfano wa CVE-2020-0423, uhamisho wa `BINDER_TYPE_WEAK_BINDER` uliofuatiwa na `BINDER_THREAD_EXIT` ulioshindana na `BC_FREE_BUFFER` ungeweza kufree `binder_work` iliyopachikwa huku njia ya cleanup ya thread inayotoka ikiwa bado inaitumia.<sup>[[15]](#references)</sup>

#### Rejesha interleavings zinazodhibitiwa ndani ya kernel ya userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) huunganisha code halisi ya kernel kwenye userspace harness na kufichua syscall interface yake kupitia `lkl_syscall`. Hii hurahisisha kuratibu protobuf state, coverage, na KASAN ndani ya process moja. Hata hivyo, LKL kwa kawaida huendesha syscall bila thread nyingine ya kernel kuikatiza. Kwa campaigns za race, weka sehemu za `schedule()` karibu na mipaka iliyochaguliwa ya lock/unlock na lifetime, kisha iruhusu harness ichague client inayofuata bila mpangilio katika kila yield. Lenga sehemu hizi kwa makini kwa sababu kila moja huongeza mara nyingi search space ya scheduling. Randomized scheduler iliyoelezwa na watafiti **si sehemu ya Binder fuzzer ya upstream**.<sup>[[15]](#references)</sup>

#### Jenga na urudie seeds za regression zilizoserialishwa

Harness ya upstream huweka toleo linalooana la `libprotobuf-mutator`, huwasha instrumentation ya LKL fuzzing na KASAN kwa `LKL_FUZZING=1`, na huwasha `CONFIG_MMU` kwa Binder kupitia `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Baada ya kuchagua revision iliyoachwa ikiwa na udhaifu kwa makusudi au kutumia rollback patches zilizoandikwa kwenye chanzo cha upstream, seed iliyoserialishwa inaweza kuiga mabadiliko yote ya hali ya multi-client bila kuyaunda upya katika C proof of concept iliyobuniwa kwa dharura:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Chukulia use-after-free ya KASAN iliyotokea kama uthibitisho kwamba seed ilifikia njia ya lifetime iliyo hatarini. Hii **haithibitishi** kuwepo kwa primitives za baadaye zinazohitajika ili kutekeleza code kwenye kernel au kufanya privilege escalation.<sup>[[16]](#references)</sup>

## Mbinu ya Utofauti kwenye Mashine Moja (Mtindo wa Jackalope)

Njia ya vitendo ya kuchanganya **ubunifu wa kuzalisha** na **utumiaji upya wa coverage** ni **kuanzisha upya workers wa muda mfupi** dhidi ya server inayoendelea kufanya kazi. Kila worker huanza na corpus tupu, husawazisha baada ya sekunde `T`, hutumia sekunde nyingine `T` kufanya kazi kwenye corpus iliyounganishwa, husawazisha tena, kisha hutoka. Hii huleta **miundo mipya katika kila kizazi** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers wa kufuatana (mfano wa kitanzi):**

<details>
<summary>Kitanzi cha kuwasha upya worker wa Jackalope</summary>

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
- `-server_update_interval T` hukadiria **delayed sync** (ubunifu kwanza, matumizi tena baadaye).
- Katika hali ya grammar fuzzing, **initial server sync hurukwa kwa chaguo-msingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadili baada ya worker kupata sehemu kubwa ya “easy” coverage kwa kawaida hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Targets Ngumu Kuandaa

Wakati msimbo unaotaka kujaribu unaweza kufikiwa tu **baada ya gharama kubwa ya usanidi** (kuwasha VM, kukamilisha kuingia, kupokea packet, kuchanganua container, kuanzisha service), njia mbadala yenye manufaa ni **snapshot fuzzing**: kunasa hali ya process au VM ikiwa tayari, kuingiza kila test case kwenye njia ya input ya target, kutekeleza hadi crash/timeout, kisha kurejesha snapshot. Hii huepusha kurudia uanzishaji au viambishi vya protocol na ni muhimu kwa **network services**, **firmware**, **attack surfaces baada ya uthibitishaji**, na **targets za binary pekee**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayokuvutia iwe tayari.
2. Tengeneza snapshot ya **memory + registers** wakati huo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Tekeleza hadi crash/timeout/reset.
5. Rejesha snapshot; kwa targets za VM, rejesha **dirty pages** pekee ikiwa inaungwa mkono, kisha urudie.

Weka snapshot karibu kadiri inavyowezekana na hatua ya kwanza ghali ya parse/dispatch, kama vile baada ya `recv`/`read` au hatua ya packet-deserialization, na rekodi input buffer inayotumiwa na target. Hii inafuata kanuni ya uwekaji unaobadilika kwa kusogeza snapshot ndani zaidi ya uchakataji wa input ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Kuchunguza Linux Kernel Race Kwa MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) hubadilisha race za Linux kernel zinazotegemea muda kuwa ratiba zinazoweza kurudiwa za ufikiaji wa memory. Inaweza kuorodhesha kiotomatiki utekelezaji wa **A-B-A** wa miktadha miwili au kumruhusu mchambuzi kuweka masharti ya mpangilio kupitia terminal UI/GUI. Hiki ni kifaa cha majaribio ya utafiti, si concurrency fuzzer kamili: kwa sasa kinahitaji LLVM 23+ na kernel iliyorekebishwa ya mradi, zana za command-line zinaunga mkono test threads mbili, na safu ya fuzzing ya userspace iliyopendekezwa haijatekelezwa.<sup>[[17]](#references)[[18]](#references)</sup>

### Kukusanya sehemu za mawasiliano kati ya miktadha

Tengeneza kernel iliyo na instrumentation kwa kutumia KASAN outline callbacks na usaidizi wa KCOV memory-record uliorekebishwa. README ya mradi pia inapendekeza kuzima sibling-call optimization ili call stacks ziendelee kutumika.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) hubadilisha accesses zilizowekewa instrumentation kuwa helper calls. Patches za kernel za MAccConc huzima `asan-opt-same-temp` ili accesses zinazofuatana zisiunganishwe; zima pia optimization ya `asan-opt-globals` wakati races za global variables zinapaswa kuonekana. KCOV husafirisha records zinazotokana na accesses hizi hadi userspace. Linganisha accesses kutoka miktadha tofauti ya utekelezaji na uhifadhi jozi ambazo byte ranges zake zinaingiliana na angalau upande mmoja unaandika; chukulia `kfree()` kuwa uandishi ili mabadiliko ya muda wa uhai pia yawe wagombeaji.<sup>[[17]](#references)</sup>

Kwa kazi inayotoka nje ya task iliyoianzisha, kama packet processing au RCU callbacks, subsystem lazima isambaze handle ya KCOV remote-coverage. KCOV remote ya upstream ni opt-in na haipatikani kiotomatiki kwa kazi yoyote ya background, kwa hiyo kutosambaza handle kunaweza kufanya mwingiliano halisi usionekane.<sup>[[17]](#references)[[19]](#references)</sup>

### Tambua access ileile inayotokea kila run

Usirudie jaribio kwa kutumia anwani halisi ya heap, ambayo inaweza kubadilika baada ya kila allocation, au kwa kutumia anwani ya instruction pekee, ambayo haina utambulisho wa kipekee ndani ya helpers kama `memcpy()` na `spin_lock()`. MAccConc hutumia **count-augmented stack trace**: kila frame hubainisha callee pamoja na idadi ya mara ilipoitwa ndani ya caller wake, na kipengele cha mwisho hubainisha instruction ya memory-access. Records za kuingia/kutoka kwa function za SanitizerCoverage huruhusu userspace kuunda upya kitambulisho hiki cha dynamic, ambacho hubaki thabiti licha ya mabadiliko ya anwani na kelele ya mtiririko wa udhibiti isiyohusiana.<sup>[[17]](#references)</sup>

### Badilisha jozi za wagombeaji kuwa schedules za lazima

Ioctl iliyorekebishwa ya `KCOV_SET_DI` huhusisha kitambulisho cha access cha count-augmented na kitendo cha shared-flag.<sup>[[17]](#references)</sup>

| Kitendo | Semantiki |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Weka flag *N* mara moja kabla ya access iliyochaguliwa. |
| `DI_STACK_WAIT` | Kabla ya access iliyochaguliwa, subiri kwa kuzunguka hadi flag *N* iwekwe au kikomo kilichosanidiwa kiishe. |
| `DI_STACK_WAKE_POST` | Weka flag *N* mara moja baada ya access iliyochaguliwa. |

Kwa sharti la sehemu la **A-happens-before-B**, ambatisha `DI_STACK_WAKE_POST` kwa A na `DI_STACK_WAIT` kwa B ukitumia flag ileile. Kwa schedule ya miktadha miwili iliyobainishwa kikamilifu, anza B ikiwa imezuiwa, kisha A iimarishe B na isubiri katika sehemu ya kwanza ya uhamisho; B ifanye operesheni ya kinyume katika uhamisho unaofuata. Hii hufanya kazi kama kubadilisha miktadha kwa njia ya deterministic, na ndiyo njia inayotumiwa na A-B-A explorer ya kiotomatiki.<sup>[[17]](#references)</sup>

Campaign ya chini kabisa ni kucompile test case ya four-hook (`test_setup`, functions mbili za thread, na `test_end`) kama shared library, kukusanya trace isiyo na constraints, kisha kuorodhesha wagombeaji wa A-B-A au kuongeza constraints za mkono kwenye accesses zinazotia shaka.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Tafsiri muda kuisha kando na kupanga upya kwa mafanikio: mpangilio ulioombwa huenda usiwezekane kwa sababu kufuli au utegemezi wa uanzishaji/uchapishaji huzuia muktadha wa pili kufika kwenye injection point yake. Pia kumbuka mapungufu ya KASAN: ufikiaji wa moja kwa moja wa stack kwa kawaida haufuatiliwi isipokuwa huenda ukavuka mipaka, globals huachwa kwa optimization chaguomsingi, na compilers za sasa haziwezi kutoa hooks za ASAN na TSAN kwa wakati mmoja. Mwishowe, prototype hupoteza buffer yake ya KCOV mgeni anapopata panic, kwa hiyo hifadhi crash console/oracle huru.<sup>[[17]](#references)</sup>

Kwa fuzzing ya baadaye inayoongozwa na concurrency, rekodi muhtasari wa ufikiaji wa kumbukumbu kwa kila ingizo au syscall, oanisha operesheni ambazo zingeunda sehemu za mawasiliano kati ya miktadha, kisha chunguza michanganyiko hiyo pekee. VM snapshots hutuliza hali ya kimataifa na anwani; bila snapshots, metadata ya allocation-site inaweza kufupisha objects katika runs mbalimbali. Hili ni pendekezo la upanuzi, si kipengele cha zana za sasa za MAccConc userspace.<sup>[[17]](#references)</sup>

## Ukaguzi wa Harness: Tambua Fuzzers Duni Mapema

Kampeni inapokwama, mara nyingi tatizo si mutator bali **harness**. Tumia **ukaguzi wa reachability/coverage** kutafuta functions zinazofikiwa kistatiki kutoka kwenye fuzz target yako lakini ambazo hazifunikwi mara chache au hazifunikwi kabisa wakati wa utekelezaji. Kwa kawaida functions hizo huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness huingia kwenye target ikiwa imechelewa au mapema mno.
- Seed corpus haina familia nzima ya vipengele.
- Target inahitaji **harness ya pili** badala ya harness moja kubwa mno ya “kufanya kila kitu”.

Ukitumia workflows za mtindo wa OSS-Fuzz / ClusterFuzz, Fuzz Introspector inaweza kulinganisha reachability ya kistatiki na coverage ya wakati wa utekelezaji, na kutengeneza ripoti kutokana na run ya muda maalum au corpus ya umma.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Tumia ripoti kuamua kama uongeze harness mpya kwa njia ya parser ambayo haijajaribiwa, upanue corpus kwa kipengele maalum, au ugawanye harness moja kubwa katika entrypoint ndogo.

## Uteuzi wa Fuzz Target kwa Kuanzia na Graph na Uchambuzi wa Mutation Triage

Ikiwa tayari una **matokeo ya static analysis**, **mutation-testing survivors**, na **ripoti za coverage**, usizichambue kama orodha zinazojitegemea. Anza kwa kuunda **call graph**, weka kwenye nodes taarifa za **cyclomatic complexity**, **ufikikaji kutoka entrypoint/input isiyoaminika**, na matokeo yoyote ya nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinaweza kufikiwa kutoka kwa input isiyoaminika?
- Ni mutation survivors zipi ziko kwenye njia kutoka kwa parsers/handlers hadi kwenye code muhimu kwa usalama?
- Ni functions zipi ni sehemu muhimu za usanifu zenye **blast radius** kubwa isivyo kawaida?

Hii kwa kawaida hufichua fuzz targets bora kuliko kutumia "coverage ya chini zaidi" pekee. Parser/decoder yenye **complexity kubwa** na **ufikikaji wa nje uliothibitishwa** ni mgombea bora zaidi wa harness kuliko helper ya ndani iliyo peke yake, yenye coverage dhaifu lakini isiyo na njia inayodhibitiwa na mshambuliaji.

### Mchakato wa vitendo wa triage

1. Unda **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branches kwa kila function.
2. Orodhesha **entrypoints** zinazokubali input inayodhibitiwa na mshambuliaji: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Tumia **path queries** kutoka kwenye entrypoints hadi kwenye functions zinazochunguzwa, ili kutenganisha attack surface inayofikika na code iliyokufa/ya ndani pekee.
4. Tanguliza nodes zinazochanganya:
   - **cyclomatic complexity** kubwa
   - **ufikikaji uliothibitishwa kutoka kwa input isiyoaminika**
   - **blast radius** kubwa au dependents wengi wa downstream
   - ushahidi unaounga mkono, kama matokeo ya **SARIF**, maelezo ya ukaguzi, au mutation survivors
5. Andika harness mahususi kwa nodes zenye alama za juu zaidi kwanza, hasa **parsers/codecs** kama vile hex/Base64/IP/message decoders.

### Mutation survivors: sawa au zinazohitaji hatua

Mutation testing mara nyingi hutoa orodha ya survivors yenye kelele nyingi. Kabla ya kuchukulia kila survivor kama pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka kwenye entrypoint inayodhibitiwa na mshambuliaji?
- Je, njia zote za mwito zinawekewa mipaka na invariants imara zaidi kuliko check iliyobadilishwa?
- Je, node iko kwenye code iliyokufa, logic ya formatting pekee, au njia muhimu yenye athari kubwa inayohusisha arithmetic/parser?

Survivors ambazo bado hazifikiwi au zimewekewa vizuizi kimuundo mara nyingi ni **equivalent mutants**. Survivors ambazo bado **zinafikika** na kugusa **boundary conditions**, **overflow/carry paths**, au **arithmetic/parsing muhimu kwa usalama** zinapaswa kuongezwa kwenye:

- fuzz harnesses mpya
- property/invariant tests za moja kwa moja
- vectors lengwa za edge-case

### Linganisha matokeo ya nje na graph

Ikiwa pipeline yako ya SAST inatoa **SARIF**, weka matokeo kwenye nodes za graph kwa kutumia **file + line range**, kisha tumia graph kupanua tathmini ya athari.<sup>[[6]](#references)</sup>

- kokotoa **blast radius** ya function iliyoalamishwa
- hakikisha kama finding iko kwenye njia yoyote kutoka kwenye entrypoint
- panga findings zilizo karibu ambazo zinaelekeza kwenye choke point ileile

Hii husaidia unapoamua kama utumie muda wa fuzzing kwenye function maalum: node ambayo **inafikika**, **ina complexity kubwa**, na tayari ina **SAST hits** mara nyingi ni target bora kuliko node yenye complexity kubwa tu lakini isiyo na njia kutoka kwa mshambuliaji.

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

Mbinu muhimu ni makutano ya: **utata x uwezekano wa kufikiwa x athari**. Tumia grafu kuchagua malengo ya fuzzing yenye thamani ya juu zaidi ya usalama inayotarajiwa, kisha tumia inputs zilizopita baada ya mutation kuamua ni mipaka na invariants zipi harness yako inapaswa kusisitiza.<sup>[[5]](#references)</sup>

## Differential fuzzing ya usimbaji wa funguo za kriptografia

Anza na funguo halali zilizosanifishwa au test vectors za kawaida. Fanya mutation kwenye sehemu zilizosimbwa bila kuvunja urefu na muundo unaohitajika kufikia njia za kuingiza na kutekeleza operesheni, kisha tuma bytes zilezile kwa implementations zinazojitegemea. Linganisha kukubaliwa na makosa. Saini na ciphertext zilizowekwa nasibu zinahitaji correctness oracles, si ulinganisho wa byte kwa byte: thibitisha saini au linganisha shared secrets kutoka kwenye mzunguko wa encapsulation/decapsulation. Test vectors huweka msingi wa ulinganifu kwa hali zinazojulikana; differential mutation huchunguza encodings zilizoharibika zilizo nje ya hali hizo.<sup>[[23]](#references)[[26]](#references)</sup>

Kwa miundo hii ya funguo, tumia oracles maalum kwa kila format:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Funguo za kusaini za ML-DSA zilizopanuliwa:** badilisha coefficients zilizopakiwa za `s1` au `s2` ili ziwe nje ya `[-η, η]`, huku ukihakikisha ufunguo bado unaweza kuchanganuliwa. Angalia kama kuingiza ufunguo au kusaini kunakataa, na kama saini yoyote inayotokana inathibitishwa. Tofauti za kukubali pekee hazimaanishi ukiukaji wa viwango, kwa sababu FIPS 204 haihitaji ukaguzi wa ziada wa funguo binafsi. Tazama [conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Jozi za funguo za ML-KEM:** tofautisha ukaguzi unaohitajika wa ufunguo wa encapsulation na wa ingizo la decapsulation na ukaguzi wa hiari wa uthabiti wa jozi (PCT) kwenye jozi iliyoingizwa. Fanya encapsulation kwa ufunguo wake wa umma, fanya decapsulation kwa ufunguo wake binafsi, kisha linganisha shared secrets; kutolingana kunaweza kuvuruga mawasiliano yaliyosimbwa kwa njia fiche hata kama funguo mahususi zimefaulu ukaguzi wa ingizo. Angalia kama API inathibitisha ingizo wakati wa operesheni au kupitia mwito tofauti; libcrux hutoa `validate_public_key(pk)` na `validate_private_key(sk, ct)`, ambazo hazichukui nafasi ya PCT.
- **Funguo ghafi za XMSS/XMSSMT:** jaribu mizunguko ya kusanifisha na kurejesha funguo za **kusaini na kuthibitisha** katika seti mbalimbali za vigezo, si operesheni kwa funguo zilizo kwenye kumbukumbu pekee. XMSS na XMSSMT zina nafasi tofauti za OID za byte nne, hivyo kichanganuzi kinachotegemea OID pekee na kujaribu XMSS kwanza kinaweza kutambua kimakosa ufunguo wa XMSSMT wenye OID inayogongana na kukataa kuuingiza. Kichanganuzi cha RustCrypto kilichoripotiwa kinaonyesha hitilafu ya interoperability/availability, si kughushi saini.

## Go Fuzzing kwa kutumia gosentry: Engine Imara Zaidi, Ingizo Zenye Aina, na Ukaguzi wa Tofauti

Ikiwa target ya Go tayari ina harness asilia ya `testing.F`, njia ya vitendo ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), toolchain ya Go iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Hii ni muhimu wakati native Go fuzzer inakwama kwenye **ulinganishi mgumu**, **ingizo zenye aina maalum**, au **miundo inayotegemea sana parser**. Mbinu inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia kampeni inayotokana na hilo kama run ya kawaida inayoongozwa na coverage, lakini ikiwa na uratibu/mutation ya LibAFL na detectors bora zaidi za ziada.

### Geuza hitilafu zisizoonekana kuwa matokeo ya fuzzing

Tatizo linalojirudia katika tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa chaguo-msingi. Kwa gosentry, unaweza kubadilisha aina kadhaa za hali “mbaya lakini zisizoonekana” ziwe matokeo.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili njia zilizochaguliwa za logging/error zifanye kazi kama crashes (inafaa kwa njia za code za mtindo wa `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kujaribu tena entries mpya zilizogunduliwa kwenye queue kwa kutumia Go race detector.
- `--catch-leaks=true` ili kujaribu tena entries mpya kwenye queue kwa kutumia `goleak` na kusitisha kukitokea goroutine leaks.
- Ushughulikiaji wa hang wa LibAFL ili kuhifadhi **mizunguko isiyoisha / ingizo zinazoendeshwa polepole sana** kama matokeo ya fuzzing badala ya kuziacha zipotee kama timeouts.
- Ukaguzi wa arithmetic overflow uliojengewa ndani na kuwashwa kwa chaguo-msingi, pamoja na ukaguzi wa truncation wa hiari kupitia instrumentation ya mtindo wa go-panikint.

Hili lina thamani hasa kwa targets ambazo athari yake ya kiusalama ni **hitilafu ya parser isiyosababisha panic**, **hitilafu ya concurrency**, au **hang inayosababisha DoS pekee**, badala ya uharibifu wa memory.

### Fuzzing inayozingatia struct kwa Go APIs zenye aina maalum

Go fuzzing ya asili hutarajia zaidi scalars kama `[]byte`, `string`, na nambari. Ikiwa code inayojaribiwa hutumia objects zenye aina maalum, gosentry inaweza kufuzz **thamani changamano** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kufanya mutation ya bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>

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

Tumia hili unapounda wire format bandia kwa ajili ya fuzzing pekee; kufanya hivyo kungeficha hitilafu za mantiki nyuma ya code ya parsing inayotumika kwenye harness pekee. Kwa kampeni za differential au grammar-based, weka ingizo la harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Fuzzing inayotegemea grammar kwa parsers na ingizo za protocol

Kwa parsers, formats na lugha za ingizo, gosentry inaweza kutumia **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni array ya JSON ya production rules, na kwa kawaida harness inapaswa kupokea argument moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Maelezo ya mbinu:

- Tumia grammar mode wakati mutations za byte-level mara nyingi husimama kwenye ukaguzi wa sintaksia wa hatua za mwanzo.
- Lenga grammar kwenye **sehemu ya lugha/protokali inayohusika na usalama** badala ya kuiga specification nzima.
- Tumia thamani kubwa za mipaka kwenye terminals/nonterminals ili kujaribu mipaka ya integer, urefu na mashine ya hali.
- Grammar mode huhakikisha kuwa inputs zinatii grammar, lakini target bado hupokea **bytes/strings**, kwa hiyo parsing na ukaguzi wa semantiki hubaki ndani ya code iliyo kwenye harness.

### Differential fuzzing: linganisha implementations, si crashes tu

Mbinu madhubuti kwa mifumo ya Go ni **grammar-based differential fuzzing**: tengeneza inputs halali na zenye muundo, kisha uzitumie kwenye parsers, clients au engines mbili za mabadiliko ya hali.<sup>[[7]](#references)[[8]](#references)</sup>

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

- implementation moja inapata panic huku nyingine ikikataa kwa usahihi
- kutolingana kwa input zinazokubaliwa/kukataliwa
- parse trees au objects zilizodecodeiwa zinatofautiana
- state transitions, nonces, balances, au state roots zinatofautiana

Hii ni njia ya vitendo ya kupata **kutolingana kwa consensus**, **utata wa parser**, na **tofauti kati ya spec na implementation** ambazo fuzzing ya crash pekee mara nyingi hukosa.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tumia tena corpus ya kampeni kwa kuripoti coverage

Baada ya kampeni, rudia corpus ya queue iliyohifadhiwa ili kutoa ripoti ya Go coverage bila kuhamisha corpus tofauti mwenyewe.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Tekeleza amri kutoka **package ileile** na kwa **target ileile ya `-fuzz`** ili gosentry ipate hali sahihi ya campaign iliyohifadhiwa kwenye cache.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing ya sarufi ya mabadiliko](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing kwa Undani](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Miaka Mitano Baadaye: Kuhusu Fuzzing ya Protokali Inayoongozwa na Coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hugeuza code kuwa grafu](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya toolkit. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer ya Greybox ya Kasi kwa Protokali za Mtandao zenye Hali kwa Kutumia Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna Grammar, Hakuna Tatizo: Kuelekea Kufanya Fuzzing ya Linux Kernel Bila Maelezo ya System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing Bora kwa Kutumia Snapshots Zinazojirekebisha na Zinazobadilika](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: coverage ya path na caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing ya Muktadha Inayotabiri](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blogu ya Usalama wa Kukera ya Android - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - nyaraka za build na regression-seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kuchunguza Race Conditions za Linux Kernel kwa Interleavings Zilizodhibitiwa za Memory Access](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: coverage ya code kwa ajili ya fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaksia Iliyopanuliwa ya Jina la Faili ya CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Ushauri wa Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing ya Sintaksia Iliyopanuliwa ya Jina la Faili ya CFITSIO: Udhaifu 16 wa Usalama wa Kumbukumbu na Uchujaji Unaosaidiwa na Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differential fuzzing kwa cryptography](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Kiwango cha Key-Encapsulation Mechanism Kinachotegemea Module-Lattice](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Hitilafu ya uchanganuzi wa XMSSMT OID - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Hali ya Utekelezaji wa Post-Quantum Cryptography](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
