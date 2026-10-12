# Mbinu ya Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **grammar-valid**. Katika hali inayoongozwa na coverage, sampuli zinazosababisha **coverage mpya** pekee ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains**, ambapo matokeo ya construct moja huwa input ya nyingine.<sup>[[1]](#references)</sup>

**Hali ya kushindwa:** fuzzer hupata seeds zinazotekeleza kila moja `document()` na `generate-id()` (au primitives zinazofanana), lakini **haihifadhi dataflow iliyounganishwa**, kwa hiyo sampuli iliyo “karibu zaidi na bug” hutupwa kwa sababu haiongezi coverage. Kwa **hatua tegemezi 3 au zaidi**, recombination ya nasibu huwa ghali na feedback ya coverage haiongozi utafutaji.<sup>[[1]](#references)</sup>

**Maana yake:** kwa grammars zenye utegemezi mwingi, fikiria **kuunganisha awamu za mutational na generative** au kuelekeza generation kwenye mifumo ya **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Changamoto za Utofauti wa Corpus

Mutation inayoongozwa na coverage ni **ya pupa**: sampuli yenye coverage mpya huhifadhiwa mara moja, mara nyingi ikiwa na maeneo makubwa ambayo hayajabadilika. Baada ya muda, corpora huwa **karibu nakala zinazofanana** zenye utofauti mdogo wa kimuundo. Minimization kali inaweza kuondoa muktadha muhimu, kwa hiyo suluhisho la kati linalofaa ni **grammar-aware minimization** inayosimama baada ya kufikia **kizingiti cha chini cha tokeni** (kupunguza kelele huku ikihifadhi muundo wa kutosha unaofaa kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye miundo tofauti zinazoongeza coverage** badala ya mkusanyiko mkubwa wa karibu nakala zinazofanana. Kwa kawaida, hii humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **sampuli za ulimwengu halisi** (corpora za umma, crawling, traffic iliyonaswa, seti za faili kutoka kwenye ecosystem ya target).
- Zichuje kwa **minimization ya corpus inayotegemea coverage** badala ya kuhifadhi kila sampuli halali.
- Hifadhi seeds **ndogo vya kutosha** ili mutations zilenge sehemu zenye maana badala ya kutumia mizunguko mingi kwenye bytes zisizo muhimu.
- Rudia minimization ya corpus baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora zaidi” hubadilika reachability inapobadilika.

## Mutation Inayotambua Comparisons kwa Thamani za Magic

Sababu ya kawaida ya fuzzers kufikia kikomo si syntax bali ni **comparisons kali**: magic bytes, ukaguzi wa urefu, strings za enum, checksums, au thamani za parser dispatch zinazolindwa na `memcmp`, switch tables, au comparisons za mfululizo. Mutation ya nasibu pekee hupoteza mizunguko ikijaribu kukisia thamani hizi byte kwa byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano, workflows za AFL++ `CMPLOG` / Redqueen) ili fuzzer iweze kuona operands kutoka kwenye comparisons zilizoshindwa na kuelekeza mutations kwenye thamani zinazotimiza masharti hayo.<sup>[[3]](#references)</sup>

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

- Hii ni muhimu hasa pale ambapo lengo huficha logic ya ndani nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iunganishe na **dictionaries** zilizotolewa kutoka kwa sampuli halisi, specs za protocol, au debug logs. Dictionary ndogo yenye tokens za sarufi, majina ya chunks, verbs, na delimiters mara nyingi huwa na thamani zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa lengo hufanya ukaguzi mwingi mfululizo, tatua ulinganisho wa mapema zaidi wa “magic” kwanza, kisha punguza corpus inayotokana tena ili hatua zinazofuata zianze na prefixes ambazo tayari ni halali.

## Maoni Tajiri Zaidi Wakati Edge Coverage Inapokunja Njia Tofauti Kuwa Moja

Edge coverage ya kawaida haiwezi kutofautisha executions mbili zinazopita kwenye helper ileile kupitia callers tofauti au kutumia mchanganyiko tofauti wa branches ndani ya function. Hili ni muhimu katika shared decoders, protocol dispatchers, na interpreter helpers ambapo **njia** ya kufikia edge huamua hali inayotumika. Kufuatilia kila calling context bila mpango pia ni hatari: coverage map na queue vinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zenye matumaini pekee badala ya kuchukulia call graph nzima kuwa context-sensitive.<sup>[[14]](#references)</sup>

Build za hivi karibuni za AFL++ hutoa **Ball-Larus per-function path coverage** pamoja na edge coverage ya kawaida. Huipa kila acyclic path kupitia function feature; loop back-edges huondolewa, kwa hiyo feedback hii hutofautisha mchanganyiko wa branches lakini **si idadi ya marudio ya loop**. Anza na level `1` isiyo kali, kisha weka modes kali zaidi kwenye code ya parser/state-machine inayotia shaka kwa sababu idadi ya paths inaweza kukua kwa kasi ya kielelezo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Kwa helper inayoitwa kutoka sehemu nyingi zinazohusiana na usalama, hali ya LTO inaweza kuunganisha kila njia ya function na sehemu yake ya karibu ya kuiita:<sup>[[13]](#references)</sup>

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

**Mwongozo wa campaign:** tumia feedback tajiri zaidi kwa tahadhari na ufuatilie gharama yake kwa coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage sambamba; feedback tajiri husaidia tu ikiwa gharama ya ziada ya queue/map haiathiri vibaya idadi ya executions kwa sekunde.
- Tumia `AFL_LLVM_ALLOWLIST` kuweka kikomo cha path/caller instrumentation wakati maktaba kubwa zenye template nyingi au code ya jumla ya utility zinapotawala map.
- Functions zenye acyclic paths nyingi kupita kiasi zinaweza kurukwa na AFL++; warnings wakati wa compilation ni ishara kwamba target inahitaji allowlisting au kiwango kisicho kali sana.
- Caller + path coverage hutumia kiwango kimoja tu cha kina cha caller. Usiichanganye na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya matoleo makuu ya LLVM. Weka toolchain ileile kwa campaign nzima na usisawazishe corpora zinazotumia PATH kana kwamba feature IDs zake ni thabiti kati ya builds.
- Feedback hii hukamilisha `CMPLOG`: comparison tracing hutatua **ni value gani inayopita guard**, ilhali path/caller feedback huhifadhi **ni route na mchanganyiko gani wa branches ulioifikisha hapo**.

## Fuzzing yenye State: Sequences ni Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, kitengo cha kuvutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kwenye faili moja na kuibadilisha bila mpango kwa kawaida si bora, kwa sababu fuzzer hubadilisha kila hatua kwa kiwango sawa, hata pale ambapo ni message ya baadaye tu inayofikia hali dhaifu.<sup>[[4]](#references)</sup>

Mbinu bora zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **hali inayoonekana** (response codes, protocol states, parser phases, aina za objects zinazorudishwa) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Hifadhi **valid prefix messages** bila mabadiliko na elekeza mutations kwenye message **inayoendesha transition**.
- Hifadhi identifiers na values zinazozalishwa na server kutoka kwa responses zilizotangulia pale hatua inayofuata inapozitegemea.
- Pendelea mutation/splicing kwa kila message badala ya kubadilisha transcript nzima iliyoserialishwa kama blob isiyoeleweka.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **state oracle** ya gharama ndogo ili kuzipa kipaumbele sequences zinazoendelea kwa kina zaidi.

Hii ndiyo sababu authenticated bugs, hidden transitions, au parser bugs zinazotokea “baada tu ya handshake” mara nyingi hukosekana na fuzzing ya kawaida ya mtindo wa faili: fuzzer lazima ihifadhi **mpangilio, hali, na dependencies**, si muundo tu.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing ya driver yenye clients wengi

Edge coverage kubwa bado inaweza kukosa bugs za IPC-driver kwa sababu coverage haielezi **umiliki wa object, reference counts, messages zinazosubiri, mpangilio wa cleanup, au interleavings za threads**. Ukurasa wa [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) unaeleza object model ya driver; mfano huu unaangazia fuzzer harness. Android Binder ni mfano mzuri: kufikia njia za allocation na free hakutoshi ikiwa fuzzer haiwezi kufanya processes nyingi zifanyie kazi kernel object ileile kwa mpangilio unaohitajika.<sup>[[15]](#references)</sup>

#### Modeli protocol, si buffers za `ioctl` zilizotengwa

Wakilisha test case kama grammar yenye mpangilio ya **utambulisho wa client + operation + arguments zenye muundo**. Binder LKL fuzzer hutumia protobuf na `libprotobuf-mutator`, ikiwa na client mmoja endelevu wa context-manager na clients wawili wa kawaida. Semantic harness kisha huhifadhi mahusiano ambayo byte mutation ya upofu ingeharibu.<sup>[[15]](#references)</sup>

- Hifadhi values zinazorejeshwa na operations zilizotangulia. Kwa mfano, `BC_FREE_BUFFER` lazima itumie tena pointer ya transaction-buffer iliyorejeshwa na `ioctl` ya awali.
- Tengeneza majibu ya kawaida yaliyo valid ili transactions za synchronous zikamilike na operations za baadaye zibaki kufikiwa.
- Kataa transitions zisizowezekana kama self-transactions au transactions nyingi zinazosubiri kwa target ileile.
- Weka hali ya bootstrap ya singleton nje ya reset ya kila input. Binder inaruhusu usajili mmoja tu wa `BINDER_SET_CONTEXT_MGR` kwa kila boot, kwa hiyo kuharibu na kuunda upya client hiyo mara kwa mara kungefanya inputs za baadaye ziwe invalid.

Template muhimu ya lifetime-race ni kufanya client mmoja ihamishe object, kuanzisha cleanup ya thread au process, na wakati huohuo kufanya client inayopokea iachilie transaction buffer. Katika mfano wa CVE-2020-0423, uhamishaji wa `BINDER_TYPE_WEAK_BINDER` uliofuatiwa na `BINDER_THREAD_EXIT` ukigongana na `BC_FREE_BUFFER` ungeweza kufree `binder_work` iliyopachikwa huku cleanup path ya thread inayotoka bado ikiitumia.<sup>[[15]](#references)</sup>

#### Rejesha interleavings zinazodhibitiwa kwenye kernel ya userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) huunganisha code halisi ya kernel kwenye userspace harness na kufichua syscall interface yake kupitia `lkl_syscall`. Hii hurahisisha kuratibu protobuf state, coverage, na KASAN katika process moja. Hata hivyo, LKL kwa kawaida huendesha syscall bila kernel thread nyingine kuikatiza. Kwa race campaigns, weka sehemu za `schedule()` karibu na mipaka iliyochaguliwa ya lock/unlock na lifetime, kisha iache harness ichague client inayofuata kwa nasibu katika kila yield. Weka sehemu hizi kwenye maeneo lengwa kwa sababu kila moja huongeza mara nyingi ukubwa wa scheduling search space. Randomized scheduler iliyoelezwa na watafiti **si** sehemu ya upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Build na replay regression seeds zilizoserialishwa

Upstream harness hufunga toleo linalooana la `libprotobuf-mutator`, huwasha LKL fuzzing instrumentation na KASAN kwa `LKL_FUZZING=1`, na huwasha `CONFIG_MMU` kwa Binder kwa kutumia `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Baada ya kufanya checkout ya revision iliyoathiriwa kimakusudi au kutumia rollback patches zilizoandikwa kwenye upstream, serialized seed inaweza kuzalisha upya mabadiliko yote ya hali ya multi-client bila kuhitaji kuijenga upya katika C proof of concept ya ad-hoc:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Chukulia use-after-free ya KASAN iliyopatikana kuwa uthibitisho kwamba seed ilifikia njia ya lifetime iliyo hatarini. **Haithibitishi** primitives za baadaye zinazohitajika ili kutekeleza code kwenye kernel au kuongeza ruhusa.<sup>[[16]](#references)</sup>

## Mbinu ya Utofauti kwenye Mashine Moja (Mtindo wa Jackalope)

Njia ya vitendo ya kuchanganya **ubunifu wa generative** na **utumiaji upya wa coverage** ni kuwasha upya workers wanaofanya kazi kwa muda mfupi dhidi ya server inayoendelea kufanya kazi. Kila worker huanza na corpus tupu, husawazisha baada ya sekunde `T`, huendesha kwa sekunde nyingine `T` kwa kutumia corpus iliyounganishwa, husawazisha tena, kisha hutoka. Hii huzalisha **miundo mipya kila kizazi** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers wa kufuatana (mfano wa loop):**

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

- `-in empty` hulazimisha **corpus mpya** kwa kila generation.
- `-server_update_interval T` hukaribia **sync iliyocheleweshwa** (novelty kwanza, reuse baadaye).
- Katika hali ya grammar fuzzing, **initial server sync hurukwa kwa chaguomsingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadilisha baada ya worker kupata coverage nyingi za “easy” kwa kawaida hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Targets Zilizo Ngumu Kuweka Katika Harness

Wakati code unayotaka ku-test inafikika tu **baada ya gharama kubwa ya setup** (ku-boot VM, kukamilisha login, kupokea packet, kuchanganua container, kuanzisha service), mbadala unaofaa ni **snapshot fuzzing**: kunasa hali ya process au VM iliyo tayari, kuingiza kila test case kwenye njia ya input ya target, kutekeleza hadi crash/timeout, kisha kurejesha snapshot. Hii huepusha kurudia initialization au protocol prefixes na inafaa kwa **network services**, **firmware**, **attack surfaces baada ya auth**, na **targets za binary pekee**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayokuvutia iwe tayari.
2. Hifadhi snapshot ya **memory + registers** wakati huo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Tekeleza hadi crash/timeout/reset.
5. Rejesha snapshot; kwa targets za VM, rejesha **dirty pages** pekee inapoungwa mkono, kisha urudie.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya parse/dispatch, kama vile baada ya `recv`/`read` au sehemu ya packet-deserialization, na urekodi input buffer inayotumiwa na target. Hii hufuata kanuni ya adaptive placement ya kusogeza snapshot ndani zaidi katika uchakataji wa input ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Kuchunguza Linux Kernel Race Kwa Kutumia MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) hubadilisha race conditions za Linux kernel zinazotegemea timing kuwa ratiba za memory-access zinazoweza kurudiwa. Inaweza kuorodhesha kiotomatiki execution za **A-B-A** za contexts mbili, au kumruhusu mchambuzi kuweka masharti ya mpangilio kwenye terminal UI/GUI. Hii ni tooling ya majaribio ya utafiti, si concurrency fuzzer kamili: kwa sasa inahitaji LLVM 23+ na kernel iliyowekewa patches na mradi, command-line tools zinaunga mkono test threads mbili, na safu ya userspace fuzzing iliyopendekezwa haijatekelezwa.<sup>[[17]](#references)[[18]](#references)</sup>

### Kukusanya sehemu za mawasiliano kati ya contexts

Build kernel yenye instrumentation kwa kutumia KASAN outline callbacks na usaidizi wa patched KCOV wa kurekodi memory. README ya mradi pia inapendekeza kuzima sibling-call optimization ili call stacks ziendelee kutumika.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) hubadilisha accesses zilizo instrumentiwa kuwa miito ya helper. Kernel patches za MAccConc huzima `asan-opt-same-temp` ili accesses zinazofuatana zisiunganishwe; zima pia optimization ya `asan-opt-globals` pale ambapo races za global variables zinapaswa kuonekana. KCOV hupeleka rekodi zinazotokana na hatua hii kwa userspace. Linganisha accesses kutoka execution contexts tofauti na uhifadhi jozi ambazo byte ranges zake zinaingiliana na ambapo angalau upande mmoja unaandika; chukulia `kfree()` kama write ili mabadiliko ya lifetime pia yawe candidates.<sup>[[17]](#references)</sup>

Kwa kazi inayoendelea nje ya task iliyoianzisha, kama vile packet processing au RCU callbacks, subsystem lazima isambaze handle ya KCOV remote-coverage. Remote KCOV ya upstream ni opt-in na haipatikani kiotomatiki kwa kazi yoyote ya background, hivyo kutosambaza handle kunaweza kufanya mwingiliano halisi usionekane.<sup>[[17]](#references)[[19]](#references)</sup>

### Tambua access ileile ya dynamic katika kila run

Usifanye replay kwa kutumia anwani halisi ya heap, ambayo inaweza kubadilika baada ya kila allocation, au anwani ya instruction pekee, ambayo ina utata ndani ya helpers kama `memcpy()` na `spin_lock()`. MAccConc hutumia **count-augmented stack trace**: kila frame hutambua callee pamoja na hesabu ya invocations ndani ya caller wake, na kipengele cha mwisho hutambua instruction ya memory-access. Rekodi za kuingia/kutoka kwenye function za SanitizerCoverage huruhusu userspace kujenga upya kitambulisho hiki cha dynamic, ambacho hubaki thabiti licha ya mabadiliko ya anwani na kelele zisizohusiana za control-flow.<sup>[[17]](#references)</sup>

### Geuza jozi za candidates kuwa ratiba zinazolazimishwa

Ioctl iliyopatchiwa ya `KCOV_SET_DI` huhusisha kitambulisho cha access cha count-augmented na kitendo cha shared-flag.<sup>[[17]](#references)</sup>

| Kitendo | Maana |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Weka flag *N* mara moja kabla ya access iliyochaguliwa. |
| `DI_STACK_WAIT` | Kabla ya access iliyochaguliwa, subiri kwa kuzunguka hadi flag *N* iwekwe au kikomo kilichosanidiwa kiishe. |
| `DI_STACK_WAKE_POST` | Weka flag *N* mara moja baada ya access iliyochaguliwa. |

Kwa sharti la sehemu la **A-happens-before-B**, weka `DI_STACK_WAKE_POST` kwenye A na `DI_STACK_WAIT` kwenye B ukitumia flag ileile. Kwa ratiba iliyobainishwa kikamilifu ya contexts mbili, anza B ikiwa imezuiwa, kisha A iamshie B na isubiri kwenye sehemu ya kwanza ya uhamishaji; B hufanya kitendo cha kinyume kwenye uhamishaji unaofuata. Hii hufanya kazi kama kubadilisha context kwa namna ya deterministic, na ndiyo inayotumiwa na A-B-A explorer ya kiotomatiki.<sup>[[17]](#references)</sup>

Campaign ndogo kabisa ni kucompile test case ya four-hook (`test_setup`, functions mbili za thread, na `test_end`) kama shared library, kukusanya trace isiyo na vikwazo, kisha kuorodhesha candidates za A-B-A au kuongeza constraints za mkono kuzunguka accesses zinazotia shaka.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Tafsiri muda wa kusubiri kando na upangaji upya uliofanikiwa: mpangilio ulioombwa huenda usiwezekane kwa sababu ya lock au utegemezi wa uanzishaji/uchapishaji unaozuia context ya pili kufika kwenye sehemu yake ya injection. Pia zingatia maeneo ambayo KASAN haikagui: ufikiaji wa moja kwa moja wa stack kwa kawaida hauwekwi hooks isipokuwa kuna uwezekano wa kwenda nje ya mipaka, globals huachwa kwa optimization chaguomsingi, na compilers za sasa haziwezi kutoa hooks za ASAN na TSAN kwa wakati mmoja. Hatimaye, prototype hupoteza buffer yake ya KCOV mgeni anapopata panic, kwa hiyo hifadhi crash console/oracle huru.<sup>[[17]](#references)</sup>

Kwa fuzzing ya baadaye inayoongozwa na concurrency, rekodi muhtasari wa ufikiaji wa kumbukumbu kwa kila ingizo au syscall, oanisha operesheni ambazo zingeunda sehemu za mawasiliano kati ya contexts, kisha chunguza michanganyiko hiyo pekee. VM snapshots huweka hali ya kimataifa na anwani thabiti; bila snapshots, metadata ya allocation-site inaweza kutoa muhtasari wa objects katika runs mbalimbali. Hili ni pendekezo la upanuzi, si kipengele cha sasa cha zana za userspace za MAccConc.<sup>[[17]](#references)</sup>

## Ukaguzi wa Harness: Tambua Fuzzers Zisizofika Mbali Mapema

Campaign inapokwama, mara nyingi tatizo si mutator bali ni **harness**. Tumia **ukaguzi wa reachability/coverage** ili kupata functions zinazoweza kufikiwa kistatiki kutoka kwenye fuzz target yako lakini ambazo hazifunikwi sana au hazifunikwi kabisa wakati wa utekelezaji. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness huingia kwenye target mapema mno au kwa kuchelewa mno.
- Seed corpus haina familia nzima ya vipengele.
- Target inahitaji **harness ya pili** badala ya harness moja kubwa kupita kiasi ya “kufanya kila kitu”.

Ukitumia workflows za aina ya OSS-Fuzz / ClusterFuzz, Fuzz Introspector inaweza kulinganisha reachability ya kistatiki na coverage ya wakati wa utekelezaji na kutoa ripoti kutokana na run ya muda maalum au corpus ya umma.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Tumia ripoti kuamua ikiwa utaongeza harness mpya kwa njia ya parser ambayo haijajaribiwa, kupanua corpus kwa kipengele mahususi, au kugawa harness moja kubwa katika entrypoint ndogo.

## Uteuzi wa Fuzz Target kwa Kutanguliza Graph na Triage ya Mutation

Ikiwa tayari una **matokeo ya static analysis**, **mutation-testing survivors**, na **ripoti za coverage**, usizichambue kama orodha zinazojitegemea. Jenga **call graph** kwanza, weka kwenye nodes taarifa za **cyclomatic complexity**, **uwezekano wa kufikiwa kutoka entrypoint/ingizo lisiloaminika**, na matokeo yoyote ya nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity ya juu zinazoweza kufikiwa kutoka kwenye ingizo lisiloaminika?
- Ni mutation survivors zipi ziko kwenye njia kutoka kwa parsers/handlers hadi kwenye code muhimu kwa usalama?
- Ni functions zipi ni vikwazo muhimu vya usanifu na zina **blast radius** kubwa isiyo ya kawaida?

Kwa kawaida, hili hufichua fuzz targets bora kuliko kuangalia "coverage ya chini zaidi" pekee. Parser/decoder yenye **complexity ya juu** na **ufikikaji wa nje uliothibitishwa** ni mgombea bora zaidi wa harness kuliko helper ya ndani iliyotengwa, yenye coverage dhaifu lakini isiyo na njia inayodhibitiwa na mshambulizi.

### Mchakato wa vitendo wa triage

1. Jenga **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branch kwa kila function.
2. Orodhesha **entrypoints** zinazopokea ingizo linalodhibitiwa na mshambulizi: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Endesha **path queries** kutoka kwenye entrypoints hadi kwenye functions zinazoweza kuchaguliwa ili kutenganisha attack surface inayofikika na code iliyokufa/inayoweza kufikiwa kutoka ndani pekee.
4. Tanguliza nodes zinazochanganya:
   - **cyclomatic complexity** ya juu
   - **ufikikaji uliothibitishwa kutoka kwenye ingizo lisiloaminika**
   - **blast radius** kubwa au dependents wengi wa chini
   - ushahidi unaothibitisha, kama matokeo ya **SARIF**, maelezo ya ukaguzi, au mutation survivors
5. Andika harnesses zinazolenga nodes bora zaidi kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: sawa au zinazoweza kuchukuliwa hatua

Mutation testing mara nyingi hutoa orodha ya survivors yenye kelele nyingi. Kabla ya kuchukulia kila survivor kuwa pengo la usalama, tumia graph kuuliza:

- Je, function iliyofanyiwa mutation inaweza kufikiwa kutoka kwenye entrypoint inayodhibitiwa na mshambulizi?
- Je, njia zote za kuita function hiyo zinadhibitiwa na invariants zenye nguvu zaidi kuliko ukaguzi uliofanyiwa mutation?
- Je, node hiyo iko kwenye code iliyokufa, logic ya uumbizaji pekee, au njia ya arithmetic/parser yenye athari kubwa?

Survivors ambazo bado hazifikiwi au zimewekewa vikwazo kimuundo mara nyingi ni **equivalent mutants**. Survivors ambazo bado **zinafikiwa** na zinagusa **mipaka**, **njia za overflow/carry**, au **arithmetic/parsing muhimu kwa usalama** zinapaswa kupewa kipaumbele katika:

- fuzz harnesses mpya
- majaribio ya moja kwa moja ya property/invariant
- vectors lengwa za hali za ukingoni

### Linganisha matokeo ya nje na graph

Ikiwa pipeline yako ya SAST inatoa **SARIF**, weka matokeo kwenye nodes za graph kwa kutumia **file + line range**, kisha tumia graph kupanua tathmini ya athari.<sup>[[6]](#references)</sup>

- kokotoa **blast radius** ya function iliyotiwa alama
- angalia ikiwa matokeo yapo kwenye njia yoyote kutoka kwenye entrypoint
- panga pamoja matokeo yaliyo karibu yanayoishia kwenye kizuizi kilekile

Hii ni muhimu unapoamua kama utatumia muda wa fuzzing kwenye function mahususi: node ambayo **inafikiwa**, **ina complexity kubwa**, na tayari ina **matokeo ya SAST** mara nyingi huwa target bora kuliko node yenye complexity kubwa tu lakini isiyo na njia kutoka kwa mshambulizi.

Mfano wa mchakato wa kazi kwa kutumia Trailmark.<sup>[[6]](#references)</sup>

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

Mbinu muhimu ni makutano ya: **complexity x exposure x impact**. Tumia grafu kuchagua fuzz targets zenye thamani ya usalama inayotarajiwa zaidi, kisha tumia mutation survivors kubaini mipaka na invariants ambazo harness yako lazima izijaribu kwa msisitizo.<sup>[[5]](#references)</sup>

## Go Fuzzing Kwa kutumia gosentry: Engine Imara Zaidi, Inputs Zenye Aina Zilizobainishwa, Na Ukaguzi Tofauti

Ikiwa target ya Go tayari ina harness ya asili ya `testing.F`, njia rahisi ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), toolchain ya Go iliyofanyiwa fork ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Hii ni muhimu pale native Go fuzzer inapokwama kwenye **ulinganisho mgumu**, **ingizo zenye aina maalum**, au **miundo inayotegemea sana parser**. Mbinu inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia campaign inayotokana na hilo kama run ya kawaida inayoongozwa na coverage, lakini yenye scheduling/mutation ya LibAFL na detectors bora zaidi zinazohusika.

### Geuza hitilafu zisizoonekana kuwa findings za fuzz

Tatizo linalojirudia katika tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa chaguo-msingi. Kwa gosentry, unaweza kugeuza aina kadhaa za hali “mbaya lakini zisizoonekana” kuwa findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili njia maalum za logging/error zifanye kazi kama crash (inafaa kwa njia za msimbo za aina ya `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kucheza tena queue entries zilizogunduliwa upya kwa kutumia Go race detector.
- `--catch-leaks=true` ili kucheza tena queue entries mpya kwa kutumia `goleak` na kusitisha kunapokuwa na goroutine leaks.
- Ushughulikiaji wa hang wa LibAFL ili kuhifadhi **infinite loops / ingizo za polepole sana** kama findings za fuzz badala ya kuzipoteza kama timeouts.
- Ukaguzi wa arithmetic overflow uliojumuishwa kwa chaguo-msingi, pamoja na ukaguzi wa hiari wa truncation kupitia instrumentation ya mtindo wa go-panikint.

Hili ni muhimu hasa kwa targets ambazo athari ya kiusalama ni **hitilafu ya parser isiyoleta panic**, **hitilafu ya concurrency**, au **hang ya DoS pekee**, badala ya uharibifu wa memory.

### Fuzzing inayotambua struct kwa Go APIs zenye aina maalum

Native Go fuzzing hutarajia zaidi scalars kama `[]byte`, `string`, na namba. Ikiwa msimbo unaojaribiwa hutumia objects zenye aina maalum, gosentry inaweza kufuzz **thamani changamano** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kubadilisha bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>

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

Tumia hili unapounda wire format bandia, kwa kuwa kufanya hivyo kwa ajili ya fuzzing pekee kungeficha hitilafu za logic ndani ya msimbo wa parsing wa harness pekee. Kwa kampeni za differential au zinazotegemea grammar, weka ingizo la harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Fuzzing inayotegemea grammar kwa parser na ingizo la protocol

Kwa parser, format na lugha za ingizo, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni safu ya JSON ya production rules, na kwa kawaida harness inapaswa kupokea hoja moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Vidokezo vya mbinu:

- Tumia grammar mode pale mutations za kiwango cha byte zinaposhindwa mara nyingi kwenye ukaguzi wa awali wa syntax.
- Lenga grammar kwenye **sehemu ndogo ya lugha/protocol inayohusika na usalama** badala ya kuiga specification nzima.
- Tumia thamani kubwa za mipaka kwenye terminals/nonterminals ili kuchunguza mipaka ya integer, urefu na state machine.
- Grammar mode huhakikisha inputs zinafuata grammar, lakini target bado hupokea **bytes/strings**, kwa hiyo parsing na ukaguzi wa semantiki hubaki ndani ya code inayofanyiwa majaribio.

### Differential fuzzing: linganisha implementations, si crashes pekee

Mbinu yenye manufaa katika mifumo ya Go ni **grammar-based differential fuzzing**: tengeneza inputs halali zenye muundo na uzitumie kwenye parsers, clients au state-transition engines mbili.<sup>[[7]](#references)[[8]](#references)</sup>

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

- implementation moja husababisha panic huku nyingine ikikataa kwa usahihi
- kutolingana kwa input zinazokubaliwa/kukataliwa
- parse trees au objects zilizofumbuliwa kuwa tofauti
- tofauti katika mabadiliko ya state, nonces, balances au state roots

Hii ni njia ya vitendo ya kupata **kutolingana kwa consensus**, **utata wa parser** na **tofauti kati ya spec na implementation** ambazo fuzzing ya crash pekee mara nyingi hukosa.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tumia tena corpus ya campaign kwa kuripoti coverage

Baada ya campaign, rudia corpus ya foleni iliyohifadhiwa ili kutoa ripoti ya Go coverage bila kuhamisha corpus tofauti mwenyewe.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Tekeleza amri kutoka **package** hiyo hiyo na kwa target ileile ya `-fuzz` ili gosentry itambue hali sahihi ya campaign iliyohifadhiwa kwenye cache.



## References

- [1] [Fuzzing ya sarufi ya mabadiliko](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing ya AFL++ kwa kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Miaka Mitano Baadaye: Kuhusu Fuzzing ya Protocol Inayoongozwa na Coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hubadilisha code kuwa grafu](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya zana. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Greybox Fuzzer ya Haraka kwa Stateful Network Protocols inayotumia Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna Grammar, Hakuna Tatizo: Kuelekea Kufanya Fuzzing ya Linux Kernel Bila Maelezo ya System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing Yenye Ufanisi kwa Kutumia Snapshots Zinazobadilika na Kurekebishwa](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation ya AFL++ LLVM: path na caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing ya Muktadha Inayotabiri](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blogu ya Android Offensive Security - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - nyaraka za build na regression-seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kuchunguza Race Condition za Linux Kernel kwa Kuingiliana kwa Memory Access Kunakodhibitiwa](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: code coverage kwa ajili ya fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
