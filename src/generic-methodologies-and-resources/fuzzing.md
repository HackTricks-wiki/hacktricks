# Mbinu za Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **valid kwa grammar**. Katika hali inayoongozwa na coverage, sampuli zinazosababisha **coverage mpya** pekee ndizo huhifadhiwa kama seeds za corpus. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **minyororo ya semantic/dataflow**, ambapo output ya construct moja inakuwa input ya nyingine.<sup>[[1]](#references)</sup>

**Hali ya kushindwa:** fuzzer hupata seeds zinazotekeleza kila moja `document()` na `generate-id()` (au primitives zinazofanana), lakini **haihifadhi dataflow iliyounganishwa**, kwa hiyo sampuli iliyo “karibu zaidi na bug” hutupwa kwa sababu haiongezi coverage. Kwa **hatua 3 au zaidi zinazotegemeana**, uunganishaji upya wa nasibu huwa wa gharama kubwa, na feedback ya coverage haielekezi utafutaji.<sup>[[1]](#references)</sup>

**Maana yake:** kwa grammars zenye utegemezi mwingi, zingatia **kuchanganya awamu za mutational na generative** au kuelekeza uzalishaji zaidi kwenye mifumo ya **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Mitego ya Utofauti wa Corpus

Mutation inayoongozwa na coverage ni **ya pupa**: sampuli yenye coverage mpya huhifadhiwa mara moja, mara nyingi ikiwa na sehemu kubwa ambazo hazijabadilika. Baada ya muda, corpora huwa **karibu nakala zinazofanana** zenye utofauti mdogo wa kimuundo. Minimization kali inaweza kuondoa muktadha muhimu, kwa hiyo suluhisho la vitendo ni **minimization inayozingatia grammar**, ambayo **husimama baada ya kufikia kiwango cha chini cha tokens** (kupunguza kelele huku ikihifadhi muundo wa kutosha unaofaa kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye miundo tofauti zinazoongeza coverage** kuliko rundo kubwa la karibu nakala zinazofanana. Kwa kawaida, hili humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **sampuli za ulimwengu halisi** (corpora za umma, crawling, traffic iliyorekodiwa, seti za faili kutoka kwenye ecosystem ya target).
- Zichuje kwa **minimization ya corpus inayotegemea coverage** badala ya kuhifadhi kila sampuli valid.
- Hifadhi seeds **ndogo vya kutosha** ili mutations ziguse fields zenye maana badala ya kutumia mizunguko mingi kwenye bytes zisizo muhimu.
- Endesha tena minimization ya corpus baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Programs kubwa zilizozalishwa na upendeleo wa timeout

Kwa fuzzing ya compiler na interpreter, input inaweza kuhitaji kuvuka **kizingiti cha ukubwa wa generated code** badala ya kufikia branch mpya ya parser. Katika mfano wa V8 [exception-handler offset](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size), testcase valid ilihitaji zaidi ya MiB 256 za bytecode kabla ya handler offset iliyokatwa kuwa muhimu. Constructs za `yield*` zilizorudiwa zingeweza kufikia kizingiti hicho, lakini kucompile testcase kulichukua sekunde kadhaa kwenye debug build. Upendeleo kwa inputs ndogo na timeouts fupi za utekelezaji unaweza kuipendelea vibaya aina hii, hata kama grammar coverage iko juu. Unapokagua offsets zilizopakiwa au metadata nyingine nyeti kwa urefu, zingatia kizingiti cha ukubwa na sera ya timeout kando; ushauri huu wa kampeni ni hitimisho linalotokana na hali ya kushindwa iliyoripotiwa.<sup>[[29]](#references)</sup>

## Mutation Inayozingatia Comparisons kwa Magic Values

Sababu ya kawaida inayofanya fuzzers kufikia kiwango cha juu na kushindwa kuendelea si syntax bali **comparisons ngumu**: magic bytes, ukaguzi wa urefu, enum strings, checksums, au thamani za parser dispatch zinazolindwa na `memcmp`, switch tables, au comparisons zinazofuatana. Mutation ya nasibu pekee hupoteza mizunguko ikijaribu kubahatisha thamani hizi byte baada ya byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano, workflows za mtindo wa AFL++ `CMPLOG` / Redqueen) ili fuzzer iweze kuona operands za comparisons zilizoshindwa na kuelekeza mutations kwenye thamani zinazozitimiza.<sup>[[3]](#references)</sup>

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

- Hii ni muhimu hasa pale ambapo target huzuia mantiki ya ndani kwa kutumia **saini za faili**, **vitenzi vya protocol**, **lebo za aina**, au **biti za vipengele zinazotegemea toleo**.
- Iunganishe na **dictionaries** zilizotolewa kutoka kwa sampuli halisi, specifikasheni za protocol, au logi za utatuzi. Dictionary ndogo yenye tokeni za sarufi, majina ya vipande, vitenzi, na vitenganishi mara nyingi huwa na manufaa zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa target hufanya ukaguzi mwingi mfululizo, tatua kwanza ulinganishaji wa mapema zaidi wa “magic”, kisha punguza tena corpus iliyopatikana ili hatua zinazofuata zianze na viambishi awali ambavyo tayari ni halali.

## Kufuzz File APIs Zinazoficha Lugha ya Filename

Kigezo kinachoitwa `filename`, `path`, au `URL` kinaweza kuwa sehemu ya kuingilia interpreter badala ya utafutaji halisi wa faili. Kwa mfano, CFITSIO Extended Filename Syntax (EFS) hutathmini viteuzi vilivyo ndani ya mabano, misemo ya safu/pikseli, safu wima zilizokokotolewa, histogramu, na mabadiliko kabla ya kurudisha kitu kilichofunguliwa; baadhi ya miundo pia huunda nakala za muda. Wakati wa kuchora ramani ya eneo la mashambulizi, ainisha kila API ya kufungua/kuingiza kama **literal-path** au **interpreted-path**, kisha fanya fuzzing kwenye entry point ya uzalishaji ambayo programu hutumia hasa.<sup>[[20]](#references)[[22]](#references)</sup>

Kwa primitives za SSRF, kunakili faili, na vishughulikiaji vya protocol vinavyotokana na hili—na API salama zaidi za literal-path—tazama [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Weka object ya msingi tofauti na programu inayofanyiwa fuzzing

Sarufi ikiwa kwenye kiambishi tamati cha filename, kubadilisha tu baiti za faili inayorejelewa hakuifikii parser. Badala yake, harness ndogo inaweza kusoma testcase moja kama mfuatano wa herufi na kuipitisha kwa API ya open iliyotafsiriwa; kampeni ya CFITSIO ilifikia parser na evaluator nyingi za EFS kwa kuita `fits_open_file()` katika hali ya kusoma pekee. Weka faili halali za msingi kando ili mabadiliko yaelekezwe kwenye lugha ya viteuzi/misemo badala ya kuendelea kuharibu njia ya msingi.<sup>[[22]](#references)</sup>

Tumia seeds ambazo kila moja hufikia familia tofauti ya sarufi, kisha tengeneza dictionary fupi kutoka kwa specifikasheni na msimbo wa lexer/parser. Coverage ikikwama huku inputs zikishindwa mara kwa mara kwenye njia ileile ya hitilafu ya sintaksia, hifadhi viambishi awali halali na uongeze vitenganishi, waendeshaji, maneno muhimu, majina ya function, na majina wakilishi ya sehemu badala ya kuongeza tu muda wa mabadiliko ya nasibu.<sup>[[22]](#references)</sup>

Endesha harness kwa kutumia dictionary ya sarufi, kwa mfano:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Zuia athari za pembeni za harness ya "read-only"

Bendera ya library ya read-only haihakikishi kuwa testcase haitasababisha athari za pembeni: lugha ya majina ya faili inaweza kuandika upya ingizo, kuunda faili za matokeo, au kuunda vitu vya muda. Kampeni ya CFITSIO iliharibu faili za seed mwanzoni na kuacha faili zisizotarajiwa kwenye mfumo wa faili, hivyo usafishaji na utengaji vilihitajika.<sup>[[22]](#references)</sup>

- Mpe kila worker directory yake ya muda inayoweza kutupwa na directory yake binafsi ya muda.
- Toa nakala za faili za msingi za kikanuni; usiruhusu target ibadilishe nakala pekee ya corpus.
- Zima ufikiaji wa mtandao isipokuwa backends za mbali ziwe ndizo target, na weka mipaka kwa njia zinazoweza kuandikika kwa kutumia container, mount namespace, au sandbox inayolingana.
- Rejesha hali ya directory baada ya kila utekelezaji au kundi la workers, na uchukulie mabadiliko yasiyotarajiwa ya mfumo wa faili kama matokeo ya ziada.

### Mzunguko wa crash-to-patch-to-fuzz

Panga crash katika makundi kabla ya kurekebisha ili maelfu ya artifacts yasigeuke kuwa maelfu ya kazi za patch. Katika tathmini ya CFITSIO, AFLTriage ilipunguza seti ya awali ya crash hadi sababu chache za msingi; advisory iliyotokana nayo inaonyesha hitilafu tofauti, zikiwemo ukaguzi usio sahihi wa ukubwa wa eneo lengwa, pointers zilizopitwa na wakati baada ya `realloc()`, hitilafu za hesabu, na njia zisizo salama za kusafisha parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Punguza ingizo wakilishi kwa kila kundi na uthibitishe tena hitilafu hiyo kwa kutumia AddressSanitizer.
2. Rekodi ufikiaji halisi ulioshindwa, eneo kwenye source, historia ya allocation/free, na hali ya parser iliyofanya invariant iwe batili.
3. Tumia candidate patch yenye wigo finyu na ujenge tena kwa instrumentation ileile ya coverage na sanitizer.
4. Cheza tena reproducer ya awali **na kila ingizo katika kundi lake**; pia washa ugunduzi wa leak kwa sababu marekebisho ya usalama wa kumbukumbu yanaweza kuvuruga umiliki kwenye njia ya hitilafu.
5. Tekeleza majaribio ya utendaji kwa kutumia faili halisi, kisha endelea kutoka kwenye queue iliyokusanywa (au i-import tena queue hiyo ikiwa engine inahitaji directory mpya ya matokeo baada ya binary kubadilika).
6. Rudia: kuondoa crash ya kwanza ya juu juu mara nyingi huruhusu seed zilizopo kufikia hali ya ndani zaidi ya parser.

LLM inaweza kuharakisha hatua ya 2 na kuandaa rasimu ya hatua ya 3 inapopewa ingizo lililosababisha crash, ripoti ya sanitizer, harness, na source husika, lakini patch yake bado haiaminiki. Uchezaji tena kwa sanitizer na vigezo vya regression—si maelezo ya model—ndivyo vinavyoamua kama marekebisho yatakubaliwa.<sup>[[22]](#references)</sup>

## Maoni Tajiri Zaidi Wakati Edge Coverage Haiwezi Kutofautisha Njia Tofauti

Edge coverage ya kawaida haiwezi kutofautisha utekelezaji miwili inayopita kwenye helper ileile kupitia callers tofauti au inayochukua michanganyiko tofauti ya branch ndani ya function. Hili ni muhimu katika decoders zinazoshirikiwa, protocol dispatchers, na helpers za interpreter ambapo **njia** ya kufikia edge huamua hali inayotumika. Kufuatilia kila calling context bila mpango pia ni hatari: coverage map na queue vinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zenye matumaini pekee badala ya kuchukulia call graph nzima kuwa context-sensitive.<sup>[[14]](#references)</sup>

Build za hivi karibuni za AFL++ hutoa **Ball-Larus per-function path coverage** pamoja na edge coverage ya kawaida. Huipa kila njia isiyo na mizunguko ndani ya function kipengele chake; back-edge za loop huondolewa, kwa hiyo maoni haya hutofautisha michanganyiko ya branch lakini **si idadi ya marudio ya loop**. Anza na kiwango tulivu `1`, kisha weka modes kali zaidi kwenye parser/state-machine code inayotia shaka kwa sababu idadi ya njia inaweza kukua kwa kasi ya kiexponential.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Kwa helper inayoitwa kutoka maeneo mengi yanayohusiana na usalama, hali ya LTO inaweza kuchanganya kila njia ya function na sehemu yake ya moja kwa moja ya mwito:<sup>[[13]](#references)</sup>

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

**Mwongozo wa campaign:** tumia feedback tajiri zaidi kwa uangalifu na ufuatilie gharama yake kwenye coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage sambamba; feedback tajiri zaidi ina manufaa tu ikiwa gharama ya ziada ya queue/map haiharibu idadi ya executions kwa sekunde.
- Tumia `AFL_LLVM_ALLOWLIST` kupunguza instrumentation ya path/caller wakati libraries kubwa zenye templates nyingi au generic utility code zinachukua sehemu kubwa ya map.
- AFL++ inaweza kuruka functions zenye acyclic paths nyingi kupita kiasi; warnings wakati wa compilation zinaashiria kuwa target inahitaji allowlisting au level isiyo kali sana.
- Coverage ya caller + path inaruhusu kina kimoja tu cha caller. Usiichanganye na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya major versions za LLVM. Tumia toolchain ileile kwa campaign nzima na usisawazishe corpora za PATH kana kwamba feature IDs zake ni thabiti kati ya builds.
- Feedback hii hukamilisha `CMPLOG`: comparison tracing hutatua **ni thamani gani inapita guard**, ilhali feedback ya path/caller huhifadhi **ni njia gani na mchanganyiko gani wa branches ulioifikisha hapo**.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, kitu cha kuvutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kwenye faili moja na kuibadilisha bila mpango kwa kawaida hakufai, kwa sababu fuzzer hubadilisha kila hatua kwa usawa, hata pale ambapo ni message ya baadaye tu inayofikia hali dhaifu.<sup>[[4]](#references)</sup>

Mbinu bora zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **hali inayoonekana** (response codes, protocol states, parser phases, aina za objects zilizorejeshwa) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Hifadhi **valid prefix messages** bila kuzibadilisha, na elekeza mutations kwenye message **inayoendesha transition**.
- Hifadhi identifiers na values zinazozalishwa na server kutoka kwa responses zilizopita pale hatua inayofuata inapozitegemea.
- Pendelea mutation/splicing kwa kila message badala ya kubadilisha transcript nzima iliyoserializwa kana kwamba ni blob isiyo na muundo.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **state oracle ya gharama ndogo** ili kutanguliza sequences zinazoendelea kufika hatua za ndani zaidi.

Hii ndiyo sababu bugs za authenticated, transitions zilizofichwa, au parser bugs zinazotokea “baada tu ya handshake” mara nyingi hukosekana kwenye vanilla file-style fuzzing: fuzzer lazima ihifadhi **mpangilio, hali na dependencies**, si muundo pekee.<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Edge coverage ya juu bado inaweza kukosa bugs za IPC-driver kwa sababu coverage haielezi **umiliki wa objects, reference counts, messages zinazosubiri, mpangilio wa cleanup, au thread interleavings**. Ukurasa wa [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) unaeleza modeli ya objects za driver; mfano huu unalenga fuzzer harness. Android Binder ni mfano mzuri: kufikia njia za allocation na free hakutoshi ikiwa fuzzer haiwezi kusababisha processes nyingi kuendesha kernel object ileile kwa mpangilio unaohitajika.<sup>[[15]](#references)</sup>

#### Model the protocol, not isolated `ioctl` buffers

Wakilisha test case kama grammar yenye mpangilio ya **utambulisho wa client + operation + structured arguments**. Binder LKL fuzzer hutumia protobuf na `libprotobuf-mutator`, pamoja na client mmoja endelevu wa context-manager na clients wawili wa kawaida. Semantic harness kisha huhifadhi mahusiano ambayo byte mutation ya upofu ingevunja.<sup>[[15]](#references)</sup>

- Hifadhi values zilizorejeshwa na operations za awali. Kwa mfano, `BC_FREE_BUFFER` lazima itumie tena pointer ya transaction-buffer iliyorejeshwa na `ioctl` ya awali.
- Tengeneza replies halali za msingi ili synchronous transactions zikamilike na operations za baadaye ziendelee kufikika.
- Kataa transitions zisizowezekana kama self-transactions au transactions nyingi zinazosubiri kwa target ileile.
- Weka hali ya bootstrap ya singleton nje ya reset ya kila input. Binder inaruhusu usajili mmoja tu wa `BINDER_SET_CONTEXT_MGR` kwa kila boot, kwa hiyo kuharibu na kuunda upya client huyo mara kwa mara kutafanya inputs za baadaye zisiwe halali.

Kiolezo muhimu cha lifetime-race ni kufanya client mmoja ahamishe object, kuanzisha cleanup ya thread au process, na wakati huohuo kufanya client inayopokea iachie transaction buffer. Katika mfano wa CVE-2020-0423, uhamisho wa `BINDER_TYPE_WEAK_BINDER` uliofuatiwa na `BINDER_THREAD_EXIT` ukipishana na `BC_FREE_BUFFER` ungeweza kufree `binder_work` iliyopachikwa huku njia ya cleanup ya thread inayotoka bado ikiitumia.<sup>[[15]](#references)</sup>

#### Reintroduce controlled interleavings in a userspace kernel

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) huunganisha kernel code halisi kwenye userspace harness na kufichua syscall interface yake kupitia `lkl_syscall`. Hii hurahisisha kuratibu protobuf state, coverage na KASAN katika process moja. Hata hivyo, kwa kawaida LKL huendesha syscall bila kernel thread nyingine kuikatiza. Kwa race campaigns, weka sehemu za `schedule()` karibu na mipaka iliyochaguliwa ya lock/unlock na lifetime, kisha uruhusu harness ichague client inayofuata kwa nasibu kila inapotokea yield. Ziweke sehemu hizi kwenye maeneo lengwa kwa sababu kila moja huongeza mara nyingi ukubwa wa scheduling search space. Randomized scheduler iliyoelezwa na watafiti **si sehemu ya upstream Binder fuzzer**.<sup>[[15]](#references)</sup>

#### Build and replay serialized regression seeds

Upstream harness hufunga toleo linalooana la `libprotobuf-mutator`, huwasha LKL fuzzing instrumentation na KASAN kwa `LKL_FUZZING=1`, na huwasha `CONFIG_MMU` kwa Binder kupitia `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Baada ya kufanya checkout ya revision iliyoachwa hatarini kimakusudi au kutumia rollback patches zilizoandikwa kwenye upstream, serialized seed inaweza kuiga mabadiliko yote ya hali ya multi-client bila kuyaunda upya katika proof of concept ya C iliyotengenezwa kwa dharura:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Chukulia KASAN use-after-free iliyosababishwa kuwa uthibitisho kwamba seed ilifikia njia ya lifetime iliyo hatarini. Hii **haithibitishi** primitives za baadaye zinazohitajika ili kutekeleza code kwenye kernel au kuongeza ruhusa.<sup>[[16]](#references)</sup>

## Mbinu ya Tofauti kwenye Mashine Moja (Mtindo wa Jackalope)

Njia inayofaa ya kuchanganya **ubunifu wa uzalishaji** na **utumiaji upya wa coverage** ni **kuanzisha upya workers wa muda mfupi** dhidi ya server inayodumu. Kila worker huanza na corpus tupu, husawazisha baada ya sekunde `T`, hutumia sekunde nyingine `T` kufanya kazi na corpus iliyounganishwa, husawazisha tena, kisha hutoka. Hii hutoa **miundo mipya kwa kila kizazi** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers wa mfuatano (mfano wa loop):**

<details>
<summary>Mzunguko wa kuwasha upya worker wa Jackalope</summary>

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

- `-in empty` hulazimisha **corpus mpya** katika kila uzalishaji.
- `-server_update_interval T` hukadiria **sync iliyocheleweshwa** (novelty kwanza, reuse baadaye).
- Katika hali ya grammar fuzzing, **initial server sync hurukwa kwa chaguomsingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora **hutegemea target**; kubadilisha baada ya worker kupata sehemu kubwa ya coverage “rahisi” kwa kawaida hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Targets Ngumu Kuandaa Harness

Wakati msimbo unaotaka kujaribu haupatikani hadi **gharama kubwa ya maandalizi** ikamilike (kuwasha VM, kukamilisha kuingia, kupokea packet, kuchanganua container, kuanzisha service), njia mbadala inayofaa ni **snapshot fuzzing**: hifadhi hali ya process au VM iliyo tayari, ingiza kila test case kwenye njia ya ingizo ya target, endesha hadi crash/timeout, kisha urejeshe snapshot. Hii huepusha kurudia uanzishaji au viambishi awali vya protocol, na inafaa kwa **network services**, **firmware**, **attack surfaces baada ya uthibitishaji**, na **targets za binary-only**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayokuvutia iwe tayari.
2. Hifadhi snapshot ya **memory + registers** katika hatua hiyo.
3. Kwa kila test case, andika ingizo lililobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Endesha hadi crash/timeout/reset.
5. Rejesha snapshot; kwa targets za VM, rejesha **dirty pages** pekee ikiwa inaungwa mkono, kisha urudie.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya kuchanganua/kuelekeza, kama vile baada ya `recv`/`read` au hatua ya kuondoa serialization ya packet, na rekodi buffer ya ingizo inayotumiwa na target. Hii hufuata kanuni ya adaptive placement ya kuisogeza snapshot ndani zaidi kwenye uchakataji wa ingizo ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

### Snapshots za hatua kwa hatua za hali za protocol

Snapshot isiyobadilika huepusha gharama ya maandalizi lakini yenyewe haichunguzi mabadiliko yanayohitaji ujumbe kadhaa halali. Harness ya LibAFL-Qemu inaweza kufuatilia uandishi kwenye sehemu ya hali ya protocol na kuhifadhi snapshot mpya hali inapobadilika. Katika [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful), hufuatilia `tcpcb.t_state`, huhash hali na response flags ili kuondoa snapshots zinazojirudia, na huhifadhi dirty pages kwa kulinganisha na mzazi. Kabla ya kubadilisha ujumbe unaofuata wenye muundo, hurejesha snapshot iliyochaguliwa kupitia mnyororo wake wa wazazi. Testcase huhifadhi `SnapshotId` na bytes za ingizo zilizozalishwa (`gen_bytes`); snapshot manager hufuatilia uhusiano wa wazazi unaohitajika kwa replay.<sup>[[27]](#references)[[28]](#references)</sup>

`SnapshotModule` ya user-mode ya LibAFL-Qemu huhifadhi mappings na memory ya target lakini si CPU registers; zihifadhi kando inapohitajika. Manager iliyofafanuliwa inaunga mkono mti mmoja wa root snapshot na haiwezi kushiriki snapshot IDs kati ya workers. Hali yake ya multi-snapshot pia haiwezi kutumia tena QASAN shadow state moja kwa moja. Kwa triage ya offline, jenga upya mnyororo wa ingizo katika process tofauti iliyo na instrumentation. Unapotumia `AsanHostModule` na `DrCovModule`, `fuzzer.evaluate_input` huendesha callbacks zinazohitajika za `pre_exec`/`post_exec`; `qemu.run` pekee haifanyi hivyo.<sup>[[27]](#references)[[28]](#references)</sup>

### Gundueni usomaji kupita kiasi wa logical ring-buffer

Usomaji unaopita *idadi ya data halali* ya buffer unaweza kubaki ndani ya ugawaji wake wa host na kukwepa ASAN ya kawaida. Mfano wa [urgent-data wa libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) pia hupunguza chini ya sifuri idadi ya unsigned byte. Ikiwa source inapatikana, instrumentation ya signed/unsigned integer overflow inaweza kugundua athari hiyo; tofautisha wrap ya makusudi ya TCP sequence number kabla ya kuzuia ripoti. Oracle yenye nguvu zaidi iliyopendekezwa ni kuwekea sumu ugawaji maalum wa ring, kuondoa sumu kwenye maeneo halali pekee kadri allocator yake ya ndani inavyosonga, na kuweka sumu tena kwenye maeneo yaliyoachiliwa. LibAFL-Qemu hutoa API ya kuweka sumu ya ASAN kwa targets ambazo instrumentation ya source haiwezekani.<sup>[[27]](#references)</sup>

## Kuchunguza Mashindano ya Linux Kernel kwa MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) hubadilisha mashindano ya Linux kernel yanayotegemea timing kuwa ratiba za memory-access zinazoweza kurudiwa. Inaweza kuorodhesha kiotomatiki utekelezaji wa **A-B-A** wa contexts mbili au kumruhusu mchambuzi kuweka masharti ya mpangilio kupitia terminal UI/GUI. Hii ni zana ya utafiti wa majaribio, si concurrency fuzzer kamili: kwa sasa inahitaji LLVM 23+ na kernel iliyorekebishwa ya mradi, zana za command-line zinaunga mkono test threads mbili, na safu ya fuzzing ya userspace iliyopendekezwa bado haijatekelezwa.<sup>[[17]](#references)[[18]](#references)</sup>

### Kusanya sehemu za mawasiliano kati ya contexts

Jenga kernel yenye instrumentation kwa callbacks za KASAN outline na usaidizi wa patched KCOV wa kurekodi memory. README ya mradi pia inapendekeza kuzima sibling-call optimization ili call stacks zibaki zinafaa kutumika.<sup>[[17]](#references)[[18]](#references)</sup>

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

Hali ya outline ya KASAN (`asan-instrumentation-with-call-threshold=0`) hubadilisha ufikiaji unaowekewa instrumentation kuwa miito ya helper. Kernel patches za MAccConc huzima `asan-opt-same-temp` ili ufikiaji unaofuatana usiunganishwe; zima pia optimization ya `asan-opt-globals` wakati mashindano ya global variable yanahitaji kuonekana. KCOV hupeleka rekodi zinazotokana na hali hiyo hadi userspace. Linganisha ufikiaji kutoka miktadha tofauti ya utekelezaji na uhifadhi jozi ambazo safu za byte zinaingiliana na angalau upande mmoja unaandika; chukulia `kfree()` kama uandishi ili mabadiliko ya lifetime nayo yawe wagombea.<sup>[[17]](#references)</sup>

Kwa kazi inayoendelea nje ya task iliyoianzisha, kama uchakataji wa packet au callbacks za RCU, subsystem lazima isambaze handle ya remote-coverage ya KCOV. Remote KCOV ya upstream ni ya kujijumuisha kwa hiari na haipatikani moja kwa moja kwa kazi yoyote ya usuli, kwa hiyo kutosambaza handle hiyo kunaweza kufanya mwingiliano halisi usionekane.<sup>[[17]](#references)[[19]](#references)</sup>

### Tambua ufikiaji uleule wa wakati wa utekelezaji katika kila run

Usirudie utekelezaji ukitegemea anwani halisi ya heap, ambayo inaweza kubadilika baada ya kila allocation, au anwani ya instruction pekee, ambayo ina utata ndani ya helpers kama `memcpy()` na `spin_lock()`. MAccConc hutumia **stack trace iliyoongezwa hesabu**: kila frame hutambua callee pamoja na idadi ya mara ilipoitwa ndani ya caller wake, na kipengele cha mwisho hutambua instruction ya ufikiaji wa memory. Rekodi za kuingia/kutoka kwa function za SanitizerCoverage huruhusu userspace kuunda upya kitambulisho hiki cha wakati wa utekelezaji, ambacho hubaki thabiti licha ya mabadiliko ya anwani na kelele za mtiririko wa udhibiti zisizohusiana.<sup>[[17]](#references)</sup>

### Geuza jozi za wagombea kuwa ratiba za utekelezaji zinazolazimishwa

Ioctl iliyorekebishwa ya `KCOV_SET_DI` huhusisha kitambulisho cha ufikiaji kilichoongezwa hesabu na kitendo cha shared-flag.<sup>[[17]](#references)</sup>

| Kitendo | Maana |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Weka flag *N* mara moja kabla ya ufikiaji uliochaguliwa. |
| `DI_STACK_WAIT` | Kabla ya ufikiaji uliochaguliwa, subiri kwa mzunguko hadi flag *N* iwekwe au kikomo kilichosanidiwa kiishe. |
| `DI_STACK_WAKE_POST` | Weka flag *N* mara moja baada ya ufikiaji uliochaguliwa. |

Kwa sharti la sehemu la **A-happens-before-B**, ambatisha `DI_STACK_WAKE_POST` kwa A na `DI_STACK_WAIT` kwa B ukitumia flag ileile. Kwa ratiba ya miktadha miwili iliyobainishwa kikamilifu, anza B ikiwa imezuiwa, kisha A iamshe B na isubiri kwenye sehemu ya kwanza ya uhamisho; B hufanya operesheni ya kinyume kwenye uhamisho unaofuata. Hii hufanya kazi kama ubadilishaji wa miktadha unaoamuliwa kwa uhakika na ndiyo njia inayotumiwa na A-B-A explorer ya kiotomatiki.<sup>[[17]](#references)</sup>

Campaign ndogo ni kukompaili test case ya hooks nne (`test_setup`, functions mbili za thread, na `test_end`) kama shared library, kukusanya trace isiyowekewa vizuizi, kisha kuorodhesha wagombea wa A-B-A au kuongeza vizuizi vya mkono kuzunguka ufikiaji unaotiliwa shaka.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Tafsiri timeout kando na mabadiliko ya mpangilio yaliyofanikiwa: mpangilio ulioombwa unaweza kuwa hauwezekani kwa sababu lock au utegemezi wa uanzishaji/uchapishaji unazuia context ya pili kufikia sehemu yake ya injection. Pia zingatia maeneo yasiyoonekana na KASAN: ufikiaji wa stack wa moja kwa moja kwa kawaida hauwekwi hooks isipokuwa unaweza kwenda nje ya mipaka, globals huachwa ikiwa optimization chaguomsingi imetumika, na compilers za sasa haziwezi kutoa hooks za ASAN na TSAN kwa wakati mmoja. Hatimaye, prototype hupoteza buffer yake ya KCOV guest inapopata panic, kwa hiyo hifadhi crash console/oracle huru.<sup>[[17]](#references)</sup>

Kwa fuzzing ya siku zijazo inayoongozwa na concurrency, hifadhi muhtasari wa ufikiaji wa memory kwa kila input au syscall, unganisha operations ambazo zingeunda sehemu za mawasiliano kati ya contexts, kisha chunguza michanganyiko hiyo pekee. VM snapshots hutuliza hali ya kimataifa na anwani; bila snapshots, metadata ya allocation-site inaweza kutoa abstraction ya objects katika runs tofauti. Hili ni pendekezo la upanuzi, si kipengele cha tools za sasa za MAccConc userspace.<sup>[[17]](#references)</sup>

## Uchunguzi wa Harness: Tambua Fuzzers Zisizofikia Kina Mapema

Campaign inapokwama, mara nyingi tatizo si mutator bali ni **harness**. Tumia **uchunguzi wa reachability/coverage** kutafuta functions zinazoweza kufikiwa kistatiki kutoka kwenye fuzz target yako lakini hazifunikwi mara nyingi au hazifunikwi kabisa wakati wa utekelezaji. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness huingia kwenye target ikiwa imechelewa au mapema mno.
- Seed corpus haina familia nzima ya vipengele.
- Target inahitaji **harness ya pili** badala ya harness moja kubwa kupita kiasi ya “kufanya kila kitu.”

Ukitumia workflows za mtindo wa OSS-Fuzz / ClusterFuzz, Fuzz Introspector inaweza kulinganisha reachability ya kistatiki na coverage ya wakati wa utekelezaji na kutoa ripoti kutoka kwenye run iliyowekewa muda au corpus ya umma.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Tumia ripoti kuamua ikiwa utaongeza harness mpya kwa njia ya parser ambayo haijajaribiwa, kupanua corpus kwa kipengele maalum, au kugawa harness kubwa moja katika entry point ndogo.

## Uteuzi wa Fuzz Target kwa Kutanguliza Graph na Utriage wa Mutation

Ikiwa tayari una **matokeo ya static analysis**, **mutation-testing survivors**, na **ripoti za coverage**, usizifanyie triage kama orodha zinazojitegemea. Anza kwa kujenga **call graph**, weka alama kwenye nodes kwa kutumia **cyclomatic complexity**, **ufikikaji kutoka entrypoint/input isiyoaminika**, na matokeo yoyote ya nje, kisha uliza maswali kuhusu graph hiyo.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity ya juu zinazoweza kufikiwa kutoka kwenye input isiyoaminika?
- Ni mutation survivors zipi zilizo kwenye njia kutoka kwa parsers/handlers hadi kwenye code muhimu kwa usalama?
- Ni functions zipi ambazo ni choke points za usanifu zenye **blast radius** kubwa isivyo kawaida?

Hii kwa kawaida hufichua fuzz targets bora kuliko kuangalia "coverage ya chini zaidi" pekee. Parser/decoder yenye **complexity ya juu** na **ufikikaji wa nje uliothibitishwa** ni chaguo bora zaidi la harness kuliko helper ya ndani iliyojitenga yenye coverage dhaifu lakini isiyo na njia inayodhibitiwa na mshambuliaji.

### Mchakato wa vitendo wa triage

1. Jenga **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branch kwa kila function.
2. Orodhesha **entrypoints** zinazopokea input inayodhibitiwa na mshambuliaji: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Tumia **path queries** kutoka kwenye entrypoints hizo hadi kwa functions zinazochunguzwa ili kutofautisha attack surface inayofikika na code iliyokufa/ya ndani pekee.
4. Tanguliza nodes zinazochanganya:
   - **cyclomatic complexity** ya juu
   - **ufikikaji kutoka kwenye input isiyoaminika** uliothibitishwa
   - **blast radius** kubwa au dependents wengi wa chini
   - ushahidi wa ziada kama matokeo ya **SARIF**, maelezo ya audit, au mutation survivors
5. Andika harnesses mahususi kwa nodes zenye alama za juu zaidi kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: equivalent dhidi ya actionable

Mutation testing mara nyingi hutoa orodha ya survivors yenye kelele nyingi. Kabla ya kuchukulia kila survivor kama pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka kwenye entrypoint inayodhibitiwa na mshambuliaji?
- Je, njia zote za mwito zimewekewa masharti na invariants imara zaidi kuliko ukaguzi uliobadilishwa?
- Je, node iko kwenye code iliyokufa, logic ya uumbizaji pekee, au njia ya arithmetic/parser yenye athari kubwa?

Survivors ambazo bado hazifikiki au zimewekewa masharti kimuundo mara nyingi ni **equivalent mutants**. Survivors ambazo zinabaki **kufikika** na kugusa **masharti ya mipaka**, **overflow/carry paths**, au **arithmetic/parsing muhimu kwa usalama** zinapaswa kupewa kipaumbele na kuongezwa kwenye:

- fuzz harnesses mpya
- majaribio ya moja kwa moja ya properties/invariants
- vectors mahususi za edge cases

### Linganisha matokeo ya nje na graph

Ikiwa pipeline yako ya SAST inatoa **SARIF**, weka matokeo kwenye nodes za graph kwa kutumia **file + line range** na utumie graph kupanua uelewa wa athari.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya function iliyoalamishwa
- angalia ikiwa finding iko kwenye njia yoyote kutoka kwa entrypoint
- panga findings zilizo karibu zinazoungana kwenye choke point ileile

Hii husaidia unapoamua kama utatumia muda wa fuzzing kwenye function maalum: node ambayo **inafikika**, ina **complexity**, na tayari ina **matokeo ya SAST** mara nyingi ni target bora kuliko node yenye complexity pekee isiyo na njia ya mshambuliaji.

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

Mbinu muhimu ni makutano ya **ugumu x kiwango cha kufichuliwa x athari**. Tumia grafu kuchagua malengo ya fuzzing yenye thamani kubwa zaidi ya usalama inayotarajiwa, kisha tumia mutation survivors kuamua mipaka na invariants ambazo harness yako lazima isisitize.<sup>[[5]](#references)</sup>

## Fuzzing ya kulinganisha kwa usimbaji wa funguo za kriptografia

Anza na funguo halali zilizosanifishwa au test vectors za kawaida. Fanya mutation kwenye sehemu zilizosimbwa bila kuvunja urefu na muundo unaohitajika ili kufikia njia za uingizaji na uendeshaji, kisha peleka bytes zilezile kwa implementations huru. Linganisha kama zimekubaliwa na makosa yanayoripotiwa. Saini na ciphertext zenye matokeo ya nasibu zinahitaji correctness oracles, si kulinganisha byte kwa byte: hakiki saini au linganisha shared secrets zinazopatikana baada ya mzunguko wa encapsulation/decapsulation. Test vectors huthibitisha ufuataji wa viwango kwa visa vinavyojulikana; differential mutation huchunguza usimbaji usio sahihi ulio nje ya visa hivyo.<sup>[[23]](#references)[[26]](#references)</sup>

Kwa miundo hii ya funguo, tumia oracles maalum kwa kila format:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Funguo zilizopanuliwa za kusaini za ML-DSA:** badilisha coefficients za `s1` au `s2` zilizopakiwa ziwe nje ya `[-η, η]`, huku ukihakikisha ufunguo bado unaweza kuchanganuliwa. Angalia kama uingizaji au usainishaji unaukataa na kama saini yoyote inayotokana nayo inathibitishwa. Tofauti za kukubali pekee hazimaanishi ukiukaji wa viwango, kwa sababu FIPS 204 hailazimishi ukaguzi wa ziada wa funguo za faragha. Tazama [utaratibu wa conditional leakage](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Jozi za funguo za ML-KEM:** tofautisha ukaguzi unaohitajika wa ufunguo wa encapsulation na ingizo la decapsulation na ukaguzi wa hiari wa pairwise-consistency (PCT) kwenye jozi iliyoingizwa. Fanya encapsulation kwa kutumia ufunguo wake wa umma, fanya decapsulation kwa kutumia ufunguo wake wa faragha, kisha linganisha shared secrets; kutolingana kunaweza kuvuruga mawasiliano yaliyosimbwa hata kama kila ufunguo unapita ukaguzi wa ingizo. Angalia kama API inathibitisha ingizo wakati wa uendeshaji au kupitia mwito tofauti; libcrux hutoa `validate_public_key(pk)` na `validate_private_key(sk, ct)`, ambazo hazichukui nafasi ya PCT.
- **Funguo ghafi za XMSS/XMSSMT:** jaribu mizunguko ya kusafirisha na kuingiza funguo za **kusaini na kuthibitisha** zilizosanifishwa katika seti mbalimbali za vigezo, badala ya kujaribu tu uendeshaji kwa funguo zilizo kwenye kumbukumbu. XMSS na XMSSMT zina nafasi tofauti za OID zenye baiti nne, kwa hiyo kichanganuzi cha OID pekee kinachojaribu XMSS kwanza kinaweza kuainisha vibaya ufunguo wa XMSSMT wenye OID inayogongana na kuukataa wakati wa kuingiza. Kichanganuzi cha RustCrypto kilichoripotiwa kinaonyesha hitilafu ya interoperability/availability, si kughushi saini.

## Go Fuzzing na gosentry: Injini Imara Zaidi, Ingizo Zenye Aina, na Ukaguzi wa Kulinganisha

Ikiwa lengo la Go tayari lina harness asilia ya `testing.F`, njia ya kuboresha kwa vitendo ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), toolchain ya Go iliyoforkiwa inayohifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Hii ni muhimu wakati Go fuzzer asilia inakwama kwenye **hard comparisons**, **ingizo zenye aina**, au **miundo inayotegemea sana parser**. Mbinu inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia campaign inayotokana na hilo kama run ya kawaida inayoongozwa na coverage, lakini yenye scheduling/mutation ya LibAFL na detectors bora zaidi zinazoiunga mkono.

### Geuza hitilafu zisizoonekana kuwa matokeo ya fuzzing

Tatizo linalojirudia katika tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa chaguomsingi. Kwa gosentry, unaweza kugeuza aina kadhaa za hali “mbaya lakini zisizoonekana” kuwa matokeo.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili kufanya njia teule za logging/error zitende kama crash (inafaa kwa njia za msimbo za aina ya `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kuendesha tena queue entries zilizogunduliwa hivi karibuni kwa kutumia Go race detector.
- `--catch-leaks=true` ili kuendesha tena queue entries mpya kwa kutumia `goleak` na kusitisha panapokuwa na goroutine leaks.
- Ushughulikiaji wa hang wa LibAFL ili kuhifadhi **infinite loops / ingizo zinazoendeshwa polepole sana** kama matokeo ya fuzzing badala ya kuziacha zipotee kama timeouts.
- Ukaguzi wa arithmetic overflow uliojengwa ndani huwashwa kwa chaguomsingi, pamoja na ukaguzi wa truncation wa hiari kupitia instrumentation ya aina ya go-panikint.

Hili lina thamani hasa kwa targets ambazo athari ya kiusalama ni **hitilafu ya parser isiyosababisha panic**, **hitilafu ya concurrency**, au **hang inayosababisha DoS pekee**, badala ya uharibifu wa memory.

### Fuzzing inayozingatia Struct kwa API za Go zenye aina

Go fuzzing asilia hutarajia hasa scalars kama `[]byte`, `string`, na nambari. Ikiwa msimbo unaojaribiwa hutumia objects zenye aina, gosentry inaweza kufanya fuzzing ya **thamani changamano** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kufanya mutation ya bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>

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

Tumia hili wakati kuunda wire format bandia kwa ajili ya fuzzing pekee kungeficha hitilafu za logic nyuma ya msimbo wa parsing unaotumika kwenye harness pekee. Kwa kampeni za differential au grammar-based, weka input ya harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Fuzzing inayotegemea grammar kwa parser na input za protocol

Kwa parser, format na lugha za input, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni array ya JSON ya production rules, na kwa kawaida harness inapaswa kupokea argument moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Maelezo ya mbinu:

- Tumia grammar mode wakati byte-level mutations nyingi huishia kwenye ukaguzi wa sintaksia wa awali.
- Weka grammar kwenye **sehemu ya lugha/protokali inayohusiana na usalama** badala ya kuiga specification yote.
- Tumia thamani kubwa za mipaka kwenye terminals/nonterminals ili kujaribu mipaka ya integer, urefu na state machine.
- Grammar mode hudumisha inputs zilizo halali kisarufi, lakini target bado hupokea **bytes/strings**, kwa hiyo uchanganuzi na ukaguzi wa kisemantiki hubaki ndani ya msimbo uliowekewa harness.

### Differential fuzzing: linganisha implementations, si crashes tu

Mbinu thabiti kwa mifumo ya Go ni **grammar-based differential fuzzing**: tengeneza inputs halali zenye muundo na uzitumie kwa parsers, clients au injini mbili za state-transition.<sup>[[7]](#references)[[8]](#references)</sup>

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

- implementation moja hupata panic huku nyingine ikikataa kwa usafi
- kutolingana kwa ingizo linalokubaliwa au kukataliwa
- parse trees au objects zilizofasiriwa kuwa tofauti
- tofauti katika mabadiliko ya hali, nonces, salio au state roots

Hii ni njia ya vitendo ya kupata **kutolingana kwa consensus**, **utata wa parser** na **mkengeuko kati ya spec na implementation** ambao fuzzing ya crash pekee mara nyingi hukosa.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tumia tena corpus ya campaign kuripoti coverage

Baada ya campaign, rudia corpus ya queue iliyohifadhiwa ili kutengeneza ripoti ya Go coverage bila kuhamisha corpus tofauti wewe mwenyewe.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Endesha amri kutoka kwenye **package** hiyo hiyo na kwa target ileile ya `-fuzz` ili gosentry ipate hali sahihi ya kampeni iliyohifadhiwa kwenye cache.

## References

- [1] [Fuzzing ya sarufi ya mabadiliko](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing ya AFL++ kwa undani](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet baada ya miaka mitano: Kuhusu Fuzzing ya Itifaki inayoongozwa na Coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hugeuza code kuwa grafu](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya zana. Tulifanya fork ya toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer ya Haraka ya Greybox kwa Itifaki za Mtandao zenye Hali kwa Kutumia Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna Grammar, Hakuna Tatizo: Kuelekea Kufanya Fuzzing ya Linux Kernel Bila Maelezo ya System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing Yenye Ufanisi kwa Snapshots Zinazobadilika na Kurekebishika](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Uwekaji wa instrumentation wa AFL++ LLVM: path na caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing ya Muktadha Inayotabiri](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blogu ya Usalama wa Android: Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - nyaraka za ujenzi na regression seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kuchunguza Hali za Mashindano za Linux Kernel kwa Kuingiliana Kudhibitiwa kwa Ufikiaji wa Kumbukumbu](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: code coverage kwa ajili ya fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaksia ya Extended Filename ya CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Ushauri wa Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Kufanya Fuzzing ya Sintaksia ya Extended Filename ya CFITSIO: Udhaifu 16 wa Usalama wa Kumbukumbu na Uchambuzi wa Awali Uliosaidiwa na Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing tofauti kwa cryptography](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Kiwango cha Key-Encapsulation Mechanism Kinachotegemea Module-Lattice](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Hitilafu ya uchanganuzi wa OID ya XMSSMT - tatizo la RustCrypto #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Hali ya Utekelezaji wa Cryptography ya Baada ya Quantum](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Kutumia Snapshotting kufikia CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzers dhidi ya AI: Kulinganisha Fuzzilli na BigSleep kwenye JavaScript Engines](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
