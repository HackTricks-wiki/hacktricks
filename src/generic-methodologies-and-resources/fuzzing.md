# Mbinu za Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **halali kwa grammar**. Katika hali inayoongozwa na coverage, samples zinazosababisha **coverage mpya** pekee ndizo huhifadhiwa kama seeds za corpus. Kwa **malengo ya lugha** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **minyororo ya semantic/dataflow**, ambapo matokeo ya construct moja yanakuwa input ya nyingine.<sup>[[1]](#references)</sup>

**Hali ya kushindwa:** fuzzer hupata seeds zinazotekeleza `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haihifadhi dataflow iliyounganishwa**, kwa hiyo sample iliyo “karibu zaidi na bug” hutupwa kwa sababu haiongezi coverage. Kwa **hatua 3 au zaidi zinazotegemeana**, kuunganisha upya kwa nasibu kunakuwa ghali na maoni ya coverage hayaelekezi utafutaji.<sup>[[1]](#references)</sup>

**Athari:** kwa grammars zinazotegemea sana miunganisho, zingatia **kuchanganya awamu za mutational na generative** au kuelekeza generation zaidi kwenye mifumo ya **kuunganisha functions** (si coverage pekee).<sup>[[1]](#references)</sup>

## Mitego ya Utofauti wa Corpus

Mutation inayoongozwa na coverage ni **ya pupa**: sample inayoleta coverage mpya huhifadhiwa mara moja, mara nyingi ikiwa na sehemu kubwa ambazo hazijabadilika. Kadiri muda unavyopita, corpora huwa na **nakala zinazokaribiana sana** zenye utofauti mdogo wa kimuundo. Minimization kali inaweza kuondoa muktadha unaofaa, kwa hiyo njia ya kati inayofaa ni **minimization inayotambua grammar**, ambayo **husimama baada ya kufikia kiwango cha chini cha tokens** (kupunguza kelele huku ikihifadhi muundo wa kutosha kuendelea kufaa kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo kwa corpus ya mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye miundo tofauti zinazoongeza coverage** badala ya rundo kubwa la nakala zinazokaribiana sana. Kwa kawaida, hii humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **samples za ulimwengu halisi** (corpora za umma, data iliyokusanywa kwa crawling, traffic iliyonaswa, seti za faili kutoka kwenye mfumo-ikolojia wa target).
- Zipunguze kwa kutumia **minimization ya corpus inayotegemea coverage** badala ya kuhifadhi kila sample halali.
- Hifadhi seeds **ndogo vya kutosha** ili mutations zilenge fields zenye maana badala ya kutumia sehemu kubwa ya cycles kwenye bytes zisizo muhimu.
- Rudia minimization ya corpus baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Mutation Inayozingatia Ulinganisho kwa Thamani za Kichawi

Sababu ya kawaida ya fuzzers kufikia kikomo cha maendeleo si syntax bali **ulinganisho mgumu**: magic bytes, ukaguzi wa urefu, strings za enum, checksums, au thamani za parser dispatch zinazolindwa na `memcmp`, jedwali za switch, au ulinganisho wa mfululizo. Mutation tupu ya nasibu hupoteza cycles ikijaribu kukisia thamani hizi byte kwa byte.

Kwa targets hizi, tumia **ufuatiliaji wa ulinganisho** (kwa mfano, workflows za AFL++ `CMPLOG` / Redqueen) ili fuzzer iweze kuona operands kutoka kwenye ulinganisho ulioshindwa na kuelekeza mutations kwenye thamani zinazokidhi masharti hayo.<sup>[[3]](#references)</sup>

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

**Vidokezo vya vitendo:**

- Hii ni muhimu hasa pale ambapo lengo huficha mantiki ya ndani nyuma ya **saini za faili**, **vitenzi vya protocol**, **lebo za aina**, au **biti za vipengele vinavyotegemea toleo**.
- Itumie pamoja na **dictionaries** zilizotolewa kutoka kwa sampuli halisi, specs za protocol, au debug logs. Dictionary ndogo yenye tokeni za sarufi, majina ya chunk, vitenzi na vitenganishi mara nyingi huwa na thamani zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa lengo hufanya ukaguzi mwingi wa mfululizo, tatua kwanza ulinganishaji wa awali wa “magic”, kisha punguza tena corpus iliyopatikana ili hatua zinazofuata zianze na prefixes ambazo tayari ni halali.

## Kufanya Fuzzing kwa File APIs Zinazoficha Lugha ya Filename

Kigezo kinachoitwa `filename`, `path`, au `URL` kinaweza kuwa sehemu ya kuingilia kwa interpreter badala ya kutafuta faili moja kwa moja. Kwa mfano, CFITSIO Extended Filename Syntax (EFS) hutathmini selectors zilizowekwa kwenye mabano, expressions za row/pixel, calculated columns, histograms na transformations kabla ya kurejesha object iliyofunguliwa; baadhi ya miundo pia huunda nakala za muda. Wakati wa kuchora ramani ya attack surface, ainisha kila API ya open/import kuwa **literal-path** au **interpreted-path**, kisha fanya fuzzing kwenye entry point ya uzalishaji ambayo programu hutumia kweli.<sup>[[20]](#references)[[22]](#references)</sup>

Kwa primitives zinazotokana na SSRF, kunakili faili na protocol handlers—pamoja na APIs salama zaidi za literal-path—tazama [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Weka object ya msingi tofauti na programu inayofanyiwa fuzzing

Sarufi inapokuwa kwenye kiambishi tamati cha filename, kubadilisha tu byte za faili husika hakufikii parser. Badala yake, harness ndogo inaweza kusoma testcase moja kama string na kuipitisha kwa API ya open inayotafsiriwa; kampeni ya CFITSIO ilifikia parser na evaluator nyingi za EFS kwa kuita `fits_open_file()` katika hali ya kusoma pekee. Weka faili halali za msingi zipatikane kando ili mabadiliko yaweze kulenga lugha ya selector/expression badala ya kuvunja mara kwa mara njia ya msingi.<sup>[[22]](#references)</sup>

Tumia seeds ambazo kila moja hufikia familia tofauti ya sarufi, kisha toa dictionary fupi kutoka kwa spec na source ya lexer/parser. Ikiwa coverage itakwama huku inputs zikifeli mara kwa mara kwenye njia ileile ya syntax-error, hifadhi prefixes halali na uongeze delimiters, operators, keywords, majina ya functions na majina wakilishi ya fields badala ya kuongeza tu muda wa random-mutation.<sup>[[22]](#references)</sup>

Endesha harness pamoja na dictionary ya sarufi, kwa mfano:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Zuia athari za pembeni za harness ya "read-only"

Bendera ya library ya read-only haihakikishi testcase isiyo na athari za pembeni: lugha ya majina ya faili inaweza kuandika upya ingizo, kuunda faili za matokeo, au kutengeneza vitu vya muda. Kampeni ya CFITSIO iliharibu awali faili za seed na kuacha faili zisizotarajiwa katika mfumo mzima wa faili, hivyo usafishaji na utengaji vilihitajika.<sup>[[22]](#references)</sup>

- Mpe kila worker directory ya muda inayoweza kutupwa na directory yake binafsi ya muda.
- Toa nakala za faili za msingi zilizo kanoni; usiruhusu target ibadilishe nakala pekee ya corpus.
- Zima ufikiaji wa mtandao isipokuwa backends za mbali ndizo zinazolengwa, na zuia njia zinazoweza kuandikiwa kwa kutumia container, mount namespace, au sandbox inayolingana.
- Rejesha directory baada ya kila utekelezaji au kundi la worker, na chukulia mabadiliko yasiyotarajiwa ya mfumo wa faili kama matokeo ya ziada.

### Mzunguko wa crash-to-patch-to-fuzz

Panga crash katika makundi kabla ya kufanya marekebisho ili maelfu ya artifacts zisigeuke kuwa maelfu ya kazi za patch. Katika tathmini ya CFITSIO, AFLTriage ilipunguza seti ya awali ya crash hadi visababishi vikuu vichache; advisory iliyotokana na tathmini hiyo inaonyesha hitilafu tofauti, zikiwemo ukaguzi usio sahihi wa ukubwa wa destination, pointers zilizopitwa na wakati baada ya `realloc()`, hitilafu za hesabu, na njia zisizo salama za kusafisha parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Punguza input wakilishi kwa kila kundi na urudie hitilafu hiyo chini ya AddressSanitizer.
2. Rekodi access halisi iliyoshindwa, eneo la source code, historia ya ugawaji na uachiliaji wa kumbukumbu, na hali ya parser iliyofanya invariant kuwa ya uongo.
3. Tekeleza patch moja inayolenga eneo finyu na ujenge upya kwa kutumia instrumentation ileile ya coverage na sanitizer.
4. Rudia reproducer asilia **na kila input katika kundi lake**; pia washa ugunduzi wa leak kwa sababu marekebisho ya usalama wa kumbukumbu yanaweza kuvuruga umiliki wa kumbukumbu kwenye njia ya hitilafu.
5. Endesha majaribio ya utendaji kwa faili halisi, kisha endelea kutoka kwenye queue iliyokusanywa (au iingize tena queue hiyo ikiwa engine inahitaji directory mpya ya matokeo baada ya binary kubadilika).
6. Rudia: kuondoa crash ya kwanza ya juu juu mara nyingi huruhusu seeds zilizopo kuendelea hadi hali ya ndani zaidi ya parser.

LLM inaweza kuharakisha hatua ya 2 na kuandaa rasimu ya hatua ya 3 ikiwekewa input inayosababisha crash, ripoti ya sanitizer, harness na source code husika, lakini patch yake bado haipaswi kuaminiwa. Uamuzi wa kukubali marekebisho hutegemea marudio ya sanitizer na masharti ya regression, si maelezo ya model.<sup>[[22]](#references)</sup>

## Feedback Tajiri Zaidi Wakati Edge Coverage Inapounganisha Njia Tofauti

Edge coverage ya kawaida haiwezi kutofautisha utekelezaji miwili inayopitia helper ileile kupitia callers tofauti au kuchukua mchanganyiko tofauti wa matawi ndani ya function. Hili ni muhimu katika shared decoders, protocol dispatchers na interpreter helpers ambako **route** ya kufikia edge huamua hali hai. Kufuatilia kila calling context kwa njia ya moja kwa moja pia ni hatari: ramani ya coverage na queue zinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zinazoonekana kuahidi pekee badala ya kuchukulia call graph nzima kuwa context-sensitive.<sup>[[14]](#references)</sup>

Build za hivi karibuni za AFL++ hutoa **Ball-Larus per-function path coverage** pamoja na edge coverage ya kawaida. Huweka feature kwa kila njia isiyo na mizunguko kupitia function; loop back-edges huondolewa, hivyo feedback hii hutofautisha mchanganyiko wa matawi lakini **si idadi ya marudio ya loop**. Anza na kiwango kilicholegezwa cha `1`, kisha tumia modes kali zaidi kwenye parser/state-machine code inayotiliwa shaka, kwa sababu idadi ya njia inaweza kukua kwa kasi ya kielelezo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Kwa helper inayoitwa kutoka maeneo mengi yanayohusiana na usalama, hali ya LTO inaweza kuunganisha kila njia ya function na call site yake ya moja kwa moja:<sup>[[13]](#references)</sup>

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

**Mwongozo wa kampeni:** tumia feedback tajiri zaidi kwa tahadhari na ufuatilie gharama yake ya coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage sambamba; feedback tajiri zaidi ina manufaa tu ikiwa gharama ya ziada ya queue/map haiathiri vibaya executions per second.
- Tumia `AFL_LLVM_ALLOWLIST` kuzuia path/caller instrumentation pale ambapo maktaba kubwa zilizojaa templates au generic utility code zinatawala map.
- Functions zenye acyclic paths nyingi kupita kiasi zinaweza kurukwa na AFL++; warnings wakati wa compilation ni ushahidi kwamba target inahitaji allowlisting au kiwango kisicho strict sana.
- Caller + path coverage inaunga mkono kina kimoja tu cha caller. Usiichanganye na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya matoleo makuu ya LLVM. Tumia toolchain ileile wakati wote wa kampeni na usisawazishe corpora zinazotegemea PATH kana kwamba feature IDs zake ni thabiti kati ya builds.
- Feedback hii inakamilisha `CMPLOG`: comparison tracing hutafuta **ni thamani gani inayopita guard**, ilhali path/caller feedback huhifadhi **ni njia na mchanganyiko gani wa branches ulioufikia**.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, kitu cha kuvutia mara nyingi si blob moja bali **message sequence**. Kuunganisha transcript nzima kwenye faili moja na kuibadilisha bila mpangilio kwa kawaida hakufanyi kazi vizuri, kwa sababu fuzzer hubadilisha kila hatua kwa kiwango sawa, hata pale ambapo ni message ya baadaye pekee inayofikia hali dhaifu.<sup>[[4]](#references)</sup>

Mbinu yenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **hali inayoonekana** (response codes, protocol states, parser phases, aina za objects zinazorudishwa) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Hifadhi **valid prefix messages** bila mabadiliko na lenga mutations kwenye message **inayoendesha mpito**.
- Hifadhi identifiers na values zinazozalishwa na server kutoka kwa responses za awali pale hatua inayofuata inapozitegemea.
- Pendelea mutation/splicing ya kila message badala ya kubadilisha transcript nzima iliyoserializwa kana kwamba ni blob isiyoeleweka.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **state oracle** ya bei nafuu ili kuweka kipaumbele kwa sequences zinazoendelea zaidi.

Hii ndiyo sababu ileile inayofanya bugs za authenticated, hidden transitions, au bugs za parser zinazotokea “baada tu ya handshake” mara nyingi kukosekana kwenye vanilla file-style fuzzing: fuzzer lazima ihifadhi **mpangilio, hali, na dependencies**, si muundo pekee.<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Edge coverage ya juu bado inaweza kukosa bugs za IPC driver kwa sababu coverage haielezi **umiliki wa objects, reference counts, pending messages, mpangilio wa cleanup, au thread interleavings**. Ukurasa wa [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) unaeleza object model ya driver; mfano huu unalenga fuzzer harness. Android Binder ni kielelezo chenye manufaa: kufikia paths za allocation na free zote mbili hakutoshi ikiwa fuzzer haiwezi kufanya processes nyingi zifanye kazi kwenye kernel object ileile kwa mpangilio unaohitajika.<sup>[[15]](#references)</sup>

#### Model the protocol, not isolated `ioctl` buffers

Wakilisha test case kama grammar iliyopangwa ya **client identity + operation + structured arguments**. Binder LKL fuzzer hutumia protobuf na `libprotobuf-mutator`, ikiwa na client mmoja wa persistent context-manager na clients wawili wa kawaida. Kisha semantic harness huhifadhi mahusiano ambayo blind byte mutation ingevunja.<sup>[[15]](#references)</sup>

- Hifadhi values zinazorejeshwa na operations za awali. Kwa mfano, `BC_FREE_BUFFER` lazima itumie tena pointer ya transaction-buffer iliyorejeshwa na `ioctl` ya awali.
- Tengeneza default replies halali ili synchronous transactions zikamilike na operations za baadaye ziweze kufikiwa.
- Kataa transitions zisizowezekana kama self-transactions au pending transactions nyingi zinazoelekezwa kwa target ileile.
- Weka singleton bootstrap state nje ya per-input reset. Binder huruhusu usajili mmoja tu wa `BINDER_SET_CONTEXT_MGR` kwa kila boot, kwa hiyo kuharibu na kuunda upya client huyo mara kwa mara kutafanya inputs zinazofuata zisihalali.

Kiolezo chenye manufaa cha lifetime-race ni kufanya client mmoja ahamishe object, kisha kuanzisha thread au process cleanup, huku client anayepokea akiachilia transaction buffer kwa wakati mmoja. Katika mfano wa CVE-2020-0423, uhamishaji wa `BINDER_TYPE_WEAK_BINDER` uliofuatwa na `BINDER_THREAD_EXIT` ukigongana na `BC_FREE_BUFFER` ungeweza kufuta `binder_work` iliyopachikwa huku cleanup path ya thread inayotoka ikiendelea kuitumia.<sup>[[15]](#references)</sup>

#### Reintroduce controlled interleavings in a userspace kernel

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) huunganisha kernel code halisi kwenye userspace harness na kufichua syscall interface yake kupitia `lkl_syscall`. Hii hurahisisha kuratibu protobuf state, coverage, na KASAN katika process moja. Hata hivyo, kwa kawaida LKL huendesha syscall bila kernel thread nyingine kuikatiza. Kwa race campaigns, ingiza sehemu za `schedule()` kuzunguka lock/unlock zilizochaguliwa na mipaka ya lifetime, kisha uache harness ichague client inayofuata kwa nasibu kila inapofika yield. Weka sehemu hizi kwenye maeneo lengwa kwa sababu kila moja huongeza mara nyingi scheduling search space. Randomized scheduler iliyoelezwa na watafiti **si** sehemu ya upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Build and replay serialized regression seeds

Upstream harness hubandika toleo linalooana la `libprotobuf-mutator`, huwasha LKL fuzzing instrumentation na KASAN kwa kutumia `LKL_FUZZING=1`, na huwasha `CONFIG_MMU` kwa Binder kwa kutumia `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Baada ya kupata revision iliyoachwa ikiwa na udhaifu kimakusudi au kutumia rollback patches zilizoandikwa kwenye upstream, seed iliyoserialishwa inaweza kuiga mabadiliko yote ya hali ya multi-client bila kuyaunda upya katika proof of concept ya C iliyobuniwa kwa haraka:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Chukulia use-after-free ya KASAN iliyopatikana kuwa uthibitisho kwamba seed ilifikia njia ya lifetime iliyo hatarini. Hii **haithibitishi** primitives za baadaye zinazohitajika kwa kernel code execution au privilege escalation.<sup>[[16]](#references)</sup>

## Mbinu ya Utofauti wa Mashine Moja (Mtindo wa Jackalope)

Njia ya vitendo ya kuunganisha **ubunifu wa uzalishaji** na **utumiaji upya wa coverage** ni kuanzisha upya workers wa muda mfupi dhidi ya server inayoendelea kufanya kazi. Kila worker huanza na corpus tupu, husawazisha baada ya sekunde `T`, huendesha kwa sekunde nyingine `T` kwenye corpus iliyounganishwa, husawazisha tena, kisha hutoka. Hii huzalisha **miundo mipya kila kizazi** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers wa mfululizo (mfano wa loop):**

<details>
<summary>Mzunguko wa kuwasha upya wa worker wa Jackalope</summary>

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

- `-in empty` hulazimisha **corpus mpya** kwa kila kizazi.
- `-server_update_interval T` hukaribia kuiga **usawazishaji uliocheleweshwa** (novelty kwanza, utumiaji upya baadaye).
- Katika hali ya grammar fuzzing, **usawazishaji wa awali wa server hurukwa kwa chaguomsingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadili baada ya worker kupata sehemu kubwa ya coverage “rahisi” kwa kawaida hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Targets Zenye Ugumu Wa Kuandaa Harness

Wakati msimbo unaotaka kujaribu unafikika tu **baada ya gharama kubwa ya maandalizi** (kuwasha VM, kukamilisha login, kupokea packet, kuchanganua container, kuanzisha service), njia mbadala yenye manufaa ni **snapshot fuzzing**: kunasa hali ya process au VM iliyo tayari, kuingiza kila test case kupitia njia ya ingizo ya target, kutekeleza hadi crash/timeout, kisha kurejesha snapshot. Hii huepusha kurudia uanzishaji au viambishi awali vya protocol, na ni muhimu kwa **network services**, **firmware**, **attack surfaces baada ya uthibitishaji**, na **targets za binary pekee**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayohitajika iwe tayari.
2. Hifadhi snapshot ya **memory + registers** katika hatua hiyo.
3. Kwa kila test case, andika ingizo lililobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Tekeleza hadi crash/timeout/reset.
5. Rejesha snapshot; kwa targets za VM, rejesha **dirty pages** pekee inapotumika, kisha urudie.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya uchanganuzi/dispatch, kama vile baada ya `recv`/`read` au hatua ya packet-deserialization, na rekodi input buffer inayotumiwa na target. Hii hufuata kanuni ya uwekaji unaobadilika ya kusogeza snapshot ndani zaidi ya uchakataji wa ingizo ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

### Snapshots za hatua kwa hatua kwa hali za protocol

Snapshot isiyobadilika huepusha gharama ya maandalizi, lakini yenyewe haiwezi kuchunguza mabadiliko yanayohitaji ujumbe kadhaa halali. Harness ya LibAFL-Qemu inaweza kufuatilia maandishi kwenye sehemu ya hali ya protocol na kuhifadhi snapshot mpya hali inapobadilika. Katika [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful), hufuatilia `tcpcb.t_state`, huhash hali na bendera za majibu ili kuondoa snapshots zinazojirudia, na huhifadhi dirty pages kulingana na snapshot ya mzazi. Kabla ya kubadilisha ujumbe unaofuata wenye muundo, hurejesha snapshot iliyochaguliwa kupitia mnyororo wake wa wazazi. Testcase huhifadhi `SnapshotId` na baiti za ingizo zilizozalishwa (`gen_bytes`); snapshot manager hufuatilia uhusiano wa mzazi unaohitajika kwa replay.<sup>[[27]](#references)[[28]](#references)</sup>

`SnapshotModule` ya LibAFL-Qemu katika user-mode huhifadhi mappings na memory ya target lakini si CPU registers; zihifadhi kando inapohitajika. Manager iliyoelezwa inaunga mkono mti mmoja wa root snapshot na haiwezi kushiriki snapshot IDs kati ya workers. Hali yake ya snapshots nyingi pia haiwezi kutumia tena hali ya kivuli ya QASAN moja kwa moja. Kwa uchunguzi wa offline, tengeneza upya mnyororo wa ingizo katika process tofauti yenye instrumentation. Unapotumia `AsanHostModule` na `DrCovModule`, `fuzzer.evaluate_input` huendesha callbacks zinazohitajika za `pre_exec`/`post_exec`; `qemu.run` pekee haifanyi hivyo.<sup>[[27]](#references)[[28]](#references)</sup>

### Tambua usomaji kupita kiasi wa logical ring buffer

Usomaji unaopita *idadi ya data halali* ya buffer unaweza kubaki ndani ya allocation yake ya host na kuepuka ASAN ya kawaida. Mfano wa [libslirp urgent-data](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) pia hupunguza thamani ya unsigned byte count chini ya sifuri. Ikiwa source inapatikana, instrumentation ya signed/unsigned integer-overflow inaweza kutambua athari hiyo; tofautisha wrap ya makusudi ya TCP sequence number kabla ya kuzuia ripoti. Oracle iliyopendekezwa iliyo imara zaidi ni kuweka poison kwenye allocation maalum ya ring, kuondoa poison kwenye sehemu halali pekee kadri allocator yake ya ndani inavyosonga, na kuweka poison tena kwenye sehemu zilizoachiliwa. LibAFL-Qemu hutoa API ya kuweka poison ya ASAN kwa targets ambazo instrumentation ya source haiwezekani.<sup>[[27]](#references)</sup>

## Uchunguzi Wa Linux Kernel Race Kwa MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) hubadilisha race za Linux kernel zinazotegemea timing kuwa ratiba za ufikiaji wa memory zinazoweza kurudiwa. Inaweza kuorodhesha kiotomatiki utekelezaji wa **A-B-A** wa contexts mbili au kumruhusu mchambuzi kuweka vikwazo vya mpangilio kupitia terminal UI/GUI. Hii ni zana ya utafiti wa majaribio badala ya concurrency fuzzer kamili: kwa sasa inahitaji LLVM 23+ na kernel iliyotiwa viraka ya mradi, zana za command-line zinaunga mkono test threads mbili, na safu ya fuzzing ya userspace iliyopendekezwa haijatekelezwa.<sup>[[17]](#references)[[18]](#references)</sup>

### Kusanya sehemu za mawasiliano kati ya contexts

Jenga kernel yenye instrumentation kwa kutumia callbacks za KASAN outline na usaidizi uliotiwa viraka wa KCOV wa kurekodi memory. README ya mradi pia inapendekeza kuzima sibling-call optimization ili call stacks zibaki zinafaa kutumika.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) hubadilisha accesses zilizowekewa instrumentation kuwa miito ya helper. Kernel patches za MAccConc huzima `asan-opt-same-temp` ili accesses zinazofuatana zisiunganishwe; zima pia optimization ya `asan-opt-globals` wakati race za global variables zinapaswa kuonekana. KCOV husafirisha rekodi zinazotokana na hili hadi userspace. Linganisha accesses kutoka execution contexts tofauti na uhifadhi jozi ambazo byte ranges zake zinaingiliana na angalau upande mmoja unaandika; chukulia `kfree()` kama uandishi ili mabadiliko ya lifetime pia yawe wagombea.<sup>[[17]](#references)</sup>

Kwa kazi inayotekelezwa nje ya task iliyoianzisha, kama vile uchakataji wa packet au RCU callbacks, subsystem lazima isambaze handle ya KCOV remote-coverage. KCOV remote ya upstream huwashwa kwa hiari na haipatikani kiotomatiki kwa kazi yoyote ya background, kwa hivyo kutosambaza handle kunaweza kufanya mwingiliano halisi usionekane.<sup>[[17]](#references)[[19]](#references)</sup>

### Tambua access ileile ya dynamic katika kila run

Usirudie jaribio ukitumia anwani halisi ya heap, ambayo inaweza kubadilika baada ya kila allocation, au anwani ya instruction pekee, ambayo haina utambulisho wa kipekee ndani ya helpers kama `memcpy()` na `spin_lock()`. MAccConc hutumia **stack trace iliyoongezwa count**: kila frame hutambua callee pamoja na idadi ya miito yake ndani ya caller wake, na kipengele cha mwisho hutambua instruction ya memory access. Rekodi za kuingia/kutoka kwenye function za SanitizerCoverage huwezesha userspace kuunda upya kitambulisho hiki cha dynamic, ambacho hubaki thabiti licha ya mabadiliko ya anwani na kelele zisizohusiana za control flow.<sup>[[17]](#references)</sup>

### Badilisha jozi za wagombea kuwa schedules za kulazimishwa

Ioctl iliyorekebishwa ya `KCOV_SET_DI` huhusisha kitambulisho cha access kilichoongezwa count na kitendo cha shared-flag.<sup>[[17]](#references)</sup>

| Kitendo | Maana |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Weka flag *N* mara moja kabla ya access iliyochaguliwa. |
| `DI_STACK_WAIT` | Kabla ya access iliyochaguliwa, endelea kusubiri hadi flag *N* iwekwe au kikomo kilichosanidiwa kiishe. |
| `DI_STACK_WAKE_POST` | Weka flag *N* mara moja baada ya access iliyochaguliwa. |

Kwa kizuizi cha sehemu cha **A-happens-before-B**, ambatisha `DI_STACK_WAKE_POST` kwa A na `DI_STACK_WAIT` kwa B, ukitumia flag ileile. Kwa schedule ya contexts mbili iliyoainishwa kikamilifu, anza B ikiwa imesimamishwa, kisha fanya A iamshie B na isubiri kwenye sehemu ya kwanza ya uhamisho; B ifanye operesheni ya kinyume kwenye uhamisho unaofuata. Njia hii hutenda kama kubadilisha contexts kwa determinism na ndiyo inayotumiwa na A-B-A explorer ya kiotomatiki.<sup>[[17]](#references)</sup>

Campaign ya chini kabisa ni kukompile test case yenye hooks nne (`test_setup`, functions mbili za thread, na `test_end`) kama shared library, kukusanya trace isiyo na vikwazo, kisha kuorodhesha wagombea wa A-B-A au kuongeza vikwazo vya mikono kwenye accesses zinazotia shaka.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Tafsiri timeouts kando na successful reorderings: mpangilio ulioombwa unaweza usiwezekane kwa sababu lock au dependency ya initialization/publication inazuia context ya pili kufikia sehemu yake ya injection. Pia zingatia maeneo ambayo KASAN haiwezi kugundua: direct stack accesses kwa kawaida hazifuatiliwi isipokuwa zinaweza kuzidi mipaka, globals huachwa wakati optimization ya default inatumika, na compilers za sasa haziwezi kutoa hooks za ASAN na TSAN kwa wakati mmoja. Pia prototype hupoteza KCOV buffer yake guest inapopata panic, kwa hiyo hifadhi crash console/oracle inayojitegemea.<sup>[[17]](#references)</sup>

Kwa concurrency-guided fuzzing ya baadaye, rekodi muhtasari wa memory-access kwa kila input au syscall, oanisha operations ambazo zinaweza kuunda cross-context communication points, kisha chunguza combinations hizo pekee. VM snapshots hutuliza global state na addresses; bila snapshots, metadata ya allocation-site inaweza kufupisha objects za runs tofauti. Hili ni pendekezo la upanuzi, si kipengele cha sasa cha MAccConc userspace tools.<sup>[[17]](#references)</sup>

## Harness Introspection: Tambua Shallow Fuzzers Mapema

Campaign inaposimama, mara nyingi tatizo si mutator bali ni **harness**. Tumia **reachability/coverage introspection** kutafuta functions zinazoweza kufikiwa kistatiki kutoka kwa fuzz target yako lakini ambazo hazifunikwi mara chache au hazifunikwi kabisa wakati wa utekelezaji. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness huingia kwenye target mapema mno au kwa kuchelewa mno.
- Seed corpus haina familia nzima ya features.
- Target inahitaji **harness ya pili**, badala ya harness moja kubwa ya “kufanya kila kitu”.

Ukitumia workflows za mtindo wa OSS-Fuzz / ClusterFuzz, Fuzz Introspector inaweza kulinganisha reachability ya kistatiki na coverage ya runtime, na kutoa reports kutokana na run iliyowekewa muda au corpus ya umma.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Tumia ripoti kuamua kama uongeze harness mpya kwa njia ya parser ambayo haijajaribiwa, upanue corpus kwa feature mahususi, au ugawanye harness moja kubwa katika entrypoint ndogo zaidi.

## Uteuzi wa Malengo ya Fuzz kwa Kutanguliza Graph na Uchambuzi wa Mutation

Ikiwa tayari una **matokeo ya static analysis**, **mutation-testing survivors**, na **ripoti za coverage**, usizichanganue kama orodha zinazojitegemea. Kwanza tengeneza **call graph**, weka kwenye nodes alama za **cyclomatic complexity**, **ufikikaji kutoka kwa entrypoint/ingizo lisiloaminika**, na matokeo yoyote ya nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinazoweza kufikiwa kutoka kwenye ingizo lisiloaminika?
- Ni mutation survivors zipi zilizo kwenye njia kutoka kwa parsers/handlers hadi kwenye code muhimu kwa usalama?
- Ni functions zipi zilizo vizuizi muhimu vya usanifu zenye **blast radius** kubwa isiyo ya kawaida?

Hii kwa kawaida huibua malengo bora ya fuzz kuliko kuzingatia tu "coverage ya chini zaidi". Parser/decoder yenye **complexity kubwa** na **ufikikaji wa nje uliothibitishwa** ni mgombea bora zaidi wa harness kuliko helper ya ndani isiyohusiana na sehemu nyingine, yenye coverage dhaifu lakini isiyokuwa na njia inayodhibitiwa na mshambuliaji.

### Mchakato wa vitendo wa triage

1. Tengeneza **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branch kwa kila function.
2. Orodhesha **entrypoints** zinazopokea ingizo linalodhibitiwa na mshambuliaji: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Tekeleza **path queries** kutoka kwenye entrypoints hadi kwa functions zinazoweza kuchaguliwa, ili kutenganisha sehemu inayoweza kushambuliwa na code iliyokufa/inayotumiwa ndani pekee.
4. Zipe kipaumbele nodes zinazojumuisha:
   - **cyclomatic complexity** kubwa
   - **ufikikaji uliothibitishwa kutoka kwenye ingizo lisiloaminika**
   - **blast radius** kubwa au dependents wengi wa chini yake
   - ushahidi wa ziada kama matokeo ya **SARIF**, maelezo ya ukaguzi, au mutation survivors
5. Andika harnesses zinazolenga nodes zenye alama za juu zaidi kwanza, hasa **parsers/codecs** kama vile decoders za hex/Base64/IP/message.

### Mutation survivors: equivalent dhidi ya actionable

Mutation testing mara nyingi hutoa orodha yenye kelele ya survivors. Kabla ya kuchukulia kila survivor kuwa pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka kwenye entrypoint inayodhibitiwa na mshambuliaji?
- Je, njia zote za miito zimewekewa vikwazo na invariants imara zaidi kuliko ukaguzi uliobadilishwa?
- Je, node iko kwenye code iliyokufa, logic ya uumbizaji pekee, au njia yenye athari kubwa ya arithmetic/parser?

Survivors ambazo bado haziwezi kufikiwa au zimewekewa vikwazo vya kimuundo mara nyingi ni **equivalent mutants**. Survivors ambazo bado **zinaweza kufikiwa** na kugusa **mipaka**, **overflow/carry paths**, au **arithmetic/parsing muhimu kwa usalama** zinapaswa kuongezwa kwenye:

- harnesses mpya za fuzz
- tests za moja kwa moja za property/invariant
- vectors maalum za edge-case

### Linganisha matokeo ya nje na graph

Ikiwa pipeline yako ya SAST inatoa **SARIF**, weka matokeo kwenye nodes za graph kwa kutumia **file + line range** na utumie graph kuchunguza athari zaidi.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya function iliyowekewa alama
- angalia kama matokeo yako kwenye njia yoyote kutoka kwa entrypoint
- panga matokeo ya karibu yaliyo katika choke point moja

Hii ni muhimu unapoamua kama utatumia muda wa fuzzing kwenye function fulani: node ambayo **inaweza kufikiwa**, **ina complexity kubwa**, na tayari ina **matokeo ya SAST** mara nyingi huwa lengo bora kuliko node yenye complexity kubwa tu lakini isiyo na njia ya mshambuliaji.

Mfano wa workflow kwa kutumia Trailmark.<sup>[[6]](#references)</sup>

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

Mbinu muhimu ni makutano haya: **utata x uwazi x athari**. Tumia grafu kuchagua malengo ya fuzzing yenye thamani kubwa zaidi ya usalama inayotarajiwa, kisha tumia mabadiliko yaliyopita ili kuamua ni mipaka na invariants zipi harness yako inapaswa kusisitiza.<sup>[[5]](#references)</sup>

## Fuzzing tofauti ya usimbaji wa funguo za kriptografia

Anza na funguo halali zilizosanifishwa katika mfuatano wa biti au test vectors za kawaida. Badilisha sehemu zilizosimbwa bila kuvunja urefu na muundo unaohitajika kufikia njia za uingizaji na uendeshaji, kisha tuma biti hizo hizo kwa implementations huru. Linganisha kukubaliwa na hitilafu. Saini na ciphertext zilizobahatishwa zinahitaji correctness oracles, si ulinganisho wa biti kwa biti: thibitisha saini au linganisha shared secrets kutoka kwa mzunguko wa encapsulation/decapsulation. Test vectors huonyesha ulinganifu kwa mifano inayojulikana; mabadiliko tofauti huchunguza usimbaji usio sahihi zaidi ya mifano hiyo.<sup>[[23]](#references)[[26]](#references)</sup>

Kwa fomati hizi za funguo, tumia oracles maalum kwa kila fomati:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Funguo za kusaini za ML-DSA zilizopanuliwa:** badilisha coefficients za `s1` au `s2` zilizopakiwa ziwe nje ya `[-η, η]`, huku ukihifadhi uwezo wa kuchanganua ufunguo. Angalia kama uingizaji au usainishaji unaukataa na kama saini yoyote inayotokana inathibitishwa. Tofauti za kukubaliwa pekee si ukiukaji wa viwango, kwa kuwa FIPS 204 haihitaji ukaguzi wa ziada wa funguo binafsi. Tazama [utaratibu wa kuvuja kwa masharti](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Jozi za funguo za ML-KEM:** tofautisha ukaguzi unaohitajika wa ufunguo wa encapsulation na ingizo la decapsulation na ukaguzi wa hiari wa uthabiti wa jozi (PCT) kwenye jozi iliyoingizwa. Fanya encapsulation kwa kutumia ufunguo wake wa umma, decapsulation kwa kutumia ufunguo wake binafsi, kisha linganisha shared secrets; kutolingana kunaweza kuvuruga mawasiliano yaliyosimbwa hata kama funguo za kibinafsi zimefaulu ukaguzi wa ingizo. Angalia kama API inathibitisha ingizo wakati wa operesheni au kupitia mwito tofauti; libcrux hutoa `validate_public_key(pk)` na `validate_private_key(sk, ct)`, ambazo hazichukui nafasi ya PCT.
- **Funguo ghafi za XMSS/XMSSMT:** jaribu mizunguko ya kusanifisha na kurejesha funguo za **kusaini na kuthibitisha** katika seti mbalimbali za vigezo, badala ya kujaribu tu operesheni kwa funguo zilizo kwenye kumbukumbu. XMSS na XMSSMT zina nafasi tofauti za OID za baiti nne, kwa hiyo kichanganuzi cha OID pekee kinachojaribu XMSS kwanza kinaweza kuainisha vibaya ufunguo wa XMSSMT wenye OID inayogongana na kuukataa uingizaji. Kichanganuzi cha RustCrypto kilichoripotiwa kinaonyesha hitilafu ya interoperability/availability, si kughushi saini.

## Go Fuzzing kwa gosentry: Injini Imara Zaidi, Ingizo Zenye Aina, na Ukaguzi Tofauti

Ikiwa lengo la Go tayari lina harness asilia ya `testing.F`, njia ya vitendo ya kuboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), toolchain ya Go iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Hii ni muhimu wakati Go fuzzer asilia inakwama kwenye **ulinganisho mgumu**, **ingizo zenye aina maalum**, au **miundo inayotegemea sana parser**. Mbinu inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia campaign inayotokana nayo kama run ya kawaida inayoongozwa na coverage, lakini yenye uratibu/mutation za LibAFL na detectors saidizi bora zaidi.

### Geuza hitilafu zisizoonekana kuwa matokeo ya fuzzing

Tatizo linalojirudia katika tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa chaguo-msingi. Kwa gosentry, unaweza kugeuza hali kadhaa za “mbaya lakini zisizoonekana” kuwa matokeo ya fuzzing.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili kufanya njia zilizochaguliwa za logging/error zifanye kazi kama crashes (inafaa kwa njia za aina ya `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kuendesha tena entries mpya zilizogunduliwa kwenye queue kwa kutumia Go race detector.
- `--catch-leaks=true` ili kuendesha tena entries mpya zilizogunduliwa kwenye queue kwa kutumia `goleak` na kusitisha kazi kukitokea goroutine leak.
- Ushughulikiaji wa hang wa LibAFL ili kuhifadhi **mizunguko isiyoisha / ingizo zinazoenda polepole sana** kama matokeo ya fuzzing badala ya kuziacha zitoweke kama timeouts.
- Ukaguzi wa arithmetic overflow uliojengewa ndani huwashwa kwa chaguo-msingi, pamoja na ukaguzi wa hiari wa truncation kupitia instrumentation ya mtindo wa go-panikint.

Hili ni la thamani hasa kwa targets ambapo athari ya kiusalama ni **hitilafu ya parser isiyosababisha panic**, **hitilafu ya concurrency**, au **hang inayosababisha DoS pekee**, badala ya uharibifu wa memory.

### Fuzzing inayozingatia struct kwa Go APIs zenye aina maalum

Go fuzzing asilia hulenga zaidi scalars kama `[]byte`, `string`, na nambari. Ikiwa code inayojaribiwa hutumia objects zenye aina maalum, gosentry inaweza kufanya fuzzing moja kwa moja kwenye **thamani changamani** (structs, slices, arrays, pointers) huku ikiendelea kufanya mutation ya bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>

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

Tumia hili wakati kujenga wire format bandia kwa ajili ya fuzzing pekee kungeficha hitilafu za logic kwenye msimbo wa parsing wa harness pekee. Kwa kampeni za differential au grammar-based, weka ingizo la harness kama `[]byte` au `string` moja, kisha ufanye parsing ndani ya callback badala yake.

### Fuzzing inayotegemea grammar kwa parsers na ingizo za protocol

Kwa parsers, fomati na lugha za ingizo, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni safu ya JSON ya kanuni za uzalishaji, na kwa kawaida harness inapaswa kupokea hoja moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Vidokezo vya mbinu:

- Tumia grammar mode pale ambapo byte-level mutations nyingi huishia kwenye ukaguzi wa sintaksia wa awali.
- Lenga grammar kwenye **sehemu ndogo ya lugha/protokali inayohusika na usalama** badala ya kuiga vipimo vyote.
- Tumia thamani kubwa za mipaka kwenye terminals/nonterminals ili kujaribu mipaka ya integer, urefu na mashine ya hali.
- Grammar mode huhakikisha inputs zinatii grammar, lakini target bado hupokea **bytes/strings**, kwa hiyo parsing na ukaguzi wa kisemantiki hubaki ndani ya code iliyowekewa harness.

### Differential fuzzing: linganisha implementations, si crashes pekee

Muundo bora kwa mifumo ya Go ni **grammar-based differential fuzzing**: zalisha inputs halali zenye muundo na uzitumie kwa parsers, clients au state-transition engines mbili.<sup>[[7]](#references)[[8]](#references)</sup>

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

Zichukulie yafuatayo kuwa findings:

- implementation moja husababisha panic huku nyingine ikikataa input kwa usafi
- kutolingana kwa input zinazokubaliwa/kukataliwa
- parse trees au objects zilizodecodeiwa zinatofautiana
- state transitions, nonces, balances, au state roots zinatofautiana

Hii ni njia ya vitendo ya kupata **kutolingana kwa consensus**, **utata wa parser**, na **mkengeuko kati ya spec na implementation** ambao mara nyingi hukosekana katika crash fuzzing pekee.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tumia tena corpus ya campaign kuripoti coverage

Baada ya campaign, rudia corpus ya queue iliyohifadhiwa ili kutengeneza ripoti ya Go coverage bila kuhamisha corpus tofauti kwa mikono.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Tekeleza amri kutoka kwenye **package ileile** na kwa kutumia **lengo lilelile la `-fuzz`** ili gosentry ipate hali sahihi ya kampeni iliyohifadhiwa kwenye cache.

## References

- [1] [Fuzzing ya sarufi ya kimabadiliko](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing ya AFL++ kwa kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet baada ya miaka mitano: Kuhusu fuzzing ya protocol inayoongozwa na coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hubadilisha code kuwa grafu](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya zana. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer ya haraka ya greybox kwa protocol za mtandao zenye state kwa kutumia snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna grammar, hakuna shida: Kuelekea kufuzz kernel ya Linux bila maelezo ya system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing yenye ufanisi kwa kutumia snapshots zinazobadilika kulingana na hali na zinazoweza kubadilishwa](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Uwekaji wa instrumentation wa LLVM wa AFL++: coverage ya njia na ya caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing ya muktadha nyeti inayotabiri](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blogu ya Android Offensive Security - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - nyaraka za build na regression-seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kuchunguza race condition za kernel ya Linux kwa kupanga mipishano ya ufikiaji wa kumbukumbu kwa udhibiti](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: coverage ya code kwa ajili ya fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaksia ya jina la faili lililopanuliwa la CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Ushauri wa Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Kufuzz CFITSIO Extended Filename Syntax: udhaifu 16 wa usalama wa kumbukumbu na uchunguzi wa awali uliosaidiwa na Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing tofauti kwa cryptography](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Kiwango cha utaratibu wa ufungaji wa funguo unaotegemea moduli-lattice](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Hitilafu ya uchanganuzi wa XMSSMT OID - suala la RustCrypto #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Hali ya utekelezaji wa cryptography ya baada ya quantum](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Kutumia snapshotting kufikia CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
