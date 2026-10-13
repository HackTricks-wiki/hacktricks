# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage बनाम Semantics

**Mutational grammar fuzzing** में inputs को mutate किया जाता है, लेकिन वे **grammar-valid** बने रहते हैं। Coverage-guided mode में केवल वे samples corpus seeds के रूप में सहेजे जाते हैं जो **नई coverage** को trigger करते हैं। **Language targets** (parsers, interpreters, engines) के लिए इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** की ज़रूरत होती है, जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds खोजता है जो अलग-अलग `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow को बनाए नहीं रखता**। इसलिए “bug के करीब” वाला sample हटा दिया जाता है, क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** के साथ, random recombination महँगा हो जाता है और coverage feedback search को दिशा नहीं देता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए, **mutational और generative phases को hybridize करने** या generation को **function chaining** patterns की ओर झुकाने पर विचार करें (सिर्फ coverage पर नहीं)।<sup>[[1]](#references)</sup>

## Corpus Diversity की चुनौतियाँ

Coverage-guided mutation **greedy** होता है: नई coverage वाला sample तुरंत सहेज लिया जाता है, और अक्सर उसके बड़े अपरिवर्तित हिस्से भी बने रहते हैं। समय के साथ corpora में **कम structural diversity वाले लगभग-एक-जैसे samples** जमा हो जाते हैं। बहुत आक्रामक minimization से उपयोगी context हट सकता है, इसलिए एक व्यावहारिक समझौता है **grammar-aware minimization**, जो **minimum token threshold** पर रुक जाए (noise कम करते हुए आसपास की इतनी structure बनाए रखे कि mutations प्रभावी रहें)।<sup>[[1]](#references)</sup>

Mutational fuzzing के लिए corpus का एक व्यावहारिक नियम है: near-duplicates के बड़े संग्रह के बजाय **ऐसे कुछ structurally अलग seeds को प्राथमिकता दें जो coverage को अधिकतम करें**। व्यवहार में, आम तौर पर इसका मतलब यह है।<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem से file sets)।
- हर valid sample को रखने के बजाय **coverage-based corpus minimization** से उन्हें छाँटें।
- Seeds को इतना **छोटा** रखें कि mutations अर्थपूर्ण fields पर हों, न कि अधिकतर cycles अप्रासंगिक bytes पर खर्च हों।
- Harness/instrumentation में बड़े बदलावों के बाद corpus minimization दोबारा चलाएँ, क्योंकि reachability बदलने पर “सबसे अच्छा” corpus भी बदल जाता है।

## Magic Values के लिए Comparison-Aware Mutation

Fuzzers के plateau पर पहुँचने का एक आम कारण syntax नहीं, बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums या parser dispatch values, जिन्हें `memcmp`, switch tables या cascaded comparisons से जाँचा जाता है। Pure random mutation में इन values का byte-by-byte अनुमान लगाने की कोशिश में cycles बर्बाद होते हैं।

ऐसे targets के लिए **comparison tracing** (उदाहरण के लिए, AFL++ `CMPLOG` / Redqueen-style workflows) का उपयोग करें, ताकि fuzzer असफल comparisons के operands देख सके और mutations को उन values की ओर मोड़ सके जो उन्हें satisfy करती हैं।<sup>[[3]](#references)</sup>

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

**व्यावहारिक नोट्स:**

- यह खास तौर पर तब उपयोगी है जब target गहरे logic तक पहुँच को **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे सीमित करता है।
- इसे वास्तविक samples, protocol specs, या debug logs से निकाली गई **dictionaries** के साथ इस्तेमाल करें। Grammar tokens, chunk names, verbs, और delimiters वाली छोटी dictionary अक्सर बहुत बड़ी generic wordlist से अधिक उपयोगी होती है।
- अगर target कई sequential checks करता है, तो पहले सबसे शुरुआती “magic” comparisons हल करें, फिर बने हुए corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## उन File APIs को Fuzz करना जो Filename Language छिपाते हैं

`filename`, `path`, या `URL` नाम वाला parameter literal file lookup के बजाय interpreter का entry point हो सकता है। उदाहरण के लिए, CFITSIO Extended Filename Syntax (EFS) खोले गए object को लौटाने से पहले bracketed selectors, row/pixel expressions, calculated columns, histograms, और transformations evaluate करता है; कुछ forms temporary copies भी बनाते हैं। Attack-surface mapping के दौरान, हर open/import API को **literal-path** या **interpreted-path** के रूप में वर्गीकृत करें, फिर उस production entry point को fuzz करें जिसे applications वास्तव में call करती हैं।<sup>[[20]](#references)[[22]](#references)</sup>

इसके परिणामस्वरूप मिलने वाले SSRF, file-copy, और protocol-handler primitives—और अधिक सुरक्षित literal-path APIs—के लिए देखें [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)।<sup>[[20]](#references)</sup>

### Backing object को fuzz किए जा रहे program से अलग रखें

जब grammar filename suffix में हो, तो केवल referenced file bytes को mutate करने से parser तक पहुँचना छूट जाता है। इसके बजाय, एक छोटा harness testcase को string के रूप में पढ़ सकता है और उसे interpreted open API में pass कर सकता है; CFITSIO campaign ने `fits_open_file()` को read-only mode में call करके अधिकांश EFS parsers और evaluators तक पहुँच बनाई। Valid backing files को अलग से उपलब्ध रखें, ताकि mutations का ध्यान base path को बार-बार तोड़ने के बजाय selector/expression language पर केंद्रित रहे।<sup>[[22]](#references)</sup>

ऐसे seeds इस्तेमाल करें जिनमें से हर एक अलग grammar family तक पहुँचता हो, फिर specification और lexer/parser source—दोनों से एक compact dictionary बनाएँ। अगर coverage एक ही syntax-error path में बार-बार fail होने वाले inputs के साथ plateau हो जाए, तो केवल random-mutation समय बढ़ाने के बजाय valid prefixes सुरक्षित रखें और delimiters, operators, keywords, function names, तथा representative field names जोड़ें।<sup>[[22]](#references)</sup>

उदाहरण के लिए, grammar dictionary के साथ harness चलाएँ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness के side effects को नियंत्रित करना

केवल read-only library flag से यह गारंटी नहीं मिलती कि testcase का कोई side effect नहीं होगा: filename language इनपुट को फिर से लिख सकती है, output files बना सकती है या temporary objects materialize कर सकती है। CFITSIO campaign ने शुरू में seed files नष्ट कर दीं और filesystem पर अनपेक्षित files छोड़ दीं, इसलिए cleanup और isolation ज़रूरी थे।<sup>[[22]](#references)</sup>

- हर worker को एक disposable working directory और निजी temporary directory दें।
- canonical backing files की copies उपलब्ध कराएँ; target को corpus की इकलौती copy कभी mutate न करने दें।
- जब तक remote backends ही लक्षित न हों, network access बंद रखें और container, mount namespace या किसी समकक्ष sandbox से writable paths सीमित करें।
- हर execution या worker batch के बाद directory reset करें और filesystem में होने वाले अनपेक्षित बदलावों को अतिरिक्त findings मानें।

### Crash-to-patch-to-fuzz चक्र

Repair से पहले crashes को cluster करें, ताकि हज़ारों artifacts हज़ारों patch tasks में न बदल जाएँ। CFITSIO assessment में AFLTriage ने शुरुआती crash set को कुछ root causes तक सीमित किया; इसके बाद बने advisory में अलग-अलग failures दिखे, जिनमें destination-size की गलत checks, `realloc()` के बाद stale pointers, arithmetic faults और असुरक्षित parser cleanup paths शामिल थे।<sup>[[21]](#references)[[22]](#references)</sup>

1. हर cluster के लिए एक प्रतिनिधि input को minimize करें और उसे AddressSanitizer के तहत reproduce करें।
2. वह exact failing access, source location, allocation/free history और parser state दर्ज करें जिसकी वजह से invariant गलत हुआ।
3. एक सीमित दायरे वाला candidate patch लागू करें और उसी coverage तथा sanitizer instrumentation के साथ rebuild करें।
4. मूल reproducer **और उसके cluster के हर input** को फिर से चलाएँ; leak detection भी चालू करें, क्योंकि memory-safety fix किसी error path पर ownership को बिगाड़ सकता है।
5. असली files के साथ functional tests चलाएँ, फिर संचित queue से आगे बढ़ें (या binary बदलने के बाद यदि engine को नई output directory चाहिए, तो उस queue को फिर से import करें)।
6. दोहराएँ: पहला सतही crash हटाने से अक्सर मौजूदा seeds को parser की अधिक गहरी state तक पहुँचने का मौका मिलता है।

LLM, crashing input, sanitizer report, harness और संबंधित source मिलने पर, step 2 को तेज़ कर सकता है और step 3 का draft बना सकता है, लेकिन उसके patch पर भरोसा नहीं किया जाना चाहिए। Repair स्वीकार होगा या नहीं, इसका फैसला sanitizer replay और regression gates करेंगे—model की व्याख्या नहीं।<sup>[[22]](#references)</sup>

## Edge Coverage से अलग-अलग Paths का पता न चलने पर बेहतर Feedback

सामान्य edge coverage दो executions के बीच अंतर नहीं कर सकती, यदि वे अलग-अलग callers के ज़रिए उसी helper से गुज़रें या किसी function के भीतर अलग-अलग branch combinations लें। यह shared decoders, protocol dispatchers और interpreter helpers में महत्वपूर्ण है, जहाँ किसी edge तक पहुँचने का **route** ही live state तय करता है। हर calling context को बिना सोचे-समझे track करना भी जोखिमभरा है: coverage map और queue का आकार बहुत बढ़ सकता है। इसलिए context-sensitive fuzzing research पूरे call graph को context-sensitive मानने के बजाय केवल संभावनाशील contexts को refine करने की सलाह देती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds सामान्य edge coverage के साथ **per-function Ball-Larus path coverage** भी देते हैं। यह किसी function के हर acyclic path के लिए एक feature assign करता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations में अंतर बता सकता है, लेकिन **loop iterations की संख्या में नहीं**। शुरुआत में relaxed level `1` इस्तेमाल करें, फिर सख्त modes को संदिग्ध parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या तेज़ी से बढ़ सकती है।<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

कई सुरक्षा-संबंधी स्थानों से call किए जाने वाले helper के लिए, LTO mode प्रत्येक function path को उसके तत्काल call site के साथ जोड़ सकता है:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** richer feedback का उपयोग सावधानी से करें और इसकी coverage-map/queue लागत पर नज़र रखें।<sup>[[13]](#references)[[14]](#references)</sup>

- एक सामान्य edge-coverage instance समानांतर में चलाएँ; richer feedback तभी उपयोगी है, जब इसकी अतिरिक्त queue/map लागत से executions per second में भारी कमी न आए।
- बड़ी template-heavy libraries या generic utility code के कारण map का अधिकांश हिस्सा भरने पर path/caller instrumentation सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- अत्यधिक acyclic paths वाले functions को AFL++ छोड़ सकता है; compilation के दौरान आने वाली warnings बताती हैं कि target को allowlisting या कम strict level की ज़रूरत है।
- Caller + path coverage केवल एक caller depth को support करता है। इसे अधिक गहरे context stacks के साथ न मिलाएँ।
- LLVM के major versions के बीच Path IDs बदल सकते हैं। Campaign के दौरान toolchain को स्थिर रखें और PATH-based corpora को ऐसे synchronize न करें मानो उनके feature IDs अलग-अलग builds में स्थिर हों।
- यह feedback, `CMPLOG` का पूरक है: comparison tracing बताती है कि **कौन-सी value guard को पार करती है**, जबकि path/caller feedback यह दर्ज रखता है कि **कौन-सा route और branch combination वहाँ तक पहुँचा**।

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows** और **multi-stage parsers** के लिए अक्सर दिलचस्प इकाई एक अकेला blob नहीं, बल्कि **message sequence** होती है। पूरे transcript को एक file में जोड़कर आँख मूँदकर mutate करना आम तौर पर अक्षम होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है—भले ही fragile state तक केवल बाद वाला message पहुँचाता हो।<sup>[[4]](#references)</sup>

ज़्यादा प्रभावी तरीका है **sequence को ही seed** मानना और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback के रूप में उपयोग करना।<sup>[[4]](#references)</sup>

- **Valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- जब अगला step उन पर निर्भर हो, तो पिछले responses से मिले identifiers और server-generated values cache करें।
- पूरे serialized transcript को एक opaque blob मानकर mutate करने के बजाय, per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol सार्थक response codes देता है, तो उन्हें **सस्ते state oracle** की तरह उपयोग करें, ताकि ज़्यादा गहराई तक पहुँचने वाली sequences को प्राथमिकता दी जा सके।

इसीलिए authenticated bugs, hidden transitions या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing से छूट जाते हैं: fuzzer को केवल structure नहीं, बल्कि **क्रम, state और dependencies** भी बनाए रखने होते हैं।<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Edge coverage अधिक होने पर भी IPC-driver bugs छूट सकते हैं, क्योंकि coverage **object ownership, reference counts, pending messages, cleanup order या thread interleavings** नहीं बताती। [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) पेज driver का object model बताता है; यह उदाहरण fuzzer harness पर केंद्रित है। Android Binder एक उपयोगी मॉडल है: allocation और free paths, दोनों तक पहुँचना पर्याप्त नहीं है, अगर fuzzer कई processes से एक ही kernel object पर ज़रूरी क्रम में काम नहीं करवा सकता।<sup>[[15]](#references)</sup>

#### अलग-अलग `ioctl` buffers के बजाय protocol को model करें

Test case को **client identity + operation + structured arguments** के ordered grammar के रूप में दर्शाएँ। Binder LKL fuzzer protobuf और `libprotobuf-mutator` का उपयोग करता है, जिसमें एक persistent context-manager client और दो सामान्य clients होते हैं। इसके बाद semantic harness उन संबंधों को बनाए रखता है जिन्हें blind byte mutation नष्ट कर देती।<sup>[[15]](#references)</sup>

- पहले के operations से लौटे values cache करें। उदाहरण के लिए, `BC_FREE_BUFFER` को पिछले `ioctl` से मिला transaction-buffer pointer फिर से उपयोग करना चाहिए।
- Valid default replies बनाएँ, ताकि synchronous transactions पूरी हो सकें और बाद के operations तक पहुँचना संभव रहे।
- Self-transactions या एक ही target के लिए कई pending transactions जैसे असंभव transitions को अस्वीकार करें।
- Singleton bootstrap state को per-input reset से बाहर रखें। Binder हर boot में केवल एक `BINDER_SET_CONTEXT_MGR` registration की अनुमति देता है, इसलिए उस client को बार-बार नष्ट करके फिर से बनाने से बाद के inputs invalid हो जाएँगे।

Lifetime-race का एक उपयोगी template यह है कि एक client से object transfer करवाएँ, thread या process cleanup शुरू करें और उसी समय receiving client से transaction buffer release करवाएँ। CVE-2020-0423 के उदाहरण में, `BINDER_TYPE_WEAK_BINDER` transfer के बाद `BINDER_THREAD_EXIT` और `BC_FREE_BUFFER` के बीच race होने पर embedded `binder_work` free हो सकता था, जबकि exiting thread का cleanup path अभी भी उसका उपयोग कर रहा होता।<sup>[[15]](#references)</sup>

#### userspace kernel में नियंत्रित interleavings फिर से शामिल करें

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) वास्तविक kernel code को userspace harness में link करती है और `lkl_syscall` के ज़रिए उसका syscall interface उपलब्ध कराती है। इससे एक ही process में protobuf state, coverage और KASAN को आसानी से coordinate किया जा सकता है। हालाँकि, LKL आम तौर पर एक syscall के दौरान किसी दूसरे kernel thread को interrupt नहीं करने देता। Race campaigns के लिए, चुनी हुई lock/unlock और lifetime boundaries के आसपास `schedule()` points डालें, फिर हर yield पर harness को अगला client randomly चुनने दें। इन points को लक्षित रखें, क्योंकि हर point scheduling search space को कई गुना बढ़ाता है। Researchers द्वारा बताया गया randomized scheduler **upstream Binder fuzzer का हिस्सा नहीं है**।<sup>[[15]](#references)</sup>

#### Serialized regression seeds बनाएँ और replay करें

Upstream harness एक compatible `libprotobuf-mutator` version pin करता है, `LKL_FUZZING=1` के साथ LKL fuzzing instrumentation और KASAN सक्षम करता है, और Binder के लिए `MMU=1` के साथ `CONFIG_MMU` सक्षम करता है।<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

जानबूझकर कमजोर revision checkout करने या upstream में दस्तावेज़ीकृत rollback patches लागू करने के बाद, serialized seed पूरे multi-client state transition को ad-hoc C proof of concept में दोबारा बनाए बिना पुनरुत्पादित कर सकता है:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

परिणामी KASAN use-after-free को इस बात की पुष्टि मानें कि seed, vulnerable lifetime path तक पहुँचा। यह kernel code execution या privilege escalation के लिए आवश्यक बाद के primitives को प्रदर्शित **नहीं** करता।<sup>[[16]](#references)</sup>

## एक ही मशीन पर विविधता की तरकीब (Jackalope-Style)

**Generative novelty** को **coverage के पुनः उपयोग** के साथ मिलाने का एक व्यावहारिक तरीका है कि persistent server के विरुद्ध कम समय तक चलने वाले workers को **restart** किया जाए। हर worker खाली corpus से शुरू होता है, `T` सेकंड बाद sync करता है, संयुक्त corpus पर अगले `T` सेकंड तक चलता है, फिर दोबारा sync करके बाहर निकल जाता है। इससे **हर generation में नए structures** मिलते हैं और साथ ही संचित coverage का लाभ भी उठता है।<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**क्रमिक workers (उदाहरण के तौर पर loop):**

<details>
<summary>Jackalope worker को पुनः शुरू करने वाला loop</summary>

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

**नोट्स:**

- `-in empty` हर generation में **नया corpus** सुनिश्चित करता है।
- `-server_update_interval T` **विलंबित sync** का अनुमान देता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **शुरुआती server sync डिफ़ॉल्ट रूप से छोड़ दिया जाता है** (`-skip_initial_server_sync` की ज़रूरत नहीं है)।
- सर्वोत्तम `T` **target पर निर्भर करता है**; worker के अधिकांश “आसान” coverage खोज लेने के बाद switch करना आमतौर पर सबसे अच्छा रहता है।

## कठिनाई से Harness किए जा सकने वाले Targets के लिए Snapshot Fuzzing

जब आप जिस code का परीक्षण करना चाहते हैं, वह केवल **setup में अधिक समय लगने के बाद** उपलब्ध होता है (VM boot करना, login पूरा करना, packet प्राप्त करना, container parse करना, service initialize करना), तो एक उपयोगी विकल्प **snapshot fuzzing** है: तैयार process या VM state को capture करें, हर test case को target के input path में inject करें, crash/timeout तक execute करें और snapshot restore करें। इससे initialization या protocol prefixes को दोहराने की ज़रूरत नहीं पड़ती। यह **network services**, **firmware**, **post-auth attack surfaces** और **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ जब तक इच्छित state तैयार न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, यदि supported हो तो केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को यथासंभव पहले महँगे parse/dispatch step के पास रखें, जैसे `recv`/`read` के बाद या packet-deserialization point पर, और target द्वारा इस्तेमाल किए गए input buffer को दर्ज करें। यह input processing में snapshot को और भीतर ले जाकर काम दोहराने से बचने के adaptive-placement सिद्धांत का पालन करता है।<sup>[[11]](#references)</sup>

## MAccConc के साथ Linux Kernel Race Exploration

[MAccConc](https://github.com/googleprojectzero/MAccConc) timing-sensitive Linux-kernel races को दोहराए जा सकने वाले memory-access schedules में बदलता है। यह दो-context **A-B-A** executions को स्वचालित रूप से enumerate कर सकता है या analyst को terminal UI/GUI में order constraints लागू करने देता है। यह पूर्ण concurrency fuzzer के बजाय experimental research tooling है: फ़िलहाल इसे LLVM 23+ और project के patched kernel की ज़रूरत है, command-line tools दो test threads को support करते हैं, और प्रस्तावित userspace fuzzing layer लागू नहीं की गई है।<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication points एकत्र करें

Instrumented kernel को KASAN outline callbacks और patched KCOV memory-record support के साथ build करें। Project README यह भी सुझाता है कि call stacks को उपयोगी बनाए रखने के लिए sibling-call optimization को disable करें।<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) instrument किए गए accesses को helper calls में बदल देता है। MAccConc kernel patches `asan-opt-same-temp` को disable करते हैं, ताकि लगातार होने वाले accesses merge न हों; जब global-variable races दिखनी ज़रूरी हों, तो `asan-opt-globals` optimization को भी disable करें। KCOV इससे बने records userspace तक पहुँचाता है। अलग-अलग execution contexts के accesses की तुलना करें और उन pairs को रखें जिनकी byte ranges overlap करती हैं और जिनमें कम-से-कम एक तरफ़ write होता है; lifetime transitions को भी candidate बनाने के लिए `kfree()` को write के रूप में model करें।<sup>[[17]](#references)</sup>

शुरुआती task से बाहर होने वाले work, जैसे packet processing या RCU callbacks, के लिए subsystem को KCOV remote-coverage handle आगे पहुँचाना होगा। Upstream remote KCOV opt-in है और arbitrary background work के लिए अपने-आप उपलब्ध नहीं होता, इसलिए propagation न होने पर कोई वास्तविक interaction दिखाई नहीं दे सकता।<sup>[[17]](#references)[[19]](#references)</sup>

### हर run में उसी dynamic access की पहचान करें

किसी निश्चित heap address पर replay न करें, क्योंकि हर allocation के बाद वह बदल सकता है; और न ही सिर्फ़ instruction address के आधार पर replay करें, क्योंकि `memcpy()` और `spin_lock()` जैसे helpers के अंदर यह अस्पष्ट होता है। MAccConc **count-augmented stack trace** का उपयोग करता है: हर frame में callee और उसके caller के भीतर invocation count की पहचान होती है, जबकि अंतिम element memory-access instruction की पहचान करता है। SanitizerCoverage function-entry/exit records userspace को इस dynamic identifier को फिर से बनाने देते हैं, जो address बदलने और control flow में असंबंधित बदलावों के बावजूद स्थिर रहता है।<sup>[[17]](#references)</sup>

### Candidate pairs को forced schedules में बदलें

Patched `KCOV_SET_DI` ioctl, count-augmented access identifier को shared-flag action से जोड़ता है।<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | चुने गए access से ठीक पहले flag *N* set करें। |
| `DI_STACK_WAIT` | चुने गए access से पहले, flag *N* के set होने तक या configured limit समाप्त होने तक spin करें। |
| `DI_STACK_WAKE_POST` | चुने गए access के ठीक बाद flag *N* set करें। |

आंशिक **A-happens-before-B** constraint के लिए, A पर `DI_STACK_WAKE_POST` और B पर उसी flag के साथ `DI_STACK_WAIT` लगाएँ। पूरी तरह निर्दिष्ट two-context schedule के लिए, B को blocked शुरू करें, फिर A से B को wake करवाएँ और पहले transfer point पर wait करवाएँ; अगले transfer पर B उलटा operation करता है। यह deterministic context switching की तरह काम करता है और automatic A-B-A explorer इसी का उपयोग करता है।<sup>[[17]](#references)</sup>

एक minimal campaign में four-hook test case (`test_setup`, दो thread functions और `test_end`) को shared library के रूप में compile करें, unconstrained trace collect करें, फिर A-B-A candidates enumerate करें या संदिग्ध accesses के आसपास manual constraints जोड़ें।<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts को सफल reorderings से अलग समझें: मांगा गया order असंभव हो सकता है, क्योंकि कोई lock या initialization/publication dependency दूसरे context को उसके injection point तक पहुँचने से रोकती है। KASAN के blind spots भी ध्यान में रखें: direct stack accesses आमतौर पर hook नहीं किए जाते, जब तक उनके out of bounds होने की आशंका न हो; default optimization के साथ globals को छोड़ दिया जाता है; और मौजूदा compilers ASAN और TSAN hooks एक साथ emit नहीं कर सकते। आखिर में, guest के panic होने पर prototype अपना KCOV buffer खो देता है, इसलिए एक स्वतंत्र crash console/oracle बनाए रखें।<sup>[[17]](#references)</sup>

भविष्य के concurrency-guided fuzzing के लिए, हर input या syscall के memory-access summaries रिकॉर्ड करें, उन operations को pair करें जो cross-context communication points बनाएँगे, और फिर केवल उन्हीं combinations को explore करें। VM snapshots global state और addresses को स्थिर रखते हैं; snapshots के बिना, allocation-site metadata का उपयोग करके runs के बीच objects को abstract किया जा सकता है। यह एक प्रस्तावित extension है, मौजूदा MAccConc userspace tools की सुविधा नहीं।<sup>[[17]](#references)</sup>

## Harness Introspection: Shallow Fuzzers को जल्दी पहचानें

जब कोई campaign रुक जाता है, तो समस्या अक्सर mutator में नहीं, बल्कि **harness** में होती है। ऐसे functions खोजने के लिए **reachability/coverage introspection** का उपयोग करें जो statically आपके fuzz target से reachable हैं, लेकिन dynamically बहुत कम या बिल्कुल cover नहीं होते। ऐसे functions आमतौर पर तीन में से किसी एक समस्या का संकेत देते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी पूरे feature family की कमी है।
- Target को एक बहुत बड़े “सब कुछ करने वाले” harness के बजाय सचमुच **दूसरे harness** की ज़रूरत है।

अगर आप OSS-Fuzz / ClusterFuzz-शैली के workflows इस्तेमाल करते हैं, तो Fuzz Introspector static reachability की runtime coverage से तुलना कर सकता है और timed run या public corpus से reports बना सकता है।<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

रिपोर्ट का उपयोग करके तय करें कि किसी ऐसे parser path के लिए नया harness जोड़ना है जिसकी जाँच नहीं हुई है, किसी खास feature के लिए corpus बढ़ाना है, या एक बड़े harness को छोटे entry points में बाँटना है।

## Graph-First Fuzz Target Selection और Mutation Triage

अगर आपके पास पहले से **static-analysis findings**, **mutation-testing survivors**, और **coverage reports** हैं, तो उन्हें अलग-अलग सूचियों के रूप में triage न करें। पहले **call graph** बनाएँ, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, और बाहरी findings की जानकारी जोड़ें, फिर graph से जुड़े सवाल पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- कौन-से high-complexity functions untrusted input से reachable हैं?
- कौन-से mutation survivors, parsers/handlers से security-critical code तक जाने वाले paths पर हैं?
- किन functions की architectural choke point के रूप में भूमिका है और जिनका **blast radius** असामान्य रूप से बड़ा है?

अक्सर इससे "सबसे कम coverage" के आधार पर चुने गए targets से बेहतर fuzz targets सामने आते हैं। **High complexity** और प्रमाणित **external reachability** वाला parser/decoder, ऐसे अलग-थलग internal helper से बेहतर harness candidate है जिसकी coverage कमज़ोर है, लेकिन वहाँ attacker-controlled path नहीं पहुँचता।

### Practical triage workflow

1. Codebase से **code graph** बनाएँ और हर function के complexity/branch metrics निकालें।
2. उन **entrypoints** की सूची बनाएँ जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. Candidate functions तक पहुँचने वाले paths पर queries चलाएँ, ताकि reachable attack surface को dead/internal-only code से अलग किया जा सके।
4. उन nodes को प्राथमिकता दें जिनमें ये बातें एक साथ हों:
   - high **cyclomatic complexity**
   - **untrusted input से reachability** की पुष्टि
   - high **blast radius** या कई downstream dependents
   - सहायक प्रमाण, जैसे **SARIF** findings, audit notes, या mutation survivors
5. पहले सबसे अच्छे score वाले nodes के लिए focused harnesses लिखें, खासकर **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent बनाम actionable

Mutation testing से अक्सर survivors की एक शोरभरी सूची मिलती है। हर survivor को security gap मानने से पहले, graph की मदद से ये सवाल पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths, mutated check से ज़्यादा मज़बूत invariants से constrained हैं?
- क्या node dead code में, केवल formatting वाले logic में, या high-impact arithmetic/parser path में है?

जो survivors unreachable रहें या संरचनात्मक रूप से constrained हों, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** हों और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** से जुड़े हों, उन्हें इन रूपों में आगे बढ़ाना चाहिए:

- नए fuzz harnesses
- सीधे property/invariant tests
- लक्षित edge-case vectors

### External findings को graph पर जोड़ें

अगर आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर दिखाएँ और प्रभाव का दायरा बढ़ाने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** निकालें
- जाँचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- पास-पास की findings को ऐसे समूहों में बाँटें जो एक ही choke point तक पहुँचती हों

किसी खास function पर fuzzing का समय लगाने का निर्णय लेते समय यह उपयोगी है: ऐसा node जो **reachable**, **complex**, और पहले से **SAST hits** वाला हो, अक्सर उस node से बेहतर target होता है जो केवल complex है, लेकिन वहाँ तक attacker path नहीं पहुँचता।

Trailmark के साथ workflow का उदाहरण।<sup>[[6]](#references)</sup>

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

महत्वपूर्ण पद्धति इनका प्रतिच्छेदन है: **जटिलता x एक्सपोज़र x प्रभाव**। सबसे अधिक अपेक्षित सुरक्षा-मूल्य वाले fuzz targets चुनने के लिए ग्राफ़ का उपयोग करें, फिर mutation survivors से तय करें कि आपके harness को किन सीमाओं और invariants पर ज़ोर देना चाहिए।<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: अधिक मज़बूत इंजन, टाइप किए गए इनपुट और Differential Checks

अगर किसी Go target में पहले से native `testing.F` harness है, तो इसे बेहतर बनाने का एक व्यावहारिक तरीका है कि उसी harness को [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाएँ। यह Go toolchain का fork है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

यह तब उपयोगी है जब native Go fuzzer **कठिन तुलनाओं**, **typed inputs** या **parser-heavy formats** पर अटक जाता है। तरीका वही रहता है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का इस्तेमाल करते रहें।
- वही harness दोबारा इस्तेमाल करें, लेकिन इसे stock toolchain के बजाय gosentry के `go` binary से चलाएँ।
- नतीजे को सामान्य coverage-guided run की तरह लें, लेकिन इसमें LibAFL scheduling/mutation और आसपास के बेहतर detectors होंगे।

### खामोश failures को fuzz findings में बदलें

Go assessments में एक बार-बार आने वाली समस्या यह है कि खतरनाक व्यवहार अक्सर डिफ़ॉल्ट रूप से **crash** नहीं करता। gosentry के साथ, आप “खराब, लेकिन खामोश” स्थितियों की कई श्रेणियों को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` से चुने हुए logging/error paths को crash जैसा व्यवहार कराएँ। यह `log.Fatal`-शैली के उन code paths के लिए उपयोगी है जो अन्यथा केवल log करते हैं और जारी रहते हैं।
- `--catch-races=true` से नए खोजे गए queue entries को Go race detector के साथ दोबारा चलाएँ।
- `--catch-leaks=true` से नए queue entries को `goleak` के साथ दोबारा चलाएँ और goroutine leaks मिलने पर रोकें।
- LibAFL का hang handling **infinite loops / बहुत धीमे inputs** को timeouts के रूप में गायब होने देने के बजाय fuzz findings के रूप में बनाए रखता है।
- डिफ़ॉल्ट रूप से अंतर्निहित arithmetic overflow checks, और go-panikint-शैली के instrumentation के ज़रिए वैकल्पिक truncation checks।

यह उन targets के लिए खास तौर पर उपयोगी है जहाँ security impact memory corruption के बजाय **panicless parser failure**, **concurrency bug** या केवल **DoS वाला hang** होता है।

### typed Go APIs के लिए struct-aware fuzzing

Native Go fuzzing मुख्यतः `[]byte`, `string` और numbers जैसे scalars की अपेक्षा करता है। अगर जाँचा जा रहा code typed objects लेता है, तो gosentry सीधे **composite values** (structs, slices, arrays, pointers) को fuzz कर सकता है, और साथ ही नीचे के bytes को mutate करता रहता है।<sup>[[7]](#references)[[8]](#references)</sup>

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

फज़िंग के लिए ही fake wire format बनाने से logic bugs harness-only parsing code के पीछे छिप सकते हों, तो इसका उपयोग करें। Differential या grammar-based campaigns के लिए, harness input को एक single `[]byte` या `string` रखें और इसके बजाय callback के अंदर parse करें।

### Parsers और protocol inputs के लिए Grammar-based fuzzing

Parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules का एक JSON array होता है, और harness को आमतौर पर एक single `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- जब byte-level mutations ज़्यादातर शुरुआती syntax checks में ही विफल हो जाएँ, तो grammar mode का उपयोग करें।
- Grammar को भाषा/प्रोटोकॉल के पूरे specification के बजाय उसके **security-relevant subset** पर केंद्रित रखें।
- Integer, length और state-machine की सीमाओं को stress करने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अब भी **bytes/strings** ही मिलते हैं, इसलिए parsing और semantic checks harnessed code के भीतर ही होते हैं।

### Differential fuzzing: केवल crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक मज़बूत तरीका है **grammar-based differential fuzzing**: वैध structured inputs जनरेट करें और उन्हें दो parsers, clients या state-transition engines को दें।<sup>[[7]](#references)[[8]](#references)</sup>

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

इन्हें निष्कर्ष मानें:

- एक implementation panic करता है, जबकि दूसरा साफ़ तौर पर input अस्वीकार करता है
- स्वीकार/अस्वीकार किए गए input में बेमेल
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में अंतर

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing से अक्सर नहीं खोजा जा सकता।

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage reporting के लिए campaign corpus का दोबारा इस्तेमाल करें

Campaign के बाद, अलग से corpus को मैन्युअल रूप से export किए बिना Go coverage report बनाने के लिए सेव किए गए queue corpus को फिर से चलाएँ।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Run कमांड को **उसी package** से और **उसी `-fuzz` target** के साथ चलाएँ, ताकि gosentry सही cached campaign state को resolve करे।

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: A Fast Greybox Fuzzer for Stateful Network Protocols using Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [No Grammar, No Problem: Towards Fuzzing the Linux Kernel without System-Call Descriptions](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efficient Fuzzing with Adaptive and Mutable Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path and caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build and regression-seed documentation](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Exploring Linux Kernel Race Conditions with Controlled Memory-Access Interleavings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: code coverage for fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Extended Filename Syntax](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing CFITSIO Extended Filename Syntax: 16 Memory-Safety Vulnerabilities and Codex-Assisted Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
