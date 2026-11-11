# Fuzzing की कार्यप्रणाली

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage बनाम Semantics

**Mutational grammar fuzzing** में inputs को mutate करते समय **grammar-valid** रखा जाता है। Coverage-guided mode में केवल वे samples corpus seeds के रूप में सहेजे जाते हैं जो **नई coverage** उत्पन्न करते हैं। **Language targets** (parsers, interpreters, engines) के लिए इससे ऐसे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** ज़रूरी होती हैं—जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds ढूँढता है जो अलग-अलग `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow को बनाए नहीं रखता**। इसलिए “bug के ज़्यादा करीब” वाला sample हटा दिया जाता है, क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** होने पर random recombination महँगा हो जाता है और coverage feedback search को दिशा नहीं देता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए **mutational और generative phases को hybridize करने** या generation को **function chaining** patterns की ओर bias करने पर विचार करें (सिर्फ coverage की ओर नहीं)।<sup>[[1]](#references)</sup>

## Corpus Diversity की समस्याएँ

Coverage-guided mutation **greedy** होती है: नई coverage वाला sample तुरंत सहेज लिया जाता है और अक्सर उसमें बड़े unchanged regions बने रहते हैं। समय के साथ corpora **लगभग एक जैसे** samples से भर जाते हैं, जिनमें structural diversity कम होती है। बहुत आक्रामक minimization उपयोगी context हटा सकती है, इसलिए एक व्यावहारिक समझौता है **grammar-aware minimization** को **न्यूनतम token threshold पर रोकना** (noise कम करते हुए इतना surrounding structure बनाए रखना कि आगे mutation करना आसान रहे)।<sup>[[1]](#references)</sup>

Mutational fuzzing के लिए corpus का एक व्यावहारिक नियम है: near-duplicates के बड़े ढेर के बजाय **ऐसे seeds का छोटा सेट चुनें जो संरचना में अलग-अलग हों और coverage को अधिकतम करें**। व्यवहार में, आम तौर पर इसका अर्थ है:<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem के file sets)।
- हर valid sample को रखने के बजाय उन्हें **coverage-based corpus minimization** से छाँटें।
- Seeds को इतना **छोटा रखें** कि mutations meaningful fields पर पड़ें, न कि ज़्यादातर cycles अप्रासंगिक bytes पर खर्च हों।
- Harness या instrumentation में बड़े बदलावों के बाद corpus minimization दोबारा चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Magic Values के लिए Comparison-Aware Mutation

Fuzzers के एक सीमा पर अटक जाने की आम वजह syntax नहीं, बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums या `memcmp`, switch tables अथवा cascaded comparisons से नियंत्रित parser dispatch values। Pure random mutation इन values का byte-by-byte अनुमान लगाने में cycles बर्बाद करती है।

ऐसे targets के लिए **comparison tracing** इस्तेमाल करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows), ताकि fuzzer विफल comparisons के operands देख सके और mutations को उन values की ओर bias कर सके जो उन्हें संतुष्ट करती हैं।<sup>[[3]](#references)</sup>

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

- यह विशेष रूप से तब उपयोगी है जब target गहरे logic को **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे रखता है।
- इसे वास्तविक samples, protocol specs, या debug logs से निकाली गई **dictionaries** के साथ इस्तेमाल करें। Grammar tokens, chunk names, verbs, और delimiters वाली छोटी dictionary अक्सर बहुत बड़ी generic wordlist से ज़्यादा उपयोगी होती है।
- अगर target कई sequential checks करता है, तो सबसे पहले शुरुआती “magic” comparisons हल करें और फिर मिले हुए corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## फ़ाइल APIs को fuzz करना जो फ़ाइलनाम की भाषा छिपाते हैं

`filename`, `path`, या `URL` नाम वाला parameter, literal file lookup के बजाय interpreter का entry point हो सकता है। उदाहरण के लिए, CFITSIO Extended Filename Syntax (EFS) खुले गए object को लौटाने से पहले bracketed selectors, row/pixel expressions, calculated columns, histograms, और transformations को evaluate करता है; कुछ रूप temporary copies भी बनाते हैं। Attack-surface mapping के दौरान, हर open/import API को **literal-path** या **interpreted-path** के रूप में वर्गीकृत करें, फिर उस production entry point को fuzz करें जिसे applications वास्तव में call करती हैं।<sup>[[20]](#references)[[22]](#references)</sup>

इससे मिलने वाले SSRF, file-copy, और protocol-handler primitives—और अधिक सुरक्षित literal-path APIs—के लिए देखें [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)।<sup>[[20]](#references)</sup>

### Backing object को fuzz किए गए program से अलग रखें

जब grammar filename suffix में हो, तो केवल referenced file bytes को mutate करने से parser छूट जाता है। इसके बजाय, एक छोटा harness हर testcase को string के रूप में पढ़कर interpreted open API को दे सकता है; CFITSIO campaign ने `fits_open_file()` को read-only mode में call करके अधिकांश EFS parsers और evaluators तक पहुँचा। Valid backing files को अलग से उपलब्ध रखें, ताकि mutations लगातार base path को तोड़ने के बजाय selector/expression language पर केंद्रित रहें।<sup>[[22]](#references)</sup>

ऐसे seeds इस्तेमाल करें जो अलग-अलग grammar families तक पहुँचते हों, फिर specification और lexer/parser source—दोनों से एक compact dictionary तैयार करें। अगर coverage स्थिर हो जाए और inputs बार-बार उसी syntax-error path में विफल हों, तो केवल random-mutation का समय बढ़ाने के बजाय valid prefixes सुरक्षित रखें और delimiters, operators, keywords, function names, तथा प्रतिनिधि field names जोड़ें।<sup>[[22]](#references)</sup>

उदाहरण के लिए, grammar dictionary के साथ harness चलाएँ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness के side effects को सीमित करें

Library का read-only flag यह गारंटी नहीं देता कि testcase side-effect-free होगा: filename language input को rewrite कर सकती है, output files बना सकती है, या temporary objects materialize कर सकती है। CFITSIO campaign ने शुरू में seed files को नष्ट किया और filesystem में अप्रत्याशित files छोड़ दीं, इसलिए cleanup और isolation आवश्यक थे।<sup>[[22]](#references)</sup>

- हर worker को disposable working directory और private temporary directory दें।
- Canonical backing files की copies उपलब्ध कराएँ; target को corpus की एकमात्र copy कभी mutate न करने दें।
- जब तक remote backends लक्ष्य न हों, network access बंद रखें और writable paths को container, mount namespace या equivalent sandbox से सीमित करें।
- हर execution या worker batch के बाद directory reset करें और filesystem में अप्रत्याशित बदलावों को अतिरिक्त findings मानें।

### Crash-to-patch-to-fuzz loop

Repair से पहले crashes को cluster करें, ताकि हजारों artifacts के कारण हजारों patch tasks न बनें। CFITSIO assessment में, AFLTriage ने शुरुआती crash set को घटाकर कुछ root causes तक सीमित किया; इसके बाद के advisory में अलग-अलग failures दिखाए गए, जिनमें destination-size की गलत जाँच, `realloc()` के बाद stale pointers, arithmetic faults और असुरक्षित parser cleanup paths शामिल थे।<sup>[[21]](#references)[[22]](#references)</sup>

1. हर cluster के लिए एक representative input को minimize करें और उसे AddressSanitizer के तहत reproduce करें।
2. उस exact failing access, source location, allocation/free history और parser state को दर्ज करें जिसने invariant को false किया।
3. एक narrowly scoped candidate patch लागू करें और उसी coverage तथा sanitizer instrumentation के साथ rebuild करें।
4. Original reproducer **और उसके cluster के हर input** को replay करें; leak detection भी चालू करें, क्योंकि memory-safety fix error path पर ownership को बिगाड़ सकता है।
5. Real files के साथ functional tests चलाएँ, फिर accumulated queue से जारी रखें (या binary बदलने के बाद engine को नया output directory चाहिए तो उस queue को फिर से import करें)।
6. दोहराएँ: पहला shallow crash हटाने से अक्सर मौजूदा seeds parser की अधिक गहरी state तक पहुँच पाते हैं।

जब LLM को crashing input, sanitizer report, harness और संबंधित source दिया जाए, तो वह step 2 को तेज़ कर सकता है और step 3 का draft बना सकता है, लेकिन उसका patch भरोसेमंद नहीं माना जाना चाहिए। Repair स्वीकार करना है या नहीं, यह sanitizer replay और regression gates तय करते हैं—model की explanation नहीं।<sup>[[22]](#references)</sup>

## जब Edge Coverage अलग-अलग Paths को एक जैसा मान ले, तब बेहतर Feedback

सामान्य edge coverage दो executions में अंतर नहीं कर सकती, यदि वे अलग callers के ज़रिए उसी helper से गुजरें या किसी function के भीतर अलग branch combinations लें। Shared decoders, protocol dispatchers और interpreter helpers में यह महत्वपूर्ण है, जहाँ किसी edge तक पहुँचने का **route** live state तय करता है। हर calling context को सीधे track करना भी खतरनाक है: coverage map और queue बहुत बड़े हो सकते हैं। इसलिए context-sensitive fuzzing research, पूरे call graph को context-sensitive मानने के बजाय, केवल promising contexts को refine करने की सलाह देती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds सामान्य edge coverage के अलावा **Ball-Larus per-function path coverage** देते हैं। यह किसी function से होकर गुजरने वाले हर acyclic path को एक feature देता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations में अंतर करता है, लेकिन **loop iterations की संख्या में नहीं**। Relaxed level `1` से शुरू करें, फिर सख्त modes को संदिग्ध parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या exponentially बढ़ सकती है।<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

कई security-relevant स्थानों से call किए जाने वाले helper के लिए, LTO mode प्रत्येक function path को उसके तत्काल call site के साथ जोड़ सकता है:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** अधिक समृद्ध feedback का सावधानी से उपयोग करें और इसके coverage-map/queue cost की निगरानी करें।<sup>[[13]](#references)[[14]](#references)</sup>

- एक सामान्य edge-coverage instance समानांतर में चलाएँ; समृद्ध feedback तभी उपयोगी है, जब अतिरिक्त queue/map cost प्रति सेकंड executions को कम न करे।
- बड़े template-heavy libraries या generic utility code के map पर हावी होने पर path/caller instrumentation सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- अत्यधिक acyclic paths वाले functions को AFL++ छोड़ सकता है; compilation के दौरान आने वाली warnings इस बात का संकेत हैं कि target को allowlisting या कम strict level की आवश्यकता है।
- Caller + path coverage केवल एक caller depth का समर्थन करता है। इसे अधिक गहरे context stacks के साथ न जोड़ें।
- Path IDs, LLVM के major versions के बीच बदल सकते हैं। किसी campaign के दौरान toolchain को स्थिर रखें और PATH-आधारित corpora को ऐसे synchronize न करें, मानो उनके feature IDs builds के बीच स्थिर हों।
- यह feedback `CMPLOG` का पूरक है: comparison tracing बताता है कि guard को **कौन-सी value पार करती है**, जबकि path/caller feedback यह सुरक्षित रखता है कि **कौन-सा route और branch combination वहाँ तक पहुँचा**।

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows** और **multi-stage parsers** के लिए अक्सर दिलचस्प unit एक अकेला blob नहीं, बल्कि **message sequence** होता है। पूरे transcript को एक file में जोड़कर बिना सोचे-समझे mutate करना आमतौर पर अक्षम होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है, भले ही fragile state तक केवल बाद वाला message पहुँचता हो।<sup>[[4]](#references)</sup>

ज़्यादा प्रभावी तरीका है **sequence को ही seed** मानना और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback के रूप में उपयोग करना।<sup>[[4]](#references)</sup>

- **Valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- जब अगला step उन पर निर्भर हो, तो पिछले responses से मिले identifiers और server-generated values को cache करें।
- पूरे serialized transcript को एक opaque blob की तरह mutate करने के बजाय, per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol अर्थपूर्ण response codes देता है, तो उन्हें **सस्ते state oracle** के रूप में उपयोग करके उन sequences को प्राथमिकता दें जो और गहराई तक पहुँचती हैं।

इसी कारण authenticated bugs, hidden transitions या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing की पकड़ में नहीं आते: fuzzer को केवल structure नहीं, बल्कि **क्रम, state और dependencies** भी बनाए रखनी होती हैं।<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

उच्च edge coverage के बावजूद IPC-driver bugs छूट सकते हैं, क्योंकि coverage **object ownership, reference counts, pending messages, cleanup order या thread interleavings** का वर्णन नहीं करती। [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) पेज driver object model बताता है; यह उदाहरण fuzzer harness पर केंद्रित है। Android Binder एक उपयोगी मॉडल है: allocation और free paths, दोनों तक पहुँचना पर्याप्त नहीं है, यदि fuzzer कई processes से आवश्यक क्रम में एक ही kernel object पर काम नहीं करवा सकता।<sup>[[15]](#references)</sup>

#### अलग-अलग `ioctl` buffers के बजाय protocol को model करें

एक test case को **client identity + operation + structured arguments** की ordered grammar के रूप में दर्शाएँ। Binder LKL fuzzer, protobuf और `libprotobuf-mutator` का उपयोग करता है; इसमें एक persistent context-manager client और दो सामान्य clients होते हैं। फिर एक semantic harness उन relationships को बनाए रखता है जिन्हें blind byte mutation नष्ट कर देती।<sup>[[15]](#references)</sup>

- पहले के operations से लौटे values को cache करें। उदाहरण के लिए, `BC_FREE_BUFFER` को पिछले `ioctl` से लौटे transaction-buffer pointer का फिर से उपयोग करना चाहिए।
- वैध default replies बनाएँ, ताकि synchronous transactions पूरे हो सकें और बाद के operations तक पहुँचना संभव रहे।
- self-transactions या एक ही target पर कई pending transactions जैसे असंभव transitions को अस्वीकार करें।
- Singleton bootstrap state को per-input reset से बाहर रखें। Binder, प्रति boot केवल एक `BINDER_SET_CONTEXT_MGR` registration की अनुमति देता है, इसलिए उस client को बार-बार नष्ट करके फिर से बनाने से बाद के inputs अमान्य हो जाएँगे।

Lifetime-race का एक उपयोगी template यह है कि एक client से object transfer करवाएँ, thread या process cleanup शुरू करें, और साथ ही receiving client से transaction buffer release करवाएँ। CVE-2020-0423 उदाहरण में, `BINDER_TYPE_WEAK_BINDER` transfer के बाद `BINDER_THREAD_EXIT` का `BC_FREE_BUFFER` के साथ race होने पर embedded `binder_work` free हो सकता था, जबकि exiting thread का cleanup path अभी भी उसका उपयोग कर रहा था।<sup>[[15]](#references)</sup>

#### userspace kernel में नियंत्रित interleavings फिर से शामिल करें

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), वास्तविक kernel code को userspace harness में link करता है और `lkl_syscall` के माध्यम से उसका syscall interface उपलब्ध कराता है। इससे protobuf state, coverage और KASAN को एक ही process में आसानी से coordinate किया जा सकता है। हालाँकि, LKL आम तौर पर किसी syscall के दौरान दूसरे kernel thread को interrupt नहीं करने देता। Race campaigns के लिए, चुने हुए lock/unlock और lifetime boundaries के आसपास `schedule()` points जोड़ें, फिर हर yield पर harness को अगला client randomly चुनने दें। इन points को लक्षित रखें, क्योंकि हर point scheduling search space को कई गुना बढ़ा देता है। शोधकर्ताओं द्वारा वर्णित randomized scheduler, upstream Binder fuzzer का हिस्सा **नहीं** है।<sup>[[15]](#references)</sup>

#### Serialized regression seeds बनाएँ और replay करें

Upstream harness, संगत `libprotobuf-mutator` को pin करता है, `LKL_FUZZING=1` के साथ LKL fuzzing instrumentation और KASAN सक्षम करता है, और Binder के लिए `MMU=1` के साथ `CONFIG_MMU` सक्षम करता है।<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

जानबूझकर असुरक्षित revision चेक आउट करने या upstream में दर्ज rollback patches लागू करने के बाद, एक serialized seed बिना किसी ad-hoc C proof of concept में state को फिर से बनाए ही पूरे multi-client state transition को दोहरा सकता है:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

परिणामी KASAN use-after-free को इस बात की पुष्टि मानें कि seed vulnerable lifetime path तक पहुँचा। यह kernel code execution या privilege escalation के लिए आवश्यक बाद के primitives को प्रदर्शित **नहीं** करता।<sup>[[16]](#references)</sup>

## एकल-मशीन विविधता ट्रिक (Jackalope-Style)

**Generative novelty** को **coverage reuse** के साथ मिलाने का एक व्यावहारिक तरीका है कि persistent server के विरुद्ध कम समय तक चलने वाले workers को **restart** किया जाए। हर worker खाली corpus से शुरू होता है, `T` सेकंड बाद sync करता है, combined corpus पर अगले `T` सेकंड तक चलता है, फिर दोबारा sync करके बाहर निकल जाता है। इससे संचित coverage का लाभ लेते हुए भी हर generation में **नई संरचनाएँ** मिलती हैं।<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**क्रमिक workers (उदाहरण loop):**

<details>
<summary>Jackalope worker restart loop</summary>

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
- Grammar fuzzing mode में, **initial server sync डिफ़ॉल्ट रूप से छोड़ दिया जाता है** (`-skip_initial_server_sync` की आवश्यकता नहीं है)।
- सबसे उपयुक्त `T` **target पर निर्भर करता है**; worker द्वारा अधिकांश “आसान” coverage खोज लेने के बाद switching करना आम तौर पर सबसे अच्छा काम करता है।

## मुश्किल-से-harness किए जाने वाले Targets के लिए Snapshot Fuzzing

जब जिस code को आप test करना चाहते हैं, वह **बहुत अधिक setup के बाद ही reachable** होता है (VM boot करना, login पूरा करना, packet प्राप्त करना, container parse करना, service initialize करना), तो **snapshot fuzzing** एक उपयोगी विकल्प है: तैयार process या VM state को capture करें, हर test case को target के input path में inject करें, crash/timeout तक execute करें और snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने की आवश्यकता नहीं रहती। यह **network services**, **firmware**, **post-auth attack surfaces** और **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ जब तक दिलचस्प state तैयार न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, अगर supported हो तो केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को जहाँ व्यावहारिक हो, पहले महँगे parse/dispatch step के जितना करीब हो सके रखें, जैसे `recv`/`read` के बाद या packet-deserialization point पर, और target द्वारा इस्तेमाल किए गए input buffer को दर्ज करें। यह adaptive-placement principle के अनुसार snapshot को input processing में और भीतर ले जाने से जुड़ा है, ताकि दोहराए जाने वाले काम से बचा जा सके।<sup>[[11]](#references)</sup>

### Protocol states के लिए Incremental snapshots

एक fixed snapshot setup की लागत घटाता है, लेकिन अपने-आप उन transitions को explore नहीं करता जिनके लिए कई valid messages चाहिए। LibAFL-Qemu harness, protocol-state field में writes पर नज़र रख सकता है और state बदलने पर नया snapshot save कर सकता है। [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) में, यह `tcpcb.t_state` पर नज़र रखता है, snapshots को deduplicate करने के लिए state और response flags का hash बनाता है, और parent के सापेक्ष dirty pages store करता है। अगला structured message mutate करने से पहले, यह parent chain के ज़रिए चुना हुआ snapshot restore करता है। Testcase में `SnapshotId` और generated input bytes (`gen_bytes`) रहते हैं; snapshot manager replay के लिए आवश्यक parent relationship को track करता है।<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu का user-mode `SnapshotModule` mappings और target memory save करता है, लेकिन CPU registers नहीं; ज़रूरत पड़ने पर उन्हें अलग से सुरक्षित रखें। वर्णित manager एक root snapshot tree को support करता है और workers के बीच snapshot IDs share नहीं कर सकता। इसका multi-snapshot mode QASAN shadow state को सीधे reuse भी नहीं कर सकता। Offline triage के लिए, अलग instrumented process में input chain को फिर से बनाएँ। `AsanHostModule` और `DrCovModule` इस्तेमाल करते समय, `fuzzer.evaluate_input` आवश्यक `pre_exec`/`post_exec` callbacks चलाता है; केवल `qemu.run` ऐसा नहीं करता।<sup>[[27]](#references)[[28]](#references)</sup>

### Logical ring-buffer overreads पकड़ें

Buffer की *valid-data count* से आगे का read उसके host allocation के भीतर रह सकता है और सामान्य ASAN से बच सकता है। [libslirp urgent-data example](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) में unsigned byte count underflow भी होता है। Source उपलब्ध होने पर, signed/unsigned integer-overflow instrumentation इस side effect का पता लगा सकता है; reports suppress करने से पहले जानबूझकर किए गए TCP sequence-number wrap को अलग पहचानें। एक अधिक मज़बूत प्रस्तावित oracle यह है कि custom ring allocation को poison करें, उसके internal allocator के आगे बढ़ने पर केवल valid ranges को unpoison करें, और released ranges को फिर से poison करें। LibAFL-Qemu उन targets के लिए ASAN poisoning API देता है जहाँ source instrumentation व्यावहारिक नहीं है।<sup>[[27]](#references)</sup>

## MAccConc के साथ Linux Kernel Race Exploration

[MAccConc](https://github.com/googleprojectzero/MAccConc) timing-sensitive Linux-kernel races को दोहराए जा सकने वाले memory-access schedules में बदलता है। यह दो-context **A-B-A** executions को अपने-आप enumerate कर सकता है या analyst को terminal UI/GUI में order constraints तय करने देता है। यह complete concurrency fuzzer के बजाय experimental research tooling है: वर्तमान में इसे LLVM 23+ और project के patched kernel की आवश्यकता है, command-line tools दो test threads को support करते हैं, और प्रस्तावित userspace fuzzing layer लागू नहीं की गई है।<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication points इकट्ठा करें

KASAN outline callbacks और patched KCOV memory-record support के साथ instrumented kernel build करें। Project README यह भी सुझाता है कि call stacks को उपयोगी बनाए रखने के लिए sibling-call optimization को disable करें।<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) instrument किए गए accesses को helper calls में बदल देता है। MAccConc kernel patches, `asan-opt-same-temp` को disable करते हैं ताकि लगातार होने वाले accesses merge न हों; global-variable races को दिखाना हो, तो `asan-opt-globals` optimization भी disable करें। KCOV इनसे बने records userspace तक पहुँचाता है। अलग-अलग execution contexts के accesses की तुलना करें और उन pairs को रखें जिनकी byte ranges overlap करती हैं और जिनमें कम-से-कम एक side write करती है; `kfree()` को write मानें, ताकि lifetime transitions भी candidates बनें।<sup>[[17]](#references)</sup>

जो काम शुरू करने वाले task से आगे जारी रहता है, जैसे packet processing या RCU callbacks, उसके लिए subsystem को KCOV remote-coverage handle आगे पहुँचाना होगा। Upstream remote KCOV opt-in है और arbitrary background work के लिए अपने-आप उपलब्ध नहीं होता, इसलिए propagation न होने पर कोई वास्तविक interaction दिखाई नहीं दे सकता।<sup>[[17]](#references)[[19]](#references)</sup>

### हर run में उसी dynamic access की पहचान करें

किसी concrete heap address पर replay न करें, जो हर allocation के बाद बदल सकता है; और न ही केवल instruction address पर, जो `memcpy()` और `spin_lock()` जैसे helpers के अंदर अस्पष्ट होता है। MAccConc **count-augmented stack trace** का उपयोग करता है: हर frame में callee और उसके caller के भीतर invocation count की पहचान होती है, और अंतिम element memory-access instruction की पहचान करता है। SanitizerCoverage के function-entry/exit records userspace को इस dynamic identifier को फिर से बनाने देते हैं। यह address में बदलावों और असंबंधित control-flow noise के बावजूद स्थिर रहता है।<sup>[[17]](#references)</sup>

### Candidate pairs को forced schedules में बदलें

Patched `KCOV_SET_DI` ioctl, count-augmented access identifier को shared-flag action से जोड़ता है।<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | चुने हुए access से तुरंत पहले flag *N* सेट करें। |
| `DI_STACK_WAIT` | चुने हुए access से पहले, flag *N* सेट होने तक या configured limit समाप्त होने तक spin करें। |
| `DI_STACK_WAKE_POST` | चुने हुए access के तुरंत बाद flag *N* सेट करें। |

आंशिक **A-happens-before-B** constraint के लिए, A से `DI_STACK_WAKE_POST` और B से उसी flag का उपयोग करने वाला `DI_STACK_WAIT` जोड़ें। पूरी तरह निर्दिष्ट दो-context schedule के लिए, B को blocked शुरू करें, फिर A से B को जगाएँ और पहले transfer point पर wait कराएँ; अगले transfer पर B उलटा operation करे। यह deterministic context switching की तरह काम करता है और automatic A-B-A explorer इसी का उपयोग करता है।<sup>[[17]](#references)</sup>

एक न्यूनतम campaign में four-hook test case (`test_setup`, दो thread functions और `test_end`) को shared library के रूप में compile करें, बिना किसी constraint के trace collect करें, फिर A-B-A candidates enumerate करें या संदिग्ध accesses के आसपास manual constraints जोड़ें।<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts को सफल reorderings से अलग समझें: अनुरोधित order असंभव हो सकता है, क्योंकि कोई lock या initialization/publication dependency दूसरे context को उसके injection point तक पहुँचने से रोकती है। KASAN के blind spots भी ध्यान में रखें: direct stack accesses आमतौर पर hook नहीं होते, जब तक उनके out of bounds होने की आशंका न हो; default optimization में globals को छोड़ दिया जाता है; और मौजूदा compilers ASAN और TSAN hooks एक साथ emit नहीं कर सकते। अंत में, guest के panic होने पर prototype अपना KCOV buffer खो देता है, इसलिए एक स्वतंत्र crash console/oracle बनाए रखें।<sup>[[17]](#references)</sup>

भविष्य के concurrency-guided fuzzing के लिए, प्रति-input या प्रति-syscall memory-access summaries रिकॉर्ड करें, उन operations के जोड़े बनाएँ जो cross-context communication points बनाते, और फिर केवल उन्हीं combinations को explore करें। VM snapshots global state और addresses को स्थिर रखते हैं; snapshots के बिना, allocation-site metadata objects को runs के बीच abstract कर सकता है। यह एक प्रस्तावित extension है, मौजूदा MAccConc userspace tools की feature नहीं।<sup>[[17]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

जब कोई campaign रुक जाता है, तो अक्सर समस्या mutator में नहीं, बल्कि **harness** में होती है। उन functions को खोजने के लिए **reachability/coverage introspection** का उपयोग करें जो statically आपके fuzz target से reachable हैं, लेकिन runtime में बहुत कम या कभी cover नहीं होते। ऐसे functions आमतौर पर तीन में से किसी एक समस्या का संकेत देते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी पूरे feature family की कमी है।
- Target को एक बहुत बड़े “सब कुछ करने वाले” harness के बजाय वास्तव में **दूसरे harness** की ज़रूरत है।

यदि आप OSS-Fuzz / ClusterFuzz-शैली के workflows का उपयोग करते हैं, तो Fuzz Introspector static reachability की तुलना runtime coverage से कर सकता है और timed run या public corpus से reports बना सकता है।<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

इस report का उपयोग करके तय करें कि किसी untested parser path के लिए नया harness जोड़ना है, किसी खास feature के लिए corpus बढ़ाना है, या एक monolithic harness को छोटे entry points में बाँटना है।

## Graph-First Fuzz Target Selection और Mutation Triage

अगर आपके पास पहले से **static-analysis findings**, **mutation-testing survivors** और **coverage reports** हैं, तो उन्हें अलग-अलग सूचियों की तरह triage न करें। पहले **call graph** बनाएँ, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability** और बाहरी findings को annotate करें, फिर graph से जुड़े सवाल पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- untrusted input से कौन-से high-complexity functions तक पहुँचा जा सकता है?
- parsers/handlers से security-critical code तक के paths पर कौन-से mutation survivors हैं?
- कौन-से functions वास्तुशिल्पीय choke points हैं, जिनका **blast radius** असामान्य रूप से बड़ा है?

इससे आम तौर पर केवल "सबसे कम coverage" देखने की तुलना में बेहतर fuzz targets सामने आते हैं। **High complexity** और पुष्टि की गई **external reachability** वाला parser/decoder, कमज़ोर coverage वाले ऐसे isolated internal helper से बेहतर harness candidate है, जिस तक attacker-controlled path न हो।

### Practical triage workflow

1. Codebase से **code graph** बनाएँ और हर function के complexity/branch metrics निकालें।
2. ऐसे **entrypoints** की सूची बनाएँ जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. Entry points से candidate functions तक **path queries** चलाएँ, ताकि reachable attack surface को dead/internal-only code से अलग किया जा सके।
4. उन nodes को प्राथमिकता दें जिनमें ये विशेषताएँ एक साथ हों:
   - high **cyclomatic complexity**
   - untrusted input से पुष्टि की गई **reachability**
   - बड़ा **blast radius** या कई downstream dependents
   - सहायक प्रमाण, जैसे **SARIF** findings, audit notes या mutation survivors
5. सबसे बेहतर score वाले nodes के लिए पहले focused harnesses लिखें, खास तौर पर **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent बनाम actionable

Mutation testing से अक्सर survivors की एक noisy सूची मिलती है। हर survivor को security gap मानने से पहले, graph की मदद से पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths, mutated check से अधिक मज़बूत invariants से constrained हैं?
- क्या node dead code, केवल formatting वाले logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable रहते हैं या संरचनात्मक रूप से constrained होते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को प्रभावित करते हैं, उन्हें आगे बढ़ाकर इनमें शामिल करना चाहिए:

- नए fuzz harnesses
- सीधे property/invariant tests
- लक्षित edge-case vectors

### External findings को graph पर correlate करें

अगर आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर project करें और impact का दायरा समझने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** निकालें
- जाँचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- आस-पास की उन findings को समूहित करें जो एक ही choke point पर केंद्रित होती हैं

यह तय करते समय उपयोगी है कि किसी खास function पर fuzzing का समय लगाना चाहिए या नहीं: **reachable**, **complex**, और पहले से **SAST hits** वाला node अक्सर ऐसे node से बेहतर target होता है जो केवल complex हो, लेकिन उस तक attacker path न हो।

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

महत्वपूर्ण methodology इनका intersection है: **complexity x exposure x impact**। सबसे अधिक अपेक्षित security value वाले fuzz targets चुनने के लिए graph का उपयोग करें, फिर mutation से बचे cases के आधार पर तय करें कि आपके harness को किन boundaries और invariants पर दबाव डालना चाहिए।<sup>[[5]](#references)</sup>

## क्रिप्टोग्राफ़िक key encodings की differential fuzzing

Valid serialized keys या standard test vectors से शुरू करें। Encoded fields को इस तरह mutate करें कि import और operation paths तक पहुँचने के लिए ज़रूरी length और structure न टूटे, फिर वही bytes independent implementations को दें। Acceptance और errors की तुलना करें। Randomized signatures और ciphertexts के लिए byte-for-byte तुलना नहीं, बल्कि correctness oracles चाहिए: signatures verify करें या encapsulation/decapsulation round trip से मिले shared secrets की तुलना करें। Test vectors ज्ञात मामलों के लिए conformance स्थापित करते हैं; differential mutation इनसे परे malformed encodings की जाँच करती है।<sup>[[23]](#references)[[26]](#references)</sup>

इन key formats के लिए format-specific oracles उपयोग करें:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** packed `s1` या `s2` coefficients को `[-η, η]` के बाहर बदलें, लेकिन key को parseable रखें। जाँचें कि import या signing इसे reject करता है या नहीं, और क्या इससे बनी कोई signature verify होती है। केवल acceptance में अंतर standards का उल्लंघन नहीं है, क्योंकि FIPS 204 अतिरिक्त private-key checks अनिवार्य नहीं करता। [conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage) देखें।
- **ML-KEM key pairs:** आवश्यक encapsulation-key और decapsulation-input checks को imported pair पर होने वाले optional pairwise-consistency check (PCT) से अलग जाँचें। इसकी public key से encapsulate करें, private key से decapsulate करें, और shared secrets की तुलना करें; mismatch से encrypted communication टूट सकती है, भले ही अलग-अलग keys input checks पास कर लें। जाँचें कि API inputs को operation के दौरान validate करता है या अलग call के ज़रिए; libcrux `validate_public_key(pk)` और `validate_private_key(sk, ct)` उपलब्ध कराता है, लेकिन ये PCT का विकल्प नहीं हैं।
- **XMSS/XMSSMT raw keys:** केवल in-memory keys से operations करने के बजाय, parameter sets के बीच serialized **signing और verifying** key round trips जाँचें। XMSS और XMSSMT के चार-byte OID namespaces अलग-अलग हैं, इसलिए ऐसा OID-only parser जो पहले XMSS आज़माता है, मिलते-जुलते OID वाली XMSSMT key को गलत वर्गीकृत कर सकता है और import reject कर सकता है। रिपोर्ट किया गया RustCrypto parser interoperability/availability failure दिखाता है, signature forgery नहीं।

## gosentry के साथ Go Fuzzing: बेहतर Engine, Typed Inputs और Differential Checks

अगर किसी Go target में पहले से native `testing.F` harness है, तो उसे चलाने का एक व्यावहारिक upgrade path [gosentry](https://github.com/trailofbits/gosentry) का उपयोग करना है—यह एक forked Go toolchain है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

यह तब उपयोगी होता है जब native Go fuzzer **कठिन comparisons**, **typed inputs**, या **parser-heavy formats** पर अटक जाता है। कार्यप्रणाली वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का इस्तेमाल करते रहें।
- उसी harness का फिर से इस्तेमाल करें, लेकिन उसे stock toolchain के बजाय gosentry के `go` binary के साथ चलाएँ।
- इस campaign को सामान्य coverage-guided run की तरह लें, लेकिन इसमें LibAFL scheduling/mutation और आसपास के बेहतर detectors का लाभ मिलता है।

### खामोश failures को fuzz findings में बदलें

Go assessments में एक आम समस्या यह है कि खतरनाक व्यवहार अक्सर डिफ़ॉल्ट रूप से **crash नहीं करता**। gosentry के साथ, आप “खराब लेकिन खामोश” स्थितियों की कई श्रेणियों को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` से चुने गए logging/error paths को crashes की तरह व्यवहार करने के लिए सेट करें (यह `log.Fatal`-style code paths के लिए उपयोगी है, जो अन्यथा केवल log करते हैं और चलते रहते हैं)।
- `--catch-races=true` से नए खोजे गए queue entries को Go race detector के साथ दोबारा चलाएँ।
- `--catch-leaks=true` से नए queue entries को `goleak` के साथ दोबारा चलाएँ और goroutine leaks मिलने पर रोक दें।
- LibAFL hang handling का इस्तेमाल करके **infinite loops / बहुत धीमे inputs** को timeouts के रूप में गायब होने देने के बजाय fuzz findings के रूप में रखें।
- डिफ़ॉल्ट रूप से built-in arithmetic overflow checks, साथ ही go-panikint-style instrumentation के ज़रिए वैकल्पिक truncation checks।

यह उन targets के लिए विशेष रूप से उपयोगी है जहाँ security impact memory corruption के बजाय **panicless parser failure**, **concurrency bug**, या केवल **DoS वाला hang** हो।

### Typed Go APIs के लिए struct-aware fuzzing

Native Go fuzzing मुख्य रूप से `[]byte`, `string`, और numbers जैसे scalars की अपेक्षा करता है। अगर test के तहत code typed objects का इस्तेमाल करता है, तो gosentry bytes को अंदरूनी तौर पर mutate करते हुए सीधे **composite values** (structs, slices, arrays, pointers) को fuzz कर सकता है।<sup>[[7]](#references)[[8]](#references)</sup>

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

Fuzzing के लिए fake wire format बनाते समय इसका उपयोग करें, ताकि harness-only parsing code के पीछे logic bugs छिप न जाएँ। Differential या grammar-based campaigns के लिए, harness input को एक single `[]byte` या `string` रखें और इसके बजाय callback के अंदर parse करें।

### Parsers और protocol inputs के लिए grammar-based fuzzing

Parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules का एक JSON array होता है, और harness को आमतौर पर एक single `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- जब byte-level mutations शुरुआती syntax checks में ही ज़्यादातर विफल हो जाएँ, तो grammar mode का उपयोग करें।
- Grammar को पूरी specification का मॉडल बनाने के बजाय भाषा/प्रोटोकॉल के **security-relevant subset** तक सीमित रखें।
- Integer, length और state-machine की सीमाओं को stress करने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अब भी **bytes/strings** ही मिलते हैं, इसलिए parsing और semantic checks harness किए गए code के भीतर ही होते हैं।

### Differential fuzzing: सिर्फ crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक मज़बूत तरीका **grammar-based differential fuzzing** है: valid structured inputs generate करें और उन्हें दो parsers, clients या state-transition engines को दें।<sup>[[7]](#references)[[8]](#references)</sup>

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

- एक implementation panic करता है, जबकि दूसरा साफ़ तौर पर अस्वीकार करता है
- स्वीकार/अस्वीकार किए गए inputs में बेमेल
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में अंतर

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing से अक्सर नहीं खोजा जा सकता।

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage रिपोर्टिंग के लिए campaign corpus का पुनः उपयोग करें

Campaign के बाद, अलग corpus को manually export किए बिना Go coverage रिपोर्ट बनाने के लिए सहेजे गए queue corpus को फिर से चलाएँ।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

उसी package से और उसी `-fuzz` target के साथ command चलाएँ, ताकि gosentry सही cached campaign state को resolve करे।

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing की गहराई में](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet के पाँच साल बाद: Coverage-Guided Protocol Fuzzing पर](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark कोड को graphs में बदलता है](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing में toolkit का आधा हिस्सा नहीं था। इसे ठीक करने के लिए हमने toolchain fork किया।](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots का उपयोग करके Stateful Network Protocols के लिए Fast Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [कोई Grammar नहीं, कोई समस्या नहीं: System-Call Descriptions के बिना Linux Kernel को Fuzz करने की दिशा में](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive और Mutable Snapshots के साथ Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path और caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build और regression-seed documentation](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Controlled Memory-Access Interleavings के साथ Linux Kernel Race Conditions की पड़ताल](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing के लिए code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Extended Filename Syntax](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Extended Filename Syntax की Fuzzing: 16 Memory-Safety Vulnerabilities और Codex-Assisted Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Cryptography के लिए Differential fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID parsing bug - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Post-Quantum Cryptography Implementations की स्थिति](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [CVE-2026-9539 तक पहुँचने के लिए Snapshotting](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
