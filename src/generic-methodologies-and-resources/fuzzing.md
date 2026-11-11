# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** में inputs को mutate किया जाता है और साथ ही उन्हें **grammar-valid** रखा जाता है। Coverage-guided mode में केवल वे samples corpus seeds के रूप में सहेजे जाते हैं जो **new coverage** trigger करते हैं। **language targets** (parsers, interpreters, engines) के लिए इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** की ज़रूरत होती है, जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds ढूँढता है जो अलग-अलग `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow को बनाए नहीं रखता**। इसलिए “closer-to-bug” sample को छोड़ दिया जाता है, क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** के साथ, random recombination महँगा हो जाता है और coverage feedback search को दिशा नहीं देता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए **mutational और generative phases को hybridize करने** या generation को **function chaining** patterns की ओर bias करने पर विचार करें (सिर्फ coverage पर नहीं)।<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होता है: new-coverage sample तुरंत सहेज लिया जाता है, जिसमें अक्सर बड़े unchanged regions बने रहते हैं। समय के साथ corpora में कम structural diversity वाले **near-duplicates** भर जाते हैं। Aggressive minimization उपयोगी context हटा सकता है, इसलिए एक व्यावहारिक समझौता है **grammar-aware minimization**, जो **minimum token threshold के बाद रुक जाता है** (शोर कम करते हुए इतना आसपास का structure बनाए रखता है कि mutations प्रभावी रहें)।<sup>[[1]](#references)</sup>

Mutational fuzzing के लिए corpus का एक व्यावहारिक नियम है: near-duplicates के बड़े ढेर के बजाय **ऐसे structurally different seeds का छोटा समूह चुनें जो coverage को अधिकतम करे**। आम तौर पर इसका मतलब है कि निम्नलिखित करें।<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world samples** से शुरुआत करें (public corpora, crawling, captured traffic, target ecosystem के file sets)।
- हर valid sample को रखने के बजाय **coverage-based corpus minimization** से उन्हें छाँटें।
- Seeds को इतना **छोटा रखें** कि mutations सार्थक fields पर हों, न कि ज़्यादातर cycles अप्रासंगिक bytes पर खर्च हों।
- बड़े harness/instrumentation बदलावों के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Large generated programs and timeout bias

Compiler और interpreter fuzzing में, किसी input को नया parser branch पार करने के बजाय **generated-code size threshold** पार करना पड़ सकता है। V8 के [exception-handler offset example](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size) में, truncated handler offset के मायने रखने से पहले एक valid testcase को 256 MiB से अधिक bytecode की ज़रूरत थी। बार-बार `yield*` constructs इस्तेमाल करके उस सीमा तक पहुँचा जा सकता था, लेकिन debug build पर testcase compile करने में कुछ सेकंड लगते थे। छोटे inputs को प्राथमिकता और कम execution timeouts इस तरह के cases को नज़रअंदाज़ कर सकते हैं, भले ही grammar coverage अधिक हो। Packed offsets या अन्य length-sensitive metadata का audit करते समय, size thresholds और timeout policy पर अलग-अलग विचार करें; यह campaign advice बताए गए failure mode से निकाला गया निष्कर्ष है।<sup>[[29]](#references)</sup>

## Comparison-Aware Mutation For Magic Values

Fuzzers के एक स्तर पर अटक जाने की आम वजह syntax नहीं, बल्कि **hard comparisons** होती हैं: magic bytes, length checks, enum strings, checksums या parser dispatch values, जिन्हें `memcmp`, switch tables या cascaded comparisons से जाँचा जाता है। Pure random mutation में इन values का byte-by-byte अनुमान लगाने की कोशिश में cycles बर्बाद होते हैं।

ऐसे targets के लिए **comparison tracing** का इस्तेमाल करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows), ताकि fuzzer failed comparisons के operands देख सके और mutations को उन्हें संतुष्ट करने वाली values की ओर bias कर सके।<sup>[[3]](#references)</sup>

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
- इसे वास्तविक samples, protocol specs, या debug logs से निकाले गए **dictionaries** के साथ इस्तेमाल करें। Grammar tokens, chunk names, verbs, और delimiters वाला छोटा dictionary अक्सर विशाल generic wordlist से अधिक उपयोगी होता है।
- यदि target कई sequential checks करता है, तो सबसे पहले शुरुआती “magic” comparisons हल करें और फिर बने corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## Filename Language छिपाने वाले File APIs की Fuzzing

`filename`, `path`, या `URL` नाम वाला parameter, literal file lookup के बजाय interpreter का entry point हो सकता है। उदाहरण के लिए, CFITSIO Extended Filename Syntax (EFS) खुले गए object को लौटाने से पहले bracketed selectors, row/pixel expressions, calculated columns, histograms, और transformations को evaluate करता है; कुछ forms temporary copies भी बनाते हैं। Attack-surface mapping के दौरान, हर open/import API को **literal-path** या **interpreted-path** के रूप में वर्गीकृत करें, फिर उस production entry point को fuzz करें जिसे applications वास्तव में call करती हैं।<sup>[[20]](#references)[[22]](#references)</sup>

इससे मिलने वाले SSRF, file-copy, और protocol-handler primitives—और अधिक सुरक्षित literal-path APIs—के लिए देखें [SSRF/file primitives के रूप में Filename mini-languages](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)।<sup>[[20]](#references)</sup>

### Backing object को fuzz किए जा रहे program से अलग रखें

जब grammar filename suffix में हो, तो केवल संदर्भित file के bytes को mutate करने से parser छूट जाता है। इसके बजाय, एक छोटा harness हर testcase को string के रूप में पढ़कर interpreted open API को दे सकता है; CFITSIO campaign ने read-only mode में `fits_open_file()` call करके अधिकांश EFS parsers और evaluators तक पहुँच बनाई। Valid backing files को अलग से उपलब्ध रखें, ताकि mutations लगातार base path को तोड़ने के बजाय selector/expression language पर केंद्रित रहें।<sup>[[22]](#references)</sup>

ऐसे seeds इस्तेमाल करें जिनमें से हर एक अलग grammar family तक पहुँचे, फिर specification और lexer/parser source—दोनों से एक compact dictionary तैयार करें। यदि coverage एक ही syntax-error path में बार-बार विफल होने वाले inputs के साथ plateau पर पहुँच जाए, तो केवल random-mutation का समय बढ़ाने के बजाय valid prefixes सुरक्षित रखें और delimiters, operators, keywords, function names, तथा प्रतिनिधि field names जोड़ें।<sup>[[22]](#references)</sup>

उदाहरण के लिए, grammar dictionary के साथ harness चलाएँ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness के side effects सीमित करें

Library का read-only flag side-effect-free testcase की गारंटी नहीं देता: filename language इनपुट को फिर से लिख सकती है, output files बना सकती है, या अस्थायी objects को materialize कर सकती है। CFITSIO campaign ने शुरुआत में seed files नष्ट कर दीं और filesystem में अनपेक्षित files छोड़ दीं, इसलिए cleanup और isolation आवश्यक थे।<sup>[[22]](#references)</sup>

- हर worker को एक disposable working directory और private temporary directory दें।
- Canonical backing files की copies उपलब्ध कराएँ; target को corpus की एकमात्र copy कभी mutate न करने दें।
- जब तक remote backends लक्ष्य न हों, network access बंद रखें और container, mount namespace या equivalent sandbox से writable paths सीमित करें।
- हर execution या worker batch के बाद directory reset करें और filesystem में हुए अनपेक्षित बदलावों को अतिरिक्त findings मानें।

### Crash-to-patch-to-fuzz loop

Repair से पहले crashes को cluster करें, ताकि हज़ारों artifacts हज़ारों patch tasks न बन जाएँ। CFITSIO assessment में AFLTriage ने शुरुआती crash set को कुछ root causes तक सीमित किया; नतीजे में आए advisory में अलग-अलग failures दिखे, जिनमें destination-size की गलत checks, `realloc()` के बाद stale pointers, arithmetic faults, और unsafe parser cleanup paths शामिल हैं।<sup>[[21]](#references)[[22]](#references)</sup>

1. हर cluster के लिए एक representative input को minimize करें और उसे AddressSanitizer के अंतर्गत reproduce करें।
2. ठीक उस failing access, source location, allocation/free history, और उस parser state को दर्ज करें जिसने invariant को false बनाया।
3. एक narrowly scoped candidate patch लागू करें और उसी coverage तथा sanitizer instrumentation के साथ rebuild करें।
4. मूल reproducer **और उसके cluster के हर input** को फिर से चलाएँ; leak detection भी सक्षम करें, क्योंकि memory-safety fix error path में ownership तोड़ सकता है।
5. असली files के साथ functional tests चलाएँ, फिर संचित queue से आगे बढ़ें (या binary बदलने के बाद engine को नया output directory चाहिए तो उस queue को फिर से import करें)।
6. दोहराएँ: पहला shallow crash हटाने से अक्सर मौजूदा seeds को parser की किसी गहरी state तक पहुँचने का मौका मिलता है।

LLM step 2 को तेज़ कर सकता है और step 3 का draft दे सकता है, बशर्ते उसे crashing input, sanitizer report, harness और संबंधित source मिले; लेकिन उसका patch अविश्वसनीय ही माना जाना चाहिए। Repair स्वीकार करना है या नहीं, यह sanitizer replay और regression gates तय करते हैं—model की व्याख्या नहीं।<sup>[[22]](#references)</sup>

## जब Edge Coverage अलग-अलग Paths में अंतर नहीं कर पाती, तब बेहतर Feedback

सामान्य edge coverage उन दो executions में अंतर नहीं कर सकती जो अलग-अलग callers के ज़रिए उसी helper से गुजरते हैं या किसी function के भीतर branch के अलग-अलग combinations लेते हैं। Shared decoders, protocol dispatchers और interpreter helpers में यह मायने रखता है, जहाँ किसी edge तक पहुँचने वाला **route** live state तय करता है। हर calling context को सीधे track करना भी जोखिम भरा है: coverage map और queue बहुत बड़ी हो सकती है। इसलिए context-sensitive fuzzing research पूरे call graph को context-sensitive मानने के बजाय केवल आशाजनक contexts को refine करने की सलाह देती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds सामान्य edge coverage के अलावा **Ball-Larus per-function path coverage** देते हैं। यह function के हर acyclic path को एक feature देता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations में अंतर करता है, लेकिन **loop iteration counts में नहीं**। Relaxed level `1` से शुरू करें, फिर सख्त modes को केवल संदिग्ध parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या घातांकीय रूप से बढ़ सकती है।<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

कई security-relevant जगहों से कॉल किए जाने वाले helper के लिए, LTO mode हर function path को उसके तत्काल call site के साथ जोड़ सकता है:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** अधिक समृद्ध feedback का उपयोग सावधानी से करें और इसके coverage-map/queue cost की निगरानी करें।<sup>[[13]](#references)[[14]](#references)</sup>

- एक साधारण edge-coverage instance समानांतर में चलाएँ; अधिक समृद्ध feedback तभी उपयोगी है, जब अतिरिक्त queue/map cost से executions per second कम न हों।
- यदि बड़ी template-heavy libraries या generic utility code map पर हावी हों, तो path/caller instrumentation सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- बहुत अधिक acyclic paths वाले functions को AFL++ छोड़ सकता है; compilation के दौरान warnings इस बात का संकेत हैं कि target को allowlisting या कम सख्त level की ज़रूरत है।
- Caller + path coverage केवल एक caller depth का समर्थन करता है। इसे अधिक गहरे context stacks के साथ न मिलाएँ।
- Path IDs LLVM के major versions के बीच बदल सकते हैं। किसी campaign के दौरान toolchain को स्थिर रखें और PATH-based corpora को ऐसे synchronize न करें, मानो उनके feature IDs सभी builds में स्थिर हों।
- यह feedback `CMPLOG` का पूरक है: comparison tracing हल करता है कि **कौन-सी value guard को पार करती है**, जबकि path/caller feedback यह बनाए रखता है कि **कौन-सा route और branch combination वहाँ तक पहुँचा**।

## Stateful Fuzzing: Sequences ही Seeds हैं

**Protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए अक्सर दिलचस्प इकाई कोई एक blob नहीं, बल्कि **message sequence** होती है। पूरे transcript को एक file में जोड़कर बिना सोचे-समझे mutate करना आम तौर पर अक्षम होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है, जबकि अक्सर केवल बाद का message ही fragile state तक पहुँचता है।<sup>[[4]](#references)</sup>

एक अधिक प्रभावी तरीका है **sequence को ही seed** मानना और **observable state** (response codes, protocol states, parser phases, लौटाए गए object types) को अतिरिक्त feedback के रूप में उपयोग करना।<sup>[[4]](#references)</sup>

- **Valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- यदि अगला step पिछली responses पर निर्भर हो, तो उनसे मिले identifiers और server-generated values को cache करें।
- पूरे serialized transcript को opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol अर्थपूर्ण response codes देता है, तो अधिक गहराई तक पहुँचने वाली sequences को प्राथमिकता देने के लिए उन्हें **सस्ते state oracle** के रूप में उपयोग करें।

इसी कारण authenticated bugs, hidden transitions, या “केवल handshake के बाद” वाले parser bugs अक्सर vanilla file-style fuzzing से छूट जाते हैं: fuzzer को केवल structure नहीं, बल्कि **order, state, और dependencies** भी बनाए रखनी चाहिए।<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

उच्च edge coverage के बावजूद IPC-driver bugs छूट सकते हैं, क्योंकि coverage **object ownership, reference counts, pending messages, cleanup order, या thread interleavings** का वर्णन नहीं करती। [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) पेज driver object model को कवर करता है; यह उदाहरण fuzzer harness पर केंद्रित है। Android Binder एक उपयोगी मॉडल है: allocation और free paths, दोनों तक पहुँचना पर्याप्त नहीं है, यदि fuzzer कई processes से एक ही kernel object पर अपेक्षित क्रम में काम नहीं करवा सकता।<sup>[[15]](#references)</sup>

#### अलग-अलग `ioctl` buffers नहीं, protocol को model करें

एक test case को **client identity + operation + structured arguments** की ordered grammar के रूप में दर्शाएँ। Binder LKL fuzzer protobuf और `libprotobuf-mutator` का उपयोग करता है, जिसमें एक persistent context-manager client और दो सामान्य clients होते हैं। फिर semantic harness उन relationships को बनाए रखता है जिन्हें blind byte mutation नष्ट कर देती।<sup>[[15]](#references)</sup>

- पहले के operations से लौटे values को cache करें। उदाहरण के लिए, `BC_FREE_BUFFER` को पिछले `ioctl` से मिला transaction-buffer pointer दोबारा उपयोग करना चाहिए।
- Valid default replies बनाएँ, ताकि synchronous transactions पूरे हो सकें और बाद के operations तक पहुँचा जा सके।
- असंभव transitions को अस्वीकार करें, जैसे self-transactions या एक ही target के लिए कई pending transactions।
- Singleton bootstrap state को per-input reset के बाहर रखें। Binder प्रति boot केवल एक `BINDER_SET_CONTEXT_MGR` registration की अनुमति देता है, इसलिए उस client को बार-बार नष्ट करके फिर से बनाने से बाद के inputs invalid हो जाएँगे।

Lifetime-race का एक उपयोगी template यह है कि एक client से object transfer करवाएँ, thread या process cleanup शुरू करें, और साथ ही receiving client से transaction buffer release करवाएँ। CVE-2020-0423 उदाहरण में, `BINDER_TYPE_WEAK_BINDER` transfer के बाद `BINDER_THREAD_EXIT` का `BC_FREE_BUFFER` के साथ race करना embedded `binder_work` को free कर सकता था, जबकि exiting thread का cleanup path अभी भी उसका उपयोग कर रहा था।<sup>[[15]](#references)</sup>

#### userspace kernel में नियंत्रित interleavings फिर से लाएँ

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) वास्तविक kernel code को userspace harness में link करता है और `lkl_syscall` के ज़रिए उसका syscall interface उपलब्ध कराता है। इससे protobuf state, coverage, और KASAN को एक ही process में समन्वित करना आसान हो जाता है। हालाँकि, LKL आम तौर पर किसी syscall के दौरान दूसरे kernel thread को बीच में आने नहीं देता। Race campaigns के लिए, चुने हुए lock/unlock और lifetime boundaries के आसपास `schedule()` points जोड़ें, फिर हर yield पर harness को अगला client बेतरतीब ढंग से चुनने दें। इन points को लक्षित रखें, क्योंकि हर point scheduling search space को कई गुना बढ़ा देता है। शोधकर्ताओं द्वारा वर्णित randomized scheduler upstream Binder fuzzer का हिस्सा **नहीं** है।<sup>[[15]](#references)</sup>

#### Serialized regression seeds बनाएँ और replay करें

Upstream harness एक compatible `libprotobuf-mutator` version को pin करता है, `LKL_FUZZING=1` के साथ LKL fuzzing instrumentation और KASAN सक्षम करता है, और Binder के लिए `MMU=1` के साथ `CONFIG_MMU` सक्षम करता है।<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

अपस्ट्रीम में documented rollback patches लागू करने या जानबूझकर vulnerable revision को checkout करने के बाद, एक serialized seed ad-hoc C proof of concept में इसे फिर से बनाए बिना पूरे multi-client state transition को दोहरा सकता है:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

परिणामी KASAN use-after-free को इस बात की पुष्टि मानें कि seed vulnerable lifetime path तक पहुँचा। यह kernel code execution या privilege escalation के लिए आवश्यक बाद के primitives को प्रदर्शित **नहीं** करता।<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty** और **coverage reuse** को मिलाने का एक व्यावहारिक तरीका है कि persistent server के सामने कम समय तक चलने वाले workers को बार-बार restart किया जाए। हर worker खाली corpus से शुरू होता है, `T` सेकंड बाद sync करता है, संयुक्त corpus पर अगले `T` सेकंड तक चलता है, फिर दोबारा sync करके बाहर निकल जाता है। इससे संचित coverage का लाभ लेते हुए भी हर generation में **नए structures** मिलते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

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

**Notes:**

- `-in empty` हर generation में **नया corpus** सुनिश्चित करता है।
- `-server_update_interval T` **delayed sync** का अनुमान देता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync डिफ़ॉल्ट रूप से skip होता है** (`-skip_initial_server_sync` की ज़रूरत नहीं)।
- Optimal `T` **target पर निर्भर करता है**; worker द्वारा ज़्यादातर “easy” coverage खोज लेने के बाद switching करना आमतौर पर सबसे अच्छा रहता है।

## Hard-To-Harness Targets के लिए Snapshot Fuzzing

जब आप जिस code को test करना चाहते हैं, वह केवल **बड़े setup cost** के बाद reachable होता है (VM boot करना, login पूरा करना, packet receive करना, container parse करना, service initialize करना), तो एक उपयोगी विकल्प **snapshot fuzzing** है: तैयार process या VM state capture करें, हर test case को target input path में inject करें, crash/timeout तक execute करें और snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने की ज़रूरत नहीं पड़ती। यह **network services**, **firmware**, **post-auth attack surfaces** और **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ, जब तक इच्छित state तैयार न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, अगर समर्थित हो तो केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को यथासंभव उस पहले महँगे parse/dispatch step के करीब रखें, जैसे `recv`/`read` के बाद या packet-deserialization point पर, और target द्वारा इस्तेमाल किए गए input buffer को record करें। यह adaptive-placement principle का पालन करता है: काम को दोहराने से बचने के लिए snapshot को input processing में और आगे ले जाएँ।<sup>[[11]](#references)</sup>

### Protocol states के लिए Incremental snapshots

एक fixed snapshot setup cost से बचाता है, लेकिन अपने-आप उन transitions को explore नहीं करता जिनके लिए कई valid messages की ज़रूरत होती है। LibAFL-Qemu harness, protocol-state field में writes पर नज़र रख सकता है और state बदलने पर नया snapshot save कर सकता है। [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) में, यह `tcpcb.t_state` पर नज़र रखता है, snapshots deduplicate करने के लिए state और response flags को hash करता है, और parent के सापेक्ष dirty pages store करता है। अगला structured message mutate करने से पहले, यह parent chain के ज़रिए चुना हुआ snapshot restore करता है। Testcase में `SnapshotId` और generated input bytes (`gen_bytes`) होते हैं; snapshot manager replay के लिए आवश्यक parent relationship track करता है।<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu का user-mode `SnapshotModule` mappings और target memory save करता है, लेकिन CPU registers नहीं; ज़रूरत पड़ने पर उन्हें अलग से preserve करें। वर्णित manager एक root snapshot tree को support करता है और workers के बीच snapshot IDs share नहीं कर सकता। इसका multi-snapshot mode QASAN shadow state को सीधे reuse भी नहीं कर सकता। Offline triage के लिए, एक अलग instrumented process में input chain को reconstruct करें। `AsanHostModule` और `DrCovModule` का इस्तेमाल करने पर, `fuzzer.evaluate_input` आवश्यक `pre_exec`/`post_exec` callbacks चलाता है; केवल `qemu.run` ऐसा नहीं करता।<sup>[[27]](#references)[[28]](#references)</sup>

### Logical ring-buffer overreads पकड़ें

Buffer की *valid-data count* से आगे का read, host allocation के अंदर ही रह सकता है और सामान्य ASAN से बच सकता है। [libslirp urgent-data example](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) में unsigned byte count underflow भी होता है। Source उपलब्ध होने पर, signed/unsigned integer-overflow instrumentation इस side effect का पता लगा सकता है; reports suppress करने से पहले जानबूझकर होने वाले TCP sequence-number wrap को अलग पहचानें। एक अधिक मजबूत प्रस्तावित oracle है कि custom ring allocation को poison करें, उसके internal allocator के आगे बढ़ने पर केवल valid ranges को unpoison करें, और released ranges को फिर से poison करें। LibAFL-Qemu उन targets के लिए ASAN poisoning API देता है जहाँ source instrumentation व्यावहारिक नहीं है।<sup>[[27]](#references)</sup>

## MAccConc के साथ Linux Kernel Race Exploration

[MAccConc](https://github.com/googleprojectzero/MAccConc), timing-sensitive Linux-kernel races को repeatable memory-access schedules में बदलता है। यह दो-context **A-B-A** executions को अपने-आप enumerate कर सकता है या analyst को terminal UI/GUI में order constraints लगाने देता है। यह complete concurrency fuzzer के बजाय experimental research tooling है: इसे फ़िलहाल LLVM 23+ और project के patched kernel की ज़रूरत है, command-line tools दो test threads support करते हैं, और प्रस्तावित userspace fuzzing layer implement नहीं की गई है।<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication points इकट्ठा करें

KASAN outline callbacks और patched KCOV memory-record support के साथ instrumented kernel build करें। Project README यह भी सुझाता है कि call stacks को उपयोगी बनाए रखने के लिए sibling-call optimization disable करें।<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) instrumented accesses को helper calls में बदल देता है। MAccConc kernel patches, लगातार होने वाले accesses को merge होने से रोकने के लिए `asan-opt-same-temp` को disable करते हैं; जब global-variable races को दिखाई देना ज़रूरी हो, तो `asan-opt-globals` optimization को भी disable करें। KCOV से बने हुए records userspace तक पहुँचते हैं। अलग-अलग execution contexts के accesses की तुलना करें और उन pairs को रखें जिनकी byte ranges overlap करती हैं और जिनमें कम-से-कम एक तरफ़ write होता है; lifetime transitions को भी candidate बनाने के लिए `kfree()` को write मानें।<sup>[[17]](#references)</sup>

शुरू करने वाले task से बाहर जाने वाले काम, जैसे packet processing या RCU callbacks, के लिए subsystem को KCOV remote-coverage handle आगे पहुँचाना होगा। Upstream remote KCOV opt-in है और arbitrary background work के लिए अपने-आप उपलब्ध नहीं होता, इसलिए propagation न होने पर कोई वास्तविक interaction दिखाई नहीं दे सकता।<sup>[[17]](#references)[[19]](#references)</sup>

### हर run पर उसी dynamic access की पहचान करें

किसी concrete heap address पर replay न करें, क्योंकि हर allocation के बाद वह बदल सकता है; न ही केवल instruction address पर replay करें, क्योंकि `memcpy()` और `spin_lock()` जैसे helpers के अंदर वह अस्पष्ट होता है। MAccConc **count-augmented stack trace** का उपयोग करता है: हर frame में callee और उसके caller के भीतर invocation count की पहचान होती है, और अंतिम element memory-access instruction की पहचान करता है। SanitizerCoverage के function-entry/exit records userspace को इस dynamic identifier को फिर से बनाने देते हैं। यह address में बदलाव और असंबंधित control-flow noise के बावजूद स्थिर रहता है।<sup>[[17]](#references)</sup>

### Candidate pairs को forced schedules में बदलें

Patched `KCOV_SET_DI` ioctl, count-augmented access identifier को shared-flag action से जोड़ता है।<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | चुने गए access से ठीक पहले flag *N* सेट करें। |
| `DI_STACK_WAIT` | चुने गए access से पहले, flag *N* सेट होने तक या configured limit समाप्त होने तक spin करें। |
| `DI_STACK_WAKE_POST` | चुने गए access के ठीक बाद flag *N* सेट करें। |

आंशिक **A-happens-before-B** constraint के लिए, उसी flag का उपयोग करते हुए A पर `DI_STACK_WAKE_POST` और B पर `DI_STACK_WAIT` जोड़ें। पूरी तरह निर्दिष्ट two-context schedule के लिए, B को blocked शुरू करें, फिर A से B को wake करवाएँ और पहले transfer point पर wait करवाएँ; अगले transfer पर B उलटा operation करता है। यह deterministic context switching जैसा काम करता है और automatic A-B-A explorer इसी का उपयोग करता है।<sup>[[17]](#references)</sup>

एक न्यूनतम campaign में four-hook test case (`test_setup`, दो thread functions और `test_end`) को shared library के रूप में compile करें, बिना किसी constraint के trace collect करें, फिर A-B-A candidates enumerate करें या संदिग्ध accesses के आसपास manual constraints जोड़ें।<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts को सफल reorderings से अलग समझें: मांगा गया order असंभव हो सकता है, क्योंकि कोई lock या initialization/publication dependency दूसरे context को उसके injection point तक पहुँचने से रोकती है। KASAN के blind spots का भी ध्यान रखें: direct stack accesses आमतौर पर hook नहीं होते, जब तक उनके out of bounds होने की संभावना न हो; default optimization के साथ globals छूट जाते हैं; और मौजूदा compilers ASAN और TSAN hooks एक साथ emit नहीं कर सकते। अंत में, guest के panic होने पर prototype अपना KCOV buffer खो देता है, इसलिए एक स्वतंत्र crash console/oracle बनाए रखें।<sup>[[17]](#references)</sup>

भविष्य के concurrency-guided fuzzing के लिए, हर input या syscall के memory-access summaries रिकॉर्ड करें, उन operations के pairs बनाएँ जो cross-context communication points बनाते हों, और फिर सिर्फ़ उन्हीं combinations को explore करें। VM snapshots global state और addresses को स्थिर रखते हैं; snapshots के बिना, allocation-site metadata का उपयोग करके अलग-अलग runs में objects को abstract किया जा सकता है। यह एक प्रस्तावित extension है, मौजूदा MAccConc userspace tools का feature नहीं।<sup>[[17]](#references)</sup>

## Harness Introspection: उथले fuzzers की जल्दी पहचान करें

जब कोई campaign रुक जाए, तो समस्या अक्सर mutator में नहीं, बल्कि **harness** में होती है। ऐसे functions खोजने के लिए **reachability/coverage introspection** का उपयोग करें जो आपके fuzz target से statically reachable हैं, लेकिन runtime पर कम या बिल्कुल cover नहीं होते। ऐसे functions आमतौर पर तीन में से किसी एक समस्या की ओर इशारा करते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी पूरे feature family का अभाव है।
- Target को वास्तव में एक बहुत बड़े “सब कुछ करने वाले” harness के बजाय **दूसरे harness** की ज़रूरत है।

अगर आप OSS-Fuzz / ClusterFuzz-style workflows का उपयोग करते हैं, तो Fuzz Introspector static reachability की तुलना runtime coverage से कर सकता है और timed run या public corpus से reports बना सकता है।<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

रिपोर्ट का उपयोग करके तय करें कि किसी ऐसे parser path के लिए नया harness जोड़ना है जिसका परीक्षण नहीं हुआ है, किसी खास feature के लिए corpus का विस्तार करना है, या एक monolithic harness को छोटे entry points में बाँटना है।

## Graph-First Fuzz Target Selection और Mutation Triage

अगर आपके पास **static-analysis findings**, **mutation-testing survivors**, और **coverage reports** पहले से हैं, तो उन्हें अलग-अलग सूचियों की तरह triage न करें। पहले **call graph** बनाएँ, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, और बाहरी findings को annotate करें, फिर graph से जुड़े सवाल पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- Untrusted input से कौन-से high-complexity functions तक पहुँचा जा सकता है?
- कौन-से mutation survivors, parsers/handlers से security-critical code तक जाने वाले paths पर मौजूद हैं?
- किन functions की architecture में choke point की भूमिका है और उनका **blast radius** असामान्य रूप से बड़ा है?

इससे आम तौर पर "सबसे कम coverage" पर ही ध्यान देने की तुलना में बेहतर fuzz targets सामने आते हैं। **High complexity** और पुष्ट **external reachability** वाला parser/decoder, कमज़ोर coverage वाले ऐसे isolated internal helper से बेहतर harness candidate है जिसके path पर attacker का नियंत्रण नहीं है।

### व्यावहारिक triage workflow

1. Codebase से **code graph** बनाएँ और हर function के complexity/branch metrics निकालें।
2. ऐसे **entrypoints** की सूची बनाएँ जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. Candidate functions तक इन entrypoints से **path queries** चलाएँ, ताकि reachable attack surface को केवल dead/internal code से अलग किया जा सके।
4. उन nodes को प्राथमिकता दें जिनमें ये बातें एक साथ हों:
   - high **cyclomatic complexity**
   - untrusted input से **reachability** की पुष्टि
   - बड़ा **blast radius** या कई downstream dependents
   - समर्थन देने वाले साक्ष्य, जैसे **SARIF** findings, audit notes, या mutation survivors
5. सबसे अच्छे score वाले nodes के लिए पहले focused harnesses लिखें, खासकर **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent बनाम actionable

Mutation testing से अक्सर noisy survivor list मिलती है। हर survivor को security gap मानने से पहले, graph का उपयोग करके पूछें:

- क्या mutated function तक attacker-controlled entrypoint से पहुँचा जा सकता है?
- क्या सभी call paths, mutated check से ज़्यादा मज़बूत invariants से constrained हैं?
- क्या node dead code, केवल formatting वाले logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable या संरचनात्मक रूप से constrained रहते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को प्रभावित करते हैं, उन्हें इनमें शामिल करना चाहिए:

- नए fuzz harnesses
- सीधे property/invariant tests
- लक्षित edge-case vectors

### बाहरी findings को graph पर correlate करें

अगर आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर project करें और impact बढ़ाकर देखने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** निकालें
- जाँचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- आस-पास की उन findings को समूहित करें जो एक ही choke point पर आकर मिलती हैं

किसी खास function पर fuzzing का समय लगाने का निर्णय लेते समय यह उपयोगी है: जो node **reachable**, **complex**, और पहले से **SAST hits** वाला हो, वह अक्सर ऐसे node से बेहतर target होता है जो केवल complex हो, लेकिन attacker path पर न हो।

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

महत्वपूर्ण methodology इनका प्रतिच्छेदन है: **complexity x exposure x impact**। सबसे अधिक अपेक्षित security value वाले fuzz targets चुनने के लिए graph का उपयोग करें, फिर mutation survivors के आधार पर तय करें कि आपके harness को किन boundaries और invariants पर तनाव डालना चाहिए।<sup>[[5]](#references)</sup>

## क्रिप्टोग्राफ़िक key encodings की Differential fuzzing

Valid serialized keys या standard test vectors से शुरुआत करें। Encoded fields को इस तरह mutate करें कि import और operation paths तक पहुँचने के लिए ज़रूरी length और structure न टूटे, फिर वही bytes independent implementations को दें। Acceptance और errors की तुलना करें। Randomized signatures और ciphertexts के लिए byte-for-byte comparison नहीं, बल्कि correctness oracles की ज़रूरत होती है: signatures verify करें या encapsulation/decapsulation round trip से shared secrets की तुलना करें। Test vectors ज्ञात मामलों के लिए conformance स्थापित करते हैं; differential mutation उनसे आगे malformed encodings की जाँच करती है।<sup>[[23]](#references)[[26]](#references)</sup>

इन key formats के लिए format-specific oracles का उपयोग करें:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** Packed `s1` या `s2` coefficients को `[-η, η]` के बाहर बदलें, लेकिन key को parseable रखें। जाँचें कि import या signing इसे अस्वीकार करता है या नहीं और इससे बनी कोई signature verify होती है या नहीं। केवल acceptance में अंतर होना standards का उल्लंघन नहीं है, क्योंकि FIPS 204 अतिरिक्त private-key checks अनिवार्य नहीं करता। [conditional leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage) देखें।
- **ML-KEM key pairs:** ज़रूरी encapsulation-key और decapsulation-input checks को imported pair पर होने वाले optional pairwise-consistency check (PCT) से अलग रखें। इसकी public key से encapsulate करें, private key से decapsulate करें और shared secrets की तुलना करें; mismatch से encrypted communication टूट सकता है, भले ही अलग-अलग keys input checks पास कर लें। जाँचें कि API inputs को operation के दौरान validate करता है या अलग call के ज़रिए; libcrux `validate_public_key(pk)` और `validate_private_key(sk, ct)` देता है, जो PCT का विकल्प नहीं हैं।
- **XMSS/XMSSMT raw keys:** केवल in-memory keys से operations करने के बजाय, parameter sets के बीच serialized **signing और verifying** key round trips जाँचें। XMSS और XMSSMT के चार-byte OID namespaces अलग-अलग होते हैं, इसलिए ऐसा OID-only parser जो पहले XMSS आज़माता है, मेल खाने वाले XMSSMT key को गलत वर्गीकृत करके import अस्वीकार कर सकता है। रिपोर्ट किया गया RustCrypto parser interoperability/availability failure का उदाहरण है, signature forgery का नहीं।

## gosentry के साथ Go Fuzzing: अधिक सक्षम Engine, Typed Inputs और Differential Checks

अगर किसी Go target में पहले से native `testing.F` harness है, तो उसे अपग्रेड करने का एक व्यावहारिक तरीका है उसी harness को [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाना। यह forked Go toolchain है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

यह तब उपयोगी होता है जब native Go fuzzer **कठिन तुलनाओं**, **टाइप किए गए इनपुट**, या **पार्सर-प्रधान फ़ॉर्मैट** पर अटक जाता है। कार्यप्रणाली वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का उपयोग जारी रखें।
- उसी harness का दोबारा उपयोग करें, लेकिन उसे stock toolchain के बजाय gosentry के `go` binary से चलाएँ।
- परिणामी campaign को सामान्य coverage-guided run मानें, लेकिन इसमें LibAFL scheduling/mutation और बेहतर आसपास के detectors का उपयोग होता है।

### बिना संकेत वाली विफलताओं को fuzz findings में बदलें

Go assessments में बार-बार आने वाली समस्या यह है कि खतरनाक व्यवहार अक्सर डिफ़ॉल्ट रूप से **crash नहीं करता**। gosentry के साथ, आप “खराब लेकिन बिना संकेत वाली” कई स्थितियों को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` चुनिंदा logging/error paths को crashes की तरह व्यवहार करने देता है (यह `log.Fatal`-जैसे code paths के लिए उपयोगी है, जो अन्यथा सिर्फ़ log करके जारी रहते हैं)।
- `--catch-races=true` नए खोजे गए queue entries को Go race detector से दोबारा चलाता है।
- `--catch-leaks=true` नए queue entries को `goleak` से दोबारा चलाता है और goroutine leaks मिलने पर रुक जाता है।
- LibAFL hang handling **अनंत loops / बहुत धीमे inputs** को timeouts के रूप में गायब होने देने के बजाय fuzz findings के रूप में बनाए रखती है।
- डिफ़ॉल्ट रूप से अंतर्निहित arithmetic overflow checks, साथ ही go-panikint-शैली के instrumentation के ज़रिए वैकल्पिक truncation checks।

यह उन targets के लिए विशेष रूप से उपयोगी है जहाँ सुरक्षा पर असर memory corruption के बजाय **बिना panic वाली parser विफलता**, **concurrency bug**, या केवल **DoS वाला hang** होता है।

### टाइप किए गए Go APIs के लिए Struct-aware fuzzing

Native Go fuzzing मुख्यतः `[]byte`, `string` और numbers जैसे scalars की अपेक्षा करता है। यदि जाँचा जा रहा code typed objects लेता है, तो gosentry **composite values** (structs, slices, arrays, pointers) को सीधे fuzz कर सकता है, और साथ ही नीचे bytes को mutate करता रहता है।<sup>[[7]](#references)[[8]](#references)</sup>

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

Fuzzing के लिए नकली wire format बनाते समय इसका उपयोग करने से logic bugs, harness-only parsing code के पीछे छिप सकते हैं। Differential या grammar-based campaigns के लिए, harness input को एकल `[]byte` या `string` रखें और इसके बजाय callback के अंदर parse करें।

### Parsers और protocol inputs के लिए grammar-based fuzzing

Parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules की एक JSON array होती है, और harness को आमतौर पर एकल `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- जब byte-level mutations शुरुआती syntax checks में ही अक्सर विफल हो जाते हैं, तब grammar mode का उपयोग करें।
- Grammar को भाषा/प्रोटोकॉल के **security-relevant subset** पर केंद्रित रखें, पूरी specification को model करने पर नहीं।
- Integer, length और state-machine की सीमाओं को stress करने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अब भी **bytes/strings** ही मिलते हैं, इसलिए parsing और semantic checks harnessed code के भीतर ही होते हैं।

### Differential fuzzing: केवल crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक मजबूत तरीका **grammar-based differential fuzzing** है: valid structured inputs generate करें और उन्हें दो parsers, clients या state-transition engines को दें।<sup>[[7]](#references)[[8]](#references)</sup>

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

इनको findings मानें:

- एक implementation panic करता है, जबकि दूसरा साफ़ तौर पर reject करता है
- स्वीकार/अस्वीकार किए गए inputs में विसंगतियां
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में अंतर

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का एक व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing से अक्सर नहीं खोजा जा सकता।

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage reporting के लिए campaign corpus का पुनः उपयोग करें

Campaign के बाद, अलग corpus को मैन्युअल रूप से export किए बिना Go coverage report बनाने के लिए सहेजे गए queue corpus को फिर से चलाएँ।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

उसी package से और उसी `-fuzz` target के साथ command चलाएँ, ताकि gosentry सही cached campaign state को resolve करे।

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
- [23] [Differential fuzzing for cryptography](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID parsing bug - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [State of Post-Quantum Cryptography Implementations](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Snapshotting Our Way to CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzers vs. AI: Comparing Fuzzilli and BigSleep on JavaScript Engines](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
