# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing** में inputs को mutate किया जाता है, लेकिन वे **grammar-valid** बने रहते हैं। Coverage-guided mode में केवल वे samples corpus seeds के रूप में सहेजे जाते हैं जो **नई coverage** trigger करते हैं। **Language targets** (parsers, interpreters, engines) के लिए इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** ज़रूरी होती हैं—जहाँ एक construct का output दूसरे construct का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds खोजता है जो अलग-अलग `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow को बनाए नहीं रखता**। इसलिए “bug के करीब” वाला sample हटा दिया जाता है, क्योंकि उससे coverage नहीं बढ़ती। **3+ dependent steps** के साथ random recombination महँगा हो जाता है और coverage feedback search को दिशा नहीं देता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए **mutational और generative phases को hybridize करने** या generation को **function chaining** patterns की ओर झुकाने पर विचार करें (सिर्फ coverage की ओर नहीं)।<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होती है: नई coverage वाला sample तुरंत सहेज लिया जाता है और अक्सर उसमें बड़े unchanged regions बने रहते हैं। समय के साथ corpora में कम structural diversity वाले **near-duplicates** भर जाते हैं। Aggressive minimization उपयोगी context हटा सकती है, इसलिए एक व्यावहारिक समझौता है **grammar-aware minimization**, जो **minimum token threshold पर रुक जाती है** (शोर कम करते हुए इतना surrounding structure बनाए रखना कि mutation करना आसान रहे)।<sup>[[1]](#references)</sup>

Mutational fuzzing के लिए corpus का एक व्यावहारिक नियम है: near-duplicates के बड़े ढेर के बजाय **ऐसे छोटे seed set को प्राथमिकता दें जो coverage अधिकतम करते हुए संरचनात्मक रूप से अलग हों**। व्यवहार में, इसका आमतौर पर मतलब है कि नीचे दिए गए काम करें।<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world samples** से शुरुआत करें (public corpora, crawling, captured traffic, target ecosystem के file sets)।
- हर valid sample को रखने के बजाय **coverage-based corpus minimization** से उन्हें छाँटें।
- Seeds को इतना **छोटा रखें** कि mutations अर्थपूर्ण fields पर असर डालें, न कि ज़्यादातर cycles अप्रासंगिक bytes पर खर्च हों।
- बड़े harness/instrumentation बदलावों के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Comparison-Aware Mutation For Magic Values

Fuzzers के रुक जाने का एक आम कारण syntax नहीं, बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums या parser dispatch values, जिनकी जाँच `memcmp`, switch tables या cascaded comparisons से की जाती है। Pure random mutation इन values का byte-by-byte अनुमान लगाने में cycles बर्बाद करती है।

ऐसे targets के लिए **comparison tracing** का उपयोग करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows), ताकि fuzzer असफल comparisons के operands देख सके और mutations को ऐसी values की ओर मोड़ सके जो उन्हें पूरा करती हैं।<sup>[[3]](#references)</sup>

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

**व्यावहारिक सुझाव:**

- यह खास तौर पर तब उपयोगी है, जब target, **file signatures**, **protocol verbs**, **type tags** या **version-dependent feature bits** के पीछे जटिल logic को छिपाता है।
- इसे वास्तविक samples, protocol specs या debug logs से निकाली गई **dictionaries** के साथ इस्तेमाल करें। Grammar tokens, chunk names, verbs और delimiters वाली छोटी dictionary अक्सर बड़ी generic wordlist से ज़्यादा उपयोगी होती है।
- अगर target कई sequential checks करता है, तो सबसे पहले शुरुआती “magic” comparisons को हल करें। फिर बने हुए corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## ऐसी File APIs को Fuzz करना जो Filename की भाषा छिपाती हैं

`filename`, `path` या `URL` नाम वाला parameter, literal file lookup के बजाय interpreter entry point हो सकता है। उदाहरण के लिए, CFITSIO Extended Filename Syntax (EFS), खोले गए object को लौटाने से पहले bracketed selectors, row/pixel expressions, calculated columns, histograms और transformations को evaluate करता है; कुछ forms temporary copies भी बनाते हैं। Attack-surface mapping के दौरान, हर open/import API को **literal-path** या **interpreted-path** के रूप में वर्गीकृत करें, फिर उस production entry point को fuzz करें जिसे applications वास्तव में call करते हैं।<sup>[[20]](#references)[[22]](#references)</sup>

इससे मिलने वाले SSRF, file-copy और protocol-handler primitives—और अधिक सुरक्षित literal-path APIs—के लिए देखें [SSRF/file primitives के रूप में Filename mini-languages](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)।<sup>[[20]](#references)</sup>

### Backing object को fuzz किए जा रहे program से अलग रखें

जब grammar filename suffix में हो, तो सिर्फ referenced file के bytes को mutate करने से parser तक नहीं पहुँचा जा सकता। इसके बजाय, एक छोटा harness हर testcase को string के रूप में पढ़कर interpreted open API को दे सकता है; CFITSIO campaign ने read-only mode में `fits_open_file()` call करके ज़्यादातर EFS parsers और evaluators तक पहुँच बनाई। Valid backing files अलग से उपलब्ध रखें, ताकि mutations लगातार base path को तोड़ने के बजाय selector/expression language पर केंद्रित रहें।<sup>[[22]](#references)</sup>

ऐसे seeds इस्तेमाल करें जो हर बार अलग grammar family तक पहुँचें, फिर specification और lexer/parser source—दोनों से एक compact dictionary तैयार करें। अगर coverage plateau हो जाए और inputs बार-बार उसी syntax-error path में fail हों, तो सिर्फ random-mutation का समय बढ़ाने के बजाय valid prefixes को सुरक्षित रखें और delimiters, operators, keywords, function names तथा representative field names जोड़ें।<sup>[[22]](#references)</sup>

उदाहरण के लिए, grammar dictionary के साथ harness चलाएँ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness के side effects को सीमित करें

Library का read-only flag यह गारंटी नहीं देता कि testcase का कोई side effect नहीं होगा: filename language इनपुट को फिर से लिख सकती है, output files बना सकती है, या temporary objects materialize कर सकती है। CFITSIO campaign ने शुरू में seed files नष्ट कर दीं और filesystem में अनपेक्षित files छोड़ दीं, इसलिए cleanup और isolation ज़रूरी थे।<sup>[[22]](#references)</sup>

- हर worker को एक disposable working directory और private temporary directory दें।
- canonical backing files की copies उपलब्ध कराएँ; target को corpus की एकमात्र copy कभी mutate न करने दें।
- जब तक remote backends ही target न हों, network access बंद रखें और container, mount namespace, या equivalent sandbox से writable paths सीमित करें।
- हर execution या worker batch के बाद directory reset करें और filesystem में हुए अनपेक्षित बदलावों को अतिरिक्त findings मानें।

### Crash-to-patch-to-fuzz loop

Repair से पहले crashes को cluster करें, ताकि हज़ारों artifacts हज़ारों patch tasks न बन जाएँ। CFITSIO assessment में AFLTriage ने शुरुआती crash set को कुछ root causes तक सीमित किया; परिणामी advisory में अलग-अलग failures दिखते हैं, जिनमें destination-size की गलत जाँच, `realloc()` के बाद stale pointers, arithmetic faults, और parser cleanup के असुरक्षित paths शामिल हैं।<sup>[[21]](#references)[[22]](#references)</sup>

1. हर cluster के लिए एक representative input को minimize करें और उसे AddressSanitizer के तहत reproduce करें।
2. उस सटीक access, source location, allocation/free history, और parser state को दर्ज करें जिसके कारण invariant गलत हुआ।
3. एक सीमित दायरे वाला candidate patch लागू करें और उसी coverage तथा sanitizer instrumentation के साथ rebuild करें।
4. मूल reproducer **और उसके cluster के हर input** को फिर से चलाएँ; leak detection भी सक्षम करें, क्योंकि memory-safety fix किसी error path पर ownership बिगाड़ सकता है।
5. वास्तविक files के साथ functional tests चलाएँ, फिर संचित queue से जारी रखें (या उस queue को फिर से import करें, यदि binary बदलने के बाद engine को नई output directory चाहिए)।
6. दोहराएँ: पहला सतही crash हटाने से मौजूदा seeds अक्सर parser की किसी गहरी state तक पहुँच पाते हैं।

जब LLM को crashing input, sanitizer report, harness, और संबंधित source दिया जाए, तो वह step 2 को तेज़ कर सकता है और step 3 का draft बना सकता है, लेकिन उसके patch पर भरोसा नहीं किया जाना चाहिए। Repair स्वीकार होगा या नहीं, यह sanitizer replay और regression gates तय करते हैं—model की व्याख्या नहीं।<sup>[[22]](#references)</sup>

## जब Edge Coverage अलग-अलग Paths को एक जैसा मान ले, तब बेहतर Feedback

सामान्य edge coverage यह नहीं पहचान सकती कि दो executions ने अलग-अलग callers के ज़रिए उसी helper को traverse किया है या किसी function के भीतर branch combinations अलग थे। यह shared decoders, protocol dispatchers, और interpreter helpers में मायने रखता है, जहाँ किसी edge तक पहुँचने वाला **route** live state तय करता है। हर calling context को सीधे track करना भी जोखिमभरा है: coverage map और queue बहुत तेज़ी से बढ़ सकते हैं। इसलिए context-sensitive fuzzing research पूरे call graph को context-sensitive मानने के बजाय केवल आशाजनक contexts को refine करने की सलाह देती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds सामान्य edge coverage के साथ **per-function Ball-Larus path coverage** भी देते हैं। यह function के हर acyclic path को एक feature देता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations में अंतर करता है, लेकिन **loop iterations की गिनती में नहीं**। शुरुआत relaxed level `1` से करें, फिर सख्त modes को संदिग्ध parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या exponentially बढ़ सकती है।<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

कई सुरक्षा-संबंधी स्थानों से call किए जाने वाले helper के लिए, LTO mode प्रत्येक function path को उसके immediate call site के साथ जोड़ सकता है:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** richer feedback को सावधानी से लागू करें और इसके coverage-map/queue cost की निगरानी करें।<sup>[[13]](#references)[[14]](#references)</sup>

- समानांतर में एक सामान्य edge-coverage instance चलाएँ; richer feedback तभी उपयोगी है, जब अतिरिक्त queue/map cost से प्रति सेकंड executions की संख्या बहुत कम न हो।
- बड़े template-heavy libraries या generic utility code के कारण map का अधिकांश हिस्सा भरने पर path/caller instrumentation को सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- अत्यधिक acyclic paths वाले functions को AFL++ से छोड़ा जा सकता है; compilation के दौरान warnings इस बात का संकेत हैं कि target को allowlisting या कम strict level की ज़रूरत है।
- Caller + path coverage केवल एक caller depth को support करता है। इसे अधिक गहरे context stacks के साथ न मिलाएँ।
- Path IDs, LLVM के major versions के बीच बदल सकते हैं। पूरे campaign में toolchain को स्थिर रखें और PATH-आधारित corpora को ऐसे synchronize न करें, मानो उनके feature IDs अलग-अलग builds में स्थिर हों।
- यह feedback `CMPLOG` का पूरक है: comparison tracing यह पता लगाती है कि **कौन-सी value guard को पार करती है**, जबकि path/caller feedback यह सुरक्षित रखता है कि **कौन-सा route और branch combination वहाँ तक पहुँचा**।

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows** और **multi-stage parsers** के लिए, अक्सर दिलचस्प unit एक अकेला blob नहीं, बल्कि **message sequence** होता है। पूरे transcript को एक file में जोड़कर बिना सोचे-समझे mutate करना आम तौर पर अक्षम होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है—भले ही fragile state तक केवल बाद वाला message पहुँचता हो।<sup>[[4]](#references)</sup>

इससे बेहतर तरीका है **sequence को ही seed** मानना और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback के रूप में इस्तेमाल करना।<sup>[[4]](#references)</sup>

- **Valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- जब अगला step पिछली responses पर निर्भर हो, तो उनसे मिले identifiers और server-generated values को cache करें।
- पूरे serialized transcript को opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol उपयोगी response codes देता है, तो उन्हें **सस्ते state oracle** के रूप में इस्तेमाल करके उन sequences को प्राथमिकता दें जो आगे की स्थिति तक पहुँचती हैं।

इसी कारण authenticated bugs, hidden transitions या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing से छूट जाते हैं: fuzzer को केवल structure नहीं, बल्कि **क्रम, state और dependencies** भी बनाए रखनी होती हैं।<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

उच्च edge coverage के बावजूद IPC-driver bugs छूट सकते हैं, क्योंकि coverage **object ownership, reference counts, pending messages, cleanup order या thread interleavings** को नहीं दर्शाती। [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) पेज driver object model समझाता है; यह उदाहरण fuzzer harness पर केंद्रित है। Android Binder एक उपयोगी model है: allocation और free paths, दोनों तक पहुँचना पर्याप्त नहीं, यदि fuzzer कई processes से आवश्यक क्रम में एक ही kernel object पर काम नहीं करवा सकता।<sup>[[15]](#references)</sup>

#### अलग-अलग `ioctl` buffers के बजाय protocol को model करें

Test case को **client identity + operation + structured arguments** के क्रमबद्ध grammar के रूप में दर्शाएँ। Binder LKL fuzzer protobuf और `libprotobuf-mutator` का उपयोग करता है, जिसमें एक persistent context-manager client और दो सामान्य clients होते हैं। फिर एक semantic harness उन संबंधों को बनाए रखता है जिन्हें blind byte mutation नष्ट कर देती।<sup>[[15]](#references)</sup>

- पहले के operations से मिली values को cache करें। उदाहरण के लिए, `BC_FREE_BUFFER` में पिछले `ioctl` से मिला transaction-buffer pointer दोबारा इस्तेमाल होना चाहिए।
- मान्य default replies बनाएँ, ताकि synchronous transactions पूरी हो सकें और बाद के operations तक पहुँचना संभव रहे।
- self-transactions या एक ही target के लिए कई pending transactions जैसे असंभव transitions को अस्वीकार करें।
- Singleton bootstrap state को per-input reset से बाहर रखें। Binder हर boot में केवल एक `BINDER_SET_CONTEXT_MGR` registration की अनुमति देता है, इसलिए उस client को बार-बार नष्ट करके फिर बनाने से बाद के inputs invalid हो जाएँगे।

Lifetime-race का एक उपयोगी template यह है कि एक client से object transfer करवाएँ, thread या process cleanup शुरू करें, और उसी समय receiving client से transaction buffer release करवाएँ। CVE-2020-0423 उदाहरण में, `BINDER_TYPE_WEAK_BINDER` transfer के बाद `BINDER_THREAD_EXIT` और `BC_FREE_BUFFER` के बीच race होने पर embedded `binder_work` free हो सकता था, जबकि exiting thread का cleanup path अब भी उसका उपयोग कर रहा था।<sup>[[15]](#references)</sup>

#### userspace kernel में controlled interleavings फिर से जोड़ें

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) असली kernel code को userspace harness में link करती है और `lkl_syscall` के ज़रिए उसका syscall interface उपलब्ध कराती है। इससे protobuf state, coverage और KASAN को एक process में समन्वित करना आसान हो जाता है। हालांकि, LKL आम तौर पर किसी syscall के चलते समय दूसरे kernel thread को interrupt नहीं करने देता। Race campaigns के लिए, चुने हुए lock/unlock और lifetime boundaries के आसपास `schedule()` points जोड़ें, फिर हर yield पर harness को अगला client बेतरतीब ढंग से चुनने दें। इन points को चुनिंदा जगहों पर ही रखें, क्योंकि हर point scheduling search space को कई गुना बढ़ाता है। शोधकर्ताओं द्वारा वर्णित randomized scheduler upstream Binder fuzzer का हिस्सा **नहीं** है।<sup>[[15]](#references)</sup>

#### Serialized regression seeds बनाएँ और replay करें

Upstream harness एक compatible `libprotobuf-mutator` version को pin करता है, `LKL_FUZZING=1` के साथ LKL fuzzing instrumentation और KASAN enable करता है, और Binder के लिए `MMU=1` के साथ `CONFIG_MMU` enable करता है।<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

जानबूझकर असुरक्षित revision को checkout करने या upstream में दर्ज rollback patches लागू करने के बाद, एक serialized seed बिना ad-hoc C proof of concept में state को फिर से बनाए, पूरे multi-client state transition को दोहरा सकता है:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

परिणामस्वरूप KASAN use-after-free इस बात की पुष्टि करता है कि seed, vulnerable lifetime path तक पहुँचा। यह kernel code execution या privilege escalation के लिए आवश्यक बाद के primitives को प्रदर्शित **नहीं** करता।<sup>[[16]](#references)</sup>

## एकल-मशीन विविधता की तरकीब (Jackalope-Style)

**Generative novelty** को **coverage reuse** के साथ जोड़ने का एक व्यावहारिक तरीका है कि persistent server के विरुद्ध कम समय तक चलने वाले workers को **restart** किया जाए। हर worker एक खाली corpus से शुरू होता है, `T` सेकंड बाद sync करता है, संयुक्त corpus पर अगले `T` सेकंड तक चलता है, फिर दोबारा sync करता है और उसके बाद exit हो जाता है। इससे संचित coverage का लाभ लेते हुए भी हर generation में **नई संरचनाएँ** मिलती हैं।<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` हर generation में **fresh corpus** का उपयोग करता है।
- `-server_update_interval T` **delayed sync** का अनुमान देता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync डिफ़ॉल्ट रूप से skip होता है** (`-skip_initial_server_sync` की ज़रूरत नहीं)।
- सबसे अच्छा `T` **target पर निर्भर करता है**; worker के ज़्यादातर “easy” coverage खोज लेने के बाद इसे बदलना आम तौर पर बेहतर काम करता है।

## मुश्किल-से-harness किए जा सकने वाले targets के लिए Snapshot Fuzzing

जब जिस code को आप test करना चाहते हैं, वह केवल **बड़े setup cost** के बाद ही reachable होता है (VM boot करना, login पूरा करना, packet प्राप्त करना, container parse करना, service initialize करना), तो **snapshot fuzzing** एक उपयोगी विकल्प है: ready process या VM state capture करें, हर test case को target input path में inject करें, crash/timeout होने तक execute करें, फिर snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने की ज़रूरत नहीं पड़ती। यह **network services**, **firmware**, **post-auth attack surfaces**, और **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ जब तक इच्छित state ready न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset होने तक execute करें।
5. Snapshot restore करें; VM targets के लिए, यदि समर्थित हो तो केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को पहले महँगे parse/dispatch step के जितना व्यावहारिक हो उतना करीब रखें, जैसे `recv`/`read` के बाद या packet-deserialization point पर, और target द्वारा उपयोग किए गए input buffer को दर्ज करें। यह input processing में snapshot को और भीतर ले जाने के adaptive-placement principle का पालन करता है, ताकि काम दोहराना न पड़े।<sup>[[11]](#references)</sup>

## MAccConc के साथ Linux Kernel Race Exploration

[MAccConc](https://github.com/googleprojectzero/MAccConc) timing-sensitive Linux-kernel races को repeatable memory-access schedules में बदलता है। यह दो contexts वाले **A-B-A** executions को स्वचालित रूप से enumerate कर सकता है या analyst को terminal UI/GUI में order constraints तय करने देता है। यह पूर्ण concurrency fuzzer के बजाय experimental research tooling है: फ़िलहाल इसे LLVM 23+ और project के patched kernel की ज़रूरत है, command-line tools दो test threads को support करते हैं, और प्रस्तावित userspace fuzzing layer अभी implement नहीं की गई है।<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication points इकट्ठा करें

Instrumented kernel को KASAN outline callbacks और patched KCOV memory-record support के साथ build करें। Project README यह भी सुझाता है कि call stacks को उपयोगी बनाए रखने के लिए sibling-call optimization disable करें।<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) instrumented accesses को helper calls में बदलता है। MAccConc kernel patches `asan-opt-same-temp` को disable करते हैं, ताकि लगातार होने वाले accesses merge न हों; जब global-variable races दिखनी चाहिए, तो `asan-opt-globals` optimization को भी disable करें। KCOV से ये records userspace तक पहुँचते हैं। अलग-अलग execution contexts के accesses की तुलना करें और उन pairs को रखें जिनकी byte ranges overlap करती हैं और जिनमें कम-से-कम एक side write करती है; `kfree()` को write मानें, ताकि lifetime transitions भी candidates बन सकें।<sup>[[17]](#references)</sup>

शुरू करने वाले task से बाहर जाने वाले काम, जैसे packet processing या RCU callbacks, के लिए subsystem को KCOV remote-coverage handle आगे पहुँचाना होगा। Upstream remote KCOV opt-in है और arbitrary background work के लिए अपने-आप उपलब्ध नहीं होता, इसलिए propagation न होने पर वास्तविक interaction दिखाई नहीं दे सकता।<sup>[[17]](#references)[[19]](#references)</sup>

### हर run में उसी dynamic access की पहचान करें

किसी concrete heap address के आधार पर replay न करें, जो हर allocation के बाद बदल सकता है; और न ही केवल instruction address के आधार पर, जो `memcpy()` और `spin_lock()` जैसे helpers के भीतर ambiguous होता है। MAccConc **count-augmented stack trace** का उपयोग करता है: हर frame एक callee और उसके caller के भीतर invocation count की पहचान करता है, और अंतिम element memory-access instruction की पहचान करता है। SanitizerCoverage function-entry/exit records userspace को यह dynamic identifier दोबारा बनाने देते हैं, जो address में बदलाव और असंबंधित control-flow noise के बावजूद स्थिर रहता है।<sup>[[17]](#references)</sup>

### Candidate pairs को forced schedules में बदलें

Patched `KCOV_SET_DI` ioctl एक count-augmented access identifier को shared-flag action से जोड़ता है।<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | चुने गए access से तुरंत पहले flag *N* सेट करें। |
| `DI_STACK_WAIT` | चुने गए access से पहले, flag *N* सेट होने तक या configured limit समाप्त होने तक spin करें। |
| `DI_STACK_WAKE_POST` | चुने गए access के तुरंत बाद flag *N* सेट करें। |

आंशिक **A-happens-before-B** constraint के लिए, A पर `DI_STACK_WAKE_POST` और B पर उसी flag का उपयोग करके `DI_STACK_WAIT` लगाएँ। पूरी तरह निर्दिष्ट two-context schedule के लिए, B को blocked शुरू करें, फिर A से B को wake करवाएँ और पहले transfer point पर wait करवाएँ; अगले transfer पर B उलटा operation करे। यह deterministic context switching की तरह काम करता है और automatic A-B-A explorer इसी का उपयोग करता है।<sup>[[17]](#references)</sup>

एक minimal campaign में four-hook test case (`test_setup`, दो thread functions, और `test_end`) को shared library के रूप में compile करें, बिना constraints वाला trace collect करें, फिर A-B-A candidates enumerate करें या संदिग्ध accesses के आसपास manual constraints जोड़ें।<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts को सफल reorderings से अलग समझें: अनुरोधित order संभव नहीं हो सकता, क्योंकि कोई lock या initialization/publication dependency दूसरे context को अपने injection point तक पहुँचने से रोकती है। KASAN की blind spots का भी ध्यान रखें: direct stack accesses पर आमतौर पर hooks नहीं लगते, जब तक कि उनके out of bounds होने की आशंका न हो; default optimization में globals छोड़ दिए जाते हैं; और मौजूदा compilers ASAN और TSAN hooks एक साथ emit नहीं कर सकते। अंत में, guest के panic होने पर prototype अपना KCOV buffer खो देता है, इसलिए एक स्वतंत्र crash console/oracle बनाए रखें।<sup>[[17]](#references)</sup>

भविष्य में concurrency-guided fuzzing के लिए, हर input या syscall के memory-access summaries रिकॉर्ड करें, उन operations की जोड़ियाँ बनाएँ जो cross-context communication points बना सकती हैं, और फिर केवल उन्हीं combinations को explore करें। VM snapshots global state और addresses को स्थिर रखते हैं; snapshots के बिना, allocation-site metadata का उपयोग करके अलग-अलग runs में objects को abstract किया जा सकता है। यह एक प्रस्तावित extension है, मौजूदा MAccConc userspace tools का feature नहीं।<sup>[[17]](#references)</sup>

## Harness Introspection: सतही Fuzzers को जल्दी पहचानें

जब कोई campaign रुक जाए, तो अक्सर समस्या mutator में नहीं, बल्कि **harness** में होती है। ऐसे functions खोजने के लिए **reachability/coverage introspection** का इस्तेमाल करें जो statically आपके fuzz target से reachable हैं, लेकिन dynamically उन तक शायद ही कभी पहुँचा जाता है या कभी नहीं पहुँचा जाता। ये functions आमतौर पर तीन में से किसी एक समस्या की ओर इशारा करते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी पूरे feature family की कमी है।
- Target को एक बड़े “सब कुछ करने वाले” harness के बजाय वास्तव में **दूसरे harness** की ज़रूरत है।

अगर आप OSS-Fuzz / ClusterFuzz-शैली के workflows इस्तेमाल करते हैं, तो Fuzz Introspector statically reachable code की तुलना runtime coverage से कर सकता है और timed run या public corpus से reports बना सकता है।<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

रिपोर्ट का उपयोग यह तय करने के लिए करें कि किसी untested parser path के लिए नया harness जोड़ना है, किसी खास feature के लिए corpus बढ़ाना है, या monolithic harness को छोटे entry points में बाँटना है।

## Graph-First Fuzz Target Selection And Mutation Triage

यदि आपके पास पहले से **static-analysis findings**, **mutation-testing survivors**, और **coverage reports** हैं, तो उन्हें अलग-अलग सूचियों की तरह triage न करें। पहले एक **call graph** बनाएँ, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, और बाहरी findings को annotate करें, फिर graph से जुड़े सवाल पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- Untrusted input से कौन-से high-complexity functions तक पहुँचा जा सकता है?
- कौन-से mutation survivors, parsers/handlers से security-critical code तक जाने वाले paths पर हैं?
- कौन-से functions, असामान्य रूप से बड़े **blast radius** वाले architectural choke points हैं?

इससे अक्सर "सबसे कम coverage" के आधार पर चुने गए targets से बेहतर fuzz targets सामने आते हैं। **High complexity** और पुष्टि की गई **external reachability** वाला parser/decoder, कम coverage वाले लेकिन attacker-controlled path से न जुड़े किसी isolated internal helper की तुलना में बेहतर harness candidate है।

### व्यावहारिक triage workflow

1. Codebase से **code graph** बनाएँ और हर function के complexity/branch metrics निकालें।
2. ऐसे **entrypoints** की सूची बनाएँ जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. Candidate functions तक पहुँचने वाले paths की queries चलाएँ, ताकि reachable attack surface को dead/internal-only code से अलग किया जा सके।
4. ऐसे nodes को प्राथमिकता दें जिनमें ये गुण हों:
   - उच्च **cyclomatic complexity**
   - **untrusted input से confirmed reachability**
   - बड़ा **blast radius** या कई downstream dependents
   - सहायक साक्ष्य, जैसे **SARIF** findings, audit notes या mutation survivors
5. पहले सबसे बेहतर score वाले nodes के लिए focused harnesses लिखें, खासकर **parsers/codecs**, जैसे hex/Base64/IP/message decoders।

### Mutation survivors: equivalent बनाम actionable

Mutation testing से अक्सर survivors की noisy सूची मिलती है। हर survivor को security gap मानने से पहले, graph का उपयोग करके पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths, mutated check से अधिक मजबूत invariants के अधीन हैं?
- क्या node dead code, केवल formatting वाले logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable रहें या जिन पर संरचनात्मक सीमाएँ हों, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** हों और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को प्रभावित करें, उन्हें इन कामों के लिए आगे बढ़ाएँ:

- नए fuzz harnesses
- सीधे property/invariant tests
- लक्षित edge-case vectors

### External findings को graph पर correlate करें

यदि आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर project करें और impact बढ़ाकर देखने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** निकालें
- जाँचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- आस-पास की उन findings को समूहित करें जो एक ही choke point पर मिलती हैं

यह तब उपयोगी होता है जब आप तय कर रहे हों कि किसी खास function पर fuzzing का समय लगाना चाहिए या नहीं: **reachable**, **complex**, और पहले से **SAST hits** वाला node, केवल complex लेकिन attacker path से न जुड़े node से अक्सर बेहतर target होता है।

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

महत्वपूर्ण कार्यविधि इनका प्रतिच्छेदन है: **जटिलता x एक्सपोज़र x प्रभाव**। सबसे अधिक अपेक्षित सुरक्षा-मूल्य वाले fuzz targets चुनने के लिए ग्राफ़ का उपयोग करें, फिर mutation survivors के आधार पर तय करें कि आपके harness को किन सीमाओं और invariants पर दबाव डालना चाहिए।<sup>[[5]](#references)</sup>

## क्रिप्टोग्राफ़िक key encodings की Differential fuzzing

मान्य serialized keys या standard test vectors से शुरू करें। Encoded fields में ऐसे बदलाव करें कि import और operation paths तक पहुँचने के लिए आवश्यक लंबाई और संरचना बनी रहे, फिर समान bytes को स्वतंत्र implementations में सबमिट करें। स्वीकृति और errors की तुलना करें। Randomized signatures और ciphertexts के लिए byte-for-byte तुलना नहीं, बल्कि correctness oracles चाहिए: signatures verify करें या encapsulation/decapsulation round trip से प्राप्त shared secrets की तुलना करें। Test vectors ज्ञात मामलों के लिए conformance स्थापित करते हैं; differential mutation उनसे परे malformed encodings की जाँच करता है।<sup>[[23]](#references)[[26]](#references)</sup>

इन key formats के लिए, format-specific oracles का उपयोग करें:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** packed `s1` या `s2` coefficients में ऐसे बदलाव करें कि वे `[-η, η]` की सीमा से बाहर हों, लेकिन key parseable रहे। जाँचें कि import या signing इसे अस्वीकार करता है या नहीं, और क्या इससे बनी कोई signature verify होती है। केवल acceptance में अंतर होना standards का उल्लंघन नहीं है, क्योंकि FIPS 204 अतिरिक्त private-key जाँच अनिवार्य नहीं करता। [सशर्त leakage mechanism](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage) देखें।
- **ML-KEM key pairs:** आवश्यक encapsulation-key और decapsulation-input checks को imported pair पर वैकल्पिक pairwise-consistency check (PCT) से अलग रखें। इसकी public key से encapsulate करें, private key से decapsulate करें और shared secrets की तुलना करें; mismatch से encrypted communication टूट सकता है, भले ही अलग-अलग keys input checks पास कर लें। जाँचें कि API inputs को operation के दौरान validate करता है या अलग call के ज़रिए; libcrux `validate_public_key(pk)` और `validate_private_key(sk, ct)` उपलब्ध कराता है, जो PCT का विकल्प नहीं हैं।
- **XMSS/XMSSMT raw keys:** केवल in-memory keys से operations करने के बजाय, parameter sets में serialized **signing और verifying** key round trips जाँचें। XMSS और XMSSMT के चार-byte OID namespaces अलग-अलग हैं, इसलिए ऐसा OID-only parser जो पहले XMSS आज़माता है, टकराने वाले XMSSMT key को गलत पहचानकर import अस्वीकार कर सकता है। रिपोर्ट किया गया RustCrypto parser interoperability/availability failure दिखाता है, signature forgery नहीं।

## gosentry के साथ Go Fuzzing: बेहतर Engine, Typed Inputs और Differential Checks

यदि किसी Go target में पहले से native `testing.F` harness है, तो इसे बेहतर बनाने का एक व्यावहारिक तरीका यही harness [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाना है। यह forked Go toolchain `go test -fuzz` बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

यह तब उपयोगी है जब native Go fuzzer **hard comparisons**, **typed inputs** या **parser-heavy formats** पर अटक जाता है। Methodology वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का इस्तेमाल जारी रखें।
- उसी harness को दोबारा इस्तेमाल करें, लेकिन उसे stock toolchain के बजाय gosentry के `go` binary से चलाएँ।
- परिणामी campaign को सामान्य coverage-guided run की तरह मानें, लेकिन इसमें LibAFL scheduling/mutation और बेहतर आसपास के detectors मिलते हैं।

### मौन विफलताओं को fuzz findings में बदलें

Go assessments में बार-बार आने वाली समस्या यह है कि खतरनाक व्यवहार अक्सर डिफ़ॉल्ट रूप से crash **नहीं** करता। gosentry की मदद से, आप “खराब लेकिन मौन” स्थितियों की कई श्रेणियों को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` चुनिंदा logging/error paths को crashes की तरह व्यवहार करने देता है (यह `log.Fatal`-style code paths के लिए उपयोगी है, जो अन्यथा केवल log करके आगे चलते रहते हैं)।
- `--catch-races=true` नए खोजे गए queue entries को Go race detector के साथ दोबारा चलाता है।
- `--catch-leaks=true` नए queue entries को `goleak` के साथ दोबारा चलाता है और goroutine leaks मिलने पर रुक जाता है।
- LibAFL hang handling **infinite loops / बहुत धीमे inputs** को timeouts के रूप में गायब होने देने के बजाय fuzz findings के रूप में बनाए रखती है।
- डिफ़ॉल्ट रूप से built-in arithmetic overflow checks, साथ ही go-panikint-style instrumentation के ज़रिए वैकल्पिक truncation checks।

यह उन targets के लिए विशेष रूप से उपयोगी है जहाँ security impact memory corruption के बजाय **बिना panic वाली parser failure**, **concurrency bug** या केवल **DoS वाला hang** होता है।

### Typed Go APIs के लिए struct-aware fuzzing

Native Go fuzzing मुख्य रूप से `[]byte`, `string` और numbers जैसे scalars की अपेक्षा करता है। यदि test किया जा रहा code typed objects लेता है, तो gosentry bytes को अंदरूनी तौर पर mutate करते हुए सीधे composite values (structs, slices, arrays, pointers) को fuzz कर सकता है।<sup>[[7]](#references)[[8]](#references)</sup>

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

Fuzzing के लिए नकली wire format बनाते समय इसका उपयोग करें, क्योंकि harness-only parsing code के पीछे logic bugs छिप सकते हैं। Differential या grammar-based campaigns के लिए, harness input को एकल `[]byte` या `string` के रूप में रखें और इसके बजाय callback के अंदर parse करें।

### Parsers और protocol inputs के लिए grammar-based fuzzing

Parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules की एक JSON array होती है, और harness को आमतौर पर एकल `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- जब byte-level mutations शुरुआती syntax checks में ही ज़्यादातर विफल हो जाते हैं, तो grammar mode का उपयोग करें।
- Grammar को पूरी specification मॉडल करने के बजाय, भाषा/protocol के **security-relevant subset** तक सीमित रखें।
- Integer, length और state-machine की सीमाओं को परखने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अब भी **bytes/strings** ही मिलते हैं, इसलिए parsing और semantic checks harnessed code के भीतर ही होते हैं।

### Differential fuzzing: केवल crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक प्रभावी तरीका है **grammar-based differential fuzzing**: valid structured inputs जनरेट करें और उन्हें दो parsers, clients या state-transition engines को दें।<sup>[[7]](#references)[[8]](#references)</sup>

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
- स्वीकार/अस्वीकार किए गए input में बेमेल
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में अंतर

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का एक व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing से अक्सर नहीं पकड़ा जा सकता।

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage report के लिए campaign corpus का दोबारा उपयोग करें

Campaign के बाद, अलग corpus को मैन्युअल रूप से export किए बिना Go coverage report बनाने के लिए सहेजे गए queue corpus को फिर से चलाएँ।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

उसी package से और उसी `-fuzz` target के साथ command चलाएँ, ताकि gosentry सही cached campaign state को resolve करे।

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet पाँच साल बाद: Coverage-Guided Protocol Fuzzing पर](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark कोड को graphs में बदलता है](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing में आधा toolkit नहीं था। इसे ठीक करने के लिए हमने toolchain को fork किया।](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots का उपयोग करके Stateful Network Protocols के लिए एक Fast Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [कोई Grammar नहीं, कोई समस्या नहीं: System-Call Descriptions के बिना Linux Kernel को Fuzz करने की दिशा में](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive और Mutable Snapshots के साथ Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path और caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build और regression-seed documentation](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Controlled Memory-Access Interleavings के साथ Linux Kernel Race Conditions की खोज](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing के लिए code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Extended Filename Syntax](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Extended Filename Syntax की Fuzzing: 16 Memory-Safety Vulnerabilities और Codex-सहायता प्राप्त Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Cryptography के लिए Differential fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID parsing bug - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Post-Quantum Cryptography Implementations की स्थिति](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
