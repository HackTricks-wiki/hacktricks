# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage बनाम Semantics

**Mutational grammar fuzzing** में inputs को mutate किया जाता है, लेकिन वे **grammar-valid** बने रहते हैं। Coverage-guided mode में केवल वे samples corpus seeds के रूप में सहेजे जाते हैं जो **नई coverage** ट्रिगर करते हैं। **Language targets** (parsers, interpreters, engines) के लिए इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** की आवश्यकता होती है, जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds खोजता है जो अलग-अलग `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow को बनाए नहीं रखता**। इसलिए “bug के करीब” वाला sample छोड़ दिया जाता है, क्योंकि उससे coverage नहीं बढ़ती। **3+ dependent steps** होने पर random recombination महँगा हो जाता है और coverage feedback search को दिशा नहीं देता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए **mutational और generative phases को hybridize करने** या generation को **function chaining** patterns की ओर bias करने पर विचार करें (सिर्फ coverage की ओर नहीं)।<sup>[[1]](#references)</sup>

## Corpus Diversity की समस्याएँ

Coverage-guided mutation **greedy** होती है: नई coverage वाला sample तुरंत सहेज लिया जाता है और उसमें अक्सर बड़े unchanged regions बने रहते हैं। समय के साथ corpora में कम structural diversity वाले **लगभग एक जैसे duplicates** जमा हो जाते हैं। Aggressive minimization से उपयोगी context हट सकता है, इसलिए एक व्यावहारिक समझौता है **grammar-aware minimization**, जो **minimum token threshold** पर रुक जाती है (noise घटाते हुए इतना आसपास का structure बनाए रखना कि वह mutation-friendly रहे)।<sup>[[1]](#references)</sup>

Mutational fuzzing के लिए corpus का एक व्यावहारिक नियम है: near-duplicates के बड़े ढेर की बजाय **ऐसे छोटे seed set को प्राथमिकता दें जिनकी संरचना अलग-अलग हो और जो coverage को अधिकतम करें**। व्यवहार में, इसका आम तौर पर मतलब है:<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world samples** से शुरुआत करें (public corpora, crawling, captured traffic, target ecosystem के file sets)।
- हर valid sample को रखने की बजाय उन्हें **coverage-based corpus minimization** से छाँटें।
- Seeds को **इतना छोटा रखें** कि mutations अर्थपूर्ण fields पर हों, न कि अधिकांश cycles अप्रासंगिक bytes पर खर्च हों।
- बड़े harness/instrumentation बदलावों के बाद corpus minimization दोबारा चलाएँ, क्योंकि reachability बदलने पर “सबसे अच्छा” corpus भी बदल जाता है।

## Magic Values के लिए Comparison-Aware Mutation

Fuzzers के plateau पर पहुँचने का एक आम कारण syntax नहीं, बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums या parser dispatch values, जिन्हें `memcmp`, switch tables या cascaded comparisons द्वारा जाँचा जाता है। Pure random mutation इन values का byte-by-byte अनुमान लगाने की कोशिश में cycles बर्बाद करती है।

ऐसे targets के लिए **comparison tracing** का उपयोग करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows), ताकि fuzzer असफल comparisons के operands देख सके और mutations को उन values की ओर bias कर सके जो उन्हें संतुष्ट करती हैं।<sup>[[3]](#references)</sup>

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

- यह खास तौर पर तब उपयोगी है जब target, गहरे logic तक पहुँच को **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे सीमित करता है।
- इसे वास्तविक samples, protocol specs या debug logs से निकाली गई **dictionaries** के साथ इस्तेमाल करें। Grammar tokens, chunk names, verbs और delimiters वाली छोटी dictionary अक्सर बहुत बड़ी सामान्य wordlist से ज़्यादा काम की होती है।
- अगर target कई sequential checks करता है, तो पहले शुरुआती “magic” comparisons हल करें। फिर बने हुए corpus को दोबारा minimize करें, ताकि अगले stages पहले से valid prefixes से शुरू हों।

## जब Edge Coverage अलग-अलग Paths में भेद न कर पाए, तब बेहतर Feedback

सामान्य edge coverage, उन दो executions में भेद नहीं कर सकता जो अलग-अलग callers से होकर एक ही helper तक पहुँचते हैं या किसी function के अंदर अलग-अलग branch combinations लेते हैं। Shared decoders, protocol dispatchers और interpreter helpers में यह मायने रखता है, क्योंकि edge तक पहुँचने वाला **route** live state तय करता है। हर calling context को सीधे track करना भी जोखिमभरा है: coverage map और queue बहुत तेज़ी से बढ़ सकते हैं। इसलिए context-sensitive fuzzing research, पूरे call graph को context-sensitive मानने के बजाय, केवल आशाजनक contexts को refine करने की सलाह देती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds, सामान्य edge coverage के अलावा **Ball-Larus per-function path coverage** भी उपलब्ध कराते हैं। यह किसी function के हर acyclic path को एक feature देता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations में भेद करता है, लेकिन **loop iterations की संख्या में नहीं**। पहले relaxed level `1` से शुरू करें, फिर stricter modes को केवल संदिग्ध parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या exponentially बढ़ सकती है।<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

कई सुरक्षा-संबंधी स्थानों से कॉल किए जाने वाले helper के लिए, LTO mode प्रत्येक function path को उसके तत्काल call site के साथ जोड़ सकता है:<sup>[[13]](#references)</sup>

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

- समानांतर में एक सामान्य edge-coverage instance चलाएँ; अधिक समृद्ध feedback तभी उपयोगी है, जब इससे होने वाला अतिरिक्त queue/map cost प्रति सेकंड executions को कम न करे।
- जब बड़ी template-heavy libraries या generic utility code map पर हावी हों, तो path/caller instrumentation को सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- अत्यधिक acyclic paths वाले functions को AFL++ छोड़ सकता है; compilation के दौरान आने वाली warnings इस बात का संकेत हैं कि target को allowlisting या कम strict level की जरूरत है।
- Caller + path coverage केवल एक caller depth का समर्थन करता है। इसे अधिक गहरे context stacks के साथ न जोड़ें।
- LLVM के major versions में Path IDs बदल सकते हैं। Campaign के दौरान toolchain को स्थिर रखें और PATH-आधारित corpora को ऐसे synchronize न करें, मानो उनके feature IDs builds के बीच स्थिर हों।
- यह feedback `CMPLOG` का पूरक है: comparison tracing बताता है कि guard को **कौन-सी value पास करती है**, जबकि path/caller feedback यह सुरक्षित रखता है कि **कौन-सा route और branch combination वहाँ तक पहुँचा**।

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए अक्सर दिलचस्प इकाई एक अकेला blob नहीं, बल्कि **message sequence** होती है। पूरे transcript को एक file में जोड़कर बिना सोचे-समझे mutate करना आमतौर पर अक्षम होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है, भले ही fragile state तक केवल बाद वाला message पहुँचता हो।<sup>[[4]](#references)</sup>

एक अधिक प्रभावी तरीका है कि **sequence को ही seed** माना जाए और **observable state** (response codes, protocol states, parser phases, लौटाए गए object types) को अतिरिक्त feedback के रूप में इस्तेमाल किया जाए।<sup>[[4]](#references)</sup>

- **Valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- जब अगला step पिछले responses पर निर्भर हो, तो उनसे मिले identifiers और server-generated values को cache करें।
- पूरे serialized transcript को एक opaque blob की तरह mutate करने के बजाय, per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol उपयोगी response codes देता है, तो उन्हें **सस्ते state oracle** की तरह इस्तेमाल करके उन sequences को प्राथमिकता दें जो आगे के चरणों तक पहुँचती हैं।

यही कारण है कि authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing से छूट जाते हैं: fuzzer को केवल structure ही नहीं, बल्कि **क्रम, state और dependencies** भी सुरक्षित रखनी होती हैं।<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Edge coverage अधिक होने पर भी IPC-driver bugs छूट सकते हैं, क्योंकि coverage **object ownership, reference counts, pending messages, cleanup order या thread interleavings** को नहीं दर्शाता। [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) पेज driver object model बताता है; यह उदाहरण fuzzer harness पर केंद्रित है। Android Binder एक उपयोगी मॉडल है: allocation और free paths तक पहुँचना पर्याप्त नहीं, यदि fuzzer आवश्यक क्रम में कई processes से एक ही kernel object पर काम नहीं करवा सकता।<sup>[[15]](#references)</sup>

#### अलग-अलग `ioctl` buffers नहीं, protocol को model करें

एक test case को **client identity + operation + structured arguments** के ordered grammar के रूप में दर्शाएँ। Binder LKL fuzzer protobuf और `libprotobuf-mutator` का उपयोग करता है, जिसमें एक persistent context-manager client और दो सामान्य clients होते हैं। फिर एक semantic harness उन संबंधों को सुरक्षित रखता है जिन्हें blind byte mutation नष्ट कर देती।<sup>[[15]](#references)</sup>

- पहले के operations से लौटे values को cache करें। उदाहरण के लिए, `BC_FREE_BUFFER` को पिछले `ioctl` से मिला transaction-buffer pointer दोबारा इस्तेमाल करना चाहिए।
- Valid default replies बनाएँ, ताकि synchronous transactions पूरी हो सकें और बाद के operations तक पहुँचना संभव रहे।
- असंभव transitions को अस्वीकार करें, जैसे self-transactions या एक ही target के लिए कई pending transactions।
- Singleton bootstrap state को per-input reset के बाहर रखें। Binder हर boot में केवल एक `BINDER_SET_CONTEXT_MGR` registration की अनुमति देता है, इसलिए उस client को बार-बार नष्ट करके फिर बनाने से बाद के inputs invalid हो जाएँगे।

Lifetime-race के लिए एक उपयोगी template यह है कि एक client से object transfer करवाएँ, thread या process cleanup शुरू करें, और साथ ही receiving client से transaction buffer release करवाएँ। CVE-2020-0423 के उदाहरण में, `BINDER_TYPE_WEAK_BINDER` transfer के बाद `BINDER_THREAD_EXIT` का `BC_FREE_BUFFER` के साथ race करने पर एक embedded `binder_work` free हो सकता था, जबकि exiting thread का cleanup path अब भी उसका उपयोग कर रहा होता।<sup>[[15]](#references)</sup>

#### Userspace kernel में नियंत्रित interleavings फिर से लाएँ

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) असली kernel code को userspace harness में link करती है और `lkl_syscall` के ज़रिए इसका syscall interface उपलब्ध कराती है। इससे protobuf state, coverage और KASAN को एक ही process में आसानी से coordinate किया जा सकता है। हालांकि, LKL सामान्यतः किसी syscall के दौरान दूसरे kernel thread को interrupt नहीं करने देता। Race campaigns के लिए, चुनी हुई lock/unlock और lifetime boundaries के आसपास `schedule()` points डालें, फिर हर yield पर harness को अगला client randomly चुनने दें। इन points को चुनिंदा जगहों पर ही रखें, क्योंकि हर point scheduling search space को कई गुना बढ़ा देता है। Researchers द्वारा बताया गया randomized scheduler upstream Binder fuzzer का हिस्सा **नहीं** है।<sup>[[15]](#references)</sup>

#### Serialized regression seeds बनाएँ और replay करें

Upstream harness एक compatible `libprotobuf-mutator` version pin करता है, `LKL_FUZZING=1` के साथ LKL fuzzing instrumentation और KASAN सक्षम करता है, और Binder के लिए `MMU=1` के साथ `CONFIG_MMU` सक्षम करता है।<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

जानबूझकर असुरक्षित revision checkout करने या upstream में दस्तावेज़ीकृत rollback patches लागू करने के बाद, एक serialized seed को ad-hoc C proof of concept में इसे फिर से बनाने के बजाय, पूरे multi-client state transition को दोहराने के लिए इस्तेमाल किया जा सकता है:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

प्राप्त KASAN use-after-free इस बात की पुष्टि करता है कि seed, vulnerable lifetime path तक पहुँचा। यह kernel code execution या privilege escalation के लिए आवश्यक बाद के primitives को प्रदर्शित **नहीं** करता।<sup>[[16]](#references)</sup>

## एकल-मशीन विविधता ट्रिक (Jackalope-Style)

**Generative novelty** को **coverage reuse** के साथ हाइब्रिड करने का एक व्यावहारिक तरीका है कि persistent server के विरुद्ध कम समय तक चलने वाले workers को **restart** किया जाए। हर worker खाली corpus से शुरू होता है, `T` सेकंड बाद sync करता है, संयुक्त corpus पर और `T` सेकंड चलता है, फिर दोबारा sync करता है और बाहर निकल जाता है। इससे संचित coverage का लाभ उठाते हुए हर generation में **नई संरचनाएँ** मिलती हैं।<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**क्रमिक workers (उदाहरण loop):**

<details>
<summary>Jackalope worker पुनरारंभ loop</summary>

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

- `-in empty` हर generation में **नया corpus** बनाता है।
- `-server_update_interval T` **देरी से sync** का अनुमानित व्यवहार देता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync डिफ़ॉल्ट रूप से छोड़ दिया जाता है** (`-skip_initial_server_sync` की ज़रूरत नहीं)।
- सबसे अच्छा `T` **target पर निर्भर करता है**; worker द्वारा ज़्यादातर “आसान” coverage खोज लेने के बाद इसे बदलना आम तौर पर सबसे अच्छा काम करता है।

## कठिनाई से Harness किए जाने वाले Targets के लिए Snapshot Fuzzing

जब आप जिस code को test करना चाहते हैं, वह **बड़ी setup लागत** के बाद ही reachable होता है (VM boot करना, login पूरा करना, packet पाना, container parse करना, service initialize करना), तो एक उपयोगी विकल्प **snapshot fuzzing** है: तैयार process या VM state capture करें, हर test case को target के input path में डालें, crash/timeout तक execute करें और snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने की ज़रूरत नहीं पड़ती। यह **network services**, **firmware**, **post-auth attack surfaces** और **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ, जब तक वांछित state तैयार न हो जाए।
2. उस समय **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, यदि समर्थित हो, तो केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को व्यावहारिक रूप से पहले महँगे parse/dispatch step के जितना संभव हो उतना करीब रखें, जैसे `recv`/`read` के बाद या packet-deserialization point पर, और target द्वारा उपयोग किए जाने वाले input buffer को रिकॉर्ड करें। यह adaptive-placement principle का पालन करता है: दोहराए जाने वाले काम से बचने के लिए snapshot को input processing के और भीतर ले जाएँ।<sup>[[11]](#references)</sup>

## MAccConc के साथ Linux Kernel Race Exploration

[MAccConc](https://github.com/googleprojectzero/MAccConc) timing-sensitive Linux-kernel races को दोहराए जा सकने वाले memory-access schedules में बदलता है। यह दो-context **A-B-A** executions को अपने-आप enumerate कर सकता है या analyst को terminal UI/GUI में order constraints लागू करने देता है। यह complete concurrency fuzzer के बजाय experimental research tooling है: फिलहाल इसके लिए LLVM 23+ और project का patched kernel चाहिए, command-line tools दो test threads का समर्थन करते हैं, और प्रस्तावित userspace fuzzing layer लागू नहीं है।<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication points एकत्र करें

KASAN outline callbacks और patched KCOV memory-record support के साथ instrumented kernel build करें। Project README यह भी सुझाता है कि call stacks को उपयोगी बनाए रखने के लिए sibling-call optimization बंद कर दें।<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) instrument किए गए accesses को helper calls में बदल देता है। MAccConc kernel patches `asan-opt-same-temp` को disable करते हैं, ताकि लगातार होने वाले accesses merge न हों; जब global-variable races दिखनी ज़रूरी हों, तो `asan-opt-globals` optimization को भी disable करें। KCOV से परिणामी records userspace तक पहुँचते हैं। अलग-अलग execution contexts के accesses की तुलना करें और उन pairs को रखें जिनकी byte ranges overlap करती हों और जिनमें कम-से-कम एक तरफ write हो; lifetime transitions को भी candidate बनाने के लिए `kfree()` को write की तरह model करें।<sup>[[17]](#references)</sup>

शुरू करने वाले task से बाहर जाने वाले काम, जैसे packet processing या RCU callbacks, के लिए subsystem को KCOV remote-coverage handle आगे पहुँचाना होगा। Upstream remote KCOV opt-in है और arbitrary background work के लिए अपने-आप उपलब्ध नहीं होता, इसलिए propagation न होने पर कोई वास्तविक interaction दिखाई नहीं दे सकता।<sup>[[17]](#references)[[19]](#references)</sup>

### हर run में उसी dynamic access की पहचान करें

किसी ठोस heap address के आधार पर replay न करें, क्योंकि हर allocation के बाद यह बदल सकता है; न ही केवल instruction address के आधार पर replay करें, क्योंकि `memcpy()` और `spin_lock()` जैसे helpers के भीतर यह अस्पष्ट होता है। MAccConc **count-augmented stack trace** का उपयोग करता है: हर frame में callee और उसके caller के भीतर invocation count की पहचान होती है, और अंतिम element memory-access instruction की पहचान करता है। SanitizerCoverage के function-entry/exit records से userspace इस dynamic identifier को फिर से बना सकता है, जो address में बदलाव और असंबंधित control-flow noise के बावजूद स्थिर रहता है।<sup>[[17]](#references)</sup>

### Candidate pairs को forced schedules में बदलें

Patched `KCOV_SET_DI` ioctl, count-augmented access identifier को shared-flag action से जोड़ता है।<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | चुने गए access से ठीक पहले flag *N* set करें। |
| `DI_STACK_WAIT` | चुने गए access से पहले, flag *N* set होने तक या configured limit समाप्त होने तक spin करें। |
| `DI_STACK_WAKE_POST` | चुने गए access के ठीक बाद flag *N* set करें। |

आंशिक **A-happens-before-B** constraint के लिए, A पर `DI_STACK_WAKE_POST` और B पर उसी flag के साथ `DI_STACK_WAIT` attach करें। पूरी तरह निर्दिष्ट two-context schedule के लिए, B को blocked शुरू करें, फिर A से B को wake करवाएँ और पहले transfer point पर wait करवाएँ; अगले transfer पर B उलटा operation करता है। यह deterministic context switching की तरह काम करता है और automatic A-B-A explorer इसी का उपयोग करता है।<sup>[[17]](#references)</sup>

एक न्यूनतम campaign में four-hook test case (`test_setup`, दो thread functions, और `test_end`) को shared library के रूप में compile करें, बिना constraints वाला trace collect करें, फिर A-B-A candidates को enumerate करें या suspicious accesses के आसपास manual constraints जोड़ें।<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts को सफल reorderings से अलग समझें: कोई requested order असंभव हो सकता है, क्योंकि कोई lock या initialization/publication dependency दूसरे context को उसके injection point तक पहुँचने से रोकती है। KASAN के blind spots का भी ध्यान रखें: direct stack accesses आम तौर पर hook नहीं होते, जब तक उनके out of bounds होने की संभावना न हो; default optimization के साथ globals को छोड़ दिया जाता है; और मौजूदा compilers ASAN और TSAN hooks एक साथ emit नहीं कर सकते। अंत में, guest के panic होने पर prototype अपना KCOV buffer खो देता है, इसलिए एक स्वतंत्र crash console/oracle बनाए रखें।<sup>[[17]](#references)</sup>

भविष्य के concurrency-guided fuzzing के लिए, हर input या syscall के memory-access summaries रिकॉर्ड करें, उन operations के जोड़े बनाएँ जो cross-context communication points बना सकते हैं, और फिर केवल उन्हीं combinations को explore करें। VM snapshots global state और addresses को स्थिर रखते हैं; snapshots के बिना, allocation-site metadata का इस्तेमाल runs के बीच objects को abstract करने के लिए किया जा सकता है। यह एक प्रस्तावित extension है, मौजूदा MAccConc userspace tools की सुविधा नहीं।<sup>[[17]](#references)</sup>

## Harness Introspection: उथले Fuzzers का जल्दी पता लगाएँ

जब कोई campaign रुक जाता है, तो अक्सर समस्या mutator में नहीं, बल्कि **harness** में होती है। ऐसे functions खोजने के लिए **reachability/coverage introspection** का उपयोग करें जो statically रूप से आपके fuzz target से reachable हैं, लेकिन dynamic रूप से शायद ही कभी या कभी cover नहीं होते। ऐसे functions आम तौर पर तीन में से किसी एक समस्या की ओर संकेत करते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में एक पूरा feature family मौजूद नहीं है।
- Target को वास्तव में एक बहुत बड़े “सब कुछ करने वाले” harness के बजाय **दूसरे harness** की ज़रूरत है।

यदि आप OSS-Fuzz / ClusterFuzz-शैली के workflows का उपयोग करते हैं, तो Fuzz Introspector static reachability की तुलना runtime coverage से कर सकता है और timed run या public corpus से reports बना सकता है।<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

रिपोर्ट का उपयोग करके तय करें कि किसी untested parser path के लिए नया harness जोड़ना है, किसी खास feature के लिए corpus बढ़ाना है, या monolithic harness को छोटे entry points में बाँटना है।

## Graph-First Fuzz Target Selection And Mutation Triage

अगर आपके पास पहले से **static-analysis findings**, **mutation-testing survivors** और **coverage reports** हैं, तो उन्हें अलग-अलग सूचियों की तरह triage न करें। पहले **call graph** बनाएँ, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability** और बाहरी findings को annotate करें, फिर graph से जुड़े सवाल पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- कौन-से high-complexity functions untrusted input से reachable हैं?
- कौन-से mutation survivors, parsers/handlers से security-critical code तक जाने वाले paths पर हैं?
- कौन-से functions असामान्य रूप से बड़े **blast radius** वाले architectural choke points हैं?

इससे आम तौर पर सिर्फ़ "सबसे कम coverage" के आधार पर बेहतर fuzz targets मिलते हैं। **High complexity** और पुष्टि की गई **external reachability** वाला parser/decoder, कम coverage वाले लेकिन attacker-controlled path से न जुड़े isolated internal helper की तुलना में बेहतर harness candidate है।

### व्यावहारिक triage workflow

1. Codebase से **code graph** बनाएँ और हर function के complexity/branch metrics निकालें।
2. ऐसे **entrypoints** की सूची बनाएँ जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. Candidate functions तक इन entrypoints से **path queries** चलाएँ, ताकि reachable attack surface को केवल dead/internal code से अलग किया जा सके।
4. उन nodes को प्राथमिकता दें जिनमें ये गुण एक साथ हों:
   - high **cyclomatic complexity**
   - untrusted input से पुष्टि की गई **reachability**
   - high **blast radius** या कई downstream dependents
   - सहायक साक्ष्य, जैसे **SARIF** findings, audit notes या mutation survivors
5. सबसे अच्छे score वाले nodes के लिए पहले focused harnesses लिखें, खासकर **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent बनाम actionable

Mutation testing से अक्सर noisy survivor list मिलती है। हर survivor को security gap मानने से पहले, graph का उपयोग करके पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths, mutated check से अधिक मजबूत invariants द्वारा constrained हैं?
- क्या node dead code, केवल formatting वाले logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable या संरचनात्मक रूप से constrained रहते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को प्रभावित करते हैं, उन्हें इन कामों के लिए आगे बढ़ाएँ:

- नए fuzz harnesses
- सीधे property/invariant tests
- लक्षित edge-case vectors

### बाहरी findings को graph पर correlate करें

अगर आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर project करें और impact बढ़ाकर देखने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** निकालें
- जाँचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- आस-पास की उन findings को समूहित करें जो एक ही choke point पर केंद्रित होती हैं

यह तय करते समय उपयोगी है कि किसी खास function पर fuzzing का समय लगाना चाहिए या नहीं: **reachable**, **complex** और पहले से **SAST hits** वाला node, अक्सर ऐसे node से बेहतर target होता है जो केवल complex हो लेकिन attacker path से न जुड़ा हो।

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

महत्वपूर्ण methodology इनका intersection है: **जटिलता x एक्सपोज़र x प्रभाव**। सबसे अधिक अपेक्षित security value वाले fuzz targets चुनने के लिए graph का उपयोग करें, फिर mutation survivors के आधार पर तय करें कि आपके harness को किन boundaries और invariants पर ज़ोर देना चाहिए।<sup>[[5]](#references)</sup>

## gosentry के साथ Go Fuzzing: अधिक शक्तिशाली Engine, Typed Inputs और Differential Checks

अगर किसी Go target में पहले से native `testing.F` harness है, तो उसे अपग्रेड करने का एक व्यावहारिक तरीका उसी harness को [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाना है। यह एक forked Go toolchain है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

यह तब उपयोगी होता है जब native Go fuzzer **कठिन comparisons**, **typed inputs**, या **parser-heavy formats** पर अटक जाता है। Methodology वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का इस्तेमाल जारी रखें।
- उसी harness का दोबारा इस्तेमाल करें, लेकिन इसे stock toolchain के बजाय gosentry के `go` binary से चलाएँ।
- मिले हुए campaign को सामान्य coverage-guided run मानें, लेकिन इसमें LibAFL scheduling/mutation और बेहतर आसपास के detectors होते हैं।

### चुपचाप होने वाली विफलताओं को fuzz findings में बदलें

Go assessments में एक आम समस्या यह है कि खतरनाक व्यवहार अक्सर डिफ़ॉल्ट रूप से **crash** नहीं करता। gosentry के साथ, आप “खराब लेकिन चुपचाप होने वाली” कई तरह की स्थितियों को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` चुनिंदा logging/error paths को crashes की तरह व्यवहार करवाता है (यह `log.Fatal`-शैली के उन code paths के लिए उपयोगी है जो अन्यथा सिर्फ़ log करते हैं और आगे चलते रहते हैं)।
- `--catch-races=true` नए खोजे गए queue entries को Go race detector से दोबारा चलाता है।
- `--catch-leaks=true` नए queue entries को `goleak` से दोबारा चलाता है और goroutine leaks मिलने पर रुक जाता है।
- LibAFL hang handling **infinite loops / बहुत धीमे inputs** को timeouts के रूप में गायब होने देने के बजाय fuzz findings के रूप में बनाए रखती है।
- डिफ़ॉल्ट रूप से अंतर्निहित arithmetic overflow checks, साथ ही go-panikint-शैली के instrumentation के ज़रिए वैकल्पिक truncation checks।

यह उन targets के लिए विशेष रूप से उपयोगी है जहाँ security impact memory corruption के बजाय **बिना panic के parser failure**, **concurrency bug**, या केवल **DoS वाला hang** होता है।

### Typed Go APIs के लिए struct-aware fuzzing

Native Go fuzzing में मुख्यतः `[]byte`, `string`, और numbers जैसे scalars अपेक्षित होते हैं। अगर test किया जा रहा code typed objects लेता है, तो gosentry सीधे **composite values** (structs, slices, arrays, pointers) को fuzz कर सकता है, जबकि उनके नीचे bytes को mutate करना जारी रखता है।<sup>[[7]](#references)[[8]](#references)</sup>

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

इसका उपयोग तब करें जब केवल fuzzing के लिए fake wire format बनाने से harness-only parsing code के पीछे logic bugs छिप जाएँ। Differential या grammar-based campaigns के लिए, harness input को एक single `[]byte` या `string` रखें और इसके बजाय callback के अंदर parse करें।

### Parsers और protocol inputs के लिए grammar-based fuzzing

Parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules की एक JSON array होती है, और harness को आमतौर पर एक single `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- जब byte-level mutations अधिकतर शुरुआती syntax checks में ही विफल हो जाते हैं, तो grammar mode का उपयोग करें।
- Grammar को पूरी specification के बजाय भाषा/protocol के **security-relevant subset** तक सीमित रखें।
- Integer, length और state-machine की सीमाओं को stress करने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अब भी **bytes/strings** ही मिलते हैं, इसलिए parsing और semantic checks harness किए गए code के भीतर ही होते हैं।

### Differential fuzzing: केवल crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक प्रभावी तरीका **grammar-based differential fuzzing** है: valid structured inputs जनरेट करें और उन्हें दो parsers, clients या state-transition engines को दें।<sup>[[7]](#references)[[8]](#references)</sup>

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

इन्हें findings मानें:

- एक implementation panic करता है, जबकि दूसरा साफ़ तौर पर reject करता है
- स्वीकार/अस्वीकार किए गए input में mismatch
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में अंतर

यह **consensus mismatches**, **parser ambiguity**, और **spec-vs-implementation drift** खोजने का एक व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing से अक्सर नहीं पकड़ा जा सकता।

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### coverage रिपोर्टिंग के लिए campaign corpus का पुनः उपयोग करें

campaign के बाद, अलग corpus को manually export किए बिना Go coverage रिपोर्ट बनाने के लिए सहेजे गए queue corpus को दोबारा चलाएँ।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

उसी package से और उसी `-fuzz` target के साथ command चलाएँ, ताकि gosentry सही cached campaign state resolve करे।



## References

- [1] [म्यूटेशनल grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing की गहराई में](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [पाँच साल बाद AFLNet: Coverage-Guided Protocol Fuzzing पर](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark कोड को graphs में बदलता है](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing में आधे toolkit की कमी थी। इसे ठीक करने के लिए हमने toolchain fork किया।](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots का उपयोग करके Stateful Network Protocols के लिए एक तेज़ Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar नहीं? कोई समस्या नहीं: System-Call Descriptions के बिना Linux Kernel को Fuzzing करने की दिशा में](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive और Mutable Snapshots के साथ Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path और caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build और regression-seed documentation](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: नियंत्रित Memory-Access Interleavings के साथ Linux Kernel Race Conditions की पड़ताल](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing के लिए code coverage](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
