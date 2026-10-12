# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing** में inputs को mutate किया जाता है, लेकिन वे **grammar-valid** बने रहते हैं। Coverage-guided mode में केवल वे samples corpus seeds के रूप में सहेजे जाते हैं जो **नई coverage** ट्रिगर करते हैं। **Language targets** (parsers, interpreters, engines) के लिए इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** ज़रूरी होती हैं, जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds ढूँढ़ता है जो अलग-अलग `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow को बनाए नहीं रखता**। इसलिए “bug के करीब” वाला sample हटा दिया जाता है, क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** के साथ random recombination महँगा हो जाता है और coverage feedback search को दिशा नहीं देता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए **mutational और generative phases को मिलाने** या generation को **function chaining** patterns की ओर झुकाने पर विचार करें (सिर्फ coverage की ओर नहीं)।<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होती है: नई coverage वाला sample तुरंत सहेज लिया जाता है और अक्सर उसके बड़े unchanged हिस्से भी बने रहते हैं। समय के साथ corpora में **लगभग एक जैसे duplicates** जमा हो जाते हैं और structural diversity कम हो जाती है। Aggressive minimization से उपयोगी context हट सकता है, इसलिए एक व्यावहारिक समझौता है **grammar-aware minimization**, जो **minimum token threshold** पर रुक जाती है (noise कम करते हुए आसपास की पर्याप्त structure बनाए रखती है, ताकि mutations करना आसान रहे)।<sup>[[1]](#references)</sup>

Mutational fuzzing के लिए corpus का एक व्यावहारिक नियम है: near-duplicates के बड़े ढेर के बजाय **ऐसे कम seeds चुनें जिनकी structure अलग-अलग हो और जो coverage को अधिकतम करें**। व्यवहार में, इसका आम तौर पर मतलब यह है।<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem के file sets)।
- हर valid sample को रखने के बजाय उन्हें **coverage-based corpus minimization** से छाँटें।
- Seeds को **इतना छोटा रखें** कि mutations meaningful fields पर लागू हों, न कि ज़्यादातर cycles irrelevant bytes पर खर्च हों।
- बड़े harness/instrumentation बदलावों के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “सबसे अच्छा” corpus भी बदल जाता है।

## Magic Values के लिए Comparison-Aware Mutation

Fuzzers के plateau पर पहुँचने का एक आम कारण syntax नहीं, बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums या parser dispatch values, जिन्हें `memcmp`, switch tables या cascaded comparisons से जाँचा जाता है। Pure random mutation इन values का byte-by-byte अनुमान लगाने में cycles बर्बाद करती है।

ऐसे targets के लिए **comparison tracing** का उपयोग करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows), ताकि fuzzer असफल comparisons के operands देख सके और mutations को उन values की ओर निर्देशित कर सके जो उन्हें पूरा करती हैं।<sup>[[3]](#references)</sup>

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

- यह खास तौर पर तब उपयोगी होता है जब target, **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे गहरे logic तक पहुँच को सीमित करता है।
- इसे वास्तविक samples, protocol specs या debug logs से निकाले गए **dictionaries** के साथ इस्तेमाल करें। Grammar tokens, chunk names, verbs और delimiters वाला एक छोटा dictionary अक्सर किसी विशाल generic wordlist से ज़्यादा उपयोगी होता है।
- अगर target कई क्रमिक checks करता है, तो पहले सबसे शुरुआती “magic” comparisons हल करें और फिर बने हुए corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## जब Edge Coverage अलग-अलग Paths में फ़र्क नहीं कर पाता, तब बेहतर Feedback

सामान्य edge coverage दो executions में फ़र्क नहीं कर सकता, अगर वे अलग-अलग callers से होकर उसी helper तक पहुँचते हैं या किसी function के भीतर branch combinations के अलग-अलग रास्ते लेते हैं। यह shared decoders, protocol dispatchers और interpreter helpers में महत्वपूर्ण है, जहाँ किसी edge तक पहुँचने का **route**, live state तय करता है। हर calling context को सीधे track करना भी जोखिम भरा है: coverage map और queue बहुत तेज़ी से बढ़ सकते हैं। इसलिए context-sensitive fuzzing के शोध में पूरे call graph को context-sensitive मानने के बजाय केवल आशाजनक contexts को बेहतर बनाने की सलाह दी जाती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds सामान्य edge coverage के अलावा **Ball-Larus per-function path coverage** भी देते हैं। यह किसी function के हर acyclic path को एक feature देता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations में फ़र्क करता है, लेकिन **loop iterations की संख्या में नहीं**। शुरुआत relaxed level `1` से करें, फिर सख्त modes को केवल संदिग्ध parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या exponentially बढ़ सकती है।<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

कई सुरक्षा-संबंधी स्थानों से बुलाए जाने वाले helper के लिए, LTO mode हर function path को उसके तत्काल call site के साथ जोड़ सकता है:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** अधिक समृद्ध feedback सावधानी से लागू करें और इसके coverage-map/queue की लागत पर नज़र रखें।<sup>[[13]](#references)[[14]](#references)</sup>

- एक सामान्य edge-coverage instance समानांतर में चलाएँ; समृद्ध feedback तभी उपयोगी है जब अतिरिक्त queue/map लागत प्रति सेकंड executions को बहुत कम न करे।
- बड़े template-heavy libraries या generic utility code के कारण map का अधिकांश हिस्सा भर रहा हो, तो path/caller instrumentation सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- अत्यधिक acyclic paths वाले functions को AFL++ छोड़ सकता है; compilation के दौरान आने वाली warnings इस बात का संकेत हैं कि target के लिए allowlisting या कम strict level की ज़रूरत है।
- Caller + path coverage केवल एक caller depth का समर्थन करता है। इसे अधिक गहरे context stacks के साथ न मिलाएँ।
- Path IDs, LLVM के major versions के बीच बदल सकते हैं। किसी campaign के लिए toolchain को स्थिर रखें और PATH-आधारित corpora को ऐसे synchronize न करें मानो उनके feature IDs अलग-अलग builds में स्थिर हों।
- यह feedback `CMPLOG` का पूरक है: comparison tracing बताता है कि guard को **कौन-सी value पार करती है**, जबकि path/caller feedback यह बनाए रखता है कि **किस route और branch combination से वहाँ पहुँचे**।

## Stateful Fuzzing: Sequences ही Seeds हैं

**Protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए अक्सर दिलचस्प इकाई कोई एक blob नहीं, बल्कि **message sequence** होती है। पूरे transcript को एक file में जोड़कर बिना सोचे-समझे mutate करना आम तौर पर अक्षम होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है, जबकि fragile state तक केवल बाद वाला message पहुँचता है।<sup>[[4]](#references)</sup>

एक अधिक प्रभावी तरीका है **sequence को ही seed** मानना और **observable state** (response codes, protocol states, parser phases, लौटाए गए object types) को अतिरिक्त feedback के रूप में इस्तेमाल करना।<sup>[[4]](#references)</sup>

- **Valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- पिछले responses से मिले identifiers और server-generated values को cache करें, जब अगला step उन पर निर्भर हो।
- पूरे serialized transcript को एक opaque blob की तरह mutate करने के बजाय, प्रति-message mutation/splicing को प्राथमिकता दें।
- यदि protocol अर्थपूर्ण response codes देता है, तो उन्हें **सस्ते state oracle** की तरह इस्तेमाल करके उन sequences को प्राथमिकता दें जो आगे तक पहुँचती हैं।

यही कारण है कि authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing से छूट जाते हैं: fuzzer को केवल structure नहीं, बल्कि **क्रम, state और dependencies** भी बनाए रखनी होती हैं।<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Edge coverage अधिक होने पर भी IPC-driver bugs छूट सकते हैं, क्योंकि coverage **object ownership, reference counts, pending messages, cleanup order या thread interleavings** नहीं बताती। [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) पेज driver object model समझाता है; यह उदाहरण fuzzer harness पर केंद्रित है। Android Binder एक उपयोगी मॉडल है: allocation और free paths, दोनों तक पहुँचना पर्याप्त नहीं है, यदि fuzzer कई processes से आवश्यक क्रम में उसी kernel object पर काम नहीं करवा सकता।<sup>[[15]](#references)</sup>

#### अलग-अलग `ioctl` buffers नहीं, protocol को model करें

एक test case को **client identity + operation + structured arguments** की ordered grammar के रूप में दर्शाएँ। Binder LKL fuzzer protobuf और `libprotobuf-mutator` का उपयोग करता है, जिसमें एक persistent context-manager client और दो सामान्य clients होते हैं। इसके बाद semantic harness उन संबंधों को बनाए रखता है जिन्हें blind byte mutation नष्ट कर देती।<sup>[[15]](#references)</sup>

- पहले के operations से लौटाए गए values को cache करें। उदाहरण के लिए, `BC_FREE_BUFFER` को पिछले `ioctl` से मिला transaction-buffer pointer दोबारा इस्तेमाल करना होगा।
- Valid default replies बनाएँ, ताकि synchronous transactions पूरी हो सकें और बाद के operations तक पहुँचना संभव रहे।
- असंभव transitions को अस्वीकार करें, जैसे self-transactions या एक ही target के लिए कई pending transactions।
- Singleton bootstrap state को per-input reset से बाहर रखें। Binder हर boot में केवल एक `BINDER_SET_CONTEXT_MGR` registration की अनुमति देता है, इसलिए उस client को बार-बार नष्ट करके फिर बनाने से बाद के inputs invalid हो जाएँगे।

Lifetime-race का एक उपयोगी template है: एक client से object transfer करवाएँ, thread या process cleanup शुरू करें, और उसी समय receiving client से transaction buffer release करवाएँ। CVE-2020-0423 के उदाहरण में, `BINDER_TYPE_WEAK_BINDER` transfer के बाद `BINDER_THREAD_EXIT` और `BC_FREE_BUFFER` के बीच race से embedded `binder_work` free हो सकता था, जबकि exiting thread का cleanup path अब भी उसका उपयोग कर रहा होता।<sup>[[15]](#references)</sup>

#### userspace kernel में नियंत्रित interleavings फिर से शामिल करें

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) असली kernel code को userspace harness में link करती है और `lkl_syscall` के ज़रिए उसका syscall interface उपलब्ध कराती है। इससे एक ही process में protobuf state, coverage और KASAN का समन्वय आसान हो जाता है। हालाँकि, LKL आम तौर पर किसी syscall के दौरान दूसरे kernel thread को interrupt नहीं करने देती। Race campaigns के लिए, चुने हुए lock/unlock और lifetime boundaries के आसपास `schedule()` points डालें, फिर हर yield पर harness को अगला client बेतरतीब ढंग से चुनने दें। इन points को चुनिंदा जगहों तक सीमित रखें, क्योंकि हर point scheduling search space को कई गुना बढ़ा देता है। Researchers द्वारा बताया गया randomized scheduler upstream Binder fuzzer का हिस्सा **नहीं** है।<sup>[[15]](#references)</sup>

#### Serialized regression seeds बनाएँ और replay करें

Upstream harness एक संगत `libprotobuf-mutator` version को pin करता है, `LKL_FUZZING=1` के साथ LKL fuzzing instrumentation और KASAN सक्षम करता है, और Binder के लिए `MMU=1` के साथ `CONFIG_MMU` सक्षम करता है।<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

जानबूझकर असुरक्षित revision को चेक आउट करने या upstream में दर्ज rollback patches लागू करने के बाद, एक serialized seed पूरी multi-client state transition को फिर से उत्पन्न कर सकता है—इसके लिए ad-hoc C proof of concept को दोबारा बनाने की ज़रूरत नहीं होती:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

मिलने वाले KASAN use-after-free को इस बात की पुष्टि मानें कि seed कमजोर lifetime path तक पहुँचा। यह kernel code execution या privilege escalation के लिए ज़रूरी बाद के primitives को प्रदर्शित **नहीं** करता।<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty** को **coverage reuse** के साथ hybridize करने का एक व्यावहारिक तरीका है कि persistent server के विरुद्ध छोटे समय तक चलने वाले workers को restart किया जाए। हर worker खाली corpus से शुरू होता है, `T` सेकंड बाद sync करता है, संयुक्त corpus पर और `T` सेकंड चलता है, फिर दोबारा sync करता है और बाहर निकल जाता है। इससे संचित coverage का लाभ लेते हुए भी हर generation में **नई structures** मिलती हैं।<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**क्रमिक workers (उदाहरण loop):**

<details>
<summary>Jackalope worker पुनः आरंभ loop</summary>

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
- `-server_update_interval T` **देरी से sync** का अनुमान देता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync डिफ़ॉल्ट रूप से skip होता है** (`-skip_initial_server_sync` की ज़रूरत नहीं)।
- सबसे अच्छा `T` **target पर निर्भर करता है**; worker द्वारा ज़्यादातर “आसान” coverage खोज लेने के बाद switching करना आम तौर पर सबसे अच्छा काम करता है।

## मुश्किल से Harness किए जा सकने वाले Targets के लिए Snapshot Fuzzing

जब जिस code को आप test करना चाहते हैं, वह **बड़े setup cost** के बाद ही reachable होता है (VM boot करना, login पूरा करना, packet पाना, container parse करना, service initialize करना), तो **snapshot fuzzing** एक उपयोगी विकल्प है: तैयार process या VM state को capture करें, हर test case को target input path में inject करें, crash/timeout तक execute करें, और snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने की ज़रूरत नहीं रहती। यह **network services**, **firmware**, **post-auth attack surfaces**, और **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ जब तक इच्छित state तैयार न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, जब समर्थित हो, केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को पहले महँगे parse/dispatch step के जितना संभव हो उतना पास रखें, जैसे `recv`/`read` के बाद या packet-deserialization point पर, और target द्वारा इस्तेमाल किए गए input buffer को रिकॉर्ड करें। यह adaptive-placement principle का पालन करता है: काम को दोहराने से बचने के लिए snapshot को input processing में और भीतर ले जाना।<sup>[[11]](#references)</sup>

## Harness Introspection: Shallow Fuzzers को जल्दी खोजें

जब campaign रुक जाता है, तो समस्या अक्सर mutator में नहीं, बल्कि **harness** में होती है। ऐसे functions खोजने के लिए **reachability/coverage introspection** का उपयोग करें जो statically आपके fuzz target से reachable हैं, लेकिन runtime में शायद ही कभी या कभी भी covered नहीं होते। ऐसे functions आम तौर पर तीन में से किसी एक समस्या की ओर संकेत करते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी feature family का पूरा अभाव है।
- Target को वास्तव में एक बहुत बड़े “do everything” harness के बजाय **दूसरे harness** की ज़रूरत है।

अगर आप OSS-Fuzz / ClusterFuzz-style workflows इस्तेमाल करते हैं, तो Fuzz Introspector static reachability की runtime coverage से तुलना कर सकता है और timed run या public corpus से reports बना सकता है।<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

रिपोर्ट का उपयोग यह तय करने के लिए करें कि किसी ऐसे parser path के लिए नया harness जोड़ना है जिसका परीक्षण नहीं हुआ है, किसी विशिष्ट feature के लिए corpus बढ़ाना है, या किसी monolithic harness को छोटे entry points में बाँटना है।

## Graph-First Fuzz Target Selection And Mutation Triage

यदि आपके पास पहले से **static-analysis findings**, **mutation-testing survivors** और **coverage reports** हैं, तो उन्हें अलग-अलग सूचियों के रूप में triage न करें। पहले **call graph** बनाएँ, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability** और बाहरी findings को annotate करें, फिर graph के आधार पर सवाल पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- कौन-से high-complexity functions untrusted input से reachable हैं?
- कौन-से mutation survivors, parsers/handlers से security-critical code तक जाने वाले paths पर मौजूद हैं?
- कौन-से functions असामान्य रूप से बड़े **blast radius** वाले architectural choke points हैं?

इससे अक्सर केवल "सबसे कम coverage" को देखकर fuzz targets चुनने से बेहतर targets सामने आते हैं। **High complexity** और पक्की **external reachability** वाला parser/decoder, कमज़ोर coverage वाले ऐसे isolated internal helper से बेहतर harness candidate है जिसके पास attacker-controlled path नहीं है।

### व्यावहारिक triage workflow

1. Codebase से **code graph** बनाएँ और हर function के complexity/branch metrics निकालें।
2. उन **entrypoints** की सूची बनाएँ जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. Reachable attack surface को dead/internal-only code से अलग करने के लिए उन entrypoints से candidate functions तक **path queries** चलाएँ।
4. उन nodes को प्राथमिकता दें जिनमें ये बातें एक साथ हों:
   - high **cyclomatic complexity**
   - untrusted input से पुष्टि की गई **reachability**
   - बड़ा **blast radius** या कई downstream dependents
   - सहायक साक्ष्य, जैसे **SARIF** findings, audit notes या mutation survivors
5. सबसे अच्छे score वाले nodes के लिए पहले focused harnesses लिखें, खासकर **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent बनाम actionable

Mutation testing से अक्सर survivors की noisy list मिलती है। हर survivor को security gap मानने से पहले, graph का उपयोग करके पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths, mutated check से ज़्यादा मज़बूत invariants द्वारा constrained हैं?
- क्या node dead code, केवल formatting वाले logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable रहते हैं या संरचनात्मक रूप से constrained होते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths** या **security-critical arithmetic/parsing** को छूते हैं, उन्हें आगे बढ़ाकर इनमें शामिल करना चाहिए:

- नए fuzz harnesses
- सीधे property/invariant tests
- लक्षित edge-case vectors

### बाहरी findings को graph पर correlate करें

यदि आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर project करें और impact का विस्तार करने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** निकालें
- जाँचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- आस-पास की उन findings को cluster करें जो एक ही choke point पर आकर मिलती हैं

यह तय करते समय उपयोगी है कि किसी खास function पर fuzzing का समय लगाया जाए या नहीं: जो node **reachable**, **complex** हो और जिस पर पहले से **SAST hits** हों, वह अक्सर ऐसे node से बेहतर target होता है जो केवल complex हो और जिसके पास attacker path न हो।

Trailmark के साथ उदाहरण workflow।<sup>[[6]](#references)</sup>

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

महत्वपूर्ण कार्यप्रणाली इनका प्रतिच्छेदन है: **जटिलता x एक्सपोज़र x प्रभाव**। सबसे अधिक अपेक्षित सुरक्षा-मूल्य वाले fuzz targets चुनने के लिए ग्राफ़ का उपयोग करें, फिर mutation survivors के आधार पर तय करें कि आपके harness को किन सीमाओं और invariants पर ज़ोर देना चाहिए।<sup>[[5]](#references)</sup>

## gosentry के साथ Go Fuzzing: अधिक शक्तिशाली इंजन, टाइप किए गए इनपुट और डिफरेंशियल जाँचें

यदि किसी Go target में पहले से native `testing.F` harness है, तो उसे [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाना एक व्यावहारिक अपग्रेड-पथ है। यह एक forked Go toolchain है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

यह तब उपयोगी है जब native Go fuzzer **hard comparisons**, **typed inputs** या **parser-heavy formats** पर अटक जाता है। कार्यप्रणाली वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का उपयोग जारी रखें।
- वही harness फिर से इस्तेमाल करें, लेकिन इसे stock toolchain के बजाय gosentry के `go` binary से चलाएँ।
- परिणामी campaign को सामान्य coverage-guided run की तरह लें, लेकिन इसमें LibAFL scheduling/mutation और बेहतर आसपास के detectors का उपयोग होता है।

### Silent failures को fuzz findings में बदलें

Go assessments में बार-बार आने वाली समस्या यह है कि खतरनाक व्यवहार अक्सर डिफ़ॉल्ट रूप से **crash** नहीं करता। gosentry के साथ, “खराब लेकिन silent” स्थितियों की कई श्रेणियों को findings में बदला जा सकता है।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` चुने हुए logging/error paths को crashes की तरह व्यवहार कराने के लिए (यह `log.Fatal`-शैली के उन code paths के लिए उपयोगी है जो अन्यथा केवल log करके आगे चलते रहते हैं)।
- `--catch-races=true` नए खोजे गए queue entries को Go race detector के साथ फिर से चलाने के लिए।
- `--catch-leaks=true` नए queue entries को `goleak` के साथ फिर से चलाने और goroutine leaks मिलने पर रोकने के लिए।
- LibAFL का hang handling, ताकि **infinite loops / बहुत धीमे inputs** timeouts के रूप में गायब होने के बजाय fuzz findings बने रहें।
- डिफ़ॉल्ट रूप से built-in arithmetic overflow checks, और go-panikint-शैली के instrumentation के ज़रिए वैकल्पिक truncation checks।

यह उन targets के लिए विशेष रूप से उपयोगी है जहाँ security impact memory corruption के बजाय **panicless parser failure**, **concurrency bug** या केवल **DoS hang** होता है।

### Typed Go APIs के लिए struct-aware fuzzing

Native Go fuzzing में मुख्य रूप से `[]byte`, `string` और numbers जैसे scalars अपेक्षित होते हैं। यदि test के तहत code typed objects का उपयोग करता है, तो gosentry सीधे **composite values** (structs, slices, arrays, pointers) को fuzz कर सकता है, जबकि नीचे bytes में mutation जारी रहती है।<sup>[[7]](#references)[[8]](#references)</sup>

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

Fuzzing के लिए fake wire format बनाते समय इसका उपयोग करने से harness-only parsing code के पीछे logic bugs छिप सकते हैं। Differential या grammar-based campaigns के लिए, harness input को एक single `[]byte` या `string` के रूप में रखें और इसके बजाय callback के अंदर parse करें।

### Parsers और protocol inputs के लिए Grammar-based fuzzing

Parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules का JSON array होता है, और harness को आम तौर पर एक single `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- जब byte-level mutations ज़्यादातर शुरुआती syntax checks में ही विफल हो जाएँ, तो grammar mode का उपयोग करें।
- Grammar को पूरी specification का मॉडल बनाने के बजाय, भाषा/प्रोटोकॉल के **security-relevant subset** तक सीमित रखें।
- Integer, length और state-machine की सीमाओं को परखने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अब भी **bytes/strings** ही मिलते हैं, इसलिए parsing और semantic checks harness किए गए code के भीतर ही होते हैं।

### Differential fuzzing: सिर्फ crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक प्रभावी तरीका है **grammar-based differential fuzzing**: वैध, संरचित inputs जनरेट करें और उन्हें दो parsers, clients या state-transition engines को दें।<sup>[[7]](#references)[[8]](#references)</sup>

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

इन बातों को निष्कर्ष मानें:

- एक implementation panic करता है, जबकि दूसरा साफ़ तौर पर अस्वीकार करता है
- स्वीकार/अस्वीकार किए गए इनपुट में बेमेल
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में अंतर

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का एक व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing से अक्सर नहीं पकड़ा जा सकता।

### Coverage reporting के लिए campaign corpus का फिर से उपयोग करें

Campaign के बाद, अलग corpus को मैन्युअल रूप से export किए बिना Go coverage report बनाने के लिए सेव किए गए queue corpus को फिर से चलाएँ।<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

कमांड को **उसी package** से और उसी `-fuzz` target के साथ चलाएँ, ताकि gosentry सही cached campaign state resolve करे।

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
{{#include ../banners/hacktricks-training.md}}
