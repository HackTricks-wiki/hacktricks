# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage बनाम Semantics

**mutational grammar fuzzing** में inputs को **grammar-valid** रखते हुए mutate किया जाता है। coverage-guided mode में केवल वे samples corpus seeds के रूप में save किए जाते हैं जो **new coverage** trigger करते हैं। **language targets** (parsers, interpreters, engines) के लिए, इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** आवश्यक होती हैं, जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds खोज लेता है जो अलग-अलग `document()` और `generate-id()` (या समान primitives) को exercise करते हैं, लेकिन **chained dataflow को preserve नहीं करता**, इसलिए “closer-to-bug” sample को drop कर दिया जाता है क्योंकि वह coverage नहीं जोड़ता। **3+ dependent steps** के साथ random recombination महँगा हो जाता है और coverage feedback search को guide नहीं करता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए **mutational और generative phases को hybridize** करने या generation को केवल coverage के बजाय **function chaining** patterns की ओर bias करने पर विचार करें।<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होता है: new-coverage sample तुरंत save कर लिया जाता है और अक्सर बड़े unchanged regions retain रहते हैं। समय के साथ corpora कम structural diversity वाले **near-duplicates** बन जाते हैं। Aggressive minimization useful context हटा सकता है, इसलिए एक practical compromise **grammar-aware minimization** है, जो **minimum token threshold** तक पहुँचने के बाद रुक जाती है (noise कम करते हुए इतना surrounding structure बनाए रखना कि mutation-friendly बना रहे)।<sup>[[1]](#references)</sup>

mutational fuzzing के लिए एक practical corpus rule है: near-duplicates के बड़े ढेर के बजाय **छोटे और structurally different seeds का ऐसा set रखें जो coverage को maximize करे**। व्यवहार में, इसका सामान्यतः निम्न अर्थ होता है।<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem से file sets)।
- हर valid sample रखने के बजाय उन्हें **coverage-based corpus minimization** से distill करें।
- Seeds को इतना **छोटा रखें** कि mutations meaningful fields पर land करें, न कि अधिकांश cycles irrelevant bytes पर खर्च हों।
- बड़े harness/instrumentation changes के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Magic Values के लिए Comparison-Aware Mutation

Fuzzers के plateau करने का एक common कारण syntax नहीं बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums या `memcmp`, switch tables अथवा cascaded comparisons द्वारा guarded parser dispatch values। Pure random mutation इन values का byte-by-byte अनुमान लगाने में cycles बर्बाद करता है।

इन targets के लिए **comparison tracing** (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows) का उपयोग करें, ताकि fuzzer failed comparisons से operands observe कर सके और mutations को उन values की ओर bias कर सके जो उन्हें satisfy करती हैं।<sup>[[3]](#references)</sup>
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

- यह विशेष रूप से तब उपयोगी है जब target deep logic को **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे रखता है।
- इसे real samples, protocol specs, या debug logs से निकाले गए **dictionaries** के साथ उपयोग करें। grammar tokens, chunk names, verbs, और delimiters वाला छोटा dictionary अक्सर massive generic wordlist से अधिक मूल्यवान होता है।
- यदि target कई sequential checks करता है, तो पहले सबसे शुरुआती “magic” comparisons को हल करें और फिर resulting corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## जब Edge Coverage अलग-अलग Paths को अलग नहीं कर पाती, तब अधिक समृद्ध Feedback

Normal edge coverage उन दो executions के बीच अंतर नहीं कर सकती जो अलग-अलग callers के माध्यम से उसी helper को traverse करती हैं या किसी function के अंदर अलग-अलग branch combinations लेती हैं। यह shared decoders, protocol dispatchers, और interpreter helpers में महत्वपूर्ण है, जहाँ किसी edge तक पहुँचने वाला **route** live state निर्धारित करता है। हर calling context को naively track करना भी खतरनाक है: coverage map और queue बहुत बड़े हो सकते हैं। इसलिए context-sensitive fuzzing research पूरे call graph को context-sensitive मानने के बजाय केवल promising contexts को refine करने की सलाह देती है।<sup>[[14]](#references)</sup>

हाल के AFL++ builds normal edge coverage के अतिरिक्त **Ball-Larus per-function path coverage** प्रदान करते हैं। यह किसी function से होकर जाने वाले प्रत्येक acyclic path को एक feature assign करता है; loop back-edges हटा दिए जाते हैं, इसलिए यह feedback branch combinations को अलग कर सकता है, लेकिन **loop iteration counts** को नहीं। relaxed level `1` से शुरू करें, फिर stricter modes को suspicious parser/state-machine code तक सीमित रखें, क्योंकि paths की संख्या exponentially बढ़ सकती है।<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
कई security-relevant sites से call किए जाने वाले helper के लिए, LTO mode प्रत्येक function path को उसके immediate call site के साथ combine कर सकता है:<sup>[[13]](#references)</sup>
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

- एक साधारण edge-coverage instance को parallel में चलाएँ; richer feedback तभी उपयोगी है जब अतिरिक्त queue/map cost प्रति सेकंड executions को नष्ट न करे।
- जब बड़ी template-heavy libraries या generic utility code map पर हावी हों, तो path/caller instrumentation को सीमित करने के लिए `AFL_LLVM_ALLOWLIST` का उपयोग करें।
- अत्यधिक acyclic paths वाले functions को AFL++ द्वारा skip किया जा सकता है; compilation के दौरान आने वाली warnings इस बात का संकेत हैं कि target को allowlisting या कम strict level की आवश्यकता है।
- Caller + path coverage केवल एक caller depth को support करता है। इसे deeper context stacks के साथ combine न करें।
- LLVM major versions के बीच Path IDs बदल सकते हैं। किसी campaign के लिए toolchain को fixed रखें और PATH-based corpora को इस तरह synchronize न करें जैसे उनके feature IDs अलग-अलग builds में stable हों।
- यह feedback `CMPLOG` का पूरक है: comparison tracing यह हल करता है कि guard को **कौन-सी value पार करती है**, जबकि path/caller feedback यह सुरक्षित रखता है कि **कौन-से route और branch combination ने वहाँ पहुँचाया**।

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए रुचिकर unit अक्सर कोई single blob नहीं, बल्कि एक **message sequence** होती है। पूरे transcript को एक file में concatenate करके blind तरीके से mutate करना आमतौर पर inefficient होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है, भले ही fragile state तक केवल बाद वाला message पहुँचता हो।<sup>[[4]](#references)</sup>

एक अधिक प्रभावी pattern यह है कि **sequence को स्वयं seed** माना जाए और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback के रूप में उपयोग किया जाए।<sup>[[4]](#references)</sup>

- **valid prefix messages** को स्थिर रखें और mutations को **transition-driving** message पर केंद्रित करें।
- जब अगला step उन पर निर्भर हो, तो पिछली responses से मिले identifiers और server-generated values को cache करें।
- पूरे serialized transcript को opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol meaningful response codes प्रदान करता है, तो sequences को प्राथमिकता देने के लिए उनका उपयोग **cheap state oracle** के रूप में करें, ताकि वे अधिक गहराई तक progress कर सकें।

यही कारण है कि authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing से छूट जाते हैं: fuzzer को केवल structure नहीं, बल्कि **order, state, और dependencies** को भी preserve करना पड़ता है।<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** को **coverage reuse** के साथ hybridize करने का एक व्यावहारिक तरीका यह है कि persistent server के विरुद्ध short-lived workers को **restart** किया जाए। प्रत्येक worker एक empty corpus से शुरू होता है, `T` seconds के बाद sync करता है, combined corpus पर अगले `T` seconds तक चलता है, फिर दोबारा sync करके exit करता है। इससे **हर generation में fresh structures** मिलती हैं और साथ ही accumulated coverage का लाभ भी मिलता है।<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (example loop):**

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

- `-in empty` हर generation में **fresh corpus** को force करता है।
- `-server_update_interval T` **delayed sync** का अनुमान लगाता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync** default रूप से skip किया जाता है (`-skip_initial_server_sync` की आवश्यकता नहीं है)।
- Optimal `T` **target-dependent** है; worker द्वारा अधिकांश “easy” coverage खोज लेने के बाद switching करना आमतौर पर सबसे अच्छा काम करता है।

## Hard-To-Harness Targets के लिए Snapshot Fuzzing

जब जिस code को आप test करना चाहते हैं, वह केवल **large setup cost** के बाद reachable होता है (VM boot करना, login पूरा करना, packet receive करना, container parse करना, service initialize करना), तब एक उपयोगी alternative **snapshot fuzzing** है: ready process या VM state को capture करें, प्रत्येक test case को target input path में inject करें, crash/timeout तक execute करें, और snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने से बचा जा सकता है और यह **network services**, **firmware**, **post-auth attack surfaces**, तथा **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक run करें जब तक interesting state ready न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. प्रत्येक test case के लिए, mutated input को सीधे relevant guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, supported होने पर केवल **dirty pages** restore करें, फिर दोहराएँ।

Snapshot को practical रूप से पहले expensive parse/dispatch step के जितना संभव हो उतना निकट रखें, जैसे `recv`/`read` या packet-deserialization point के बाद, और target द्वारा उपयोग किए गए input buffer को record करें। यह adaptive-placement principle का पालन करता है, जिसमें work को दोहराने से बचने के लिए snapshot को input processing में और deeper ले जाया जाता है।<sup>[[11]](#references)</sup>

## Harness Introspection: Shallow Fuzzers को जल्दी खोजें

जब कोई campaign stall हो जाता है, तो समस्या अक्सर mutator में नहीं बल्कि **harness** में होती है। उन functions को खोजने के लिए **reachability/coverage introspection** का उपयोग करें, जो आपके fuzz target से statically reachable हैं, लेकिन dynamic रूप से बहुत कम या कभी भी covered नहीं होते। ऐसे functions आमतौर पर तीन में से किसी एक समस्या का संकेत देते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी पूरे feature family की कमी है।
- Target को वास्तव में एक oversized “do everything” harness के बजाय **second harness** की आवश्यकता है।

यदि आप OSS-Fuzz / ClusterFuzz-style workflows का उपयोग करते हैं, तो Fuzz Introspector static reachability की तुलना runtime coverage से कर सकता है और timed run या public corpus से reports generate कर सकता है।<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
रिपोर्ट का उपयोग यह तय करने के लिए करें कि किसी अनपरीक्षित parser path के लिए नया harness जोड़ना है, किसी विशिष्ट feature के लिए corpus का विस्तार करना है, या monolithic harness को छोटे entry points में विभाजित करना है।

## Graph-First Fuzz Target Selection And Mutation Triage

यदि आपके पास पहले से **static-analysis findings**, **mutation-testing survivors**, और **coverage reports** हैं, तो उन्हें स्वतंत्र सूचियों के रूप में triage न करें। पहले एक **call graph** बनाएं, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, और बाहरी findings को annotate करें, फिर graph से जुड़े प्रश्न पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- untrusted input से कौन-से high-complexity functions तक पहुंचा जा सकता है?
- parsers/handlers से security-critical code तक जाने वाले paths पर कौन-से mutation survivors मौजूद हैं?
- कौन-से functions architectural choke points हैं और उनका **blast radius** असामान्य रूप से बड़ा है?

यह तरीका अक्सर केवल "lowest coverage" की तुलना में बेहतर fuzz targets सामने लाता है। **high complexity** और पुष्टि की गई **external reachability** वाला parser/decoder, कमजोर coverage वाले लेकिन attacker-controlled path से न जुड़े isolated internal helper की तुलना में अधिक मजबूत harness candidate होता है।

### Practical triage workflow

1. codebase से एक **code graph** बनाएं और प्रत्येक function के complexity/branch metrics निकालें।
2. ऐसे **entrypoints** की सूची बनाएं जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. candidate functions से **path queries** चलाकर यह अलग करें कि कौन-सा attack surface reachable है और कौन-सा dead/internal-only code है।
4. उन nodes को प्राथमिकता दें जिनमें ये विशेषताएं एक साथ हों:
- high **cyclomatic complexity**
- **untrusted input** से पुष्टि की गई **reachability**
- high **blast radius** या कई downstream dependents
- सहायक evidence, जैसे **SARIF** findings, audit notes, या mutation survivors
5. पहले सर्वोच्च score वाले nodes के लिए focused harnesses लिखें, विशेष रूप से **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent vs actionable

Mutation testing अक्सर survivors की noisy सूची तैयार करता है। प्रत्येक survivor को security gap मानने से पहले, graph का उपयोग करके ये प्रश्न पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths mutated check से अधिक मजबूत invariants द्वारा constrained हैं?
- क्या node dead code, केवल formatting logic, या high-impact arithmetic/parser path में स्थित है?

जो survivors unreachable या structurally constrained रहते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को प्रभावित करते हैं, उन्हें इनमें promote किया जाना चाहिए:

- नए fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### External findings को graph पर correlate करें

यदि आपका SAST pipeline **SARIF** export करता है, तो findings को **file + line range** के आधार पर graph nodes पर project करें और impact बढ़ाने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** compute करें
- जांचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- आसपास की findings को cluster करें जो एक ही choke point पर converge होती हैं

यह तब उपयोगी है जब किसी specific function पर fuzzing time खर्च करने का निर्णय लेना हो: **reachable**, **complex**, और पहले से **SAST hits** वाला node अक्सर केवल complex लेकिन attacker path से रहित node की तुलना में बेहतर target होता है।

Trailmark के साथ example workflow।<sup>[[6]](#references)</sup>
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
महत्वपूर्ण methodology intersection है: **complexity x exposure x impact**। सबसे अधिक अपेक्षित security value वाले fuzz targets चुनने के लिए graph का उपयोग करें, फिर यह तय करने के लिए mutation survivors का उपयोग करें कि आपके harness को किन boundaries और invariants पर stress डालना चाहिए।<sup>[[5]](#references)</sup>

## gosentry के साथ Go Fuzzing: अधिक शक्तिशाली Engine, Typed Inputs और Differential Checks

यदि किसी Go target में पहले से native `testing.F` harness है, तो एक व्यावहारिक upgrade path यही harness [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाना है। यह forked Go toolchain है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
यह तब उपयोगी है जब native Go fuzzer **hard comparisons**, **typed inputs**, या **parser-heavy formats** पर अटक जाता है। Methodology वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का उपयोग करते रहें।
- उसी harness का पुनः उपयोग करें, लेकिन इसे stock toolchain के बजाय gosentry के `go` binary के साथ चलाएँ।
- परिणामी campaign को सामान्य coverage-guided run की तरह मानें, लेकिन इसमें LibAFL scheduling/mutation और बेहतर surrounding detectors का उपयोग होता है।

### Silent failures को fuzz findings में बदलना

Go assessments में एक आम समस्या यह है कि खतरनाक behaviour अक्सर default रूप से **crash** नहीं करता। gosentry के साथ, आप “bad but silent” states की कई classes को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` चुने गए logging/error paths को crashes की तरह व्यवहार कराने के लिए, जो `log.Fatal`-style code paths के लिए उपयोगी है और अन्यथा केवल log करके आगे बढ़ते हैं।
- `--catch-races=true` नए खोजे गए queue entries को Go race detector के साथ replay करने के लिए।
- `--catch-leaks=true` नए queue entries को `goleak` के साथ replay करने और goroutine leaks पर रुकने के लिए।
- LibAFL hang handling, ताकि **infinite loops / very slow inputs** timeouts के रूप में गायब होने के बजाय fuzz findings के रूप में बने रहें।
- Default रूप से built-in arithmetic overflow checks, और go-panikint-style instrumentation के माध्यम से optional truncation checks।

यह उन targets के लिए विशेष रूप से मूल्यवान है जहाँ security impact memory corruption के बजाय **panicless parser failure**, **concurrency bug**, या **DoS-only hang** होता है।

### Typed Go APIs के लिए Struct-aware fuzzing

Native Go fuzzing मुख्य रूप से `[]byte`, `string`, और numbers जैसे scalars की अपेक्षा करता है। यदि test के अंतर्गत code typed objects का उपयोग करता है, तो gosentry bytes को underlying स्तर पर mutate करते हुए **composite values** (structs, slices, arrays, pointers) को सीधे fuzz कर सकता है।<sup>[[7]](#references)[[8]](#references)</sup>
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
इसका उपयोग केवल fuzzing के लिए fake wire format बनाते समय करें; अन्यथा harness-only parsing code के पीछे logic bugs छिप सकते हैं। Differential या grammar-based campaigns के लिए, harness input को एक single `[]byte` या `string` रखें और इसके बजाय callback के अंदर parse करें।

### parsers और protocol inputs के लिए Grammar-based fuzzing

parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules की एक JSON array होती है, और harness को आमतौर पर एक single `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- जब byte-level mutations अधिकतर शुरुआती syntax checks में ही समाप्त हो जाएँ, तो grammar mode का उपयोग करें।
- grammar को language/protocol के पूरे specification का मॉडल बनाने के बजाय उसके **security-relevant subset** पर केंद्रित रखें।
- integer, length और state-machine edges पर दबाव डालने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- grammar mode inputs को grammar-valid रखता है, लेकिन target को अभी भी **bytes/strings** मिलते हैं, इसलिए parsing और semantic checks harness किए गए code के भीतर ही बने रहते हैं।

### Differential fuzzing: केवल crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक मजबूत pattern **grammar-based differential fuzzing** है: valid structured inputs generate करें और उन्हें दो parsers, clients या state-transition engines को feed करें।<sup>[[7]](#references)[[8]](#references)</sup>
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

- एक implementation panic करती है, जबकि दूसरी साफ़ तौर पर reject करती है
- accepted/rejected input में mismatch
- अलग-अलग parse trees या decoded objects
- अलग-अलग state transitions, nonces, balances या state roots

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का एक व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing अक्सर नहीं खोज पाती।

### coverage reporting के लिए campaign corpus का पुन: उपयोग करें

किसी campaign के बाद, अलग से corpus export किए बिना Go coverage report बनाने के लिए saved queue corpus को replay करें।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
कमांड को **उसी package** से और **उसी `-fuzz` target** के साथ चलाएँ, ताकि gosentry सही cached campaign state को resolve कर सके।



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark code को graphs में बदलता है](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing में toolkit का आधा हिस्सा missing था। हमने इसे ठीक करने के लिए toolchain को fork किया।](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots का उपयोग करने वाला Stateful Network Protocols के लिए Fast Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [No Grammar, No Problem: System-Call Descriptions के बिना Linux Kernel को Fuzzing करने की दिशा में](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive और Mutable Snapshots के साथ Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path और caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
