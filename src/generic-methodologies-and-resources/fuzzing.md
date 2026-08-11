# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** में inputs को **grammar-valid** रखते हुए mutate किया जाता है। **coverage-guided** mode में केवल वे samples corpus seeds के रूप में save किए जाते हैं जो **new coverage** trigger करते हैं। **language targets** (parsers, interpreters, engines) के लिए, इससे वे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** आवश्यक होती हैं, जहाँ एक construct का output दूसरे का input बनता है।<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer ऐसे seeds खोजता है जो अलग-अलग रूप से `document()` और `generate-id()` (या इसी तरह के primitives) को exercise करते हैं, लेकिन **chained dataflow** को preserve **नहीं** करता। इसलिए “closer-to-bug” sample drop हो जाता है, क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** के साथ random recombination महंगा हो जाता है और coverage feedback search को guide नहीं करता।<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammars के लिए, **mutational और generative phases को hybridize** करने या generation को केवल coverage के बजाय **function chaining** patterns की ओर bias करने पर विचार करें।<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होता है: new-coverage sample को तुरंत save कर लिया जाता है और अक्सर बड़े unchanged regions भी retain रहते हैं। समय के साथ, corpora कम structural diversity वाले **near-duplicates** बन जाते हैं। Aggressive minimization उपयोगी context को हटा सकता है, इसलिए एक practical compromise **grammar-aware minimization** है, जो **minimum token threshold** तक पहुँचने के बाद रुक जाता है (noise कम करते हुए आसपास की पर्याप्त structure बनाए रखना, ताकि mutations के लिए अनुकूल रहे)।<sup>[[1]](#references)</sup>

mutational fuzzing के लिए एक practical corpus rule है: near-duplicates के बड़े pile की तुलना में **structurally different seeds का छोटा set, जो coverage को maximize करे**, बेहतर है। व्यवहार में इसका आमतौर पर निम्नलिखित अर्थ होता है।<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world samples** से शुरुआत करें (public corpora, crawling, captured traffic, target ecosystem से file sets)।
- हर valid sample को रखने के बजाय उन्हें **coverage-based corpus minimization** से distill करें।
- Seeds को इतना **छोटा** रखें कि mutations meaningful fields पर पड़ें, न कि अधिकांश cycles irrelevant bytes पर खर्च हों।
- Major harness/instrumentation changes के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Comparison-Aware Mutation For Magic Values

Fuzzers के plateau करने का एक सामान्य कारण syntax नहीं बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums, या parser dispatch values, जिन्हें `memcmp`, switch tables, या cascaded comparisons द्वारा guard किया जाता है। Pure random mutation इन values का byte-by-byte अनुमान लगाने में cycles बर्बाद करती है।

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
**Practical notes:**

- यह विशेष रूप से तब उपयोगी है जब target **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे deep logic को gate करता है।
- इसे real samples, protocol specs, या debug logs से निकाले गए **dictionaries** के साथ pair करें। Grammar tokens, chunk names, verbs, और delimiters वाला छोटा dictionary अक्सर massive generic wordlist से अधिक मूल्यवान होता है।
- यदि target कई sequential checks करता है, तो सबसे पहले शुरुआती “magic” comparisons को solve करें और फिर resulting corpus को दोबारा minimize करें, ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए interesting unit अक्सर single blob नहीं, बल्कि **message sequence** होती है। पूरे transcript को एक file में concatenate करके blind तरीके से mutate करना आमतौर पर inefficient होता है, क्योंकि fuzzer हर step को समान रूप से mutate करता है, भले ही fragile state तक केवल बाद का message पहुंचता हो।<sup>[[4]](#references)</sup>

एक अधिक effective pattern यह है कि **sequence को स्वयं seed** माना जाए और **observable state** (response codes, protocol states, parser phases, returned object types) को additional feedback के रूप में उपयोग किया जाए।<sup>[[4]](#references)</sup>

- **valid prefix messages** को stable रखें और mutations को **transition-driving** message पर केंद्रित करें।
- जब अगला step उन पर निर्भर हो, तो previous responses से मिले identifiers और server-generated values को cache करें।
- पूरे serialized transcript को opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- यदि protocol meaningful response codes expose करता है, तो उन्हें **cheap state oracle** के रूप में उपयोग करके उन sequences को प्राथमिकता दें जो अधिक गहराई तक progress करती हैं।

इसी कारण authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing से miss हो जाते हैं: fuzzer को केवल structure ही नहीं, बल्कि **order, state, और dependencies** भी preserve करने होते हैं।<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** को **coverage reuse** के साथ hybridize करने का एक practical तरीका यह है कि persistent server के विरुद्ध short-lived workers को **restart** किया जाए। प्रत्येक worker एक empty corpus से शुरू होता है, `T` seconds के बाद sync करता है, combined corpus पर अगले `T` seconds तक चलता है, फिर दोबारा sync करके exit करता है। इससे **प्रत्येक generation में fresh structures** मिलते हैं और साथ ही accumulated coverage का लाभ भी मिलता है।<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` प्रत्येक generation में **fresh corpus** को बाध्य करता है।
- `-server_update_interval T` **delayed sync** का अनुमान लगाता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync** को default रूप से skip किया जाता है (`-skip_initial_server_sync` की आवश्यकता नहीं)।
- Optimal `T` **target-dependent** होता है; worker द्वारा अधिकांश “easy” coverage खोज लेने के बाद switching करना आमतौर पर सबसे अच्छा काम करता है।

## कठिन-Harness Targets के लिए Snapshot Fuzzing

जब जिस code को आप test करना चाहते हैं, वह केवल **large setup cost** के बाद reachable होता है (VM boot करना, login पूरा करना, packet receive करना, container parse करना, service initialize करना), तब एक उपयोगी विकल्प **snapshot fuzzing** है: ready process या VM state को capture करें, प्रत्येक test case को target input path में inject करें, crash/timeout तक execute करें और snapshot restore करें। इससे initialization या protocol prefixes को बार-बार दोहराने से बचा जाता है और यह **network services**, **firmware**, **post-auth attack surfaces** तथा **binary-only targets** के लिए उपयोगी है।<sup>[[9]](#references)[[10]](#references)</sup>

1. Target को तब तक चलाएँ जब तक interesting state ready न हो जाए।
2. उस बिंदु पर **memory + registers** का snapshot लें।
3. प्रत्येक test case के लिए, mutated input को सीधे संबंधित guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. Snapshot restore करें; VM targets के लिए, यदि supported हो, तो केवल **dirty pages** restore करें और फिर दोहराएँ।

Snapshot को पहले expensive parse/dispatch step के जितना व्यावहारिक हो उतना निकट रखें, जैसे `recv`/`read` या packet-deserialization point के बाद, और target द्वारा उपयोग किए गए input buffer को record करें। यह adaptive-placement principle का पालन करता है, जिसमें input processing में snapshot को और गहराई पर ले जाया जाता है ताकि काम को दोहराने से बचा जा सके।<sup>[[11]](#references)</sup>

## Harness Introspection: Shallow Fuzzers को जल्दी खोजें

जब कोई campaign stall हो जाता है, तो समस्या अक्सर mutator नहीं बल्कि **harness** होती है। ऐसे functions खोजने के लिए **reachability/coverage introspection** का उपयोग करें, जो statically आपके fuzz target से reachable हैं लेकिन dynamically बहुत कम या कभी भी covered नहीं होते। ये functions आमतौर पर तीन में से किसी एक समस्या का संकेत देते हैं।<sup>[[12]](#references)</sup>

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में किसी पूरी feature family की कमी है।
- Target को वास्तव में एक बहुत बड़े “do everything” harness के बजाय **second harness** की आवश्यकता है।

यदि आप OSS-Fuzz / ClusterFuzz-style workflows का उपयोग करते हैं, तो Fuzz Introspector static reachability की runtime coverage से तुलना कर सकता है और timed run या public corpus से reports generate कर सकता है।<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
रिपोर्ट का उपयोग यह तय करने के लिए करें कि किसी अनटेस्टेड parser path के लिए नया harness जोड़ना है, किसी विशिष्ट feature के लिए corpus बढ़ाना है, या monolithic harness को छोटे entry points में विभाजित करना है।

## Graph-First Fuzz Target Selection And Mutation Triage

यदि आपके पास पहले से **static-analysis findings**, **mutation-testing survivors** और **coverage reports** हैं, तो उन्हें स्वतंत्र सूचियों के रूप में triage न करें। पहले एक **call graph** बनाएं, nodes पर **cyclomatic complexity**, **entrypoint/untrusted-input reachability** और सभी external findings को annotate करें, फिर graph से जुड़े प्रश्न पूछें।<sup>[[5]](#references)[[6]](#references)</sup>

- untrusted input से कौन-से high-complexity functions तक पहुंचा जा सकता है?
- parsers/handlers से security-critical code तक जाने वाले paths पर कौन-से mutation survivors मौजूद हैं?
- कौन-से functions architectural choke points हैं और उनका **blast radius** असामान्य रूप से अधिक है?

इससे आमतौर पर केवल "lowest coverage" के आधार पर चुने गए targets की तुलना में बेहतर fuzz targets सामने आते हैं। **high complexity** और confirmed **external reachability** वाला parser/decoder, कमजोर coverage वाले लेकिन attacker-controlled path से रहित किसी isolated internal helper की तुलना में बेहतर harness candidate होता है।

### Practical triage workflow

1. codebase से एक **code graph** बनाएं और प्रत्येक function के complexity/branch metrics निकालें।
2. ऐसे **entrypoints** की सूची बनाएं जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. candidate functions तक इन entrypoints से **path queries** चलाएं, ताकि reachable attack surface को dead/internal-only code से अलग किया जा सके।
4. उन nodes को प्राथमिकता दें जिनमें ये गुण संयुक्त रूप से हों:
- high **cyclomatic complexity**
- **untrusted input** से confirmed **reachability**
- high **blast radius** या कई downstream dependents
- सहायक evidence, जैसे **SARIF** findings, audit notes या mutation survivors
5. सबसे अधिक score वाले nodes के लिए पहले focused harnesses लिखें, विशेष रूप से **parsers/codecs** जैसे hex/Base64/IP/message decoders के लिए।

### Mutation survivors: equivalent vs actionable

Mutation testing अक्सर एक noisy survivor list तैयार करता है। प्रत्येक survivor को security gap मानने से पहले, graph का उपयोग करके ये प्रश्न पूछें:

- क्या mutated function किसी attacker-controlled entrypoint से reachable है?
- क्या सभी call paths mutated check से अधिक मजबूत invariants द्वारा constrained हैं?
- क्या node dead code, केवल formatting logic, या high-impact arithmetic/parser path में स्थित है?

जो survivors unreachable रहते हैं या structurally constrained होते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को प्रभावित करते हैं, उन्हें निम्न में promote किया जाना चाहिए:

- नए fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

यदि आपकी SAST pipeline **SARIF** export करती है, तो **file + line range** के आधार पर findings को graph nodes पर project करें और impact बढ़ाने के लिए graph का उपयोग करें।<sup>[[6]](#references)</sup>

- flagged function का **blast radius** compute करें
- जांचें कि finding किसी entrypoint से आने वाले path पर है या नहीं
- पास-पास की findings को cluster करें, जो एक ही choke point में collapse होती हैं

यह तब उपयोगी होता है जब किसी specific function पर fuzzing time खर्च करने का निर्णय लेना हो: जो node **reachable**, **complex** है और जिस पर पहले से **SAST hits** मौजूद हैं, वह केवल complex लेकिन attacker path से रहित node की तुलना में अक्सर बेहतर target होता है।

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
महत्वपूर्ण methodology का intersection है: **complexity x exposure x impact**। सबसे अधिक अपेक्षित security value वाले fuzz targets चुनने के लिए graph का उपयोग करें, फिर यह तय करने के लिए mutation survivors का उपयोग करें कि आपके harness को किन boundaries और invariants पर stress डालना चाहिए।<sup>[[5]](#references)</sup>

## gosentry के साथ Go Fuzzing: मजबूत Engine, Typed Inputs और Differential Checks

यदि किसी Go target में पहले से native `testing.F` harness है, तो एक व्यावहारिक upgrade path यही है कि उसी harness को [gosentry](https://github.com/trailofbits/gosentry) के साथ चलाया जाए। यह एक forked Go toolchain है, जो `go test -fuzz` को बनाए रखता है, लेकिन backend को **LibAFL** से बदल देता है।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
यह तब उपयोगी होता है जब native Go fuzzer **hard comparisons**, **typed inputs**, या **parser-heavy formats** पर रुक जाता है। Methodology वही रहती है:

- Seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का उपयोग करते रहें।
- उसी harness का पुनः उपयोग करें, लेकिन इसे stock toolchain के बजाय gosentry के `go` binary के साथ चलाएँ।
- परिणामी campaign को सामान्य coverage-guided run की तरह मानें, लेकिन LibAFL scheduling/mutation और बेहतर आसपास के detectors के साथ।

### Silent failures को fuzz findings में बदलना

Go assessments में एक बार-बार आने वाली समस्या यह है कि खतरनाक behaviour अक्सर default रूप से **crash** नहीं करता। gosentry के साथ, आप “bad but silent” states की कई classes को findings में बदल सकते हैं।<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` चुने गए logging/error paths को crashes की तरह व्यवहार कराने के लिए (यह उन `log.Fatal`-style code paths के लिए उपयोगी है जो अन्यथा केवल log करके आगे बढ़ते हैं)।
- `--catch-races=true` नए discovered queue entries को Go race detector के साथ replay करने के लिए।
- `--catch-leaks=true` नई queue entries को `goleak` के साथ replay करने और goroutine leaks पर रुकने के लिए।
- LibAFL hang handling, ताकि **infinite loops / very slow inputs** timeouts के रूप में गायब होने के बजाय fuzz findings बने रहें।
- Default रूप से built-in arithmetic overflow checks, साथ ही go-panikint-style instrumentation के माध्यम से optional truncation checks।

यह उन targets के लिए विशेष रूप से उपयोगी है जहाँ security impact memory corruption के बजाय **panicless parser failure**, **concurrency bug**, या **DoS-only hang** होता है।

### Typed Go APIs के लिए Struct-aware fuzzing

Native Go fuzzing मुख्यतः `[]byte`, `string`, और numbers जैसे scalars की अपेक्षा करता है। यदि test किया जा रहा code typed objects का उपयोग करता है, तो gosentry **composite values** (structs, slices, arrays, pointers) को सीधे fuzz कर सकता है और साथ ही underlying bytes को mutate कर सकता है।<sup>[[7]](#references)[[8]](#references)</sup>
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
इसका उपयोग तब करें जब केवल fuzzing के लिए fake wire format बनाने से harness-only parsing code के पीछे logic bugs छिप सकते हों। Differential या grammar-based campaigns के लिए, harness input को एकल `[]byte` या `string` के रूप में रखें और इसके बजाय callback के अंदर parse करें।

### parsers और protocol inputs के लिए Grammar-based fuzzing

parsers, formats और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar production rules की एक JSON array होती है, और harness को आमतौर पर एकल `[]byte` या `string` argument लेना चाहिए।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- जब byte-level mutations अधिकतर शुरुआती syntax checks में ही विफल हो जाएं, तो grammar mode का उपयोग करें।
- पूरे specification का modeling करने के बजाय grammar को language/protocol के **security-relevant subset** तक सीमित रखें।
- integer, length और state-machine edges पर दबाव डालने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target को अभी भी **bytes/strings** प्राप्त होते हैं, इसलिए parsing और semantic checks harness किए गए code के भीतर ही रहते हैं।

### Differential fuzzing: केवल crashes की नहीं, implementations की तुलना करें

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

- एक implementation panic करता है, जबकि दूसरा इसे सही तरीके से reject करता है
- accepted/rejected input में mismatch
- अलग-अलग parse trees या decoded objects
- state transitions, nonces, balances या state roots में divergence

यह **consensus mismatches**, **parser ambiguity** और **spec-vs-implementation drift** खोजने का एक व्यावहारिक तरीका है, जिन्हें केवल crash fuzzing अक्सर नहीं पकड़ पाता।

### coverage reporting के लिए campaign corpus का पुन: उपयोग करें

किसी campaign के बाद, अलग से corpus export किए बिना Go coverage report बनाने के लिए saved queue corpus को replay करें।<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
उचित cached campaign state को resolve करने के लिए command को **उसी package** से और **उसी `-fuzz` target** के साथ चलाएँ।

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet पाँच वर्ष बाद: Coverage-Guided Protocol Fuzzing पर](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark code को graphs में बदलता है](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing में toolkit का आधा हिस्सा गायब था। हमने इसे ठीक करने के लिए toolchain fork किया।](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots का उपयोग करने वाला Stateful Network Protocols के लिए Fast Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar नहीं, कोई समस्या नहीं: System-Call Descriptions के बिना Linux Kernel को Fuzzing करने की दिशा में](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive और Mutable Snapshots के साथ Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
