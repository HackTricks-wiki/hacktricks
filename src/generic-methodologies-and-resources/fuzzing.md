# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** में, inputs को mutate किया जाता है जबकि वे **grammar-valid** रहते हैं। coverage-guided mode में, केवल वे samples जो **new coverage** ट्रिगर करते हैं, corpus seeds के रूप में save किए जाते हैं। **language targets** (parsers, interpreters, engines) के लिए, इससे ऐसे bugs छूट सकते हैं जिनके लिए **semantic/dataflow chains** चाहिए होते हैं, जहाँ एक construct का output दूसरे का input बनता है।

**Failure mode:** fuzzer ऐसे seeds ढूँढ लेता है जो अलग-अलग `document()` और `generate-id()` (या similar primitives) को exercise करते हैं, लेकिन **chained dataflow को preserve नहीं करता**, इसलिए “closer-to-bug” sample drop हो जाता है क्योंकि वह coverage नहीं जोड़ता। **3+ dependent steps** के साथ, random recombination महँगा हो जाता है और coverage feedback search को guide नहीं करता।

**Implication:** dependency-heavy grammars के लिए, **mutational और generative phases को hybridize** करने पर विचार करें, या generation को **function chaining** patterns की ओर bias करें (सिर्फ coverage नहीं)।

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होती है: नया-coverage sample तुरंत save कर लिया जाता है, अक्सर बड़े unchanged regions को बनाए रखते हुए। समय के साथ, corpora **near-duplicates** बन जाते हैं जिनमें structural diversity कम होती है। Aggressive minimization useful context हटा सकती है, इसलिए एक practical compromise है **grammar-aware minimization** जो **minimum token threshold** के बाद रुक जाती है (noise कम करते हुए इतना surrounding structure बचाकर रखती है कि mutation-friendly रहे)।

Mutational fuzzing के लिए एक practical corpus rule है: **near-duplicates के बड़े ढेर** की बजाय **structurally different seeds का छोटा set** चुनें जो coverage को maximize करें। Practice में, इसका मतलब आम तौर पर यह होता है:

- **real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem से file sets)।
- हर valid sample को रखने के बजाय उन्हें **coverage-based corpus minimization** से distill करें।
- Seeds को इतना **छोटा** रखें कि mutations meaningful fields पर पड़ें, न कि ज़्यादातर cycles irrelevant bytes पर खर्च हों।
- Major harness/instrumentation changes के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Comparison-Aware Mutation For Magic Values

Fuzzers के plateau का एक common कारण syntax नहीं बल्कि **hard comparisons** होते हैं: magic bytes, length checks, enum strings, checksums, या parser dispatch values जो `memcmp`, switch tables, या cascaded comparisons से guarded होते हैं। Pure random mutation byte-by-byte इन values को guess करने में cycles waste करती है।

ऐसे targets के लिए, **comparison tracing** use करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows) ताकि fuzzer failed comparisons से operands observe कर सके और mutations को ऐसे values की ओर bias कर सके जो उन्हें satisfy करें।
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

- यह खास तौर पर तब उपयोगी है जब target गहरी logic को **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे gate करता है।
- इसे real samples, protocol specs, या debug logs से निकाले गए **dictionaries** के साथ pair करें। grammar tokens, chunk names, verbs, और delimiters वाली छोटी dictionary अक्सर massive generic wordlist से अधिक valuable होती है।
- अगर target कई sequential checks करता है, तो सबसे पहले शुरुआती “magic” comparisons solve करें और फिर resulting corpus को फिर से minimize करें ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए, interesting unit अक्सर एक single blob नहीं बल्कि एक **message sequence** होता है। पूरे transcript को एक file में concatenate करके उसे blindly mutate करना आमतौर पर inefficient होता है क्योंकि fuzzer हर step को बराबर mutate करता है, जबकि fragile state तक अक्सर सिर्फ बाद वाला message ही पहुँचता है।

एक अधिक effective pattern यह है कि **sequence itself** को seed माना जाए और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback की तरह इस्तेमाल किया जाए:

- **Valid prefix messages** को stable रखें और mutations को **transition-driving** message पर focus करें।
- पिछली responses से identifiers और server-generated values cache करें जब next step उन पर depend करता हो।
- पूरे serialized transcript को opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- अगर protocol meaningful response codes expose करता है, तो उन्हें एक **cheap state oracle** की तरह उपयोग करें ताकि deeper progress करने वाली sequences को prioritize किया जा सके।

यही कारण है कि authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs vanilla file-style fuzzing में अक्सर miss हो जाते हैं: fuzzer को सिर्फ structure नहीं, बल्कि **order, state, और dependencies** भी preserve करनी होती हैं।

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** को **coverage reuse** के साथ hybridize करने का एक practical तरीका है **persistent server** के against short-lived workers को restart करना। हर worker एक empty corpus से शुरू होता है, `T` seconds बाद sync करता है, combined corpus पर `T` seconds और चलता है, फिर दोबारा sync करके exit हो जाता है। इससे **हर generation में fresh structures** मिलती हैं, जबकि accumulated coverage का लाभ भी मिलता रहता है।

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**क्रमिक workers (example loop):**

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

- `-in empty` हर generation के लिए एक **fresh corpus** मजबूर करता है।
- `-server_update_interval T` **delayed sync** का अनुमान लगाता है (novelty पहले, reuse बाद में)।
- Grammar fuzzing mode में, **initial server sync by default skipped** होता है (`-skip_initial_server_sync` की जरूरत नहीं)।
- Optimal `T` **target-dependent** होता है; worker के most “easy” coverage ढूँढ लेने के बाद switch करना आमतौर पर सबसे अच्छा काम करता है।

## Snapshot Fuzzing For Hard-To-Harness Targets

जब जिस code को आप test करना चाहते हैं वह केवल **बड़े setup cost** के बाद reachable होता है (VM boot करना, login पूरा करना, packet receive करना, container parse करना, service initialize करना), तो एक उपयोगी alternative है **snapshot fuzzing**:

1. Target को तब तक चलाएँ जब तक interesting state तैयार न हो जाए।
2. उस point पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे relevant guest/process buffer में लिखें।
4. Crash/timeout/reset तक execute करें।
5. केवल **dirty pages** restore करें और repeat करें।

यह हर iteration में पूरा setup cost चुकाने से बचाता है और खास तौर पर **network services**, **firmware**, **post-auth attack surfaces**, और **binary-only targets** के लिए उपयोगी है जिन्हें classic in-process harness में refactor करना painful हो।

एक practical trick यह है कि `recv`/`read`/packet-deserialization point के तुरंत बाद break करें, input buffer address note करें, वहाँ snapshot लें, और फिर हर iteration में उस buffer को सीधे mutate करें। इससे आप हर बार पूरे handshake को rebuild किए बिना deep parsing logic fuzz कर सकते हैं।

## Harness Introspection: Find Shallow Fuzzers Early

जब campaign stall हो जाती है, समस्या अक्सर mutator नहीं बल्कि **harness** होती है। **Reachability/coverage introspection** का उपयोग करके ऐसे functions खोजें जो आपके fuzz target से statically reachable हैं लेकिन dynamically बहुत कम या कभी covered नहीं होते। ऐसे functions आमतौर पर तीन में से किसी एक issue की ओर इशारा करते हैं:

- Harness target में बहुत देर से या बहुत जल्दी प्रवेश करता है।
- Seed corpus में feature family का कोई पूरा हिस्सा missing है।
- Target को सच में एक **second harness** चाहिए, न कि एक oversized “do everything” harness।

अगर आप OSS-Fuzz / ClusterFuzz-style workflows उपयोग करते हैं, तो Fuzz Introspector इस triage के लिए उपयोगी है:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
रिपोर्ट का उपयोग करके तय करें कि क्या किसी अनटेस्टेड parser path के लिए नया harness जोड़ना है, किसी specific feature के लिए corpus बढ़ाना है, या एक monolithic harness को छोटे entry points में split करना है।

## Graph-First Fuzz Target Selection And Mutation Triage

अगर आपके पास पहले से **static-analysis findings**, **mutation-testing survivors**, और **coverage reports** हैं, तो उन्हें independent lists की तरह triage न करें। पहले एक **call graph** बनाएं, nodes को **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, और किसी भी external findings से annotate करें, फिर graph questions पूछें:

- कौन-सी high-complexity functions untrusted input से reachable हैं?
- कौन-से mutation survivors parsers/handlers से security-critical code तक जाने वाले paths पर हैं?
- कौन-सी functions architectural choke points हैं जिनका **blast radius** unusually high है?

यह आमतौर पर "lowest coverage" से बेहतर fuzz targets निकालता है। एक parser/decoder जिसमें **high complexity** हो और confirmed **external reachability** हो, वह isolated internal helper की तुलना में stronger harness candidate है, भले ही उसकी coverage कम हो, लेकिन attacker-controlled path न हो।

### Practical triage workflow

1. codebase से एक **code graph** बनाएं और per-function complexity/branch metrics निकालें।
2. ऐसे **entrypoints** enumerate करें जो attacker-controlled input accept करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. उन entrypoints से candidate functions तक **path queries** चलाएं ताकि reachable attack surface और dead/internal-only code अलग हो सके।
4. ऐसे nodes को प्राथमिकता दें जो combine करते हैं:
- high **cyclomatic complexity**
- confirmed **reachability from untrusted input**
- high **blast radius** या बहुत सारे downstream dependents
- corroborating evidence जैसे **SARIF** findings, audit notes, या mutation survivors
5. सबसे अच्छे-scoring nodes के लिए focused harnesses लिखें, खासकर **parsers/codecs** जैसे hex/Base64/IP/message decoders।

### Mutation survivors: equivalent vs actionable

Mutation testing अक्सर noisy survivor list देता है। हर survivor को security gap मानने से पहले, graph का उपयोग करके पूछें:

- क्या mutated function attacker-controlled entrypoint से reachable है?
- क्या सभी call paths stronger invariants से constrained हैं than the mutated check?
- क्या node dead code, formatting-only logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable रहते हैं या structurally constrained होते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को touch करते हैं, उन्हें इन में promote किया जाना चाहिए:

- नए fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

अगर आपका SAST pipeline **SARIF** export करता है, तो findings को graph nodes पर **file + line range** के आधार पर project करें और graph का उपयोग impact expand करने के लिए करें:

- flagged function का **blast radius** compute करें
- check करें कि finding किसी entrypoint से आने वाले किसी path पर है या नहीं
- nearby findings को cluster करें जो same choke point में collapse हो जाती हैं

यह तब उपयोगी है जब यह तय करना हो कि किसी specific function पर fuzzing time खर्च करना है या नहीं: एक node जो **reachable**, **complex**, और already **SAST hits** वाला है, वह अक्सर सिर्फ complex node से बेहतर target होता है जिसके पास attacker path नहीं है।

Example workflow with Trailmark:
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
महत्वपूर्ण methodology है intersection: **complexity x exposure x impact**. graph का उपयोग करके सबसे अधिक expected security value वाले fuzz targets चुनें, फिर mutation survivors का उपयोग करके तय करें कि आपकी harness को किन boundaries और invariants को stress करना चाहिए।

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
