# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** में, inputs को mutate किया जाता है जबकि वे **grammar-valid** बने रहते हैं। coverage-guided mode में, केवल वे samples save किए जाते हैं जो **new coverage** trigger करते हैं, corpus seeds के रूप में। **language targets** (parsers, interpreters, engines) के लिए, इससे वे bugs miss हो सकते हैं जिनके लिए **semantic/dataflow chains** चाहिए होती हैं, जहाँ एक construct का output दूसरे का input बनता है।

**Failure mode:** fuzzer ऐसे seeds ढूँढता है जो अलग-अलग `document()` और `generate-id()` (या similar primitives) को exercise करते हैं, लेकिन **chained dataflow को preserve नहीं करता**, इसलिए “closer-to-bug” sample drop हो जाता है क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** के साथ, random recombination expensive हो जाता है और coverage feedback search को guide नहीं करता।

**Implication:** dependency-heavy grammars के लिए, **mutational और generative phases को hybridize** करने पर विचार करें या generation को **function chaining** patterns की ओर bias करें (सिर्फ coverage नहीं)।

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होती है: नया-coverage sample तुरंत save कर लिया जाता है, अक्सर बड़े unchanged regions को retain करते हुए। समय के साथ, corpora **near-duplicates** बन जाते हैं जिनमें structural diversity कम होती है। Aggressive minimization useful context हटा सकती है, इसलिए एक practical compromise है **grammar-aware minimization** जो **minimum token threshold** के बाद रुक जाती है (noise कम करते हुए इतना surrounding structure रखती है कि mutation-friendly बनी रहे)।

Mutational fuzzing के लिए एक practical corpus rule है: **near-duplicates के बड़े ढेर की बजाय संरचनात्मक रूप से अलग seeds का छोटा set prefer करें जो coverage maximize करे**। Practice में, इसका मतलब आम तौर पर यह होता है:

- **real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem की file sets)।
- उन्हें **coverage-based corpus minimization** से distill करें, हर valid sample को रखने की बजाय।
- seeds को **इतना छोटा** रखें कि mutations meaningful fields पर land करें, न कि अधिकांश cycles irrelevant bytes पर खर्च हों।
- major harness/instrumentation changes के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus बदल जाता है।

## Comparison-Aware Mutation For Magic Values

Fuzzers के plateau होने का एक common कारण syntax नहीं बल्कि **hard comparisons** हैं: magic bytes, length checks, enum strings, checksums, या parser dispatch values जो `memcmp`, switch tables, या cascaded comparisons से guarded होते हैं। Pure random mutation इन values को byte-by-byte guess करने में cycles बर्बाद करती है।

इन targets के लिए, **comparison tracing** उपयोग करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows) ताकि fuzzer failed comparisons के operands observe कर सके और mutations को उन values की ओर bias कर सके जो उन्हें satisfy करती हैं।
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

- यह खास तौर पर तब उपयोगी होता है जब target **file signatures**, **protocol verbs**, **type tags**, या **version-dependent feature bits** के पीछे deep logic gate करता है।
- इसे real samples, protocol specs, या debug logs से निकाली गई **dictionaries** के साथ pair करें। grammar tokens, chunk names, verbs, और delimiters वाली छोटी dictionary अक्सर विशाल generic wordlist से अधिक मूल्यवान होती है।
- अगर target कई sequential checks करता है, तो पहले earliest “magic” comparisons solve करें और फिर resulting corpus को फिर से minimize करें ताकि later stages पहले से valid prefixes से शुरू हों।

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए, interesting unit अक्सर एक single blob नहीं बल्कि एक **message sequence** होती है। पूरे transcript को एक file में जोड़कर उसे blindly mutate करना आम तौर पर inefficient होता है क्योंकि fuzzer हर step को बराबर mutate करता है, जबकि अक्सर केवल बाद वाला message fragile state तक पहुँचता है।

एक अधिक effective pattern यह है कि **sequence itself** को seed माना जाए और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback के रूप में उपयोग किया जाए:

- **Valid prefix messages** को stable रखें और mutations को **transition-driving** message पर focus करें।
- यदि अगला step उन पर निर्भर करता है, तो prior responses से identifiers और server-generated values cache करें।
- पूरे serialized transcript को opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- अगर protocol meaningful response codes expose करता है, तो उन्हें **cheap state oracle** की तरह उपयोग करें ताकि deeper progress करने वाली sequences को प्राथमिकता दी जा सके।

यही कारण है कि authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing में miss हो जाते हैं: fuzzer को सिर्फ structure नहीं, बल्कि **order, state, and dependencies** भी preserve करनी पड़ती हैं।

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** और **coverage reuse** को hybridize करने का एक practical तरीका है persistent server के खिलाफ **short-lived workers** को restart करना। हर worker खाली corpus से शुरू होता है, `T` seconds बाद sync करता है, combined corpus पर फिर `T` seconds चलता है, फिर दोबारा sync करता है, और फिर exit हो जाता है। इससे **हर generation में fresh structures** मिलती हैं, जबकि accumulated coverage का फायदा भी मिलता रहता है।

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**अनुक्रमिक workers (example loop):**

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

- `-in empty` हर generation के लिए एक **fresh corpus** force करता है।
- `-server_update_interval T` **delayed sync** का approximate रूप है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync by default skip होती है** (`-skip_initial_server_sync` की जरूरत नहीं)।
- Optimal `T` **target-dependent** है; worker द्वारा ज़्यादातर “easy” coverage मिलने के बाद switch करना आम तौर पर सबसे अच्छा काम करता है।

## Snapshot Fuzzing For Hard-To-Harness Targets

जब जिस code को आप test करना चाहते हैं वह केवल **large setup cost** के बाद reachable होता है (VM boot करना, login complete करना, packet receive करना, container parse करना, service initialize करना), तो एक उपयोगी alternative है **snapshot fuzzing**:

1. target को तब तक run करें जब तक interesting state ready न हो जाए।
2. उस point पर **memory + registers** का snapshot लें।
3. हर test case के लिए, mutated input को सीधे relevant guest/process buffer में लिखें।
4. crash/timeout/reset तक execute करें।
5. केवल **dirty pages** restore करें और repeat करें।

यह हर iteration में पूरा setup cost चुकाने से बचाता है और खासकर **network services**, **firmware**, **post-auth attack surfaces**, और **binary-only targets** के लिए उपयोगी है, जिन्हें classic in-process harness में refactor करना मुश्किल होता है।

एक practical trick है `recv`/`read`/packet-deserialization point के तुरंत बाद break करना, input buffer address note करना, वहाँ snapshot लेना, और फिर हर iteration में उस buffer को सीधे mutate करना। इससे आप हर बार पूरा handshake फिर से बनाए बिना deep parsing logic fuzz कर सकते हैं।

## Harness Introspection: Find Shallow Fuzzers Early

जब कोई campaign stall हो जाता है, तो समस्या अक्सर mutator नहीं बल्कि **harness** होती है। **Reachability/coverage introspection** का उपयोग करें ताकि ऐसे functions मिल सकें जो statically आपके fuzz target से reachable हैं लेकिन dynamically बहुत कम या कभी covered नहीं होते। ऐसे functions आमतौर पर तीन समस्याओं में से किसी एक की ओर इशारा करते हैं:

- harness target में बहुत देर से या बहुत जल्दी enter कर रहा है।
- seed corpus में किसी पूरी feature family की कमी है।
- target को सच में एक **second harness** चाहिए, न कि एक oversized “do everything” harness।

अगर आप OSS-Fuzz / ClusterFuzz-style workflows use करते हैं, तो triage के लिए Fuzz Introspector उपयोगी है:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

अगर आपके पास पहले से **static-analysis findings**, **mutation-testing survivors**, और **coverage reports** हैं, तो उन्हें independent lists की तरह triage न करें। पहले एक **call graph** बनाएं, nodes को **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, और किसी भी external findings से annotate करें, फिर graph questions पूछें:

- कौन-से high-complexity functions untrusted input से reachable हैं?
- कौन-से mutation survivors parsers/handlers से security-critical code तक जाने वाले paths पर हैं?
- कौन-से functions architectural choke points हैं जिनका **blast radius** असामान्य रूप से बड़ा है?

यह आम तौर पर "lowest coverage" से बेहतर fuzz targets surface करता है। **High complexity** और confirmed **external reachability** वाला parser/decoder, कमजोर coverage लेकिन attacker-controlled path के बिना किसी isolated internal helper से ज्यादा मजबूत harness candidate होता है।

### Practical triage workflow

1. Codebase से एक **code graph** बनाएं और per-function complexity/branch metrics निकालें।
2. ऐसे **entrypoints** enumerate करें जो attacker-controlled input स्वीकार करते हैं: request handlers, decoders, importers, protocol parsers, CLI/file readers।
3. उन entrypoints से candidate functions तक **path queries** चलाएं ताकि reachable attack surface को dead/internal-only code से अलग किया जा सके।
4. उन nodes को प्राथमिकता दें जो combine करते हैं:
- high **cyclomatic complexity**
- confirmed **reachability from untrusted input**
- high **blast radius** या कई downstream dependents
- corroborating evidence जैसे **SARIF** findings, audit notes, या mutation survivors
5. सबसे अच्छे-scoring nodes के लिए focused harnesses लिखें, खासकर **parsers/codecs** जैसे hex/Base64/IP/message decoders।

### Mutation survivors: equivalent vs actionable

Mutation testing अक्सर noisy survivor list देती है। हर survivor को security gap मानने से पहले, graph का उपयोग करके पूछें:

- क्या mutated function attacker-controlled entrypoint से reachable है?
- क्या सभी call paths stronger invariants द्वारा constrained हैं than the mutated check?
- क्या node dead code, formatting-only logic, या high-impact arithmetic/parser path में है?

जो survivors unreachable रहते हैं या structurally constrained होते हैं, वे अक्सर **equivalent mutants** होते हैं। जो survivors **reachable** रहते हैं और **boundary conditions**, **overflow/carry paths**, या **security-critical arithmetic/parsing** को touch करते हैं, उन्हें इनमें promote किया जाना चाहिए:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

अगर आपका SAST pipeline **SARIF** export करता है, तो findings को **file + line range** के आधार पर graph nodes पर project करें और graph का उपयोग impact expand करने के लिए करें:

- flagged function का **blast radius** compute करें
- check करें कि finding किसी entrypoint से आने वाले किसी path पर है या नहीं
- पास-पास की findings को cluster करें जो same choke point में collapse होती हैं

यह तब useful होता है जब यह तय करना हो कि किसी specific function पर fuzzing time खर्च करना चाहिए या नहीं: एक node जो **reachable**, **complex**, और पहले से **SAST hits** वाला है, वह अक्सर उस node से बेहतर target होता है जो सिर्फ complex है लेकिन attacker path नहीं रखता।

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
महत्वपूर्ण methodology है intersection: **complexity x exposure x impact**। graph का उपयोग करके सबसे उच्च expected security value वाले fuzz targets चुनें, फिर mutation survivors का उपयोग करके तय करें कि आपके harness को किन boundaries और invariants को stress करना चाहिए।

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

अगर किसी Go target के पास पहले से native `testing.F` harness है, तो एक practical upgrade path है वही harness [gosentry](https://github.com/trailofbits/gosentry) के साथ run करना, जो एक forked Go toolchain है जो `go test -fuzz` को बनाए रखता है लेकिन backend को **LibAFL** से swap करता है।
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
यह तब उपयोगी है जब native Go fuzzer **hard comparisons**, **typed inputs**, या **parser-heavy formats** पर stall हो जाता है। methodology वही रहती है:

- seeds के लिए `f.Add(...)` और callback के लिए `f.Fuzz(...)` का उपयोग जारी रखें।
- वही harness reuse करें, लेकिन stock toolchain की बजाय इसे gosentry के `go` binary के साथ चलाएँ।
- resulting campaign को एक normal coverage-guided run की तरह treat करें, लेकिन LibAFL scheduling/mutation और बेहतर surrounding detectors के साथ।

### Silent failures को fuzz findings में बदलें

Go assessments में एक recurring problem यह है कि dangerous behaviour अक्सर default रूप से crash नहीं करती। gosentry के साथ, आप कई प्रकार की “bad but silent” states को findings में promote कर सकते हैं:

- `--panic-on=pkg.Func,...` ताकि selected logging/error paths crashes की तरह behave करें (यह `log.Fatal`-style code paths के लिए उपयोगी है जो otherwise सिर्फ log करके continue करते हैं)।
- `--catch-races=true` ताकि newly discovered queue entries को Go race detector के साथ replay किया जा सके।
- `--catch-leaks=true` ताकि new queue entries को `goleak` के साथ replay किया जा सके और goroutine leaks पर stop किया जा सके।
- LibAFL hang handling ताकि **infinite loops / very slow inputs** timeouts में गायब होने के बजाय fuzz findings बने रहें।
- default रूप से built-in arithmetic overflow checks, plus go-panikint-style instrumentation के माध्यम से optional truncation checks।

यह विशेष रूप से उन targets के लिए मूल्यवान है जहाँ security impact एक **panicless parser failure**, एक **concurrency bug**, या **DoS-only hang** होता है, memory corruption नहीं।

### Typed Go APIs के लिए Struct-aware fuzzing

Native Go fuzzing मुख्य रूप से `[]byte`, `string`, और numbers जैसे scalars की अपेक्षा करता है। यदि code under test typed objects consume करता है, तो gosentry composite values को सीधे fuzz कर सकता है (structs, slices, arrays, pointers) जबकि नीचे bytes को mutate करता रहता है।
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
फज़िंग के लिए सिर्फ fake wire format बनाते समय इसका उपयोग करने से logic bugs harness-only parsing code के पीछे छिप सकते हैं। Differential या grammar-based campaigns के लिए, harness input को एक single `[]byte` या `string` के रूप में रखें और instead callback के अंदर parse करें।

### Grammar-based fuzzing for parsers and protocol inputs

Parsers, formats, और input languages के लिए, gosentry LibAFL के ऊपर **Nautilus grammar fuzzing** चला सकता है। Grammar एक JSON array of production rules है, और harness को आमतौर पर एक single `[]byte` या `string` argument लेना चाहिए।
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
मेथडोलॉजी नोट्स:

- जब byte-level mutations ज़्यादातर शुरुआती syntax checks में ही मर जाती हैं, तब grammar mode का उपयोग करें।
- पूरे specification को model करने के बजाय grammar को language/protocol के **security-relevant subset** पर focused रखें।
- integer, length, और state-machine edges को stress करने के लिए terminals/nonterminals में बड़े boundary values का उपयोग करें।
- Grammar mode inputs को grammar-valid रखता है, लेकिन target फिर भी **bytes/strings** प्राप्त करता है, इसलिए parsing और semantic checks harnessed code के अंदर ही रहते हैं।

### Differential fuzzing: सिर्फ crashes नहीं, implementations की तुलना करें

Go ecosystems के लिए एक मजबूत pattern है **grammar-based differential fuzzing**: valid structured inputs generate करें और उन्हें दो parsers, clients, या state-transition engines को feed करें।
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
इन्हें findings के रूप में treat करें:

- एक implementation panic करता है जबकि दूसरा cleanly reject करता है
- accepted/rejected input mismatches
- different parse trees or decoded objects
- divergent state transitions, nonces, balances, or state roots

यह **consensus mismatches**, **parser ambiguity**, और **spec-vs-implementation drift** को खोजने का एक practical तरीका है, जिसे pure crash fuzzing अक्सर miss कर देता है।

### coverage reporting के लिए campaign corpus को reuse करें

एक campaign के बाद, saved queue corpus को replay करें ताकि अलग से corpus export किए बिना Go coverage report generate की जा सके:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Run the command from the **same package** and with the **same `-fuzz` target** so gosentry resolves the right cached campaign state.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
