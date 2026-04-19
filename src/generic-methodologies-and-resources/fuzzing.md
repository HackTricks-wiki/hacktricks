# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing** में, inputs को mutate किया जाता है जबकि वे **grammar-valid** बने रहते हैं। coverage-guided mode में, केवल वे samples save किए जाते हैं जो **new coverage** trigger करते हैं, और उन्हें corpus seeds के रूप में रखा जाता है। **language targets** (parsers, interpreters, engines) के लिए, इससे वे bugs miss हो सकते हैं जिनमें **semantic/dataflow chains** की ज़रूरत होती है, जहाँ एक construct का output दूसरे का input बनता है।

**Failure mode:** fuzzer ऐसे seeds ढूँढता है जो अलग-अलग `document()` और `generate-id()` (या similar primitives) को exercise करते हैं, लेकिन **chained dataflow preserve नहीं होता**, इसलिए “closer-to-bug” sample drop हो जाता है क्योंकि वह coverage नहीं बढ़ाता। **3+ dependent steps** के साथ, random recombination महँगा हो जाता है और coverage feedback search को guide नहीं करता।

**Implication:** dependency-heavy grammars के लिए, **mutational और generative phases को hybridize** करने पर विचार करें, या generation को **function chaining** patterns की ओर bias करें (सिर्फ coverage नहीं)।

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होती है: नया-coverage sample तुरंत save हो जाता है, अक्सर बड़े unchanged regions को retain करते हुए। समय के साथ, corpora **near-duplicates** बन जाते हैं जिनमें structural diversity कम होती है। Aggressive minimization useful context हटा सकती है, इसलिए एक practical compromise है **grammar-aware minimization** जो **minimum token threshold** के बाद रुक जाए (noise कम करें लेकिन mutation-friendly रहने के लिए पर्याप्त surrounding structure रखें)।

Mutational fuzzing के लिए एक practical corpus rule है: **near-duplicates के बड़े ढेर** की बजाय **structurally different seeds का छोटा set** prefer करें जो coverage maximize करे। Practice में, इसका मतलब आमतौर पर यह होता है:

- **real-world samples** से शुरू करें (public corpora, crawling, captured traffic, target ecosystem से file sets)।
- हर valid sample को रखने के बजाय उन्हें **coverage-based corpus minimization** से distill करें।
- Seeds को **इतना छोटा** रखें कि mutations meaningful fields पर land करें, न कि ज़्यादातर cycles irrelevant bytes पर खर्च हों।
- Major harness/instrumentation changes के बाद corpus minimization फिर से चलाएँ, क्योंकि reachability बदलने पर “best” corpus भी बदल जाता है।

## Comparison-Aware Mutation For Magic Values

Fuzzers के plateau होने का एक common कारण syntax नहीं बल्कि **hard comparisons** होता है: magic bytes, length checks, enum strings, checksums, या parser dispatch values, जो `memcmp`, switch tables, या cascaded comparisons द्वारा guard किए जाते हैं। Pure random mutation इन values को byte-by-byte guess करने में cycles waste करती है।

इन targets के लिए, **comparison tracing** का उपयोग करें (उदाहरण के लिए AFL++ `CMPLOG` / Redqueen-style workflows), ताकि fuzzer failed comparisons से operands observe कर सके और mutations को उन values की ओर bias कर सके जो उन्हें satisfy करती हैं।
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
- इसे real samples, protocol specs, या debug logs से निकाली गई **dictionaries** के साथ pair करें। grammar tokens, chunk names, verbs, और delimiters वाली छोटी dictionary अक्सर किसी बड़े generic wordlist से ज़्यादा मूल्यवान होती है।
- अगर target कई sequential checks करता है, तो सबसे पहले शुरुआती “magic” comparisons हल करें और फिर resulting corpus को दोबारा minimize करें ताकि बाद के stages पहले से valid prefixes से शुरू हों।

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, और **multi-stage parsers** के लिए, दिलचस्प unit अक्सर एक single blob नहीं बल्कि एक **message sequence** होती है। पूरे transcript को एक file में जोड़कर उसे blindly mutate करना आमतौर पर inefficient होता है क्योंकि fuzzer हर step को बराबर mutate करता है, भले ही सिर्फ बाद वाला message fragile state तक पहुँचे।

एक ज़्यादा प्रभावी pattern यह है कि **sequence itself को seed** माना जाए और **observable state** (response codes, protocol states, parser phases, returned object types) को अतिरिक्त feedback के रूप में इस्तेमाल किया जाए:

- **valid prefix messages** को stable रखें और mutations को **transition-driving** message पर केंद्रित करें।
- अगले step के लिए dependency होने पर पिछले responses से identifiers और server-generated values को cache करें।
- पूरे serialized transcript को एक opaque blob की तरह mutate करने के बजाय per-message mutation/splicing को प्राथमिकता दें।
- अगर protocol meaningful response codes expose करता है, तो उन्हें एक **cheap state oracle** की तरह इस्तेमाल करें ताकि उन sequences को प्राथमिकता मिले जो और गहराई तक progress करती हैं।

यही वजह है कि authenticated bugs, hidden transitions, या “only-after-handshake” parser bugs अक्सर vanilla file-style fuzzing में missed हो जाते हैं: fuzzer को सिर्फ structure नहीं, बल्कि **order, state, और dependencies** भी preserve करनी होती हैं।

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** और **coverage reuse** को hybridize करने का एक practical तरीका है persistent server के खिलाफ **short-lived workers** को restart करना। हर worker empty corpus से शुरू होता है, `T` seconds बाद sync करता है, combined corpus पर `T` seconds और चलता है, फिर फिर से sync करके exit कर जाता है। इससे **हर generation में fresh structures** मिलती हैं, जबकि accumulated coverage का लाभ भी बना रहता है।

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

- `-in empty` प्रत्येक generation के लिए **fresh corpus** को बाध्य करता है।
- `-server_update_interval T` **delayed sync** का अनुमान लगाता है (पहले novelty, बाद में reuse)।
- Grammar fuzzing mode में, **initial server sync by default छोड़ा जाता है** (`-skip_initial_server_sync` की जरूरत नहीं)।
- Optimal `T` **target-dependent** होता है; worker के most “easy” coverage खोज लेने के बाद switch करना आमतौर पर सबसे अच्छा काम करता है।

## Snapshot Fuzzing For Hard-To-Harness Targets

जब वह code जिसे आप test करना चाहते हैं केवल **बड़े setup cost** के बाद reachable होता है (VM boot करना, login complete करना, packet receive करना, container parse करना, service initialize करना), तो एक उपयोगी alternative है **snapshot fuzzing**:

1. Target को तब तक चलाएँ जब तक interesting state तैयार न हो जाए।
2. उस point पर **memory + registers** snapshot करें।
3. हर test case के लिए, mutated input को सीधे relevant guest/process buffer में लिखें।
4. crash/timeout/reset तक execute करें।
5. केवल **dirty pages** restore करें और repeat करें।

यह हर iteration में पूरे setup cost को चुकाने से बचाता है और खास तौर पर **network services**, **firmware**, **post-auth attack surfaces**, और **binary-only targets** के लिए उपयोगी है, जिन्हें classic in-process harness में refactor करना मुश्किल होता है।

एक practical trick है `recv`/`read`/packet-deserialization point के तुरंत बाद break करना, input buffer address note करना, वहाँ snapshot लेना, और फिर हर iteration में उस buffer को सीधे mutate करना। इससे आप हर बार पूरे handshake को rebuild किए बिना deep parsing logic को fuzz कर सकते हैं।

## Harness Introspection: Find Shallow Fuzzers Early

जब कोई campaign stall हो जाता है, तो समस्या अक्सर mutator नहीं बल्कि **harness** होती है। **reachability/coverage introspection** का उपयोग करके उन functions को खोजें जो statically आपके fuzz target से reachable हैं लेकिन dynamically बहुत कम या कभी covered नहीं होतीं। वे functions आमतौर पर तीन issues में से किसी एक का संकेत देती हैं:

- Harness target में बहुत देर से या बहुत जल्दी enter कर रहा है।
- Seed corpus में किसी पूरे feature family की कमी है।
- Target को सच में एक **second harness** चाहिए, न कि एक oversized “do everything” harness।

यदि आप OSS-Fuzz / ClusterFuzz-style workflows का उपयोग करते हैं, तो Fuzz Introspector इस triage के लिए उपयोगी है:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
रिपोर्ट का उपयोग करके यह तय करें कि एक अनटेस्टेड parser path के लिए नया harness जोड़ना है, किसी विशिष्ट feature के लिए corpus बढ़ाना है, या एक monolithic harness को छोटे entry points में split करना है।

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
