# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, इनपुट्स को परिवर्तित किया जाता है जबकि वे **grammar-valid** बने रहते हैं। In coverage-guided mode, केवल ऐसे सैंपल जो **new coverage** ट्रिगर करते हैं, उन्हें corpus seeds के रूप में सेव किया जाता है। For **language targets** (parsers, interpreters, engines), यह उन बग्स को मिस कर सकता है जिनके लिए **semantic/dataflow chains** की आवश्यकता होती है, जहाँ एक construct का आउटपुट दूसरे का इनपुट बन जाता है।

**विफलता का तरीका:** fuzzer उन seeds को ढूँढ लेता है जो अलग-अलग `document()` और `generate-id()` (या समान primitives) को एक्सरसाइज़ करते हैं, लेकिन **does not preserve the chained dataflow**, इसलिए “closer-to-bug” सैंपल को ड्रॉप कर दिया जाता है क्योंकि यह coverage बढ़ाता नहीं। With **3+ dependent steps**, रैंडम recombination महँगा हो जाता है और coverage feedback search का मार्गदर्शन नहीं करता।

**निहितार्थ:** dependency-heavy grammars के लिए, **hybridizing mutational and generative phases** पर विचार करें या generation को **function chaining** पैटर्न की ओर bias करें (सिर्फ coverage नहीं)।

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** होता है: नया-coverage सैंपल तुरंत सेव कर लिया जाता है, अक्सर बड़े अपरिवर्तित हिस्सों को बरकरार रखते हुए। समय के साथ, corpora **near-duplicates** बन जाती हैं जिनमें structural diversity कम होती है। Aggressive minimization उपयोगी context को हटा सकता है, इसलिए एक व्यावहारिक समझौता **grammar-aware minimization** है जो **stops after a minimum token threshold** — शोर कम करते हुए पर्याप्त surrounding structure बनाए रखता है ताकि यह mutation-friendly रहे।

## Single-Machine Diversity Trick (Jackalope-Style)

एक व्यावहारिक तरीका जिससे **generative novelty** को **coverage reuse** के साथ hybridize किया जा सकता है, वह है एक persistent server के खिलाफ **restart short-lived workers**। प्रत्येक worker एक empty corpus से शुरू होता है, `T` सेकेंड के बाद sync करता है, संयुक्त corpus पर अगले `T` सेकेंड चलाता है, फिर फिर से sync करता है और फिर exit कर देता है। इससे हर generation में **fresh structures each generation** मिलती हैं जबकि accumulated coverage का लाभ भी मिलता है।

**सर्वर:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**क्रमिक वर्कर्स (उदाहरण लूप):**

<details>
<summary>Jackalope वर्कर पुनः प्रारंभ लूप</summary>
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

- `-in empty` प्रत्येक जनरेशन में **नया corpus** लागू करता है।
- `-server_update_interval T` लगभग **विलंबित सिंक** के बराबर है (पहले नवीनता, बाद में पुन: उपयोग)।
- In grammar fuzzing mode, **initial server sync डिफ़ॉल्ट रूप से स्किप किया जाता है** (कोई ज़रूरत नहीं `-skip_initial_server_sync`)।
- Optimal `T` **लक्ष्य-निर्भर** होता है; जब worker ने अधिकांश “easy” coverage खोज ली हो तब स्विच करना आम तौर पर सबसे अच्छा काम करता है।

## संदर्भ

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
