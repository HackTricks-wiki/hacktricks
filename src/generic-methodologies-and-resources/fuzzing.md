# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Katika **mutational grammar fuzzing**, inputs zinabadilishwa huku zikibaki **grammar-valid**. Katika mode ya **coverage-guided**, sampuli ambazo zinachochea **new coverage** pekee ndizo zinahifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa mende zinazohitaji **semantic/dataflow chains** ambapo output ya muundo mmoja inakuwa input kwa mwingine.

**Failure mode:** fuzzer hupata seeds ambazo kila moja zinaita juu `document()` na `generate-id()` (au primitives zinazofanana), lakini **haitunze mtiririko wa data uliounganishwa**, hivyo sampuli "closer-to-bug" inaangushwa kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, recombination ya nasibu inakuwa ghali na feedback ya coverage haisaidii utafutaji.

**Implication:** kwa grammars zenye utegemezi mwingi, fikiria **hybridizing mutational and generative phases** au kupendelea generation kuelekea mifumo ya **function chaining** (si coverage pekee).

## Corpus Diversity Pitfalls

Coverage-guided mutation ni **greedy**: sampuli yenye new-coverage inahifadhiwa mara moja, mara nyingi ikidumisha maeneo makubwa yasiyobadilika. Kwa muda, corpora zinakuwa **near-duplicates** zenye utofauti mdogo wa muundo. Aggressive minimization inaweza kuondoa muktadha muhimu, hivyo suluhisho la vitendo ni **grammar-aware minimization** ambayo **inasimama baada ya kikomo cha tokeni kilichoainishwa** (punguza kelele huku ukihifadhi muundo wa kutosha ili kuendelea kuwa mutation-friendly).

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **generative novelty** na **coverage reuse** ni **kuanzisha upya short-lived workers** dhidi ya persistent server. Kila worker inaanza kutoka kwa corpus tupu, syncs baada ya `T` sekunde, inaendesha tena kwa `T` sekunde kwenye corpus iliyounganishwa, syncs tena, kisha inatoka. Hii inatoa **fresh structures each generation** huku ikitumia accumulated coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Wafanyakazi mfululizo (mfano wa mzunguko):**

<details>
<summary>Mzunguko wa kuanzisha upya wa Jackalope worker</summary>
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

**Vidokezo:**

- `-in empty` hufanya **corpus safi** kila kizazi.
- `-server_update_interval T` inakaribia **delayed sync** (vipya kwanza, tumia tena baadaye).
- Katika grammar fuzzing mode, **sinkroni ya awali ya serveri hupuuzwa kwa chaguo-msingi** (hakuna haja ya `-skip_initial_server_sync`).
- T bora ni **inategemea lengo**; kubadilisha baada ya worker kupata sehemu nyingi za “easy” coverage mara nyingi hufanya kazi vizuri zaidi.

## Marejeo

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
