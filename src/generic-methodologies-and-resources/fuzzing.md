# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **grammar-valid**. Katika hali ya coverage-guided, ni sampuli zile tu zinazosababisha **new coverage** ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains** ambapo output ya construct moja inakuwa input ya nyingine.

**Failure mode:** fuzzer hupata seeds zinazotumia `document()` na `generate-id()` kila moja kivyake (au primitives zinazofanana), lakini **hazihifadhi chained dataflow**, hivyo sampuli iliyo “closer-to-bug” hutupwa kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, random recombination inakuwa ghali na coverage feedback haiongozi utafutaji.

**Implication:** kwa grammars zenye dependency nyingi, fikiria **hybridizing mutational and generative phases** au kuipa uzito zaidi generation kuelekea mifumo ya **function chaining** (sio coverage pekee).

## Corpus Diversity Pitfalls

Coverage-guided mutation ni **greedy**: sampuli yenye new-coverage huhifadhiwa mara moja, mara nyingi ikiacha sehemu kubwa zisizobadilika. Kadri muda unavyopita, corpora hugeuka kuwa **near-duplicates** zenye structural diversity ndogo. Aggressive minimization inaweza kuondoa context muhimu, kwa hiyo suluhu ya vitendo ni **grammar-aware minimization** ambayo **inasimama baada ya minimum token threshold** (kupunguza noise huku ikihifadhi muundo wa kutosha kuendelea kuwa mutation-friendly).

Sheria ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya structurally different seeds zinazoongeza coverage zaidi** kuliko rundo kubwa la near-duplicates. Kwenye vitendo, hii kwa kawaida humaanisha:

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka target ecosystem).
- Zisafishe kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Weka seeds ziwe **ndogo vya kutosha** ili mutations zifike kwenye fields zenye maana badala ya kutumia cycles nyingi kwenye bytes zisizo na umuhimu.
- Endesha corpus minimization tena baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation For Magic Values

Sababu ya kawaida inayofanya fuzzers kusimama ni si syntax bali ni **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Pure random mutation hupoteza cycles kujaribu kukisia values hizi byte-by-byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano AFL++ `CMPLOG` / Redqueen-style workflows) ili fuzzer iweze kuchunguza operands kutoka comparisons zilizofeli na kuelekeza mutations kuelekea values zinazozikidhi.
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

- Hii ni hasa muhimu wakati target inapoweka logic ya kina nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Ichanganye na **dictionaries** zilizotolewa kutoka kwenye sampuli halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, chunk names, verbs, na delimiters mara nyingi ina thamani zaidi kuliko massive generic wordlist.
- Ikiwa target hufanya checks nyingi za mfululizo, suluhisha kulinganisha kwa “magic” vya mapema kwanza kisha punguza corpus iliyosalia tena ili hatua za baadaye zianze kutoka prefixes tayari-valid.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, unit ya kuvutia mara nyingi si blob moja bali **message sequence**. Kuunganisha transcript nzima kuwa faili moja na kuimodify bila mpangilio huwa ni inefficient kwa kawaida kwa sababu fuzzer hubadilisha kila hatua kwa usawa, hata wakati ni ujumbe wa baadaye tu unaofikia state dhaifu.

Pattern yenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada:

- Weka **valid prefix messages** ziwe stable na elekeza mutations kwenye ujumbe unaoendesha **transition**.
- Hifadhi identifiers na server-generated values kutoka majibu yaliyopita wakati hatua inayofuata inategemea hizo.
- Pendelea per-message mutation/splicing badala ya ku-mutate transcript nzima iliyoserialishwa kama opaque blob.
- Ikiwa protocol ina response codes zenye maana, zitumie kama **cheap state oracle** ili kutanguliza sequences zinazoendelea zaidi ndani.

Hii ndiyo sababu bugs za authenticated, hidden transitions, au bugs za parser za “only-after-handshake” mara nyingi hukosa kuonekana na vanilla file-style fuzzing: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **generative novelty** na **coverage reuse** ni **ku-restart workers wa muda mfupi** dhidi ya persistent server. Kila worker huanza kutoka corpus tupu, husync baada ya `T` seconds, huendesha tena `T` seconds kwenye combined corpus, husync tena, kisha hu-exit. Hii huleta **fresh structures each generation** huku bado ikitumia coverage iliyokusanywa.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Wafanyakazi wa mfululizo (mzunguko wa mfano):**

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

**Notes:**

- `-in empty` hulazimisha **fresh corpus** kila mara inapotengenezwa.
- `-server_update_interval T` hukadiria **delayed sync** (novelty kwanza, reuse baadaye).
- Katika hali ya grammar fuzzing, **initial server sync in skipped by default** (hakuna haja ya `-skip_initial_server_sync`).
- T bora ya `T` hutegemea **target**; kubadilisha baada ya worker kupata zaidi ya coverage “easy” mara nyingi hufanya kazi vizuri zaidi.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wakati code unayotaka kujaribu inafikiwa tu **baada ya gharama kubwa ya setup** (ku-boot VM, kukamilisha login, kupokea packet, kuchambua container, kuanzisha service), njia mbadala inayofaa ni **snapshot fuzzing**:

1. Endesha target hadi state ya kuvutia iwe tayari.
2. Fanya snapshot ya **memory + registers** katika hatua hiyo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja ndani ya buffer husika ya guest/process.
4. Execute hadi crash/timeout/reset.
5. Rejesha tu **dirty pages** na urudie.

Hii huepuka kulipa gharama kamili ya setup kila iteration na ni muhimu sana kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets** ambazo ni ngumu kuzibadilisha kuwa classic in-process harness.

Mbinu ya vitendo ni kuvunja mara moja baada ya sehemu ya `recv`/`read`/packet-deserialization, kuandika anwani ya input buffer, kufanya snapshot hapo, kisha kubadilisha buffer hiyo moja kwa moja katika kila iteration. Hii hukuwezesha fuzzing logic ya deep parsing bila kujenga upya handshake nzima kila mara.

## Harness Introspection: Find Shallow Fuzzers Early

Wakati campaign inakwama, tatizo mara nyingi si mutator bali ni **harness**. Tumia **reachability/coverage introspection** kutafuta functions ambazo zinafikiwa kistatikia kutoka kwa fuzz target yako lakini mara chache au kamwe hazifunikwi dynamically. Functions hizo kwa kawaida zinaonyesha moja ya matatizo matatu:

- Harness inaingia kwenye target kuchelewa sana au mapema sana.
- Seed corpus inakosa familia nzima ya feature.
- Target kweli inahitaji **second harness** badala ya harness moja kubwa ya “do everything”.

Ukijiendesha kwa workflow za aina ya OSS-Fuzz / ClusterFuzz, Fuzz Introspector ni muhimu kwa triage hii:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Tumia ripoti kuamua kama utaongeza harness mpya kwa njia ya parser ambayo haijajaribiwa, kupanua corpus kwa kipengele fulani, au kugawa harness moja kubwa kuwa entry points ndogo.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
