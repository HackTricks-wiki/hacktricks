# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikiendelea kuwa **grammar-valid**. Katika mode ya coverage-guided, sampuli tu zinazoanzisha **new coverage** ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains** ambapo output ya construct moja inakuwa input ya nyingine.

**Failure mode:** fuzzer hupata seeds zinazotumia `document()` na `generate-id()` kivyake (au primitives zinazofanana), lakini **haidumishi chained dataflow**, hivyo sampuli iliyo “karibu na bug” hutupwa kwa sababu haiongezi coverage. Ukiwa na hatua **3+ dependent steps**, random recombination inakuwa ghali na coverage feedback haiielekezi search.

**Implication:** kwa grammars zenye dependency nyingi, zingatia **hybridizing mutational and generative phases** au kuelekeza generation kuelekea mifumo ya **function chaining** (sio coverage tu).

## Corpus Diversity Pitfalls

Coverage-guided mutation ni **greedy**: sampuli yenye new-coverage huhifadhiwa mara moja, mara nyingi ikibakiza sehemu kubwa zisizobadilika. Kadri muda unavyopita, corpora hugeuka kuwa **near-duplicates** zenye structural diversity ndogo. Aggressive minimization inaweza kuondoa context muhimu, hivyo compromise ya vitendo ni **grammar-aware minimization** ambayo **inasimama baada ya minimum token threshold** (kupunguza noise huku ikibakiza muundo wa kutosha ili kubaki mutation-friendly).

Kanuni ya vitendo kwa corpus katika mutational fuzzing ni: **pendelea set ndogo ya structurally different seeds zinazoongeza coverage zaidi** kuliko rundo kubwa la near-duplicates. Kwa vitendo, hili kwa kawaida humaanisha:

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka ecosystem ya target).
- Zidistille kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Weka seeds ziwe **small enough** ili mutations zishuke kwenye fields zenye maana badala ya kutumia cycles nyingi kwenye bytes zisizo muhimu.
- Endesha corpus minimization tena baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora zaidi” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation For Magic Values

Sababu ya kawaida inayofanya fuzzers kufikia plateau si syntax bali **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Pure random mutation hupoteza cycles kujaribu kubahatisha values hizi byte-by-byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano AFL++ `CMPLOG` / Redqueen-style workflows) ili fuzzer iweze kuona operands kutoka kwa failed comparisons na kuelekeza mutations kuelekea values zinazozikidhi.
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
**Maelezo ya vitendo:**

- Hii ni muhimu sana wakati lengo linapoficha mantiki ya kina nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Itie pamoja na **dictionaries** zilizotolewa kutoka sampuli halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, chunk names, verbs, na delimiters mara nyingi ni muhimu zaidi kuliko massive generic wordlist.
- Ikiwa lengo linafanya many sequential checks, solve the earliest “magic” comparisons first kisha punguza tena corpus inayotokana ili hatua za baadaye zianze kutoka prefixes ambazo tayari ni valid.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, unit ya kuvutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kuwa faili moja na kuibadilisha bila mpangilio kawaida ni inefficient kwa sababu fuzzer hubadilisha kila hatua kwa usawa, hata pale ambapo ni ujumbe wa baadaye tu unaofikia state dhaifu.

Mfumo unaofaa zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada:

- Hifadhi **valid prefix messages** zikiwa stable na elekeza mutations kwenye ujumbe unaoendesha **transition**.
- Cache identifiers na values zinazotolewa na server kutoka kwa majibu ya awali wakati hatua inayofuata inategemea hizo.
- Pendelea per-message mutation/splicing badala ya kubadilisha transcript yote iliyoserailishwa kama opaque blob.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **cheap state oracle** ili kutanguliza sequences zinazoendelea zaidi ndani.

Hii ndiyo sababu bugs za authenticated, hidden transitions, au bugs za parser za “only-after-handshake” mara nyingi hukosaonekana na vanilla file-style fuzzing: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **generative novelty** na **coverage reuse** ni **kuanzisha upya workers wa muda mfupi** dhidi ya persistent server. Kila worker huanza kutoka corpus tupu, hufanya sync baada ya sekunde `T`, huendesha tena sekunde `T` nyingine kwenye combined corpus, husync tena, kisha hutoka. Hii huzalisha **fresh structures kila kizazi** huku bado ikitumia coverage iliyokusanywa.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Wafanyakazi wa mfululizo (mfano wa loop):**

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

**Maelezo:**

- `-in empty` hulazimisha **corpus mpya kabisa** kila kizazi.
- `-server_update_interval T` hukadiria **uhamasishaji uliocheleweshwa** (novelty kwanza, reuse baadaye).
- Katika mode ya grammar fuzzing, **awali server sync hurukwa kwa chaguo-msingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora ni **inategemea target**; kubadilisha baada ya worker kupata coverage nyingi za “easy” huwa hufanya kazi vizuri zaidi.

## Snapshot Fuzzing Kwa Hard-To-Harness Targets

Wakati code unayotaka kujaribu inakuwa reachable **baada ya gharama kubwa ya setup** (ku-boot VM, kukamilisha login, kupokea packet, ku-parse container, ku-initialize service), mbadala muhimu ni **snapshot fuzzing**:

1. Endesha target hadi state ya kuvutia iwe tayari.
2. Snapshot **memory + registers** katika hatua hiyo.
3. Kwa kila test case, andika mutated input moja kwa moja ndani ya relevant guest/process buffer.
4. Execute hadi crash/timeout/reset.
5. Rejesha tu **dirty pages** na rudia.

Hii huepuka kulipa gharama kamili ya setup kila iteration na ni muhimu sana kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets** ambazo ni ngumu kubadilisha kuwa classic in-process harness.

Njia ya vitendo ni kuvunja mara moja baada ya `recv`/`read`/packet-deserialization point, kumbuka anwani ya input buffer, fanya snapshot hapo, kisha mutate buffer hiyo moja kwa moja katika kila iteration. Hii hukuruhusu kufanya fuzzing ya deep parsing logic bila kujenga upya handshake nzima kila mara.

## Harness Introspection: Tafuta Shallow Fuzzers Mapema

Wakati campaign inakwama, tatizo mara nyingi si mutator bali ni **harness**. Tumia **reachability/coverage introspection** ili kupata functions ambazo kimsingi zinaweza kufikiwa kutoka fuzz target yako lakini mara chache au kamwe hazijafunikwa dynamically. Functions hizo kwa kawaida zinaonyesha mojawapo ya matatizo matatu:

- Harness inaingia kwenye target kuchelewa sana au mapema sana.
- Seed corpus inakosa family nzima ya feature.
- Target kweli inahitaji **second harness** badala ya harness moja kubwa ya “fanya kila kitu”.

Ukijaribu OSS-Fuzz / ClusterFuzz-style workflows, Fuzz Introspector ni muhimu kwa triage hii:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Tumia ripoti kuamua kama utaongeza harness mpya kwa njia ya parser ambayo haijajaribiwa, kupanua corpus kwa feature fulani, au kugawa harness moja kubwa kuwa entry points ndogo.

## Uteuzi wa Fuzz Target Kwanza kwa Graph Na Mutation Triage

Ikiwa tayari una **static-analysis findings**, **mutation-testing survivors**, na **coverage reports**, usizi triage kama orodha huru. Tengeneza kwanza **call graph**, weka maelezo kwenye nodes kwa **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, na matokeo yoyote ya nje, kisha uliza maswali ya graph:

- Ni functions zipi zenye complexity kubwa zinazoweza kufikiwa kutoka kwenye untrusted input?
- Ni mutation survivors gani ziko kwenye njia kutoka parsers/handlers hadi code muhimu ya usalama?
- Ni functions zipi ni architectural choke points zenye **blast radius** kubwa isivyo kawaida?

Hii kawaida huonyesha fuzz targets bora kuliko "lowest coverage" pekee. Parser/decoder yenye **high complexity** na **external reachability** iliyothibitishwa ni mgombea bora wa harness kuliko helper wa ndani aliyejitenga mwenye coverage hafifu lakini bila njia inayodhibitiwa na attacker.

### Practical triage workflow

1. Tengeneza **code graph** kutoka kwenye codebase na toa metrics za complexity/branch kwa kila function.
2. Orodhesha **entrypoints** zinazokubali input inayodhibitiwa na attacker: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Endesha **path queries** kutoka entrypoints hizo hadi candidate functions ili kutenganisha attack surface inayofikiwa kutoka code dead/internal-only.
4. Weka kipaumbele kwa nodes zinazochanganya:
- high **cyclomatic complexity**
- **reachability from untrusted input** iliyothibitishwa
- high **blast radius** au dependents wengi downstream
- ushahidi unaounga mkono kama **SARIF** findings, audit notes, au mutation survivors
5. Andika harnesses maalum kwa nodes zenye alama bora kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing mara nyingi huzalisha orodha yenye kelele ya survivors. Kabla hujachukulia kila survivor kama security gap, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka entrypoint inayodhibitiwa na attacker?
- Je, njia zote za call zimewekewa constraints na invariants kali kuliko check iliyobadilishwa?
- Je, node iko kwenye dead code, logic ya formatting tu, au kwenye arithmetic/parser path yenye impact kubwa?

Survivors wanaosalia bila kufikiwa au wanaozuiliwa kimuundo mara nyingi ni **equivalent mutants**. Survivors wanaosalia **reachable** na kugusa **boundary conditions**, **overflow/carry paths**, au **security-critical arithmetic/parsing** wanapaswa kupandishwa kuwa:

- harnesses mpya za fuzz
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Ikiwa SAST pipeline yako inatoa **SARIF**, panga findings kwenye graph nodes kwa **file + line range** na tumia graph kupanua impact:

- hesabu **blast radius** ya function iliyo flagged
- kagua kama finding iko kwenye njia yoyote kutoka entrypoint
- kusanya findings zilizo karibu zinazoshuka kuwa choke point moja

Hii ni muhimu unapokuwa unaamua kama utatumia muda wa fuzzing kwenye function fulani: node ambayo ni **reachable**, **complex**, na tayari ina **SAST hits** mara nyingi ni target bora kuliko node iliyo complex tu bila njia ya attacker.

Mfano wa workflow na Trailmark:
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
Mbinu muhimu ni makutano: **complexity x exposure x impact**. Tumia grafu kuchagua fuzz targets zenye thamani ya juu zaidi ya usalama inayotarajiwa, kisha tumia mutation survivors kuamua ni mipaka na invariants zipi harness yako lazima zisukume.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
