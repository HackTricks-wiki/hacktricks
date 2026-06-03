# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**에서는 입력을 **grammar-valid** 상태로 유지한 채 변형합니다. coverage-guided mode에서는 **new coverage**를 유발한 샘플만 corpus seeds로 저장합니다. **language targets**(parsers, interpreters, engines)에서는, 한 construct의 output이 다른 construct의 input이 되는 **semantic/dataflow chains**가 필요한 버그를 놓칠 수 있습니다.

**Failure mode:** fuzzer가 개별적으로 `document()`과 `generate-id()`(또는 유사한 primitive)를 실행하는 seeds를 찾지만, **연결된 dataflow는 유지하지 못해**, bug에 더 가까운 sample이라도 coverage를 추가하지 않으면 버려집니다. **3개 이상의 dependent steps**가 있으면 랜덤 recombination 비용이 급격히 커지고 coverage feedback은 탐색을 제대로 유도하지 못합니다.

**Implication:** dependency가 많은 grammar에서는 **mutational phase와 generative phase를 hybridize**하거나, coverage만이 아니라 **function chaining** 패턴 쪽으로 generation을 편향시키는 것을 고려하세요.

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy**합니다: new-coverage sample이 발견되면 즉시 저장되며, 종종 많은 부분이 그대로 유지됩니다. 시간이 지나면 corpus는 구조적 다양성이 낮은 **near-duplicates**로 채워집니다. aggressive minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **grammar-aware minimization**을 사용해 **최소 token threshold** 이후에 중단하는 것입니다(노이즈는 줄이되 mutation-friendly할 만큼 주변 구조는 유지).

mutational fuzzing에서의 실용적인 corpus 규칙은: near-duplicates를 대량으로 쌓는 것보다 **coverage를 최대화하는 구조적으로 다른 seeds의 작은 집합을 선호**하는 것입니다. 실제로는 보통 다음을 의미합니다:

- **real-world samples**(public corpora, crawling, captured traffic, target ecosystem의 file sets)에서 시작합니다.
- 모든 valid sample을 유지하기보다 **coverage-based corpus minimization**으로 정제합니다.
- mutation이 무의미한 bytes가 아니라 의미 있는 fields에 들어가도록 seeds를 **충분히 작게** 유지합니다.
- 주요 harness/instrumentation 변경 후에는 corpus minimization을 다시 실행합니다. reachability가 바뀌면 “최적” corpus도 바뀌기 때문입니다.

## Comparison-Aware Mutation For Magic Values

fuzzer가 plateau에 도달하는 흔한 이유는 syntax가 아니라 **hard comparisons**입니다: magic bytes, length checks, enum strings, checksums, 또는 `memcmp`, switch tables, cascaded comparisons으로 보호되는 parser dispatch values. pure random mutation은 이런 값을 byte-by-byte로 맞추려다 cycle을 낭비합니다.

이런 target에서는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen-style workflows)을 사용해 fuzzer가 실패한 comparison의 operands를 관찰하고, 이를 만족하는 값 쪽으로 mutation을 유도할 수 있게 하세요.
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

- This is especially useful when the target gates deep logic behind **file signatures**, **protocol verbs**, **type tags**, or **version-dependent feature bits**.
- Pair it with **dictionaries** extracted from real samples, protocol specs, or debug logs. A small dictionary with grammar tokens, chunk names, verbs, and delimiters is often more valuable than a massive generic wordlist.
- If the target performs many sequential checks, solve the earliest “magic” comparisons first and then minimize the resulting corpus again so later stages start from already-valid prefixes.

## Stateful Fuzzing: Sequences Are Seeds

For **protocols**, **authenticated workflows**, and **multi-stage parsers**, the interesting unit is often not a single blob but a **message sequence**. Concatenating the whole transcript into one file and mutating it blindly is usually inefficient because the fuzzer mutates every step equally, even when only the later message reaches the fragile state.

A more effective pattern is to treat the **sequence itself as the seed** and use **observable state** (response codes, protocol states, parser phases, returned object types) as additional feedback:

- Keep **valid prefix messages** stable and focus mutations on the **transition-driving** message.
- Cache identifiers and server-generated values from prior responses when the next step depends on them.
- Prefer per-message mutation/splicing over mutating the whole serialized transcript as an opaque blob.
- If the protocol exposes meaningful response codes, use them as a **cheap state oracle** to prioritize sequences that progress deeper.

This is the same reason authenticated bugs, hidden transitions, or “only-after-handshake” parser bugs are often missed by vanilla file-style fuzzing: the fuzzer must preserve **order, state, and dependencies**, not just structure.

## Single-Machine Diversity Trick (Jackalope-Style)

A practical way to hybridize **generative novelty** with **coverage reuse** is to **restart short-lived workers** against a persistent server. Each worker starts from an empty corpus, syncs after `T` seconds, runs another `T` seconds on the combined corpus, syncs again, then exits. This yields **fresh structures each generation** while still leveraging accumulated coverage.

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

- `-in empty`는 생성할 때마다 **새로운 corpus**를 강제합니다.
- `-server_update_interval T`는 **지연된 sync**를 근사합니다(새로움 우선, 나중에 재사용).
- grammar fuzzing 모드에서는 **초기 server sync가 기본적으로 건너뛰어집니다**(`-skip_initial_server_sync` 필요 없음).
- 최적의 `T`는 **target-dependent**이며, worker가 대부분의 “easy” coverage를 찾은 뒤에 전환하는 방식이 가장 잘 맞는 경향이 있습니다.

## Snapshot Fuzzing For Hard-To-Harness Targets

테스트하려는 code가 **큰 setup cost** 이후에만 도달 가능해질 때(VM 부팅, login 완료, packet 수신, container 파싱, service 초기화 등), 유용한 대안은 **snapshot fuzzing**입니다:

1. target을 interesting state가 준비될 때까지 실행합니다.
2. 그 시점의 **memory + registers**를 snapshot합니다.
3. 각 test case마다 mutated input을 관련 guest/process buffer에 직접 씁니다.
4. crash/timeout/reset까지 실행합니다.
5. **dirty pages**만 복원하고 반복합니다.

이 방식은 매 iteration마다 전체 setup cost를 치르지 않아도 되며, 특히 **network services**, **firmware**, **post-auth attack surfaces**, 그리고 classic in-process harness로 리팩터링하기 까다로운 **binary-only targets**에 매우 유용합니다.

실용적인 팁은 `recv`/`read`/packet-deserialization 지점 직후에 즉시 break하고, input buffer 주소를 기록한 다음, 각 iteration에서 그 buffer를 직접 mutate하는 것입니다. 이렇게 하면 매번 전체 handshake를 다시 만들지 않고도 deep parsing logic을 fuzzing할 수 있습니다.

## Harness Introspection: Find Shallow Fuzzers Early

campaign이 정체될 때, 문제는 종종 mutator가 아니라 **harness**입니다. **reachability/coverage introspection**을 사용해 fuzz target에서 statically reachable하지만 동적으로는 거의 또는 전혀 covered되지 않는 functions를 찾으세요. 그런 functions는 보통 다음 세 가지 문제 중 하나를 의미합니다:

- harness가 target에 너무 늦게 또는 너무 일찍 들어갑니다.
- seed corpus에 전체 feature family가 빠져 있습니다.
- target은 하나의 거대한 “do everything” harness보다 **second harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일 workflow를 사용한다면, Fuzz Introspector는 이 triage에 유용합니다:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
보고서를 사용해 테스트되지 않은 parser 경로를 위한 새 harness를 추가할지, 특정 기능을 위한 corpus를 확장할지, 아니면 단일 monolithic harness를 더 작은 entry point들로 분할할지 결정하세요.

## Graph-First Fuzz Target Selection And Mutation Triage

이미 **static-analysis findings**, **mutation-testing survivors**, 그리고 **coverage reports**가 있다면, 그것들을 독립적인 목록으로 triage하지 마세요. 먼저 **call graph**를 만들고, 노드에 **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, 그리고 외부 findings를 주석으로 달아놓은 뒤, graph 질문을 하세요:

- 어떤 high-complexity 함수가 untrusted input에서 도달 가능한가?
- 어떤 mutation survivors가 parser/handler에서 security-critical code로 가는 path 위에 있는가?
- 어떤 함수가 비정상적으로 큰 **blast radius**를 가진 architectural choke point인가?

이렇게 하면 보통 "가장 낮은 coverage"만 보는 것보다 더 좋은 fuzz target이 드러납니다. **high complexity**와 확인된 **external reachability**를 가진 parser/decoder는, coverage는 낮지만 attacker-controlled path가 없는 고립된 internal helper보다 더 강한 harness 후보입니다.

### Practical triage workflow

1. 코드베이스로부터 **code graph**를 만들고 함수별 complexity/branch metrics를 추출하세요.
2. attacker-controlled input을 받는 **entrypoints**를 열거하세요: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. 그런 entrypoint들에서 후보 함수까지의 **path queries**를 실행해 reachable attack surface와 dead/internal-only code를 분리하세요.
4. 다음을 함께 만족하는 노드를 우선순위로 두세요:
- 높은 **cyclomatic complexity**
- untrusted input으로부터의 확인된 **reachability**
- 높은 **blast radius** 또는 많은 downstream dependents
- **SARIF** findings, audit notes, mutation survivors 같은 보강 증거
5. 특히 hex/Base64/IP/message decoders 같은 **parsers/codecs**를 중심으로, 가장 높은 점수를 받은 노드부터 focused harness를 작성하세요.

### Mutation survivors: equivalent vs actionable

Mutation testing은 종종 noisy survivor 목록을 만듭니다. 모든 survivor를 security gap으로 취급하기 전에 graph를 사용해 다음을 확인하세요:

- mutated function이 attacker-controlled entrypoint에서 도달 가능한가?
- 모든 call path가 mutated check보다 더 강한 invariants에 의해 제한되는가?
- node가 dead code, formatting-only logic, 또는 high-impact arithmetic/parser path 안에 있는가?

도달 불가능하거나 구조적으로 제한된 survivors는 종종 **equivalent mutants**입니다. 반면 **reachable**하고 **boundary conditions**, **overflow/carry paths**, 또는 **security-critical arithmetic/parsing**에 닿는 survivors는 다음으로 승격해야 합니다:

- 새 fuzz harness
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

SAST pipeline이 **SARIF**를 내보낸다면, **file + line range**를 기준으로 findings를 graph nodes에 투영하고 graph를 사용해 impact를 확장하세요:

- flagged function의 **blast radius**를 계산하세요
- finding이 entrypoint에서 오는 어떤 path 위에 있는지 확인하세요
- 같은 choke point로 수렴하는 인접 findings를 클러스터링하세요

이는 특정 함수에 fuzzing 시간을 쓸지 결정할 때 유용합니다: **reachable**하고, **complex**하며, 이미 **SAST hits**가 있는 노드는 attacker path가 없는 단순히 complex한 노드보다 더 나은 target인 경우가 많습니다.

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
중요한 방법론은 교차점입니다: **complexity x exposure x impact**. 그래프를 사용해 가장 높은 기대 보안 가치를 가진 fuzz target를 고른 다음, mutation survivor를 사용해 harness가 어떤 boundary와 invariant를 강하게 stress해야 하는지 결정하세요.

## Go Fuzzing With gosentry: 더 강한 Engine, Typed Inputs, 그리고 Differential Checks

Go target에 이미 native `testing.F` harness가 있다면, 실용적인 업그레이드 경로는 [gosentry](https://github.com/trailofbits/gosentry)를 사용해 같은 harness를 실행하는 것입니다. gosentry는 `go test -fuzz`는 유지하면서 backend를 **LibAFL**로 바꾸는 forked Go toolchain입니다.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Go 네이티브 fuzzer가 **hard comparisons**, **typed inputs**, 또는 **parser-heavy formats**에서 멈출 때 유용하다. 방법론은 동일하다:

- 시드에는 계속 `f.Add(...)`를, 콜백에는 `f.Fuzz(...)`를 사용한다.
- 같은 harness를 재사용하되, 기본 toolchain 대신 gosentry의 `go` binary로 실행한다.
- 결과 campaign을 일반적인 coverage-guided run으로 취급하되, LibAFL scheduling/mutation과 더 나은 주변 detector를 함께 사용한다.

### Silent failures를 fuzz findings로 바꾸기

Go assessment에서 반복적으로 보이는 문제는 위험한 동작이 기본적으로는 **crash**하지 않는다는 점이다. gosentry를 사용하면 여러 종류의 “bad but silent” 상태를 findings로 승격할 수 있다:

- 선택한 logging/error 경로를 crash처럼 동작하게 만드는 `--panic-on=pkg.Func,...` (그렇지 않으면 단순히 log만 남기고 계속 진행하는 `log.Fatal` 스타일 코드 경로에 유용하다).
- 새로 발견된 queue entry를 Go race detector와 함께 재생하는 `--catch-races=true`.
- 새 queue entry를 `goleak`과 함께 재생하고 goroutine leak에서 멈추는 `--catch-leaks=true`.
- **infinite loops / very slow inputs**를 timeout으로 사라지게 두지 않고 fuzz findings으로 유지하는 LibAFL hang handling.
- 기본으로 제공되는 arithmetic overflow checks와, go-panikint 스타일 instrumentation을 통한 선택적 truncation checks.

이는 특히 보안 영향이 memory corruption이 아니라 **panicless parser failure**, **concurrency bug**, 또는 **DoS-only hang**인 대상에서 매우 유용하다.

### Typed Go API를 위한 struct-aware fuzzing

Native Go fuzzing은 주로 `[]byte`, `string`, 숫자 같은 scalar를 기대한다. 테스트 중인 코드가 typed object를 소비한다면, gosentry는 아래와 같은 **composite values**를 직접 fuzz할 수 있다(내부적으로는 여전히 bytes를 mutate하면서): structs, slices, arrays, pointers.
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
가짜 wire format을 fuzzing 용도로만 만들 때는 harness 전용 parsing code 뒤에 logic bug가 가려질 수 있다. differential 또는 grammar-based campaign의 경우에는 harness input을 하나의 `[]byte` 또는 `string`으로 유지하고, 대신 callback 내부에서 parse하라.

### Grammar-based fuzzing for parsers and protocol inputs

parsers, formats, 그리고 input languages의 경우, gosentry는 LibAFL 위에서 **Nautilus grammar fuzzing**을 실행할 수 있다. grammar는 production rules의 JSON array이며, harness는 보통 단일 `[]byte` 또는 `string` argument를 받아야 한다.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
방법론 노트:

- 바이트 수준 변형이 초반 syntax 검사에서 대부분 죽을 때는 grammar mode를 사용한다.
- 전체 specification을 모델링하기보다, grammar를 **security-relevant subset**의 language/protocol에만 집중시킨다.
- terminal/nonterminal에 큰 boundary values를 사용해 integer, length, state-machine edge를 자극한다.
- Grammar mode는 inputs를 grammar-valid하게 유지하지만, target은 여전히 **bytes/strings**를 받으므로 parsing과 semantic checks는 harnessed code 안에 남아 있다.

### Differential fuzzing: crashes만 비교하지 말고 implementations를 비교하라

Go ecosystem에서 강력한 패턴은 **grammar-based differential fuzzing**이다: valid structured inputs를 생성해 두 개의 parser, client, 또는 state-transition engine에 전달한다.
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
다음과 같이 findings로 간주하세요:

- 한 구현은 panic하지만 다른 구현은 cleanly reject함
- accepted/rejected input mismatch
- 다른 parse trees 또는 decoded objects
- divergent state transitions, nonces, balances, 또는 state roots

이는 **consensus mismatches**, **parser ambiguity**, 그리고 순수 crash fuzzing이 자주 놓치는 **spec-vs-implementation drift**를 찾는 실용적인 방법입니다.

### 캠페인 corpus를 coverage reporting에 재사용하기

캠페인 후에는 저장된 queue corpus를 replay하여 별도로 corpus를 export하지 않고도 Go coverage report를 생성하세요:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
같은 package에서, 그리고 같은 `-fuzz` target으로 command를 실행해야 gosentry가 올바른 cached campaign state를 resolve합니다.

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
