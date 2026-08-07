# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**에서는 입력이 **grammar-valid** 상태를 유지하면서 변이됩니다. **coverage-guided** 모드에서는 **new coverage**를 유발하는 샘플만 corpus seed로 저장됩니다. **language target**(parser, interpreter, engine)의 경우, 한 construct의 출력이 다른 construct의 입력이 되는 **semantic/dataflow chain**이 필요한 bug를 놓칠 수 있습니다.

**Failure mode:** fuzzer가 `document()` 및 `generate-id()`(또는 유사한 primitive)를 각각 실행하는 seed는 찾지만, **chained dataflow**를 유지하지 않으므로 “closer-to-bug” 샘플이 coverage를 추가하지 않는다는 이유로 삭제됩니다. **3+ dependent steps**에서는 random recombination에 많은 비용이 들고 coverage feedback이 search를 유도하지 못합니다.

**Implication:** dependency-heavy grammar에서는 **mutational** 및 **generative phase**를 hybridize하거나, 단순히 coverage만 추적하는 대신 **function chaining** pattern을 우선하도록 generation을 편향시키는 것을 고려하세요.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy** 방식입니다. new-coverage 샘플이 즉시 저장되며, 변경되지 않은 큰 영역이 그대로 유지되는 경우가 많습니다. 시간이 지나면 corpus가 구조적 다양성이 낮은 **near-duplicate**로 채워집니다. 과도한 minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **grammar-aware minimization**을 사용하되 **minimum token threshold**에서 중지하는 것입니다(노이즈를 줄이면서 mutation-friendly 상태를 유지할 수 있을 만큼 주변 structure를 보존).<sup>[[1]](#references)</sup>

mutational fuzzing에서 실용적인 corpus rule은 많은 near-duplicate를 쌓기보다 **coverage를 극대화하는 구조적으로 다른 소수의 seed**를 우선하는 것입니다. 실제로는 일반적으로 다음을 의미합니다.<sup>[[1]](#references)</sup>

- **real-world sample**에서 시작합니다(public corpus, crawling, captured traffic, target ecosystem의 file set).
- 모든 valid sample을 보관하는 대신 **coverage-based corpus minimization**으로 추려냅니다.
- mutation이 irrelevant byte에 대부분의 cycle을 소비하지 않고 meaningful field에 적용되도록 seed를 **충분히 작게** 유지합니다.
- 주요 harness/instrumentation 변경 후 corpus minimization을 다시 실행합니다. reachability가 변경되면 “best” corpus도 변경되기 때문입니다.

## Comparison-Aware Mutation For Magic Values

fuzzer가 plateau에 도달하는 일반적인 원인은 syntax가 아니라 **hard comparison**입니다. 예를 들어 `memcmp`, switch table 또는 연속 비교로 보호되는 magic byte, length check, enum string, checksum 또는 parser dispatch value가 있습니다. Pure random mutation은 이러한 값을 byte 단위로 추측하는 데 cycle을 낭비합니다.

이러한 target에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen-style workflow)을 사용하여, fuzzer가 failed comparison에서 operand를 관찰하고 이를 충족하는 값에 mutation을 편향시킬 수 있도록 하세요.<sup>[[3]](#references)</sup>
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
**실용적인 참고 사항:**

- 이는 target이 **file signatures**, **protocol verbs**, **type tags** 또는 **version-dependent feature bits** 뒤에 깊은 logic을 숨겨 두는 경우 특히 유용합니다.
- 실제 samples, protocol specs 또는 debug logs에서 추출한 **dictionaries**와 함께 사용하세요. grammar tokens, chunk names, verbs 및 delimiters가 포함된 작은 dictionary가 방대한 generic wordlist보다 더 가치 있는 경우가 많습니다.
- target이 여러 sequential checks를 수행한다면, 가장 먼저 수행되는 “magic” comparisons부터 해결한 다음 resulting corpus를 다시 minimize하여 이후 stages가 이미 유효한 prefixes에서 시작하도록 하세요.

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows** 및 **multi-stage parsers**에서는 흥미로운 단위가 단일 blob이 아니라 **message sequence**인 경우가 많습니다. 전체 transcript를 하나의 file로 연결한 뒤 무작위로 mutate하는 방식은 일반적으로 비효율적입니다. fuzzer가 모든 step을 동일하게 mutate하기 때문에, fragile state에 도달하는 것은 이후 message뿐인 경우에도 그렇게 동작하기 때문입니다.

더 효과적인 pattern은 **sequence 자체를 seed로 취급**하고, **observable state** (response codes, protocol states, parser phases, returned object types)를 additional feedback으로 사용하는 것입니다:<sup>[[4]](#references)</sup>

- **valid prefix messages**는 stable하게 유지하고, **transition-driving** message에 mutations를 집중하세요.
- 다음 step이 이전 response에 의존한다면, identifiers와 server-generated values를 cache하세요.
- 전체 serialized transcript를 opaque blob으로 mutate하기보다, message별 mutation/splicing을 우선하세요.
- protocol이 의미 있는 response codes를 노출한다면 이를 **cheap state oracle**로 사용하여 더 깊이 진행되는 sequences를 우선순위화하세요.

이는 authenticated bugs, hidden transitions 또는 “only-after-handshake” parser bugs가 vanilla file-style fuzzing에서 자주 누락되는 것과 같은 이유입니다. fuzzer는 단순히 structure만 보존하는 것이 아니라 **order, state 및 dependencies**를 보존해야 합니다.

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**와 **coverage reuse**를 hybridize하는 실용적인 방법은 persistent server에 대해 수명이 짧은 workers를 **restart**하는 것입니다. 각 worker는 빈 corpus에서 시작하고, `T`초 후 sync하며, 결합된 corpus로 다시 `T`초 동안 실행한 뒤, 다시 sync하고 종료합니다. 이를 통해 누적된 coverage를 계속 활용하면서도 **각 generation마다 fresh structures**를 얻을 수 있습니다.<sup>[[2]](#references)</sup>

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

- `-in empty`는 각 generation마다 **fresh corpus**를 강제합니다.
- `-server_update_interval T`는 **delayed sync**를 근사합니다(먼저 novelty를 찾고, 이후 reuse).
- grammar fuzzing mode에서는 기본적으로 **initial server sync가 skip**됩니다(`-skip_initial_server_sync`가 필요하지 않음).
- 최적의 `T`는 **target-dependent**입니다. worker가 대부분의 “easy” coverage를 찾은 후 전환하는 방식이 일반적으로 가장 효과적입니다.

## Snapshot Fuzzing For Hard-To-Harness Targets

테스트하려는 code가 **큰 setup cost** 이후에만 도달 가능한 경우(VM booting, login 완료, packet 수신, container parsing, service initializing), 유용한 대안은 **snapshot fuzzing**입니다:

1. 관심 있는 state가 준비될 때까지 target을 실행합니다.
2. 해당 시점의 **memory + registers**를 snapshot합니다.
3. 각 test case마다 mutated input을 관련 guest/process buffer에 직접 기록합니다.
4. crash/timeout/reset이 발생할 때까지 실행합니다.
5. **dirty pages**만 restore하고 반복합니다.

이 방식은 매 iteration마다 전체 setup cost를 지불하지 않도록 하며, **network services**, **firmware**, **post-auth attack surfaces**, 그리고 classic in-process harness로 refactor하기 어려운 **binary-only targets**에 특히 유용합니다.

실용적인 방법은 `recv`/`read`/packet-deserialization 지점 직후에 즉시 중단하고, input buffer address를 기록한 다음, 해당 위치에서 snapshot을 생성하고 각 iteration에서 그 buffer를 직접 mutate하는 것입니다. 이렇게 하면 매번 전체 handshake를 다시 구성하지 않고도 deep parsing logic을 fuzz할 수 있습니다.

## Harness Introspection: Find Shallow Fuzzers Early

campaign이 중단되었을 때 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **reachability/coverage introspection**을 사용하여 fuzz target에서 statically reachable하지만 dynamically는 거의 또는 전혀 coverage되지 않는 function을 찾으세요. 이러한 function은 일반적으로 다음 세 가지 문제 중 하나를 나타냅니다:

- harness가 target에 너무 늦게 또는 너무 일찍 진입합니다.
- seed corpus에 전체 feature family가 누락되어 있습니다.
- target에는 하나의 지나치게 큰 “do everything” harness 대신 실제로 **second harness**가 필요합니다.

OSS-Fuzz / ClusterFuzz-style workflow를 사용하는 경우, Fuzz Introspector는 이 triage에 유용합니다:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
보고서를 사용하여 테스트되지 않은 parser 경로를 위한 새 harness를 추가할지, 특정 feature의 corpus를 확장할지, 또는 monolithic harness를 더 작은 entry point로 분할할지 결정합니다.

## Graph-First Fuzz Target Selection And Mutation Triage

이미 **static-analysis findings**, **mutation-testing survivors**, **coverage reports**가 있다면 이를 서로 독립적인 목록으로 분류하지 마세요. 먼저 **call graph**를 구축하고, 노드에 **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, 외부 findings를 주석으로 추가한 다음 graph에 대한 질문을 수행하세요:<sup>[[5]](#references)[[6]](#references)</sup>

- 어떤 high-complexity functions가 untrusted input에서 도달 가능한가?
- 어떤 mutation survivors가 parsers/handlers에서 security-critical code로 이어지는 경로에 위치하는가?
- 비정상적으로 큰 **blast radius**를 가진 architectural choke points는 어떤 functions인가?

이는 일반적으로 "lowest coverage"만을 기준으로 하는 것보다 더 나은 fuzz targets를 찾아냅니다. **high complexity**와 확인된 **external reachability**를 가진 parser/decoder는, coverage가 낮지만 attacker-controlled path가 없는 고립된 internal helper보다 더 강력한 harness 후보입니다.

### Practical triage workflow

1. codebase에서 **code graph**를 구축하고 function별 complexity/branch metrics를 추출합니다.
2. attacker-controlled input을 받는 **entrypoints**를 열거합니다: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. 해당 entrypoints에서 candidate functions로 이어지는 **path queries**를 실행하여 도달 가능한 attack surface와 dead/internal-only code를 구분합니다.
4. 다음 조건을 조합하여 충족하는 nodes의 우선순위를 높입니다:
- 높은 **cyclomatic complexity**
- **untrusted input에서 확인된 reachability**
- 높은 **blast radius** 또는 다수의 downstream dependents
- **SARIF** findings, audit notes, mutation survivors와 같은 보강 증거
5. 먼저 점수가 가장 높은 nodes를 대상으로 focused harnesses를 작성합니다. 특히 hex/Base64/IP/message decoders와 같은 **parsers/codecs**를 우선합니다.

### Mutation survivors: equivalent vs actionable

Mutation testing은 종종 많은 noise가 포함된 survivor list를 생성합니다. 모든 survivor를 security gap으로 간주하기 전에 graph를 사용하여 다음을 확인하세요:

- mutated function이 attacker-controlled entrypoint에서 도달 가능한가?
- 모든 call paths가 mutated check보다 강력한 invariants에 의해 제한되는가?
- 해당 node가 dead code, formatting-only logic, 또는 high-impact arithmetic/parser path에 위치하는가?

도달할 수 없거나 구조적으로 제한된 상태로 남는 survivors는 흔히 **equivalent mutants**입니다. 계속해서 **reachable** 상태이며 **boundary conditions**, **overflow/carry paths**, 또는 **security-critical arithmetic/parsing**을 다루는 survivors는 다음 항목으로 승격해야 합니다:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

SAST pipeline이 **SARIF**를 export하는 경우, **file + line range**를 기준으로 findings를 graph nodes에 매핑하고 graph를 사용하여 영향을 확장합니다:

- flag된 function의 **blast radius**를 계산합니다
- 해당 finding이 entrypoint에서 시작하는 path에 포함되는지 확인합니다
- 동일한 choke point로 통합되는 인접 findings를 cluster합니다

이는 특정 function에 fuzzing 시간을 투입할지 결정할 때 유용합니다. **reachable**하고 **complex**하며 이미 **SAST hits**가 있는 node는 attacker path가 없는 단순히 complex한 node보다 더 나은 target인 경우가 많습니다.

Trailmark를 사용한 Example workflow:<sup>[[6]](#references)</sup>
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
중요한 methodology는 **complexity x exposure x impact**의 교집합입니다. 그래프를 사용해 예상되는 security value가 가장 높은 fuzz target을 선택한 다음, mutation survivors를 사용해 harness가 stress해야 하는 boundary와 invariant를 결정하세요.

## gosentry를 사용한 Go Fuzzing: 더 강력한 Engine, Typed Inputs, 그리고 Differential Checks

Go target에 이미 native `testing.F` harness가 있다면, 실용적인 upgrade path는 [gosentry](https://github.com/trailofbits/gosentry)를 사용해 동일한 harness를 실행하는 것입니다. gosentry는 `go test -fuzz`를 유지하면서 backend를 **LibAFL**로 교체한 forked Go toolchain입니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
이는 기본 Go fuzzer가 **hard comparisons**, **typed inputs**, 또는 **parser-heavy formats**에서 진행을 멈출 때 유용합니다. Methodology는 동일하게 유지됩니다:

- seeds에는 계속 `f.Add(...)`를 사용하고, callback에는 `f.Fuzz(...)`를 사용합니다.
- 동일한 harness를 재사용하되, stock toolchain 대신 gosentry의 `go` binary로 실행합니다.
- 결과 campaign을 일반적인 coverage-guided run으로 취급하되, LibAFL scheduling/mutation과 더 나은 주변 detectors를 사용합니다.

### Turn silent failures into fuzz findings

Go assessments에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 crash를 일으키지 않는 경우가 많다는 것입니다. gosentry를 사용하면 여러 유형의 “bad but silent” 상태를 findings로 승격할 수 있습니다:

- `--panic-on=pkg.Func,...`를 사용하면 선택한 logging/error 경로가 crash처럼 동작하게 됩니다. 이는 그렇지 않으면 로그만 남기고 계속 진행하는 `log.Fatal` 스타일의 code path에 유용합니다.
- `--catch-races=true`를 사용하면 새로 발견된 queue entry를 Go race detector로 replay합니다.
- `--catch-leaks=true`를 사용하면 새 queue entry를 `goleak`으로 replay하고 goroutine leak이 발생하면 중지합니다.
- LibAFL hang handling을 사용하면 **infinite loops / very slow inputs**를 timeout으로 사라지게 하지 않고 fuzz findings로 유지할 수 있습니다.
- 기본적으로 내장된 arithmetic overflow checks를 제공하며, go-panikint 스타일 instrumentation을 통해 선택적으로 truncation checks를 활성화할 수도 있습니다.

이는 security impact가 memory corruption이 아니라 **panicless parser failure**, **concurrency bug**, 또는 **DoS-only hang**인 target에서 특히 유용합니다.

### Struct-aware fuzzing for typed Go APIs

Native Go fuzzing은 주로 `[]byte`, `string`, 숫자와 같은 scalar를 대상으로 합니다. 테스트 대상 code가 typed object를 입력으로 받는 경우, gosentry는 내부에서 bytes를 mutate하면서도 struct, slice, array, pointer와 같은 **composite values**를 직접 fuzz할 수 있습니다.
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
fuzzing만을 위해 가짜 wire format을 구축하면 harness 전용 parsing code 뒤에 logic bug가 숨겨질 수 있는 경우에 사용합니다. differential 또는 grammar-based campaign의 경우 harness input을 단일 `[]byte` 또는 `string`으로 유지하고, 대신 callback 내부에서 parse합니다.

### parser 및 protocol input을 위한 Grammar-based fuzzing

parser, format 및 input language의 경우 gosentry는 LibAFL 위에서 **Nautilus grammar fuzzing**을 실행할 수 있습니다. grammar는 production rule의 JSON array이며, harness는 일반적으로 단일 `[]byte` 또는 `string` argument를 받아야 합니다.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
방법론 메모:

- byte-level mutations가 대부분 초기 syntax checks에서 중단되는 경우 grammar mode를 사용합니다.
- 전체 specification을 모델링하는 대신, language/protocol의 **security-relevant subset**에 grammar를 집중합니다.
- terminals/nonterminals에서 큰 boundary values를 사용해 integer, length, state-machine의 경계 조건을 압박합니다.
- grammar mode는 input을 grammar-valid 상태로 유지하지만, target이 받는 것은 여전히 **bytes/strings**이므로 parsing과 semantic checks는 harnessed code 내부에서 계속 수행됩니다.

### Differential fuzzing: crash뿐 아니라 implementation을 비교

Go ecosystem에서 강력한 패턴은 **grammar-based differential fuzzing**입니다. 유효한 structured inputs를 생성하고 이를 두 개의 parser, client 또는 state-transition engine에 전달합니다.
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
다음과 같은 경우를 findings로 취급하세요:

- 한 구현은 panic이 발생하는 반면 다른 구현은 정상적으로 거부함
- 허용/거부되는 input이 서로 다름
- parse tree 또는 decoded object가 서로 다름
- state transition, nonce, balance 또는 state root가 서로 다름

이는 순수한 crash fuzzing으로는 놓치기 쉬운 **consensus mismatches**, **parser ambiguity**, **spec-vs-implementation drift**를 찾는 실용적인 방법입니다.

### coverage reporting에 campaign corpus 재사용

campaign이 끝난 후, 별도의 corpus를 수동으로 export하지 않고 저장된 queue corpus를 replay하여 Go coverage report를 생성합니다:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
동일한 **package**에서, 동일한 `-fuzz` 대상을 사용하여 명령을 실행해야 gosentry가 올바른 cached campaign 상태를 확인할 수 있습니다.

## 참고 자료

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
