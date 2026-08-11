# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**에서는 입력이 **grammar-valid** 상태를 유지하도록 변형됩니다. coverage-guided 모드에서는 **new coverage**를 유발하는 샘플만 corpus seed로 저장됩니다. **language target**(parser, interpreter, engine)의 경우, 한 construct의 출력이 다른 construct의 입력이 되는 **semantic/dataflow chain**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer가 각각 `document()`와 `generate-id()`(또는 유사한 primitive)를 개별적으로 실행하는 seed는 찾지만, **chained dataflow를 보존하지 못하므로** “closer-to-bug” 샘플이 coverage를 추가하지 않는다는 이유로 삭제됩니다. **3+ dependent step**에서는 random recombination의 비용이 커지고 coverage feedback이 탐색을 유도하지 못합니다.<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammar에서는 **mutational phase와 generative phase를 hybridize**하거나, 단순히 coverage만 따르지 말고 **function chaining** 패턴을 중심으로 generation을 편향시키는 것을 고려해야 합니다.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy** 방식입니다. new-coverage 샘플이 즉시 저장되며, 변경되지 않은 큰 영역이 그대로 유지되는 경우가 많습니다. 시간이 지나면 corpus가 구조적 다양성이 낮은 **near-duplicate**로 채워집니다. 과도한 minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **minimum token threshold에서 중단하는 grammar-aware minimization**입니다. 이는 noise를 줄이면서 mutation-friendly 상태를 유지할 만큼 충분한 주변 구조를 보존합니다.<sup>[[1]](#references)</sup>

mutational fuzzing에서 실용적인 corpus 규칙은 near-duplicate의 대규모 모음보다 **coverage를 극대화하는 구조적으로 다른 소수의 seed**를 우선하는 것입니다. 실제로는 일반적으로 다음을 의미합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world sample**(public corpus, crawling, captured traffic, target ecosystem의 file set)에서 시작합니다.
- 모든 valid sample을 보관하는 대신 **coverage-based corpus minimization**으로 추려냅니다.
- mutation이 대부분의 cycle을 관련 없는 byte에 소비하지 않고 의미 있는 field에 적용되도록 seed를 **충분히 작게** 유지합니다.
- 주요 harness/instrumentation 변경 후에는 corpus minimization을 다시 실행합니다. reachability가 변경되면 “최적” corpus도 변경되기 때문입니다.

## Comparison-Aware Mutation For Magic Values

fuzzer가 plateau에 도달하는 일반적인 원인은 syntax가 아니라 **hard comparison**입니다. 여기에는 magic byte, length check, enum string, checksum, 또는 `memcmp`, switch table, 연쇄 비교로 보호되는 parser dispatch value가 포함됩니다. 순수한 random mutation은 이러한 값을 byte 단위로 추측하는 데 cycle을 낭비합니다.

이러한 target에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen-style workflow)을 사용하여 fuzzer가 실패한 comparison의 operand를 관찰하고, 이를 충족하는 값에 mutation이 집중되도록 해야 합니다.<sup>[[3]](#references)</sup>
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
**실무 참고 사항:**

- 이는 대상이 **file signatures**, **protocol verbs**, **type tags** 또는 **version-dependent feature bits**를 기준으로 깊은 로직에 대한 접근을 제한할 때 특히 유용합니다.
- 실제 샘플, protocol 사양 또는 debug 로그에서 추출한 **dictionaries**와 함께 사용하세요. grammar token, chunk name, verb, delimiter가 포함된 작은 dictionary가 대규모 일반 wordlist보다 더 유용한 경우가 많습니다.
- 대상이 순차적인 검사를 여러 번 수행한다면, 가장 이른 “magic” 비교부터 해결한 다음 결과 corpus를 다시 최소화하여 이후 단계가 이미 유효한 prefix에서 시작하도록 하세요.

## Stateful Fuzzing: Sequences Are Seeds

**protocol**, **authenticated workflow**, **multi-stage parser**에서는 흥미로운 단위가 단일 blob가 아니라 **message sequence**인 경우가 많습니다. 전체 transcript를 하나의 file로 연결한 뒤 무작정 mutate하는 방식은 일반적으로 비효율적입니다. fuzzer가 모든 단계에 동일하게 mutation을 적용하기 때문이며, 실제로는 이후 message만 취약한 state에 도달하는 경우가 많습니다.<sup>[[4]](#references)</sup>

더 효과적인 패턴은 **sequence 자체를 seed로 취급**하고, **observable state**(response code, protocol state, parser phase, 반환된 object type)를 추가 feedback으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **valid prefix message**는 안정적으로 유지하고 **transition-driving** message에 mutation을 집중하세요.
- 다음 단계가 이전 response의 값에 의존한다면, 이전 response에서 얻은 identifier와 server-generated value를 cache하세요.
- 전체 serialized transcript를 불투명한 blob로 mutate하는 대신 message 단위의 mutation/splicing을 우선하세요.
- protocol이 의미 있는 response code를 노출한다면 이를 **cheap state oracle**로 사용하여 더 깊이 진행되는 sequence를 우선 처리하세요.

이는 authenticated bug, hidden transition 또는 “only-after-handshake” parser bug가 vanilla file-style fuzzing에서 자주 발견되지 않는 이유와 같습니다. fuzzer는 구조뿐만 아니라 **order, state, dependency**도 유지해야 합니다.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**와 **coverage reuse**를 hybridize하는 실용적인 방법은 persistent server를 대상으로 수명이 짧은 worker를 재시작하는 것입니다. 각 worker는 빈 corpus에서 시작하여 `T`초 후 sync하고, 결합된 corpus로 다시 `T`초 동안 실행한 뒤 다시 sync하고 종료합니다. 이를 통해 누적된 coverage를 계속 활용하면서도 **각 generation마다 새로운 structure**를 생성할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**서버:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (예시 루프):**

<details>
<summary>Jackalope worker 재시작 루프</summary>
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
- `-server_update_interval T`는 **delayed sync**를 근사합니다(먼저 novelty를 찾고 나중에 reuse).
- grammar fuzzing mode에서는 기본적으로 **initial server sync**를 건너뜁니다(`-skip_initial_server_sync` 불필요).
- 최적의 `T`는 **target-dependent**입니다. worker가 대부분의 “easy” coverage를 찾은 후 전환하는 방식이 일반적으로 가장 효과적입니다.

## Snapshot Fuzzing For Hard-To-Harness Targets

테스트하려는 code가 **large setup cost**(VM 부팅, login 완료, packet 수신, container parsing, service 초기화) 이후에만 접근 가능해지는 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비가 완료된 process 또는 VM state를 캡처하고, 각 test case를 target input path에 주입한 다음, crash/timeout까지 실행하고 snapshot을 복원합니다. 이 방식은 initialization 또는 protocol prefix를 반복할 필요를 없애며, **network services**, **firmware**, **post-auth attack surfaces**, **binary-only targets**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 흥미로운 state가 준비될 때까지 target을 실행합니다.
2. 해당 시점의 **memory + registers**를 snapshot합니다.
3. 각 test case마다 mutated input을 관련 guest/process buffer에 직접 기록합니다.
4. crash/timeout/reset까지 실행합니다.
5. snapshot을 복원합니다. VM targets의 경우 지원된다면 **dirty pages**만 복원한 다음 반복합니다.

snapshot은 첫 번째 expensive parse/dispatch step에 최대한 가깝게 배치합니다. 예를 들어 `recv`/`read` 또는 packet-deserialization 지점 이후가 될 수 있으며, target이 사용하는 input buffer를 기록합니다. 이는 input processing 과정에서 snapshot을 더 깊은 위치로 이동하여 작업 반복을 피하는 adaptive-placement principle을 따릅니다.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

campaign이 정체되었을 때 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **reachability/coverage introspection**을 사용하여 fuzz target에서 정적으로 reachable하지만 동적으로는 거의 또는 전혀 covered되지 않는 function을 찾습니다. 이러한 function은 일반적으로 다음 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 target에 너무 늦게 또는 너무 일찍 진입합니다.
- seed corpus에 전체 feature family가 누락되어 있습니다.
- target에는 하나의 지나치게 큰 “do everything” harness 대신 실제로 **second harness**가 필요합니다.

OSS-Fuzz / ClusterFuzz-style workflow를 사용하는 경우, Fuzz Introspector는 static reachability와 runtime coverage를 비교하고 timed run 또는 public corpus에서 report를 생성할 수 있습니다.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
보고서를 사용하여 테스트되지 않은 parser 경로를 위한 새 harness를 추가할지, 특정 feature의 corpus를 확장할지, 또는 monolithic harness를 더 작은 entry point로 분할할지 결정하세요.

## Graph-First Fuzz Target Selection And Mutation Triage

이미 **static-analysis findings**, **mutation-testing survivors**, **coverage reports**가 있다면 이를 독립적인 목록으로 따로 triage하지 마세요. 먼저 **call graph**를 구축하고, 노드에 **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, 외부 findings를 주석으로 추가한 다음 graph에 관한 질문을 하세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 어떤 high-complexity 함수가 untrusted input에서 도달 가능한가?
- 어떤 mutation survivors가 parser/handler에서 security-critical code로 이어지는 경로에 있는가?
- 어떤 함수가 비정상적으로 높은 **blast radius**를 가진 architectural choke point인가?

이는 일반적으로 "lowest coverage"만을 기준으로 하는 것보다 더 나은 fuzz target을 찾아냅니다. **high complexity**와 확인된 **external reachability**를 가진 parser/decoder는 coverage가 낮지만 attacker-controlled path가 없는 고립된 internal helper보다 더 강력한 harness 후보입니다.

### Practical triage workflow

1. codebase에서 **code graph**를 구축하고 함수별 complexity/branch metric을 추출합니다.
2. attacker-controlled input을 수용하는 **entrypoint**를 열거합니다: request handler, decoder, importer, protocol parser, CLI/file reader.
3. 해당 entrypoint에서 candidate function까지 **path query**를 실행하여 도달 가능한 attack surface와 dead/internal-only code를 구분합니다.
4. 다음 조건을 결합하는 노드의 우선순위를 높입니다:
- 높은 **cyclomatic complexity**
- **untrusted input에서 도달 가능**하다는 확인
- 높은 **blast radius** 또는 많은 downstream dependent
- **SARIF** findings, audit note, mutation survivor와 같은 보강 증거
5. 먼저 점수가 가장 높은 노드를 대상으로 focused harness를 작성하며, 특히 hex/Base64/IP/message decoder와 같은 **parser/codec**을 우선합니다.

### Mutation survivors: equivalent vs actionable

Mutation testing은 종종 noisy survivor list를 생성합니다. 모든 survivor를 security gap으로 취급하기 전에 graph를 사용하여 다음을 확인하세요:

- mutated function이 attacker-controlled entrypoint에서 도달 가능한가?
- 모든 call path가 mutated check보다 더 강력한 invariant에 의해 제한되는가?
- 해당 노드가 dead code, formatting-only logic, 또는 high-impact arithmetic/parser path에 있는가?

도달할 수 없거나 구조적으로 제한된 survivor는 흔히 **equivalent mutant**입니다. 계속 **reachable** 상태이며 **boundary condition**, **overflow/carry path**, 또는 **security-critical arithmetic/parsing**을 다루는 survivor는 다음 항목으로 승격해야 합니다:

- 새 fuzz harness
- 직접적인 property/invariant test
- targeted edge-case vector

### Correlate external findings onto the graph

SAST pipeline이 **SARIF**를 export하는 경우, **file + line range**를 기준으로 findings를 graph node에 매핑하고 graph를 사용하여 impact를 확장하세요.<sup>[[6]](#references)</sup>

- flagged function의 **blast radius**를 계산합니다.
- finding이 entrypoint에서 시작하는 경로에 있는지 확인합니다.
- 동일한 choke point로 수렴하는 인접 findings를 cluster합니다.

이는 특정 function에 fuzzing 시간을 사용할지 결정할 때 유용합니다. **reachable**하고 **complex**하며 이미 **SAST hits**가 있는 노드는 attacker path가 없는 단순히 complex한 노드보다 더 나은 target인 경우가 많습니다.

Trailmark를 사용한 example workflow입니다.<sup>[[6]](#references)</sup>
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
중요한 방법론은 **complexity x exposure x impact**의 교집합입니다. 그래프를 사용해 예상 security value가 가장 높은 fuzz target을 선택한 다음, mutation survivor를 활용해 harness가 집중적으로 테스트해야 하는 경계와 invariant를 결정하세요.<sup>[[5]](#references)</sup>

## gosentry를 사용한 Go Fuzzing: 더 강력한 Engine, Typed Inputs 및 Differential Checks

Go target에 이미 네이티브 `testing.F` harness가 있다면, 실용적인 업그레이드 경로는 [gosentry](https://github.com/trailofbits/gosentry)를 사용해 동일한 harness를 실행하는 것입니다. gosentry는 `go test -fuzz`를 유지하면서 backend를 **LibAFL**로 교체한 forked Go toolchain입니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
이는 native Go fuzzer가 **hard comparisons**, **typed inputs** 또는 **parser-heavy formats**에서 멈출 때 유용합니다. 방법론은 동일하게 유지됩니다.

- seed에는 계속 `f.Add(...)`를 사용하고, callback에는 `f.Fuzz(...)`를 사용합니다.
- 동일한 harness를 재사용하되, 기본 toolchain 대신 gosentry의 `go` binary로 실행합니다.
- 결과 campaign을 일반적인 coverage-guided run으로 취급하되, LibAFL scheduling/mutation과 더 나은 주변 detectors를 사용합니다.

### 조용한 실패를 fuzz findings로 전환

Go assessment에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 crash를 일으키지 **않는** 경우가 많다는 것입니다. gosentry를 사용하면 여러 유형의 “bad but silent” 상태를 findings로 승격할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용하면 선택한 logging/error 경로가 crash처럼 동작합니다. 그렇지 않으면 로그만 기록하고 계속 실행되는 `log.Fatal` 스타일의 code path에 유용합니다.
- `--catch-races=true`를 사용하면 새로 발견된 queue entry를 Go race detector로 다시 실행합니다.
- `--catch-leaks=true`를 사용하면 새 queue entry를 `goleak`으로 다시 실행하고 goroutine leak이 발생하면 중지합니다.
- LibAFL hang handling은 **infinite loops / very slow inputs**를 timeout으로 사라지게 하지 않고 fuzz findings로 유지합니다.
- 기본적으로 내장 arithmetic overflow checks를 제공하며, go-panikint 스타일 instrumentation을 통해 선택적으로 truncation checks를 활성화할 수 있습니다.

이는 보안 영향이 memory corruption이 아니라 **panicless parser failure**, **concurrency bug** 또는 **DoS-only hang**인 target에서 특히 유용합니다.

### typed Go API를 위한 Struct-aware fuzzing

Native Go fuzzing은 주로 `[]byte`, `string` 및 숫자와 같은 scalar를 대상으로 합니다. 테스트 대상 code가 typed object를 받는 경우, gosentry는 내부에서 bytes를 계속 mutate하면서 struct, slice, array 및 pointer와 같은 **composite values**를 직접 fuzz할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>
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
fuzzing만을 위해 가짜 wire format을 만들면 harness 전용 parsing code 뒤에 logic bug가 숨겨질 수 있으므로 이를 사용할 때 주의하세요. Differential 또는 grammar-based campaign에서는 harness input을 단일 `[]byte` 또는 `string`으로 유지하고, 대신 callback 내부에서 parse하세요.

### parser 및 protocol input을 위한 Grammar-based fuzzing

parser, format 및 input language의 경우, gosentry는 LibAFL 위에서 **Nautilus grammar fuzzing**을 실행할 수 있습니다. Grammar는 production rule의 JSON array이며, harness는 일반적으로 단일 `[]byte` 또는 `string` argument를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- byte-level mutations가 대부분 초기 syntax checks에서 중단되는 경우 grammar mode를 사용합니다.
- 전체 specification을 모델링하는 대신 **security-relevant subset** of the language/protocol에 grammar를 집중합니다.
- terminals/nonterminals에서 큰 boundary values를 사용하여 integer, length 및 state-machine edge를 자극합니다.
- Grammar mode는 inputs를 grammar-valid 상태로 유지하지만, target은 여전히 **bytes/strings**를 수신하므로 parsing 및 semantic checks는 harnessed code 내부에서 계속 수행됩니다.

### Differential fuzzing: crashes뿐만 아니라 implementations 비교

Go ecosystems에서 강력한 패턴은 **grammar-based differential fuzzing**입니다. valid structured inputs를 생성하고 이를 두 개의 parsers, clients 또는 state-transition engines에 전달합니다.<sup>[[7]](#references)[[8]](#references)</sup>
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
다음을 findings로 간주합니다:

- 한 구현은 panic을 발생시키지만 다른 구현은 정상적으로 거부함
- accepted/rejected input 불일치
- 서로 다른 parse tree 또는 decoded object
- 서로 다른 state transition, nonce, balance 또는 state root

이는 순수 crash fuzzing으로는 자주 발견하지 못하는 **consensus mismatches**, **parser ambiguity**, **spec-vs-implementation drift**를 찾는 실용적인 방법입니다.

### coverage reporting에 campaign corpus 재사용

campaign 후 저장된 queue corpus를 replay하여 별도의 corpus를 수동으로 export하지 않고 Go coverage report를 생성합니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
동일한 **패키지**에서 동일한 `-fuzz` 대상을 사용해 명령을 실행해야 gosentry가 올바른 캐시된 campaign state를 확인할 수 있습니다.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: A Fast Greybox Fuzzer for Stateful Network Protocols using Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [No Grammar, No Problem: Towards Fuzzing the Linux Kernel without System-Call Descriptions](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efficient Fuzzing with Adaptive and Mutable Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
