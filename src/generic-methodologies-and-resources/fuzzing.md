# Fuzzing 방법론

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage 대 Semantics

**Mutational Grammar Fuzzing**에서는 입력이 **grammar-valid** 상태를 유지하면서 변이됩니다. Coverage-guided 모드에서는 **new coverage**를 유발한 샘플만 corpus seed로 저장됩니다. **language target**(parser, interpreter, engine)의 경우, 한 construct의 출력이 다른 construct의 입력이 되는 **semantic/dataflow chain**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer가 각각 `document()` 및 `generate-id()`(또는 유사한 primitive)를 개별적으로 실행하는 seed는 찾지만, **chained dataflow**를 보존하지 못하므로 “closer-to-bug” 샘플이 coverage를 추가하지 않는다는 이유로 삭제됩니다. **3개 이상의 dependent step**에서는 random recombination 비용이 커지고 coverage feedback이 search를 유도하지 못합니다.<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammar의 경우 **mutational phase와 generative phase를 hybridize**하거나, generation이 단순히 coverage만이 아니라 **function chaining** 패턴을 우선하도록 편향하는 방식을 고려해야 합니다.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy**합니다. new-coverage 샘플은 즉시 저장되며, 변경되지 않은 큰 영역이 그대로 유지되는 경우가 많습니다. 시간이 지나면 corpus가 구조적 다양성이 낮은 **near-duplicate**로 채워집니다. Aggressive minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **grammar-aware minimization**을 사용하여 **minimum token threshold**에 도달하면 중지하는 것입니다(노이즈를 줄이면서 mutation-friendly 상태를 유지할 수 있을 만큼 주변 structure를 보존).<sup>[[1]](#references)</sup>

Mutational fuzzing에서 실용적인 corpus rule은 near-duplicate가 대량으로 쌓인 corpus보다 **coverage를 극대화하는 구조적으로 다른 소수의 seed**를 우선하는 것입니다. 일반적으로 다음을 의미합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **real-world sample**(public corpus, crawling, captured traffic, target ecosystem의 file set)에서 시작합니다.
- 모든 valid sample을 유지하는 대신 **coverage-based corpus minimization**으로 추려냅니다.
- mutation이 대부분의 cycle을 관련 없는 byte에 소비하지 않고 의미 있는 field에 적용되도록 seed를 **충분히 작게** 유지합니다.
- 주요 harness/instrumentation 변경 후 corpus minimization을 다시 실행합니다. reachability가 변경되면 “최적” corpus도 변경되기 때문입니다.

## Magic Value를 위한 Comparison-Aware Mutation

fuzzer가 plateau에 도달하는 일반적인 이유는 syntax가 아니라 **hard comparison**입니다. 여기에는 magic byte, length check, enum string, checksum 또는 `memcmp`, switch table, 연쇄 comparison으로 보호되는 parser dispatch value가 포함됩니다. Pure random mutation은 이러한 value를 byte 단위로 추측하는 데 cycle을 낭비합니다.

이러한 target에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen-style workflow)을 사용하여 fuzzer가 실패한 comparison의 operand를 관찰하고, 이를 충족하는 value를 향해 mutation이 편향되도록 해야 합니다.<sup>[[3]](#references)</sup>
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

- 이는 대상이 **file signatures**, **protocol verbs**, **type tags** 또는 **version-dependent feature bits** 뒤에 깊은 logic을 숨기는 경우 특히 유용합니다.
- 실제 샘플, protocol 사양 또는 debug logs에서 추출한 **dictionaries**와 함께 사용하세요. grammar tokens, chunk names, verbs, delimiters가 포함된 작은 dictionary가 방대한 일반 wordlist보다 더 유용한 경우가 많습니다.
- 대상이 여러 sequential checks를 수행한다면, 가장 먼저 나타나는 “magic” comparisons부터 해결한 다음 결과 corpus를 다시 minimize하여 이후 단계가 이미 유효한 prefixes에서 시작하도록 하세요.

## Edge Coverage가 서로 다른 경로를 구분하지 못할 때의 더 풍부한 Feedback

일반적인 edge coverage는 서로 다른 caller를 통해 동일한 helper를 거치거나 function 내부에서 서로 다른 branch 조합을 수행하는 두 execution을 구분할 수 없습니다. 이는 **route**에 따라 live state가 결정되는 shared decoders, protocol dispatchers 및 interpreter helpers에서 중요합니다. 모든 calling context를 무작정 추적하는 것도 위험합니다. coverage map과 queue가 폭발적으로 증가할 수 있기 때문입니다. 따라서 context-sensitive fuzzing 연구에서는 전체 call graph를 context-sensitive로 취급하기보다 유망한 context만 정제할 것을 권장합니다.<sup>[[14]](#references)</sup>

최근 AFL++ builds는 일반적인 edge coverage에 더해 **Ball-Larus per-function path coverage**를 제공합니다. 이는 function을 통과하는 각 acyclic path에 feature를 할당합니다. loop back-edges는 제거되므로 이 feedback은 branch 조합은 구분하지만 **loop iteration counts**는 구분하지 못합니다. 먼저 완화된 level `1`로 시작한 뒤, path 수가 exponential하게 증가할 수 있으므로 의심스러운 parser/state-machine code에만 더 엄격한 modes를 적용하세요.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
여러 보안 관련 지점에서 호출되는 helper의 경우, LTO mode는 각 함수 경로를 해당 함수의 직접 호출 지점과 결합할 수 있습니다:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Campaign guidance:** 더 풍부한 feedback은 보수적으로 적용하고 coverage-map/queue 비용을 모니터링하세요.<sup>[[13]](#references)[[14]](#references)</sup>

- 일반적인 edge-coverage 인스턴스를 병렬로 실행하세요. 추가 queue/map 비용으로 인해 초당 executions가 감소하지 않는 경우에만 더 풍부한 feedback이 유용합니다.
- 대규모 template-heavy library 또는 generic utility code가 map을 지배하는 경우 `AFL_LLVM_ALLOWLIST`를 사용하여 path/caller instrumentation을 제한하세요.
- 과도한 acyclic path를 가진 function은 AFL++에서 건너뛸 수 있습니다. compilation 중 warning이 발생한다면 target에 allowlisting 또는 덜 엄격한 level이 필요하다는 증거입니다.
- Caller + path coverage는 하나의 caller depth만 지원합니다. 더 깊은 context stack과 함께 사용하지 마세요.
- Path ID는 LLVM major version에 따라 변경될 수 있습니다. campaign 동안 toolchain을 고정하고, PATH 기반 corpus를 빌드 간 feature ID가 안정적인 것처럼 동기화하지 마세요.
- 이 feedback은 `CMPLOG`를 보완합니다. comparison tracing은 **guard를 통과하는 값이 무엇인지** 해결하는 반면, path/caller feedback은 **어떤 route와 branch 조합이 해당 지점에 도달했는지** 보존합니다.

## Stateful Fuzzing: Sequences Are Seeds

**protocol**, **authenticated workflow**, **multi-stage parser**에서는 흥미로운 단위가 단일 blob가 아니라 **message sequence**인 경우가 많습니다. 전체 transcript를 하나의 file로 연결한 뒤 무작위로 mutate하는 방식은 일반적으로 비효율적입니다. fuzzer가 모든 step을 동일하게 mutate하기 때문에, fragile state에 도달하는 것은 후속 message뿐인 경우에도 마찬가지로 처리하기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 pattern은 **sequence 자체를 seed로 취급**하고, **observable state**(response code, protocol state, parser phase, 반환된 object type)를 추가 feedback으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **valid prefix message**는 안정적으로 유지하고 **transition-driving** message에 mutation을 집중하세요.
- 다음 step이 이전 response에 의존하는 경우, 이전 response에서 얻은 identifier와 server-generated value를 cache하세요.
- 전체 serialized transcript를 불투명한 blob로 mutate하기보다 message별 mutation/splicing을 우선하세요.
- protocol이 의미 있는 response code를 노출한다면 이를 **저비용 state oracle**로 사용하여 더 깊이 진행하는 sequence를 우선 처리하세요.

이는 authenticated bug, hidden transition 또는 “handshake 이후에만 발생하는” parser bug가 vanilla file-style fuzzing에서 자주 발견되지 않는 것과 같은 이유입니다. fuzzer는 단순히 structure뿐 아니라 **order, state, dependency**도 보존해야 합니다.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**와 **coverage reuse**를 hybridize하는 실용적인 방법은 persistent server에 대해 수명이 짧은 worker를 **restart**하는 것입니다. 각 worker는 빈 corpus에서 시작하여 `T`초 후 sync하고, 결합된 corpus로 다시 `T`초 동안 실행한 뒤 다시 sync하고 종료합니다. 이렇게 하면 누적된 coverage를 계속 활용하면서도 **각 generation마다 새로운 structure**를 얻을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**순차 worker(예제 루프):**

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
- `-server_update_interval T`는 **delayed sync**를 근사합니다(먼저 novelty를 탐색하고, 나중에 reuse).
- grammar fuzzing mode에서는 기본적으로 **initial server sync가 생략**됩니다(`-skip_initial_server_sync`가 필요하지 않음).
- 최적의 `T`는 **target-dependent**입니다. worker가 대부분의 “easy” coverage를 찾은 후 전환하는 방식이 일반적으로 가장 잘 작동합니다.

## Snapshot Fuzzing For Hard-To-Harness Targets

테스트하려는 code가 **큰 setup cost**(VM 부팅, login 완료, packet 수신, container parsing, service 초기화) 이후에만 reach 가능해지는 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비된 process 또는 VM state를 캡처하고, 각 test case를 target input path에 주입한 뒤 crash/timeout까지 실행하고 snapshot을 복원합니다. 이를 통해 initialization 또는 protocol prefix를 반복하지 않아도 되며, **network services**, **firmware**, **post-auth attack surfaces**, **binary-only targets**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 관심 있는 state가 준비될 때까지 target을 실행합니다.
2. 해당 시점의 **memory + registers**를 snapshot합니다.
3. 각 test case마다 mutated input을 관련 guest/process buffer에 직접 기록합니다.
4. crash/timeout/reset까지 실행합니다.
5. snapshot을 복원합니다. VM target의 경우 지원된다면 **dirty pages**만 복원한 후 반복합니다.

snapshot은 첫 번째 expensive parse/dispatch 단계에 최대한 가깝게 배치합니다. 예를 들어 `recv`/`read` 이후 또는 packet-deserialization 지점에 배치하고, target이 사용하는 input buffer를 기록합니다. 이는 input processing에서 snapshot을 더 깊은 위치로 이동해 작업 반복을 방지하는 adaptive-placement principle을 따릅니다.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

campaign이 중단되었을 때 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **reachability/coverage introspection**을 사용해 fuzz target에서 정적으로 reach 가능하지만 동적으로는 거의 또는 전혀 coverage되지 않는 function을 찾습니다. 이러한 function은 일반적으로 다음 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 target에 너무 늦게 또는 너무 일찍 진입합니다.
- seed corpus에 특정 feature family 전체가 누락되어 있습니다.
- target에는 하나의 지나치게 큰 “do everything” harness가 아니라 실제로 **두 번째 harness**가 필요합니다.

OSS-Fuzz / ClusterFuzz-style workflow를 사용하는 경우, Fuzz Introspector는 static reachability와 runtime coverage를 비교하고 timed run 또는 public corpus에서 report를 생성할 수 있습니다.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
보고서를 사용하여 테스트되지 않은 parser 경로에 새 harness를 추가할지, 특정 기능에 대한 corpus를 확장할지, 또는 단일 monolithic harness를 더 작은 entry point로 분할할지 결정합니다.

## 그래프 우선 Fuzz Target Selection And Mutation Triage

이미 **static-analysis findings**, **mutation-testing survivors**, **coverage reports**가 있다면 이를 서로 독립적인 목록으로 triage하지 마세요. 먼저 **call graph**를 구축하고, 노드에 **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, 기타 외부 findings를 annotation한 다음 그래프에 관한 질문을 던지세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 어떤 높은 complexity의 함수가 untrusted input에서 도달 가능한가?
- 어떤 mutation survivor가 parser/handler에서 security-critical code로 이어지는 경로에 있는가?
- 어떤 함수가 비정상적으로 큰 **blast radius**를 가진 architectural choke point인가?

이는 일반적으로 "lowest coverage"만을 기준으로 하는 것보다 더 나은 fuzz target을 찾아냅니다. **high complexity**와 확인된 **external reachability**를 가진 parser/decoder는 coverage가 낮지만 attacker-controlled path가 없는 고립된 internal helper보다 더 강력한 harness 후보입니다.

### Practical triage workflow

1. codebase에서 **code graph**를 구축하고 함수별 complexity/branch metric을 추출합니다.
2. attacker-controlled input을 받는 **entrypoint**를 열거합니다: request handler, decoder, importer, protocol parser, CLI/file reader.
3. 해당 entrypoint에서 candidate function까지 **path query**를 실행하여 도달 가능한 attack surface와 dead/internal-only code를 구분합니다.
4. 다음 조건을 결합하는 노드의 우선순위를 높입니다:
- 높은 **cyclomatic complexity**
- **untrusted input에서의 reachability**가 확인됨
- 높은 **blast radius** 또는 많은 downstream dependent
- **SARIF** findings, audit notes, mutation survivor와 같은 보강 증거
5. 특히 hex/Base64/IP/message decoder와 같은 **parser/codec**을 중심으로, 점수가 가장 높은 노드부터 focused harness를 작성합니다.

### Mutation survivors: equivalent vs actionable

Mutation testing은 종종 noisy survivor list를 생성합니다. 모든 survivor를 security gap으로 간주하기 전에 그래프를 사용하여 다음을 확인하세요:

- mutated function이 attacker-controlled entrypoint에서 도달 가능한가?
- 모든 call path가 mutated check보다 더 강한 invariant에 의해 제한되는가?
- 해당 노드가 dead code, formatting-only logic, 또는 high-impact arithmetic/parser path에 있는가?

도달할 수 없거나 구조적으로 제한된 survivor는 흔히 **equivalent mutant**입니다. 계속 **reachable** 상태이며 **boundary condition**, **overflow/carry path**, 또는 **security-critical arithmetic/parsing**을 다루는 survivor는 다음 대상으로 승격해야 합니다:

- 새 fuzz harness
- 직접적인 property/invariant test
- targeted edge-case vector

### Correlate external findings onto the graph

SAST pipeline이 **SARIF**를 export하는 경우, **file + line range**를 기준으로 findings를 graph node에 매핑하고 그래프를 사용하여 영향 범위를 확장합니다.<sup>[[6]](#references)</sup>

- flag된 함수의 **blast radius**를 계산합니다.
- 해당 finding이 entrypoint에서 시작하는 경로에 있는지 확인합니다.
- 동일한 choke point로 수렴하는 인접 findings를 cluster합니다.

이는 특정 함수에 fuzzing 시간을 사용할지 결정할 때 유용합니다. **reachable**하고 **complex**하며 이미 **SAST hits**가 있는 노드는 attacker path가 없는 단순히 complex한 노드보다 더 나은 target인 경우가 많습니다.

Trailmark를 사용한 예시 workflow입니다.<sup>[[6]](#references)</sup>
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
중요한 methodology는 **complexity x exposure x impact**의 교집합입니다. 그래프를 사용해 예상되는 security value가 가장 높은 fuzz target을 선택한 다음, mutation survivor를 활용해 harness가 어떤 경계와 invariant를 집중적으로 검증해야 하는지 결정하세요.<sup>[[5]](#references)</sup>

## gosentry를 사용한 Go Fuzzing: 더 강력한 Engine, Typed Inputs 및 Differential Checks

Go target에 이미 네이티브 `testing.F` harness가 있다면, 실용적인 업그레이드 경로는 [gosentry](https://github.com/trailofbits/gosentry)를 사용해 동일한 harness를 실행하는 것입니다. gosentry는 `go test -fuzz`를 유지하면서 backend를 **LibAFL**로 교체한 forked Go toolchain입니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
이는 native Go fuzzer가 **hard comparisons**, **typed inputs** 또는 **parser-heavy formats**에서 정체될 때 유용합니다. 방법론은 동일하게 유지됩니다.

- seed에는 계속 `f.Add(...)`를 사용하고, callback에는 `f.Fuzz(...)`를 사용합니다.
- 동일한 harness를 재사용하되, stock toolchain 대신 gosentry의 `go` binary로 실행합니다.
- 결과 campaign은 일반적인 coverage-guided run으로 취급하되, LibAFL의 scheduling/mutation과 더 나은 주변 detector를 사용합니다.

### 조용한 실패를 fuzz finding으로 전환

Go assessment에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 **crash하지 않는** 경우가 많다는 것입니다. gosentry를 사용하면 여러 종류의 “나쁘지만 조용한” 상태를 finding으로 승격할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용하면 선택한 logging/error 경로가 crash처럼 동작하게 만들 수 있습니다. 이는 그렇지 않으면 log만 남기고 계속 실행하는 `log.Fatal` 스타일의 code path에 유용합니다.
- `--catch-races=true`를 사용하면 새로 발견된 queue entry를 Go race detector로 재실행합니다.
- `--catch-leaks=true`를 사용하면 새 queue entry를 `goleak`으로 재실행하고 goroutine leak이 발생하면 중지합니다.
- LibAFL의 hang handling을 사용하면 **infinite loops / very slow inputs**를 timeout으로 사라지게 하지 않고 fuzz finding으로 유지할 수 있습니다.
- 기본적으로 내장된 arithmetic overflow checks를 제공하며, go-panikint 스타일 instrumentation을 통해 선택적으로 truncation checks를 활성화할 수 있습니다.

이는 보안 영향이 memory corruption이 아니라 **panicless parser failure**, **concurrency bug** 또는 **DoS-only hang**인 target에 특히 유용합니다.

### typed Go API를 위한 struct-aware fuzzing

Native Go fuzzing은 주로 `[]byte`, `string` 및 숫자와 같은 scalar를 대상으로 합니다. 테스트 대상 code가 typed object를 사용하는 경우, gosentry는 내부적으로 bytes를 mutation하면서도 **composite values**(structs, slices, arrays, pointers)를 직접 fuzz할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>
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
fake wire format을 만들 때는 harness 전용 parsing code 뒤에 logic bugs가 숨겨질 수 있으므로, fuzzing 용도로만 사용하세요. differential 또는 grammar-based campaign에서는 harness input을 단일 `[]byte` 또는 `string`으로 유지하고 대신 callback 내부에서 parse하세요.

### parser 및 protocol input을 위한 Grammar-based fuzzing

parser, format 및 input language의 경우, gosentry는 LibAFL 위에서 **Nautilus grammar fuzzing**을 실행할 수 있습니다. grammar는 production rule의 JSON array이며, harness는 일반적으로 단일 `[]byte` 또는 `string` 인자를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
방법론 참고 사항:

- byte-level mutations가 대부분 초기 syntax checks에서 중단되는 경우 grammar mode를 사용합니다.
- 전체 specification을 모델링하는 대신 grammar를 언어/프로토콜의 **security-relevant subset**에 집중합니다.
- terminals/nonterminals에서 큰 boundary values를 사용하여 integer, length 및 state-machine 경계를 압박합니다.
- grammar mode는 input을 grammar-valid 상태로 유지하지만, target은 여전히 **bytes/strings**를 수신하므로 parsing 및 semantic checks는 harness된 code 내부에서 계속 수행됩니다.

### Differential fuzzing: crash뿐 아니라 implementation 비교

Go 생태계에서 강력한 패턴은 **grammar-based differential fuzzing**입니다. 유효한 structured inputs를 생성하고 두 개의 parser, client 또는 state-transition engine에 전달합니다.<sup>[[7]](#references)[[8]](#references)</sup>
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
다음을 findings로 취급합니다:

- 한 구현은 panic을 발생시키는 반면 다른 구현은 정상적으로 거부함
- accepted/rejected input 불일치
- 서로 다른 parse tree 또는 decoded object
- divergent state transition, nonce, balance 또는 state root

이는 순수한 crash fuzzing으로는 자주 발견하지 못하는 **consensus mismatch**, **parser ambiguity**, **spec-vs-implementation drift**를 찾는 실용적인 방법입니다.

### coverage reporting에 campaign corpus 재사용

campaign 후 저장된 queue corpus를 replay하여 별도의 corpus를 수동으로 export하지 않고 Go coverage report를 생성합니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
동일한 **package**에서 동일한 `-fuzz` target으로 command를 실행해야 gosentry가 올바른 cached campaign state를 확인합니다.



## References

- [1] [변이 문법 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 심층 분석](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 5년 후: Coverage-Guided Protocol Fuzzing에 대하여](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark가 code를 그래프로 변환](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing에는 toolkit의 절반이 빠져 있었습니다. 이를 해결하기 위해 toolchain을 fork했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot을 사용하는 Stateful Network Protocol을 위한 빠른 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar가 없어도 문제없음: System-Call Description 없이 Linux Kernel을 Fuzzing하기 위한 방법](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive 및 Mutable Snapshot을 활용한 효율적인 Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path 및 caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
