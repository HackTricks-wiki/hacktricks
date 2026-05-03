# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**에서는 입력이 **grammar-valid** 상태를 유지한 채로 변이됩니다. coverage-guided 모드에서는 **new coverage**를 트리거하는 샘플만 corpus seeds로 저장됩니다. **language targets**(parsers, interpreters, engines)에서는 이 방식이 한 construct의 출력이 다른 construct의 입력이 되는 **semantic/dataflow chains**가 필요한 버그를 놓칠 수 있습니다.

**Failure mode:** fuzzer가 개별적으로 `document()`와 `generate-id()`(또는 유사한 primitive)를 실행하는 seeds를 찾지만, **연결된 dataflow를 유지하지 못해**, “bug에 더 가까운” 샘플은 coverage를 추가하지 않는다는 이유로 버려집니다. **3개 이상의 dependent steps**가 있으면 random recombination은 비용이 커지고 coverage feedback은 탐색을 잘 이끌지 못합니다.

**Implication:** dependency가 많은 grammars에서는 **mutational phase와 generative phase를 hybridizing** 하거나, generation을 단순 coverage가 아니라 **function chaining** 패턴 쪽으로 편향시키는 것을 고려하세요.

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy**합니다: new-coverage 샘플이 즉시 저장되며, 종종 큰 범위의 변경되지 않은 영역이 그대로 남습니다. 시간이 지나면 corpus는 구조적 다양성이 낮은 **near-duplicates**로 채워집니다. aggressive minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **grammar-aware minimization**으로, **최소 token threshold**에 도달하면 멈추는 것입니다(주변 구조를 충분히 남겨 mutation-friendly하게 유지하면서 노이즈를 줄임).

mutational fuzzing에서 실용적인 corpus 규칙은: **near-duplicates의 큰 더미보다 coverage를 최대화하는 구조적으로 다른 작은 seed 집합을 선호**하는 것입니다. 실제로는 보통 다음을 의미합니다:

- **real-world samples**(public corpora, crawling, captured traffic, target ecosystem의 file sets)에서 시작합니다.
- 모든 valid sample을 유지하는 대신 **coverage-based corpus minimization**으로 이를 추려냅니다.
- mutation이 대부분의 사이클을 irrelevant bytes에 쓰지 않고 의미 있는 field에 닿도록, seeds를 **작게 유지**합니다.
- reachability가 바뀌면 “최고의” corpus도 달라지므로, 큰 harness/instrumentation 변경 후에는 corpus minimization을 다시 실행합니다.

## Comparison-Aware Mutation For Magic Values

fuzzer가 제자리걸음을 하는 흔한 이유는 syntax가 아니라 **hard comparisons**입니다: magic bytes, length checks, enum strings, checksums, 또는 `memcmp`, switch tables, 혹은 cascaded comparisons으로 보호되는 parser dispatch values입니다. pure random mutation은 이런 값을 byte-by-byte로 맞추려다 사이클만 낭비합니다.

이런 target에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen-style workflows)을 사용해 fuzzer가 실패한 comparison의 operand를 관찰하고, 이를 만족하는 값 쪽으로 mutation을 편향시키도록 하세요.
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

- 특히 대상이 **file signatures**, **protocol verbs**, **type tags**, 또는 **version-dependent feature bits** 뒤에 깊은 로직을 숨길 때 매우 유용하다.
- 실제 샘플, protocol specs, 또는 debug logs에서 추출한 **dictionaries**와 함께 사용하라. grammar tokens, chunk names, verbs, delimiter로 이루어진 작은 dictionary가 거대한 generic wordlist보다 더 가치 있는 경우가 많다.
- 대상이 여러 단계의 연속 검사를 수행한다면, 가장 먼저 나오는 “magic” 비교부터 해결한 뒤 결과 corpus를 다시 최소화해서 이후 단계가 이미 유효한 prefix에서 시작되도록 하라.

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, 그리고 **multi-stage parsers**에서는 흥미로운 단위가 종종 하나의 blob이 아니라 **message sequence**다. 전체 transcript를 하나의 파일로 이어 붙여 무작정 mutate하는 방식은 보통 비효율적인데, fuzzer가 모든 단계를 동일하게 mutate해 버리기 때문이다. 실제로는 뒤쪽 message만 취약한 state에 도달하더라도 그렇다.

더 효과적인 패턴은 **sequence 자체를 seed로 취급**하고, **observable state**(response codes, protocol states, parser phases, returned object types)를 추가 feedback으로 사용하는 것이다:

- **valid prefix messages**는 안정적으로 유지하고 mutation은 **transition-driving** message에 집중하라.
- 다음 단계가 이전 response의 값에 의존한다면, 이전 response에서 identifier와 server-generated values를 cache하라.
- 전체 serialized transcript를 불투명한 blob으로 mutate하는 대신, message별 mutation/splicing을 우선하라.
- protocol이 의미 있는 response codes를 노출한다면, 이를 **cheap state oracle**로 사용해 더 깊이 진행되는 sequence를 우선순위화하라.

이것이 authenticated bugs, hidden transitions, 또는 “only-after-handshake” parser bugs가 일반적인 file-style fuzzing에서 자주 놓치는 이유와 같다. fuzzer는 구조만이 아니라 **order, state, and dependencies**까지 보존해야 한다.

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**와 **coverage reuse**를 하이브리드로 결합하는 실용적인 방법은, persistent server를 상대로 **short-lived workers**를 재시작하는 것이다. 각 worker는 빈 corpus에서 시작해 `T`초 후 sync하고, 결합된 corpus로 다시 `T`초 동안 실행한 뒤 다시 sync하고 종료한다. 이렇게 하면 누적된 coverage를 활용하면서도 각 generation마다 **fresh structures**를 얻을 수 있다.

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

- `-in empty`는 각 생성마다 **새로운 corpus**를 강제한다.
- `-server_update_interval T`는 **지연된 sync**를 근사한다(새로움 우선, 재사용 나중).
- grammar fuzzing 모드에서는 기본적으로 **initial server sync**가 건너뛰어진다(`-skip_initial_server_sync`가 필요 없음).
- 최적의 `T`는 **target-dependent**이며, worker가 대부분의 “easy” coverage를 찾은 뒤에 전환하는 방식이 가장 잘 작동하는 경향이 있다.

## Snapshot Fuzzing For Hard-To-Harness Targets

테스트하려는 코드가 **큰 setup cost**(VM 부팅, login 완료, packet 수신, container 파싱, 서비스 초기화) 이후에야 도달 가능할 때, 유용한 대안은 **snapshot fuzzing**이다:

1. target을 interesting state가 준비될 때까지 실행한다.
2. 그 시점의 **memory + registers**를 snapshot한다.
3. 각 test case마다 변형된 input을 관련 guest/process buffer에 직접 쓴다.
4. crash/timeout/reset까지 실행한다.
5. **dirty pages**만 복원하고 반복한다.

이 방식은 매 iteration마다 전체 setup cost를 지불하지 않아도 되므로, 특히 **network services**, **firmware**, **post-auth attack surfaces**, 그리고 classic in-process harness로 리팩터링하기 까다로운 **binary-only targets**에 매우 유용하다.

실용적인 팁은 `recv`/`read`/packet-deserialization 지점 직후에 바로 중단하고, input buffer address를 기록한 다음, 각 iteration마다 그 buffer를 직접 변형하는 것이다. 이렇게 하면 매번 전체 handshake를 다시 만들지 않고도 deep parsing logic을 fuzzing할 수 있다.

## Harness Introspection: Find Shallow Fuzzers Early

campaign이 멈추면, 문제는 종종 mutator가 아니라 **harness**다. **reachability/coverage introspection**을 사용해 fuzz target에서 정적으로는 도달 가능하지만 동적으로는 거의 또는 전혀 covered되지 않는 functions를 찾아라. 그런 functions는 보통 다음 세 가지 문제 중 하나를 나타낸다:

- harness가 target에 너무 늦게 또는 너무 일찍 진입한다.
- seed corpus에 전체 feature family가 빠져 있다.
- target은 하나의 과도하게 큰 “do everything” harness보다 **second harness**가 실제로 필요하다.

OSS-Fuzz / ClusterFuzz 스타일 workflow를 사용한다면, Fuzz Introspector는 이 triage에 유용하다:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
보고서를 사용해, 테스트되지 않은 parser 경로에 대해 새로운 harness를 추가할지, 특정 feature를 위한 corpus를 확장할지, 아니면 하나의 monolithic harness를 더 작은 entry point들로 분할할지 결정하세요.

## Graph-First Fuzz Target Selection And Mutation Triage

이미 **static-analysis findings**, **mutation-testing survivors**, 그리고 **coverage reports**가 있다면, 이를 독립된 목록으로 triage하지 마세요. 먼저 **call graph**를 만들고, 노드에 **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, 그리고 외부 findings를 주석으로 달아둔 뒤, 그래프 질문을 던지세요:

- 어떤 high-complexity functions가 untrusted input에서 도달 가능한가?
- 어떤 mutation survivors가 parser/handler에서 security-critical code로 가는 경로 위에 있는가?
- 어떤 functions가 비정상적으로 큰 **blast radius**를 가진 architectural choke point인가?

이 방식은 보통 "가장 낮은 coverage"만 보는 것보다 더 나은 fuzz target을 찾아냅니다. **high complexity**를 가지면서 **external reachability**가 확인된 parser/decoder는, coverage는 낮지만 attacker-controlled path가 없는 고립된 internal helper보다 더 강한 harness 후보입니다.

### Practical triage workflow

1. codebase로부터 **code graph**를 만들고, function별 complexity/branch metrics를 추출합니다.
2. attacker-controlled input을 받는 **entrypoints**를 열거합니다: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. 해당 entrypoints에서 candidate functions까지 **path queries**를 실행해, 도달 가능한 attack surface와 dead/internal-only code를 분리합니다.
4. 다음을 결합한 노드를 우선순위로 둡니다:
- 높은 **cyclomatic complexity**
- untrusted input으로부터의 확인된 **reachability**
- 높은 **blast radius** 또는 많은 downstream dependents
- **SARIF** findings, audit notes, mutation survivors 같은 보강 증거
5. 먼저 가장 점수가 높은 노드들에 대해 집중된 harness를 작성합니다. 특히 hex/Base64/IP/message decoders 같은 **parsers/codecs**에 집중하세요.

### Mutation survivors: equivalent vs actionable

Mutation testing은 종종 noisy survivor list를 생성합니다. 모든 survivor를 security gap으로 취급하기 전에, graph를 사용해 다음을 물어보세요:

- mutated function이 attacker-controlled entrypoint에서 도달 가능한가?
- 모든 call path가 mutated check보다 더 강한 invariants로 제약되는가?
- node가 dead code, formatting-only logic, 또는 high-impact arithmetic/parser path에 있는가?

도달 불가능하거나 구조적으로 제약된 survivors는 종종 **equivalent mutants**입니다. 반면 **reachable** 상태로 남아 있고 **boundary conditions**, **overflow/carry paths**, 또는 **security-critical arithmetic/parsing**을 건드리는 survivors는 다음으로 승격해야 합니다:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

SAST pipeline이 **SARIF**를 내보낸다면, **file + line range** 기준으로 findings를 graph nodes에 매핑하고 graph를 사용해 영향을 확장하세요:

- flag된 function의 **blast radius**를 계산합니다
- finding이 entrypoint에서 오는 어떤 path 위에 있는지 확인합니다
- 근처 findings를 묶어 같은 choke point로 수렴하는지 클러스터링합니다

이는 특정 function에 fuzzing 시간을 쓸지 결정할 때 유용합니다. **reachable**하고, **complex**하며, 이미 **SAST hits**가 있는 node는, 단지 complex하기만 하고 attacker path가 없는 node보다 보통 더 나은 target입니다.

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
중요한 방법론은 교차점입니다: **복잡성 x 노출도 x 영향도**. 그래프를 사용해 예상 보안 가치가 가장 높은 fuzz 대상(fuzz targets)을 선택한 다음, mutation survivors를 사용해 어떤 경계와 invariant를 하니스가 강하게 자극해야 하는지 결정하세요.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
