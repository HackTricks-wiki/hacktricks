# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**에서는 입력을 **grammar-valid** 상태를 유지한 채 변형한다. coverage-guided 모드에서는 **새로운 coverage**를 트리거하는 샘플만 corpus seeds로 저장된다. **language targets**(parsers, interpreters, engines)에서는, 한 construct의 출력이 다른 construct의 입력이 되는 **semantic/dataflow chains**가 필요한 버그를 놓칠 수 있다.

**Failure mode:** fuzzer가 개별적으로 `document()`와 `generate-id()`(또는 유사한 primitive)를 실행하는 seeds를 찾지만, **연결된 dataflow를 보존하지 못해**, bug에 더 가까운 샘플이 coverage를 추가하지 않는다는 이유로 버려진다. **3개 이상의 종속 단계**가 있으면, 무작위 재조합은 비용이 많이 들고 coverage feedback은 탐색을 안내하지 못한다.

**Implication:** dependency가 많은 grammar에서는 **mutational phase와 generative phase를 hybridize**하거나, coverage만이 아니라 **function chaining** 패턴 쪽으로 generation을 편향시키는 것을 고려하라.

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy**하다: 새로운 coverage를 가진 샘플은 즉시 저장되며, 종종 큰 변경 없는 영역을 그대로 유지한다. 시간이 지나면 corpus는 구조적 다양성이 낮은 **near-duplicates**로 채워진다. 공격적인 minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **grammar-aware minimization**을 사용해 **minimum token threshold**에 도달하면 멈추는 것이다(잡음을 줄이면서 mutation-friendly를 유지할 만큼의 주변 구조는 남긴다).

mutational fuzzing을 위한 실용적인 corpus 규칙은 다음과 같다: 대량의 near-duplicates보다 **coverage를 최대화하는 구조적으로 다른 seed의 작은 집합**을 선호하라. 실제로는 보통 다음을 의미한다:

- **real-world samples**(public corpora, crawling, captured traffic, target ecosystem의 file sets)에서 시작한다.
- 모든 valid sample을 유지하는 대신 **coverage-based corpus minimization**으로 정제한다.
- mutation이 무의미한 bytes보다 의미 있는 fields에 닿도록, seed를 **충분히 작게** 유지한다.
- reachability가 바뀌면 “최고”의 corpus도 바뀌므로, 주요 harness/instrumentation 변경 후에는 corpus minimization을 다시 실행한다.

## Comparison-Aware Mutation For Magic Values

fuzzer가 plateau에 도달하는 흔한 이유는 syntax가 아니라 **hard comparisons**이다: magic bytes, length checks, enum strings, checksums, 또는 `memcmp`, switch tables, cascade된 comparisons로 보호되는 parser dispatch values. 순수한 random mutation은 byte-by-byte로 이 값들을 맞히려다 cycle을 낭비한다.

이러한 target에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen-style workflows)을 사용해 fuzzer가 실패한 comparison의 operands를 관찰하고, 이를 만족하는 값 쪽으로 mutation을 편향시킬 수 있게 하라.
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

- 이는 대상이 **file signatures**, **protocol verbs**, **type tags**, 또는 **version-dependent feature bits** 뒤에 깊은 로직을 숨겨둘 때 특히 유용하다.
- 실제 샘플, protocol specs, 또는 debug logs에서 추출한 **dictionaries**와 함께 사용하라. grammar tokens, chunk names, verbs, delimiters를 담은 작은 dictionary가 거대한 generic wordlist보다 종종 더 가치 있다.
- 대상이 많은 순차적 검사를 수행한다면, 가장 먼저 나오는 “magic” 비교를 먼저 해결한 다음 결과 corpus를 다시 최소화하여 이후 단계가 이미 유효한 prefixes에서 시작되게 하라.

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows**, 그리고 **multi-stage parsers**에서 흥미로운 단위는 종종 단일 blob가 아니라 **message sequence**다. 전체 transcript를 하나의 file로 이어 붙여 무작정 mutate하는 것은 보통 비효율적이다. fuzzer가 모든 step을 동일하게 mutate하지만, 실제로는 나중 message만 취약한 state에 도달하기 때문이다.

더 효과적인 패턴은 **sequence 자체를 seed로 다루고**, **observable state**(response codes, protocol states, parser phases, returned object types)를 추가 feedback으로 사용하는 것이다:

- **valid prefix messages**는 안정적으로 유지하고 mutation은 **transition-driving** message에 집중하라.
- 다음 step이 이전 response의 identifier나 server-generated values에 의존한다면 이를 캐시하라.
- 전체 serialized transcript를 opaque blob로 mutate하기보다 per-message mutation/splicing을 우선하라.
- protocol이 의미 있는 response codes를 제공한다면, 이를 **cheap state oracle**로 사용해 더 깊이 진행되는 sequence를 우선순위화하라.

이것이 authenticated bugs, hidden transitions, 또는 “only-after-handshake” parser bugs가 vanilla file-style fuzzing에서 자주 놓치는 이유와 같다: fuzzer는 단순히 structure만이 아니라 **order, state, and dependencies**를 보존해야 하기 때문이다.

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty**와 **coverage reuse**를 하이브리드화하는 실용적인 방법은 persistent server를 상대로 **short-lived workers**를 재시작하는 것이다. 각 worker는 empty corpus에서 시작해 `T` seconds 후 sync하고, combined corpus로 또 다른 `T` seconds 동안 실행한 뒤 다시 sync하고 종료한다. 이렇게 하면 누적된 coverage를 활용하면서도 각 generation마다 **fresh structures**를 얻을 수 있다.

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

**참고:**

- `-in empty`는 각 생성마다 **새 코퍼스(corpus)** 를 강제합니다.
- `-server_update_interval T`는 **지연된 동기화**를 근사합니다(새로움 우선, 재사용 나중).
- grammar fuzzing 모드에서는 **초기 server sync가 기본적으로 건너뛰어집니다**(`-skip_initial_server_sync`가 필요 없음).
- 최적의 `T`는 **타깃 의존적**이며, 워커가 대부분의 “쉬운” coverage를 찾은 뒤로 전환하는 것이 가장 잘 동작하는 경향이 있습니다.

## Snapshot Fuzzing For Hard-To-Harness Targets

테스트하려는 코드가 **큰 초기화 비용**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화) 이후에야 도달 가능해진다면, 유용한 대안은 **snapshot fuzzing**입니다:

1. 타깃을 흥미로운 상태가 준비될 때까지 실행합니다.
2. 그 시점의 **메모리 + 레지스터**를 snapshot합니다.
3. 각 테스트 케이스마다 변형된 입력을 관련된 guest/process 버퍼에 직접 씁니다.
4. 크래시/timeout/reset까지 실행합니다.
5. **dirty pages**만 복원하고 반복합니다.

이 방식은 매 반복마다 전체 초기화 비용을 지불하지 않아도 되며, 특히 **network services**, **firmware**, **post-auth attack surfaces**, 그리고 클래식 in-process harness로 리팩터링하기 까다로운 **binary-only targets**에 매우 유용합니다.

실용적인 트릭은 `recv`/`read`/packet-deserialization 지점 직후에 즉시 중단하고, 입력 버퍼 주소를 기록한 뒤, 각 반복마다 그 버퍼를 직접 변형하는 것입니다. 이렇게 하면 매번 전체 handshake를 다시 구성하지 않고도 깊은 파싱 로직을 fuzzing할 수 있습니다.

## Harness Introspection: Find Shallow Fuzzers Early

캠페인이 멈출 때, 문제는 mutator가 아니라 종종 **harness**입니다. **reachability/coverage introspection**을 사용해 fuzz target에서 정적으로는 도달 가능하지만 동적으로는 거의 또는 전혀 coverage되지 않는 함수를 찾으세요. 그런 함수들은 보통 다음 세 가지 문제 중 하나를 나타냅니다:

- harness가 target에 너무 늦게 또는 너무 일찍 진입합니다.
- seed corpus에 전체 feature family가 빠져 있습니다.
- target에는 하나의 거대한 “do everything” harness보다 **second harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일 워크플로를 사용한다면, Fuzz Introspector는 이 분류 작업에 유용합니다:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report를 기준으로 아직 테스트되지 않은 parser 경로를 위해 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나의 monolithic harness를 더 작은 entry point들로 분리할지 결정하세요.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
