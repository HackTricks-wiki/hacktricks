# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, 입력은 **문법적으로 유효한** 상태를 유지하면서 변형됩니다. coverage-guided 모드에서는 **새로운 커버리지**를 유발하는 샘플만 코퍼스 시드로 저장됩니다. **language targets**(parsers, interpreters, engines)의 경우, 한 구성의 출력이 다른 구성의 입력이 되는 **semantic/dataflow 체인**을 필요로 하는 버그를 놓칠 수 있습니다.

**Failure mode:** fuzzer는 `document()`와 `generate-id()`(또는 유사한 프리미티브)를 각각 개별적으로 실행하는 시드를 찾지만, **연쇄된 데이터플로우를 보존하지 못**해 “버그에 더 가까운” 샘플이 커버리지를 추가하지 않는다는 이유로 버려집니다. **3개 이상의 종속 단계**가 있으면, 무작위 재조합은 비용이 커지고 커버리지 피드백은 탐색을 안내하지 못합니다.

**Implication:** 의존성이 많은 문법의 경우, **mutational**과 **generative** 단계를 하이브리드하거나 생성 시 **단순 커버리지뿐 아니라 함수 체이닝 패턴(function chaining)** 쪽으로 편향시키는 것을 고려하세요.

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **탐욕적(greedy)**입니다: 새 커버리지 샘플이 즉시 저장되어 큰 변경되지 않은 영역을 유지하는 경우가 많습니다. 시간이 지나면 코퍼스는 구조적 다양성이 낮은 **거의 중복된** 상태가 됩니다. 공격적인 최소화는 유용한 컨텍스트를 제거할 수 있으므로, 실용적인 타협은 **문법 인식 기반 최소화(grammar-aware minimization)**로 **최소 토큰 임계값**에 도달하면 중단하는 방식입니다(노이즈는 줄이되 변형하기에 충분한 주변 구조는 유지).

## Single-Machine Diversity Trick (Jackalope-Style)

생성적 새로움(generative novelty)과 커버리지 재사용을 하이브리드하는 실용적인 방법은 **지속 서버에 대해 단명 워커를 재시작**하는 것입니다. 각 워커는 빈 코퍼스에서 시작해 `T`초 후 동기화하고, 결합된 코퍼스에서 다시 `T`초 동안 실행한 뒤 다시 동기화하고 종료합니다. 이 방법은 **세대마다 신선한 구조**를 만들어내면서 누적된 커버리지를 활용할 수 있게 합니다.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**순차적 worker들 (예시 loop):**

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

**노트:**

- `-in empty`는 매 생성마다 **fresh corpus**를 강제한다.
- `-server_update_interval T`는 **delayed sync**를 근사한다 (novelty first, reuse later).
- grammar fuzzing 모드에서는 **initial server sync is skipped by default** (`-skip_initial_server_sync`가 필요 없다).
- Optimal `T`은 **target-dependent**; worker가 대부분의 “easy” coverage를 찾은 뒤에 전환하는 것이 가장 잘 작동하는 경향이 있다.

## 참고자료

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
