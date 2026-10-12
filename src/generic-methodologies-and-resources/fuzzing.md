# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing**에서는 입력을 **문법적으로 유효한** 상태로 유지하면서 변형합니다. Coverage-guided 모드에서는 **새로운 coverage**를 유발하는 샘플만 corpus seed로 저장합니다. **언어 타깃**(parser, interpreter, engine)의 경우, 한 구문의 출력이 다른 구문의 입력이 되는 **의미적/dataflow 연쇄**가 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**실패 유형:** fuzzer가 각각 `document()`와 `generate-id()`(또는 유사한 primitive)를 실행하는 seed를 찾지만 **연결된 dataflow를 유지하지 못해**, 버그에 더 가까운 샘플이 coverage를 추가하지 않는다는 이유로 버려집니다. **서로 의존하는 단계가 3개 이상**이면 무작위 재조합에 비용이 많이 들고, coverage 피드백도 탐색을 유도하지 못합니다.<sup>[[1]](#references)</sup>

**시사점:** 의존성이 많은 grammar의 경우 **mutational 단계와 generative 단계를 결합**하거나, coverage뿐만 아니라 **function chaining** 패턴을 우선 생성하도록 고려하세요.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **탐욕적**입니다. 새 coverage를 얻은 샘플은 대개 변경되지 않은 부분을 많이 포함한 채 즉시 저장됩니다. 시간이 지나면 corpus에 구조적 다양성이 낮은 **거의 중복된 샘플**이 쌓입니다. 지나치게 강한 minimization은 유용한 context를 제거할 수 있으므로, 실용적인 절충안은 **최소 token 임계값에서 중단하는** **grammar-aware minimization**입니다. 이렇게 하면 노이즈를 줄이면서도 mutation에 유리한 주변 구조를 충분히 유지할 수 있습니다.<sup>[[1]](#references)</sup>

Mutational fuzzing에서 실용적인 corpus 규칙은 다음과 같습니다. 거의 중복된 샘플을 많이 쌓기보다 **coverage를 극대화하는 구조적으로 서로 다른 소수의 seed를 우선하세요**. 일반적으로 다음과 같이 하면 됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **실제 샘플**(공개 corpus, crawling 결과, 캡처한 traffic, 타깃 생태계의 파일 집합)에서 시작합니다.
- 유효한 샘플을 모두 보관하는 대신 **coverage 기반 corpus minimization**으로 샘플을 추립니다.
- mutation이 대부분의 cycle을 무관한 바이트에 소비하지 않고 의미 있는 필드에 적용되도록 seed를 **충분히 작게** 유지합니다.
- harness/instrumentation을 크게 변경한 뒤에는 corpus minimization을 다시 수행합니다. reachability가 달라지면 “최적” corpus도 바뀌기 때문입니다.

## Comparison-Aware Mutation For Magic Values

Fuzzer가 정체되는 흔한 이유는 syntax가 아니라 **엄격한 비교**입니다. 예를 들어 magic byte, 길이 검사, enum 문자열, checksum 또는 `memcmp`, switch table, 연쇄 비교로 보호되는 parser dispatch 값이 있습니다. 순수한 무작위 mutation은 이런 값을 바이트 단위로 추측하는 데 cycle을 낭비합니다.

이러한 타깃에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen 스타일 workflow)을 사용하세요. 그러면 fuzzer가 실패한 비교의 피연산자를 확인하고, 이를 충족하는 값 쪽으로 mutation을 유도할 수 있습니다.<sup>[[3]](#references)</sup>

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

- 대상이 **file signatures**, **protocol verbs**, **type tags** 또는 버전에 따라 달라지는 feature bits 뒤에 깊은 로직을 숨겨 두는 경우 특히 유용합니다.
- 실제 샘플, 프로토콜 명세 또는 디버그 로그에서 추출한 **dictionaries**와 함께 사용하세요. 문법 토큰, 청크 이름, verbs, 구분 기호가 담긴 작은 dictionary가 방대한 범용 wordlist보다 더 유용한 경우가 많습니다.
- 대상이 순차적인 검사를 여러 번 수행한다면, 가장 앞에 있는 “magic” 비교부터 해결한 다음 결과 코퍼스를 다시 최소화하세요. 그러면 이후 단계가 이미 유효한 접두부에서 시작됩니다.

## 엣지 커버리지로 서로 다른 경로를 구별하기 어려울 때 더 풍부한 피드백

일반적인 엣지 커버리지는 두 실행이 같은 호출자를 통해 공유 helper를 거치거나 함수 내부에서 서로 다른 분기 조합을 선택해도 이를 구별할 수 없습니다. **경로**에 따라 활성 상태가 달라지는 공유 디코더, 프로토콜 디스패처, 인터프리터 helper에서는 이것이 중요합니다. 모든 호출 컨텍스트를 무턱대고 추적하는 것도 위험합니다. 커버리지 맵과 큐가 폭발적으로 커질 수 있기 때문입니다. 따라서 컨텍스트 민감 퍼징 연구에서는 전체 호출 그래프를 컨텍스트 민감하게 처리하기보다 유망한 컨텍스트만 정교하게 추적할 것을 권장합니다.<sup>[[14]](#references)</sup>

최신 AFL++ 빌드는 일반적인 엣지 커버리지에 더해 **함수별 Ball-Larus 경로 커버리지**를 제공합니다. 함수 안의 각 비순환 경로에 feature를 할당하며, 루프 역방향 엣지는 제거되므로 이 피드백은 분기 조합은 구별하지만 **루프 반복 횟수는 구별하지 않습니다**. 완화된 레벨 `1`부터 시작한 다음, 경로 수가 기하급수적으로 증가할 수 있으므로 의심스러운 파서/상태 머신 코드에만 더 엄격한 모드를 적용하세요.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

보안과 관련된 여러 지점에서 호출되는 헬퍼의 경우, LTO 모드는 각 함수 경로를 바로 호출하는 지점과 결합할 수 있습니다:<sup>[[13]](#references)</sup>

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

**캠페인 지침:** 더 풍부한 피드백은 신중하게 적용하고, coverage map/queue 비용이 얼마나 드는지 모니터링하세요.<sup>[[13]](#references)[[14]](#references)</sup>

- 일반적인 edge-coverage 인스턴스를 병렬로 실행하세요. 추가 queue/map 비용 때문에 초당 실행 횟수가 줄어들지 않을 때만 더 풍부한 피드백이 유용합니다.
- 대규모 템플릿 중심 라이브러리나 일반 유틸리티 코드가 map을 지배한다면 `AFL_LLVM_ALLOWLIST`를 사용해 path/caller 계측 범위를 제한하세요.
- 비순환 경로가 지나치게 많은 함수는 AFL++에서 건너뛸 수 있습니다. 컴파일 중 경고가 발생하면 대상에 allowlisting이 필요하거나 strict level을 낮춰야 한다는 신호입니다.
- Caller + path coverage는 caller depth를 하나만 지원합니다. 더 깊은 context stack과 함께 사용하지 마세요.
- Path ID는 LLVM 메이저 버전 간에 바뀔 수 있습니다. 캠페인 중에는 toolchain을 고정하고, PATH 기반 corpus의 feature ID가 빌드 간에 안정적이라고 간주해 동기화하지 마세요.
- 이 피드백은 `CMPLOG`를 보완합니다. 비교 추적은 **guard를 통과하는 값이 무엇인지** 해결하고, path/caller 피드백은 **어떤 경로와 branch 조합으로 해당 지점에 도달했는지** 보존합니다.

## Stateful Fuzzing: 시퀀스가 시드다

**프로토콜**, **인증된 워크플로**, **여러 단계로 구성된 parser**에서는 흥미로운 단위가 단일 blob이 아니라 **메시지 시퀀스**인 경우가 많습니다. 전체 대화를 하나의 파일로 연결해 무작위로 변이하는 방식은 대개 비효율적입니다. 취약한 상태에 도달하는 것은 후속 메시지뿐인 경우에도 fuzzer가 모든 단계를 똑같이 변이하기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 방식은 **시퀀스 자체를 시드로 취급**하고, **관찰 가능한 상태**(응답 코드, 프로토콜 상태, parser 단계, 반환된 객체 유형)를 추가 피드백으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **유효한 접두 메시지**는 그대로 유지하고, **전이를 유도하는** 메시지에 변이를 집중하세요.
- 다음 단계가 이전 응답에 의존한다면 식별자와 서버가 생성한 값을 캐시하세요.
- 직렬화된 대화 전체를 불투명한 blob으로 변이하는 대신 메시지별 변이/스플라이싱을 사용하세요.
- 프로토콜에서 의미 있는 응답 코드를 제공한다면 이를 **저렴한 상태 오라클**로 사용해 더 깊이 진행되는 시퀀스의 우선순위를 높이세요.

인증이 필요한 버그, 숨겨진 전이, 또는 “handshake 이후에만” 발생하는 parser 버그가 vanilla file-style fuzzing에서 자주 누락되는 이유도 같습니다. fuzzer는 구조뿐 아니라 **순서, 상태, 종속성**도 보존해야 합니다.<sup>[[4]](#references)</sup>

### Android Binder: 다중 클라이언트 드라이버 fuzzing

높은 edge coverage를 달성해도 IPC 드라이버 버그를 놓칠 수 있습니다. coverage는 **객체 소유권, 참조 횟수, 대기 중인 메시지, 정리 순서, 스레드 인터리빙**을 나타내지 않기 때문입니다. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 페이지에서는 드라이버 객체 모델을 다루며, 이 예제에서는 fuzzer harness에 초점을 맞춥니다. Android Binder는 유용한 모델입니다. fuzzer가 여러 프로세스로 하여금 필요한 순서에 따라 동일한 커널 객체를 다루게 할 수 없다면 할당 경로와 해제 경로에 모두 도달하는 것만으로는 충분하지 않습니다.<sup>[[15]](#references)</sup>

#### 분리된 `ioctl` 버퍼가 아니라 프로토콜을 모델링하세요

테스트 케이스를 **클라이언트 식별자 + 연산 + 구조화된 인수**로 구성된 순서 있는 grammar로 표현하세요. Binder LKL fuzzer는 protobuf와 `libprotobuf-mutator`를 사용하며, 영속적인 context-manager 클라이언트 하나와 일반 클라이언트 두 개를 둡니다. 그런 다음 의미를 반영하는 harness가 무작위 바이트 변이로 파괴될 관계를 보존합니다.<sup>[[15]](#references)</sup>

- 이전 연산이 반환한 값을 캐시하세요. 예를 들어 `BC_FREE_BUFFER`는 이전 `ioctl`이 반환한 트랜잭션 버퍼 포인터를 재사용해야 합니다.
- 동기식 트랜잭션이 완료되고 후속 연산에 계속 도달할 수 있도록 유효한 기본 응답을 생성하세요.
- 자기 자신에게 보내는 트랜잭션이나 동일한 대상으로 향하는 여러 개의 대기 중인 트랜잭션처럼 불가능한 전이는 거부하세요.
- 단일 인스턴스 bootstrap 상태는 입력별 초기화 대상에서 제외하세요. Binder는 부팅당 `BINDER_SET_CONTEXT_MGR` 등록을 한 번만 허용하므로 해당 클라이언트를 반복해서 제거하고 다시 만들면 이후 입력이 유효하지 않게 됩니다.

유용한 lifetime-race 템플릿은 한 클라이언트가 객체를 전송하게 하고, 스레드 또는 프로세스 정리를 시작한 다음, 수신 클라이언트가 동시에 트랜잭션 버퍼를 해제하게 하는 것입니다. CVE-2020-0423 예제에서는 `BINDER_TYPE_WEAK_BINDER` 전송 후 `BINDER_THREAD_EXIT`와 `BC_FREE_BUFFER`가 경쟁하면서, 종료 중인 스레드의 정리 경로가 계속 사용 중인 내장 `binder_work`를 해제할 수 있었습니다.<sup>[[15]](#references)</sup>

#### userspace 커널에서 통제된 인터리빙 다시 도입하기

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)는 실제 커널 코드를 userspace harness에 링크하고, `lkl_syscall`을 통해 syscall 인터페이스를 노출합니다. 덕분에 protobuf 상태, coverage, KASAN을 하나의 프로세스에서 쉽게 조율할 수 있습니다. 하지만 LKL은 일반적으로 다른 커널 스레드가 끼어들지 않은 상태에서 syscall을 실행합니다. race 캠페인에서는 선택한 lock/unlock 및 lifetime 경계 주변에 `schedule()` 지점을 삽입한 다음, 각 yield에서 harness가 다음 클라이언트를 무작위로 선택하게 하세요. 각 지점은 스케줄링 탐색 공간을 배로 늘리므로 꼭 필요한 곳에만 배치하세요. 연구자들이 설명한 무작위 스케줄러는 upstream Binder fuzzer에 포함되어 **있지 않습니다**.<sup>[[15]](#references)</sup>

#### 직렬화된 회귀 시드 빌드 및 재생하기

upstream harness는 호환되는 `libprotobuf-mutator` 버전을 고정하고, `LKL_FUZZING=1`로 LKL fuzzing 계측과 KASAN을 활성화하며, Binder용으로 `MMU=1`을 지정해 `CONFIG_MMU`를 활성화합니다.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

의도적으로 취약한 리비전을 체크아웃하거나 upstream에 문서화된 롤백 패치를 적용하면, 직렬화된 시드로 임시 C 개념 증명에서 상태 전이를 재구성하지 않고도 전체 멀티 클라이언트 상태 전이를 재현할 수 있습니다.<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

결과적으로 발생한 KASAN use-after-free는 seed가 취약한 객체 수명 경로에 도달했다는 확인으로 취급하세요. 이는 커널 코드 실행이나 권한 상승에 필요한 후속 primitive를 입증하지는 않습니다.<sup>[[16]](#references)</sup>

## 단일 머신 다양성 트릭 (Jackalope 방식)

**생성형 신규성**과 **coverage 재사용**을 결합하는 실용적인 방법은 지속 실행 중인 서버를 대상으로 수명이 짧은 worker를 재시작하는 것입니다. 각 worker는 비어 있는 corpus에서 시작해 `T`초 후 동기화하고, 통합된 corpus로 다시 `T`초 동안 실행한 뒤 한 번 더 동기화하고 종료합니다. 이렇게 하면 축적된 coverage를 활용하면서도 **세대마다 새로운 구조**를 얻을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**서버:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**순차 작업자(예시 루프):**

<details>
<summary>Jackalope 작업자 재시작 루프</summary>

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

- `-in empty`는 매 생성마다 **새 corpus**를 강제로 사용합니다.
- `-server_update_interval T`는 **지연된 동기화**(먼저 신규 입력을 찾고, 나중에 재사용)를 근사합니다.
- grammar fuzzing 모드에서는 기본적으로 **초기 서버 동기화를 건너뜁니다**(`-skip_initial_server_sync`가 필요하지 않습니다).
- 최적의 `T`는 **대상에 따라 다릅니다**. worker가 대부분의 “쉬운” coverage를 찾은 뒤 전환하는 것이 대체로 가장 효과적입니다.

## 다루기 어려운 대상의 Snapshot Fuzzing

테스트하려는 코드에 도달하기까지 **큰 초기화 비용**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화 등)이 드는 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비된 프로세스 또는 VM 상태를 캡처하고, 각 테스트 케이스를 대상 입력 경로에 주입한 뒤, crash/timeout이 발생할 때까지 실행하고 snapshot을 복원합니다. 이렇게 하면 초기화나 프로토콜 접두부를 반복할 필요가 없으며, **네트워크 서비스**, **firmware**, **인증 후 공격 표면**, **바이너리 전용 대상**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 관심 있는 상태가 준비될 때까지 대상을 실행합니다.
2. 해당 시점의 **메모리 + 레지스터**를 snapshot으로 저장합니다.
3. 각 테스트 케이스마다 변이된 입력을 관련 guest/process 버퍼에 직접 씁니다.
4. crash/timeout/reset이 발생할 때까지 실행합니다.
5. snapshot을 복원합니다. VM 대상에서는 지원되는 경우 **변경된 페이지만** 복원한 뒤 반복합니다.

snapshot은 가능하면 첫 번째 비용이 큰 parse/dispatch 단계 직전에 설정합니다. 예를 들어 `recv`/`read` 직후 또는 패킷 역직렬화 지점이 적합하며, 대상에서 사용하는 입력 버퍼를 기록해 둡니다. 이는 입력 처리 과정에서 snapshot을 더 깊은 지점으로 옮겨 작업 반복을 피하는 적응형 배치 원칙을 따릅니다.<sup>[[11]](#references)</sup>

## Harness Introspection: 얕은 fuzzer를 조기에 찾아내기

캠페인이 정체되면 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **도달 가능성/coverage introspection**을 사용해 fuzz target에서 정적으로는 도달 가능하지만 동적으로는 거의 또는 전혀 coverage되지 않는 함수를 찾습니다. 이런 함수는 대개 다음 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 너무 늦거나 너무 일찍 대상에 진입합니다.
- seed corpus에 특정 기능군 전체가 빠져 있습니다.
- 대상에는 지나치게 큰 “모든 것을 처리하는” harness 하나가 아니라 **두 번째 harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일의 workflow를 사용한다면 Fuzz Introspector를 통해 정적 도달 가능성과 runtime coverage를 비교하고, 일정 시간 실행 또는 공개 corpus를 바탕으로 보고서를 생성할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

보고서를 활용해 테스트되지 않은 parser 경로를 위한 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나로 뭉쳐 있는 harness를 더 작은 진입점으로 분리할지 결정하세요.

## Graph-First Fuzz Target Selection And Mutation Triage

이미 **static-analysis 결과**, **mutation-testing 생존 항목**, **coverage 보고서**가 있다면, 이를 서로 독립된 목록처럼 분류하지 마세요. 먼저 **call graph**를 만들고, 노드에 **cyclomatic complexity**, **진입점/신뢰할 수 없는 입력의 도달 가능성**, 외부 분석 결과를 표시한 뒤 graph를 바탕으로 질문하세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 복잡도가 높은 함수 중 신뢰할 수 없는 입력에서 도달 가능한 함수는 무엇인가요?
- parser/handler에서 보안상 중요한 코드로 이어지는 경로에 있는 mutation survivor는 무엇인가요?
- **blast radius**가 유난히 큰 아키텍처상 병목 함수는 무엇인가요?

이 방법은 보통 "coverage가 가장 낮은 항목"만 보는 것보다 더 나은 fuzz target을 찾아냅니다. **복잡도가 높고** 외부에서 도달 가능하다는 점이 확인된 parser/decoder는, coverage가 낮더라도 공격자가 제어할 수 있는 경로가 없는 고립된 내부 helper보다 더 적합한 harness 후보입니다.

### 실용적인 분류 워크플로

1. 코드베이스에서 **code graph**를 만들고 함수별 복잡도/분기 지표를 추출합니다.
2. 요청 handler, decoder, importer, protocol parser, CLI/file reader 등 공격자가 제어하는 입력을 받는 **진입점**을 열거합니다.
3. 해당 진입점에서 후보 함수까지 **경로 쿼리**를 실행해, 도달 가능한 공격 표면과 dead/internal-only 코드를 구분합니다.
4. 다음 조건을 함께 충족하는 노드를 우선순위에 둡니다.
   - 높은 **cyclomatic complexity**
   - 신뢰할 수 없는 입력으로부터 도달 가능하다는 확인
   - 높은 **blast radius** 또는 많은 하위 종속 항목
   - **SARIF** 결과, audit 기록, mutation survivor 등 뒷받침하는 근거
5. 점수가 가장 높은 노드부터 집중형 harness를 작성합니다. 특히 hex/Base64/IP/message decoder 같은 **parser/codec**를 우선합니다.

### Mutation survivor: 동등한 변이와 조치가 필요한 변이

Mutation testing은 잡음이 많은 survivor 목록을 만드는 경우가 많습니다. 모든 survivor를 보안 결함으로 취급하기 전에 graph를 사용해 다음을 확인하세요.

- 변이된 함수가 공격자가 제어하는 진입점에서 도달 가능한가요?
- 모든 호출 경로가 변이된 검사보다 더 강한 불변 조건으로 제한되나요?
- 해당 노드는 dead code, 서식 처리만 하는 로직, 영향이 큰 산술/parser 경로 중 어디에 있나요?

도달할 수 없거나 구조적으로 제한되는 survivor는 흔히 **equivalent mutant**입니다. 계속 **도달 가능**하고 **경계 조건**, **overflow/carry 경로**, **보안상 중요한 산술/파싱**을 다루는 survivor는 다음 항목으로 승격해야 합니다.

- 새 fuzz harness
- 직접적인 property/invariant 테스트
- 표적화된 edge-case 벡터

### 외부 분석 결과를 graph에 연계

SAST 파이프라인이 **SARIF**를 내보낸다면, **파일 + 줄 범위**를 기준으로 결과를 graph 노드에 반영하고 graph를 활용해 영향 범위를 확장하세요.<sup>[[6]](#references)</sup>

- 표시된 함수의 **blast radius** 계산
- 해당 결과가 진입점에서 이어지는 경로에 있는지 확인
- 인접한 결과 중 같은 병목 지점으로 모이는 항목을 그룹화

특정 함수에 fuzzing 시간을 쓸지 판단할 때 유용합니다. **도달 가능**하고 **복잡도가 높으며** 이미 **SAST 결과**도 있는 노드는, 공격 경로가 없는 단순히 복잡한 노드보다 대체로 더 나은 대상입니다.

Trailmark를 사용한 워크플로 예시.<sup>[[6]](#references)</sup>

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

중요한 방법론은 **복잡도 x 노출도 x 영향도**의 교차점입니다. 그래프를 사용해 예상 보안 가치가 가장 높은 fuzz target을 고른 다음, mutation에서 살아남은 항목을 바탕으로 harness에서 어떤 경계와 불변 조건을 집중적으로 검사해야 할지 결정하세요.<sup>[[5]](#references)</sup>

## gosentry를 이용한 Go Fuzzing: 더 강력한 엔진, 타입 지정 입력, 차등 검사

Go target에 이미 기본 `testing.F` harness가 있다면, 실용적인 업그레이드 방법은 같은 harness를 [gosentry](https://github.com/trailofbits/gosentry)로 실행하는 것입니다. gosentry는 `go test -fuzz`를 그대로 유지하면서 backend를 **LibAFL**로 교체한 Go toolchain의 fork입니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

네이티브 Go 퍼저가 **어려운 비교**, **타입이 지정된 입력** 또는 **파서 중심 형식**에서 멈출 때 유용합니다. 방법론은 동일합니다.

- 시드에는 `f.Add(...)`를, 콜백에는 `f.Fuzz(...)`를 계속 사용합니다.
- 같은 하네스를 재사용하되, 기본 툴체인 대신 gosentry의 `go` 바이너리로 실행합니다.
- 결과 캠페인을 일반적인 coverage-guided 실행으로 취급하되, LibAFL 스케줄링/뮤테이션과 더 나은 주변 탐지기를 활용합니다.

### 무음 실패를 퍼징 결과로 전환하기

Go 보안 평가에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 **크래시를 일으키지 않는 경우가 많다**는 점입니다. gosentry를 사용하면 “문제가 있지만 조용히 지나가는” 여러 상태를 퍼징 결과로 전환할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용해 선택한 로깅/오류 경로를 크래시처럼 처리합니다. (그렇지 않으면 로그만 남기고 계속 실행하는 `log.Fatal` 스타일의 코드 경로에 유용합니다.)
- `--catch-races=true`를 사용해 새로 발견된 큐 항목을 Go race detector로 다시 실행합니다.
- `--catch-leaks=true`를 사용해 새 큐 항목을 `goleak`으로 다시 실행하고 고루틴 누수가 발생하면 중단합니다.
- LibAFL의 hang 처리 기능을 사용해 **무한 루프/매우 느린 입력**이 타임아웃으로 사라지지 않고 퍼징 결과로 남게 합니다.
- 기본적으로 산술 오버플로 검사가 내장되어 있으며, go-panikint 스타일의 계측을 통해 선택적으로 절단 검사도 수행할 수 있습니다.

이는 보안 영향이 메모리 손상이 아니라 **패닉 없이 발생하는 파서 실패**, **동시성 버그** 또는 **DoS만 유발하는 hang**인 대상에서 특히 유용합니다.

### 타입이 지정된 Go API를 위한 구조체 인식 퍼징

네이티브 Go 퍼징은 주로 `[]byte`, `string`, 숫자 같은 스칼라를 대상으로 합니다. 테스트 대상 코드가 타입이 지정된 객체를 입력으로 받는 경우, gosentry는 바이트를 기반으로 계속 변이하면서 복합 값(구조체, 슬라이스, 배열, 포인터)을 직접 퍼징할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing만을 위해 가짜 wire format을 만들면 harness 전용 파싱 코드에 로직 버그가 가려질 수 있습니다. differential 또는 grammar-based 캠페인에서는 harness 입력을 단일 `[]byte` 또는 `string`으로 유지하고 대신 callback 내부에서 파싱하세요.

### 파서 및 프로토콜 입력을 위한 grammar-based fuzzing

파서, 형식, 입력 언어의 경우 gosentry는 LibAFL 기반으로 **Nautilus grammar fuzzing**을 실행할 수 있습니다. 문법은 production rule로 구성된 JSON 배열이며, harness는 일반적으로 단일 `[]byte` 또는 `string` 인수를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

방법론 메모:

- 바이트 수준 변이가 대부분 초기 구문 검사에서 실패한다면 grammar mode를 사용하세요.
- 전체 사양을 모델링하는 대신, 언어/프로토콜에서 **보안과 관련된 하위 집합**에 초점을 맞춰 grammar를 구성하세요.
- 정수, 길이, 상태 머신의 경계 조건을 자극할 수 있도록 terminal/nonterminal에 큰 경계값을 사용하세요.
- Grammar mode는 입력을 문법적으로 유효하게 유지하지만, 대상은 여전히 **바이트/문자열**을 받으므로 파싱 및 의미 검사는 하네스가 적용된 코드 안에서 수행됩니다.

### Differential fuzzing: 충돌뿐 아니라 구현도 비교하기

Go 생태계에서 효과적인 패턴은 **grammar-based differential fuzzing**입니다. 유효한 구조화 입력을 생성해 두 개의 parser, client 또는 상태 전이 엔진에 전달합니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

다음과 같은 경우를 발견 사항으로 간주하세요.

- 한 구현은 panic이 발생하지만 다른 구현은 정상적으로 거부함
- 입력을 수락하거나 거부하는 결과가 서로 다름
- 파스 트리 또는 디코딩된 객체가 서로 다름
- 상태 전이, nonce, 잔액 또는 state root가 서로 다름

이는 순수한 crash fuzzing으로는 놓치기 쉬운 **consensus mismatch**, **parser ambiguity**, **spec-vs-implementation drift**를 찾는 실용적인 방법입니다.

### 커버리지 보고를 위해 캠페인 코퍼스 재사용

캠페인이 끝난 후 저장된 큐 코퍼스를 재생해 별도의 코퍼스를 수동으로 내보내지 않고 Go 커버리지 보고서를 생성하세요.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

동일한 패키지에서 동일한 `-fuzz` 타깃으로 명령을 실행해야 gosentry가 올바른 캐시된 캠페인 상태를 확인합니다.



## References

- [1] [변이 문법 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing 심층 가이드](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet, 5년 후: 커버리지 기반 프로토콜 fuzzing에 관하여](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark가 코드를 그래프로 변환합니다](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing에는 툴킷의 절반이 빠져 있었습니다. 이를 해결하기 위해 툴체인을 포크했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 스냅샷을 사용한 상태 기반 네트워크 프로토콜용 고속 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [문법이 없어도 문제없다: 시스템 호출 설명 없이 Linux 커널 fuzzing하기](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: 적응형 및 변경 가능한 스냅샷을 사용한 효율적인 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 계측: 경로 및 호출자 커버리지](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [예측적 컨텍스트 민감 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 빌드 및 회귀 시드 문서](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
