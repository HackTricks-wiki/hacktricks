# Fuzzing 방법론

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage와 의미론

**Mutational grammar fuzzing**에서는 입력이 **문법적으로 유효한 상태**를 유지하도록 변형합니다. Coverage-guided 모드에서는 **새로운 coverage**를 유발하는 샘플만 corpus seed로 저장합니다. **언어 대상**(파서, 인터프리터, 엔진)의 경우, 한 구문의 출력이 다른 구문의 입력이 되는 **의미론적/데이터 흐름 체인**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**실패 유형:** fuzzer가 `document()`와 `generate-id()`(또는 유사한 primitive)를 각각 실행하는 seed는 찾지만, **연결된 데이터 흐름을 유지하지 못해** “버그에 더 가까운” 샘플이 coverage를 늘리지 않는다는 이유로 버려집니다. **3개 이상의 종속 단계**가 있으면 무작위 재조합에 많은 비용이 들고, coverage feedback도 탐색을 유도하지 못합니다.<sup>[[1]](#references)</sup>

**시사점:** 종속성이 많은 문법에서는 **mutational 단계와 generative 단계를 결합**하거나, coverage만이 아니라 **함수 체이닝** 패턴을 우선 생성하도록 고려하세요.<sup>[[1]](#references)</sup>

## Corpus 다양성의 함정

Coverage-guided mutation은 **greedy**합니다. 새로운 coverage를 만드는 샘플을 즉시 저장하며, 이때 변경되지 않은 큰 영역이 그대로 남는 경우가 많습니다. 시간이 지나면 corpus에 구조적 다양성이 낮은 **거의 중복된 샘플**이 쌓입니다. 지나치게 공격적인 minimization은 유용한 맥락을 제거할 수 있으므로, 실용적인 절충안은 **최소 token 임계값에 도달하면 중단하는** **grammar-aware minimization**입니다. 이를 통해 노이즈를 줄이면서도 변형에 충분한 주변 구조를 유지할 수 있습니다.<sup>[[1]](#references)</sup>

Mutational fuzzing에 실용적인 corpus 규칙은 큰 규모의 거의 중복된 샘플보다 **coverage를 극대화하는, 구조적으로 서로 다른 소수의 seed를 우선하는 것**입니다. 실제로는 대개 다음을 의미합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **실제 샘플**(공개 corpus, 크롤링 데이터, 캡처한 트래픽, 대상 생태계의 파일 모음)에서 시작합니다.
- 유효한 샘플을 모두 보관하는 대신 **coverage 기반 corpus minimization**으로 추려냅니다.
- seed를 **충분히 작게** 유지해 대부분의 사이클을 무관한 바이트에 쓰지 않고 의미 있는 필드에 변형이 적용되도록 합니다.
- 주요 harness/instrumentation 변경 후 corpus minimization을 다시 실행합니다. reachability가 바뀌면 “최적의” corpus도 달라지기 때문입니다.

## 매직 값 비교를 고려한 Mutation

fuzzer가 정체되는 흔한 이유는 구문이 아니라 **엄격한 비교 조건**입니다. 예를 들어 `memcmp`, switch 테이블 또는 연쇄 비교로 검사하는 매직 바이트, 길이 검사, enum 문자열, checksum 또는 파서 디스패치 값이 있습니다. 순수한 무작위 변형은 이러한 값을 바이트 단위로 추측하는 데 사이클을 낭비합니다.

이런 대상에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen 방식의 워크플로)을 사용하세요. fuzzer가 실패한 비교의 피연산자를 관찰하고, 조건을 충족하는 값 쪽으로 변형을 유도할 수 있습니다.<sup>[[3]](#references)</sup>

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

- 대상이 **파일 시그니처**, **프로토콜 동사**, **타입 태그** 또는 **버전에 따라 달라지는 기능 비트** 뒤에 복잡한 로직을 숨겨 두는 경우 특히 유용합니다.
- 실제 샘플, 프로토콜 사양 또는 디버그 로그에서 추출한 **사전**과 함께 사용하세요. 문법 토큰, 청크 이름, 동사, 구분 기호가 포함된 작은 사전이 방대한 범용 단어 목록보다 더 유용한 경우가 많습니다.
- 대상이 순차 검사를 많이 수행한다면, 먼저 가장 앞에 있는 “magic” 비교를 해결한 다음 결과 코퍼스를 다시 최소화하여 이후 단계가 이미 유효한 접두사부터 시작하도록 하세요.

## 엣지 커버리지로 서로 다른 경로를 구분할 수 없을 때 더 풍부한 피드백

일반적인 엣지 커버리지로는 동일한 헬퍼를 서로 다른 호출자에서 거쳐 실행되는 경우나 함수 내에서 서로 다른 분기 조합을 선택하는 경우를 구분할 수 없습니다. **경로**에 따라 활성 상태가 달라지는 공유 디코더, 프로토콜 디스패처, 인터프리터 헬퍼에서 이는 중요합니다. 모든 호출 컨텍스트를 무작정 추적하는 것도 위험합니다. 커버리지 맵과 큐가 폭발적으로 커질 수 있기 때문입니다. 따라서 컨텍스트 민감 퍼징 연구에서는 전체 호출 그래프를 컨텍스트 민감 방식으로 처리하는 대신, 유망한 컨텍스트만 정교화할 것을 권장합니다.<sup>[[14]](#references)</sup>

최근 AFL++ 빌드는 일반 엣지 커버리지에 더해 **함수별 Ball-Larus 경로 커버리지**를 제공합니다. 이 방식은 함수 내 각 비순환 경로에 기능을 할당합니다. 루프의 역방향 엣지는 제거되므로, 이 피드백은 분기 조합은 구분하지만 **루프 반복 횟수는 구분하지 않습니다**. 완화된 수준 `1`부터 시작한 다음, 경로 수가 기하급수적으로 증가할 수 있으므로 더 엄격한 모드는 의심스러운 파서/상태 머신 코드에만 적용하세요.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

여러 보안 관련 지점에서 호출되는 helper의 경우, LTO 모드는 각 함수 경로를 바로 그 호출 지점과 결합할 수 있습니다:<sup>[[13]](#references)</sup>

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

**캠페인 지침:** 더 풍부한 피드백은 신중하게 적용하고, coverage-map/queue 비용을 모니터링하세요.<sup>[[13]](#references)[[14]](#references)</sup>

- 일반적인 edge-coverage 인스턴스도 병렬로 실행하세요. 추가 queue/map 비용 때문에 초당 실행 수가 감소하지 않을 때만 더 풍부한 피드백이 유용합니다.
- 대규모 템플릿 중심 라이브러리나 일반 유틸리티 코드가 map의 대부분을 차지한다면 `AFL_LLVM_ALLOWLIST`를 사용해 경로/호출자 instrumentation 범위를 제한하세요.
- 비순환 경로가 지나치게 많은 함수는 AFL++가 건너뛸 수 있습니다. 컴파일 중 경고가 나타나면 대상에 allowlisting을 적용하거나 더 낮은 strictness level을 사용해야 한다는 신호입니다.
- Caller + path coverage는 caller depth를 하나만 지원합니다. 더 깊은 context stack과 함께 사용하지 마세요.
- Path ID는 LLVM major version에 따라 달라질 수 있습니다. 캠페인 동안 toolchain을 고정하고, 빌드 간 feature ID가 안정적이라고 가정해 PATH 기반 corpus를 동기화하지 마세요.
- 이 피드백은 `CMPLOG`를 보완합니다. comparison tracing은 **guard를 통과하는 값이 무엇인지** 해결하고, path/caller feedback은 **어떤 경로와 branch 조합으로 그 지점에 도달했는지** 보존합니다.

## Stateful Fuzzing: 시퀀스가 시드입니다

**프로토콜**, **인증된 워크플로**, **다단계 parser**에서는 흥미로운 단위가 단일 blob이 아니라 **메시지 시퀀스**인 경우가 많습니다. 전체 transcript를 하나의 파일로 연결해 무작정 변이하는 방식은 대개 비효율적입니다. fuzzer가 모든 단계에 똑같이 변이를 적용하지만, 취약한 상태에 도달하는 것은 후속 메시지뿐일 수 있기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 방식은 **시퀀스 자체를 시드로 취급**하고, **관찰 가능한 상태**(응답 코드, 프로토콜 상태, parser 단계, 반환된 객체 유형)를 추가 피드백으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **유효한 접두 메시지**는 안정적으로 유지하고, **전이를 유도하는** 메시지에 변이를 집중하세요.
- 다음 단계가 이전 응답에 의존한다면, 식별자와 서버가 생성한 값을 캐시하세요.
- 직렬화된 transcript 전체를 불투명한 blob으로 변이하는 대신 메시지별 변이/접합을 우선하세요.
- 프로토콜에서 의미 있는 응답 코드를 제공한다면, 이를 **저비용 상태 oracle**로 사용해 더 깊이 진행하는 시퀀스의 우선순위를 높이세요.

인증이 필요한 버그, 숨겨진 전이, “handshake 이후에만 발생하는” parser 버그를 일반적인 파일 방식 fuzzing으로 놓치는 이유도 같습니다. fuzzer는 구조뿐 아니라 **순서, 상태, 의존성**을 보존해야 합니다.<sup>[[4]](#references)</sup>

### Android Binder: 다중 클라이언트 driver fuzzing

높은 edge coverage를 달성해도 IPC driver 버그를 놓칠 수 있습니다. coverage는 **객체 소유권, 참조 횟수, 대기 중 메시지, 정리 순서, 스레드 interleaving**을 설명하지 않기 때문입니다. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 페이지에서는 driver 객체 모델을 다룹니다. 이 예제는 fuzzer harness에 초점을 맞춥니다. Android Binder는 유용한 모델입니다. 여러 프로세스가 필요한 순서대로 동일한 kernel 객체를 조작하지 못한다면, 할당 및 해제 경로에 모두 도달하는 것만으로는 충분하지 않습니다.<sup>[[15]](#references)</sup>

#### 개별 `ioctl` buffer가 아닌 프로토콜을 모델링하세요

테스트 케이스를 **클라이언트 ID + 연산 + 구조화된 인수**로 이루어진 순서가 있는 grammar로 표현하세요. Binder LKL fuzzer는 protobuf와 `libprotobuf-mutator`를 사용하며, 영구적인 context-manager 클라이언트 하나와 일반 클라이언트 두 개를 둡니다. 그런 다음 semantic harness가 무작위 byte 변이로 파괴될 관계를 보존합니다.<sup>[[15]](#references)</sup>

- 이전 연산에서 반환된 값을 캐시하세요. 예를 들어 `BC_FREE_BUFFER`는 이전 `ioctl`이 반환한 transaction-buffer pointer를 재사용해야 합니다.
- 유효한 기본 reply를 생성해 동기 transaction이 완료되고 이후 연산에 계속 도달할 수 있도록 하세요.
- 자기 자신에게 보내는 transaction이나 동일한 대상에 대한 여러 pending transaction처럼 불가능한 전이는 거부하세요.
- singleton bootstrap state는 입력별 reset 대상에서 제외하세요. Binder는 부팅당 `BINDER_SET_CONTEXT_MGR` 등록을 하나만 허용하므로 해당 클라이언트를 반복해서 제거하고 다시 만들면 이후 입력이 유효하지 않게 됩니다.

유용한 lifetime-race 템플릿은 한 클라이언트가 객체를 전송하고 thread 또는 process 정리를 시작한 뒤, 수신 클라이언트가 transaction buffer를 동시에 해제하게 하는 것입니다. CVE-2020-0423 사례에서는 `BINDER_TYPE_WEAK_BINDER` 전송 후 `BINDER_THREAD_EXIT`가 `BC_FREE_BUFFER`와 경합하면서, 종료 중인 thread의 정리 경로가 여전히 사용 중인 내장 `binder_work`를 해제할 수 있었습니다.<sup>[[15]](#references)</sup>

#### userspace kernel에서 제어된 interleaving을 다시 도입하기

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)는 실제 kernel 코드를 userspace harness에 링크하고 `lkl_syscall`을 통해 syscall 인터페이스를 노출합니다. 이를 통해 protobuf state, coverage, KASAN을 하나의 프로세스에서 쉽게 조정할 수 있습니다. 하지만 LKL은 일반적으로 syscall 실행 도중 다른 kernel thread가 끼어들지 않습니다. race 캠페인에서는 선택한 lock/unlock 및 lifetime 경계 주변에 `schedule()` 지점을 삽입한 다음, 각 yield 시 harness가 다음 클라이언트를 무작위로 선택하게 하세요. 각 지점은 스케줄링 탐색 공간을 배가시키므로 꼭 필요한 곳에만 추가하세요. 연구자들이 설명한 randomized scheduler는 upstream Binder fuzzer에 **포함되어 있지 않습니다**.<sup>[[15]](#references)</sup>

#### 직렬화된 regression seed 빌드 및 재실행

upstream harness는 호환되는 `libprotobuf-mutator` 버전을 고정하고, `LKL_FUZZING=1`로 LKL fuzzing instrumentation과 KASAN을 활성화하며, Binder용으로 `CONFIG_MMU`를 `MMU=1`로 활성화합니다.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

의도적으로 취약한 리비전을 체크아웃하거나 upstream에 문서화된 rollback 패치를 적용한 뒤에는, 직렬화된 시드로 임시 C proof of concept에서 상태 전이를 재구성하지 않고도 전체 멀티 클라이언트 상태 전이를 재현할 수 있습니다:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

결과적으로 발생한 KASAN use-after-free는 seed가 취약한 객체 수명 경로에 도달했음을 확인해 줍니다. 하지만 커널 코드 실행이나 권한 상승에 필요한 이후의 primitive까지 입증하는 것은 아닙니다.<sup>[[16]](#references)</sup>

## 단일 머신 다양성 트릭 (Jackalope 스타일)

**생성형 새로움**과 **coverage 재사용**을 결합하는 실용적인 방법은 지속적으로 실행되는 서버를 대상으로 수명이 짧은 worker를 재시작하는 것입니다. 각 worker는 빈 corpus에서 시작해 `T`초 후 동기화하고, 결합된 corpus로 다시 `T`초 동안 실행한 뒤 다시 동기화하고 종료합니다. 이렇게 하면 누적된 coverage를 활용하면서도 **세대마다 새로운 구조를 생성**할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**서버:**

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

**참고:**

- `-in empty`는 각 생성 시 **새 corpus**를 강제합니다.
- `-server_update_interval T`는 **지연된 동기화**를 근사합니다(먼저 새로운 입력을 찾고 나중에 재사용).
- grammar fuzzing 모드에서는 기본적으로 **초기 서버 동기화가 생략됩니다**(`-skip_initial_server_sync` 불필요).
- 최적의 `T`는 **대상에 따라 다릅니다**. worker가 대부분의 “쉬운” coverage를 찾은 뒤 전환하는 방식이 대체로 가장 효과적입니다.

## 접근하기 어려운 하네스 대상에 대한 Snapshot Fuzzing

테스트하려는 코드에 **큰 초기화 비용을 들여야만 도달할 수 있는 경우**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화), 유용한 대안은 **snapshot fuzzing**입니다. 준비된 프로세스 또는 VM 상태를 캡처하고, 각 테스트 케이스를 대상 입력 경로에 주입한 뒤, crash/timeout까지 실행하고 snapshot을 복원합니다. 이렇게 하면 초기화나 프로토콜 접두부를 반복할 필요가 없어 **network services**, **firmware**, **인증 이후 공격 표면**, **바이너리 전용 대상**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 관심 있는 상태가 준비될 때까지 대상을 실행합니다.
2. 해당 시점의 **메모리 + 레지스터**를 snapshot으로 저장합니다.
3. 각 테스트 케이스에 대해 변형된 입력을 관련 guest/process 버퍼에 직접 기록합니다.
4. crash/timeout/reset까지 실행합니다.
5. snapshot을 복원합니다. VM 대상의 경우 지원된다면 **변경된 페이지만** 복원한 다음 반복합니다.

가능한 한 첫 번째 고비용 파싱/디스패치 단계 직전에 snapshot을 배치합니다. 예를 들어 `recv`/`read` 직후 또는 패킷 역직렬화 지점이 해당합니다. 또한 대상에서 사용하는 입력 버퍼를 기록합니다. 이는 입력 처리 과정에서 snapshot을 더 깊은 지점으로 옮겨 작업의 반복을 피하는 적응형 배치 원칙을 따릅니다.<sup>[[11]](#references)</sup>

## MAccConc를 사용한 Linux 커널 Race 탐색

[MAccConc](https://github.com/googleprojectzero/MAccConc)는 타이밍에 민감한 Linux 커널 race를 반복 가능한 메모리 접근 스케줄로 변환합니다. 두 컨텍스트의 **A-B-A** 실행을 자동으로 열거하거나, 분석가가 terminal UI/GUI에서 순서 제약을 지정할 수 있습니다. 이는 완전한 동시성 fuzzer라기보다 실험적인 연구 도구입니다. 현재 LLVM 23+와 프로젝트에서 패치한 커널이 필요하고, command-line 도구는 두 개의 테스트 스레드를 지원하며, 제안된 userspace fuzzing 계층은 구현되지 않았습니다.<sup>[[17]](#references)[[18]](#references)</sup>

### 컨텍스트 간 통신 지점 수집

KASAN outline callback과 패치된 KCOV 메모리 기록 지원을 사용해 계측된 커널을 빌드합니다. 프로젝트 README에서는 호출 스택을 계속 사용할 수 있도록 sibling-call 최적화를 비활성화할 것도 권장합니다.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`)는 instrument된 접근을 helper 호출로 변환합니다. MAccConc 커널 패치는 연속된 접근이 병합되지 않도록 `asan-opt-same-temp`를 비활성화합니다. 전역 변수의 race도 감지해야 한다면 `asan-opt-globals` 최적화도 비활성화하세요. KCOV는 결과 레코드를 userspace로 전달합니다. 서로 다른 실행 컨텍스트의 접근을 비교하고, 바이트 범위가 겹치며 한쪽 이상이 쓰기인 쌍을 유지하세요. 수명 전환도 후보가 되도록 `kfree()`를 쓰기로 모델링합니다.<sup>[[17]](#references)</sup>

시작 task에서 벗어나는 작업(예: 패킷 처리나 RCU 콜백)의 경우, 해당 subsystem은 KCOV remote-coverage handle을 전파해야 합니다. Upstream remote KCOV는 opt-in 방식이며 임의의 백그라운드 작업에서 자동으로 사용할 수 없으므로, 전파가 누락되면 실제 상호작용이 감지되지 않을 수 있습니다.<sup>[[17]](#references)[[19]](#references)</sup>

### 매 실행에서 동일한 동적 접근 식별하기

매 할당 후 달라질 수 있는 구체적인 heap 주소만을 기준으로 재생하거나, `memcpy()` 및 `spin_lock()`과 같은 helper 내부에서 모호한 명령어 주소만을 기준으로 재생하지 마세요. MAccConc는 **count-augmented stack trace**를 사용합니다. 각 프레임은 callee와 caller 내 호출 횟수를 식별하고, 마지막 요소는 메모리 접근 명령어를 식별합니다. SanitizerCoverage의 함수 진입/종료 레코드를 통해 userspace가 이 동적 식별자를 재구성할 수 있습니다. 이 식별자는 주소 변경이나 무관한 제어 흐름의 잡음에도 안정적으로 유지됩니다.<sup>[[17]](#references)</sup>

### 후보 쌍을 강제 스케줄로 변환하기

패치된 `KCOV_SET_DI` ioctl은 count-augmented 접근 식별자를 공유 플래그 동작과 연결합니다.<sup>[[17]](#references)</sup>

| 동작 | 의미 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 선택한 접근 직전에 플래그 *N*을 설정합니다. |
| `DI_STACK_WAIT` | 선택한 접근 직전에 플래그 *N*이 설정되거나 구성된 제한 시간이 만료될 때까지 spin 대기합니다. |
| `DI_STACK_WAKE_POST` | 선택한 접근 직후 플래그 *N*을 설정합니다. |

부분적인 **A-happens-before-B** 제약을 적용하려면 A에 `DI_STACK_WAKE_POST`를, B에 `DI_STACK_WAIT`를 연결하고 같은 플래그를 사용합니다. 두 컨텍스트의 스케줄을 완전히 지정하려면 B를 차단된 상태로 시작한 다음, 첫 번째 전환 지점에서 A가 B를 깨우고 대기하도록 합니다. 다음 전환 지점에서는 B가 반대 동작을 수행합니다. 후자는 결정적 컨텍스트 전환처럼 동작하며 자동 A-B-A 탐색기가 사용하는 방식입니다.<sup>[[17]](#references)</sup>

최소 캠페인은 4개 hook 테스트 케이스(`test_setup`, 두 thread 함수, `test_end`)를 shared library로 컴파일하고, 제약 없는 trace를 수집한 다음, A-B-A 후보를 열거하거나 의심스러운 접근 주변에 수동 제약을 추가하는 것입니다.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

타임아웃은 성공적인 재정렬과 별도로 해석하세요. 잠금이나 초기화/게시 의존성으로 인해 두 번째 컨텍스트가 주입 지점에 도달하지 못해 요청된 순서가 불가능할 수 있습니다. 또한 KASAN의 사각지대도 고려하세요. 스택에 직접 접근하는 작업은 범위를 벗어날 가능성이 있는 경우가 아니면 대개 후킹되지 않고, 기본 최적화에서는 전역 변수가 제외되며, 현재 컴파일러는 ASAN과 TSAN 후크를 동시에 생성할 수 없습니다. 마지막으로 프로토타입은 게스트가 패닉에 빠지면 KCOV 버퍼를 잃으므로, 별도의 크래시 콘솔/오라클을 유지하세요.<sup>[[17]](#references)</sup>

향후 동시성 유도 fuzzing을 위해 입력 또는 syscall별 메모리 접근 요약을 기록하고, 컨텍스트 간 통신 지점이 될 작업 쌍을 구성한 다음 해당 조합만 탐색하세요. VM 스냅샷은 전역 상태와 주소를 안정화합니다. 스냅샷이 없으면 할당 지점 메타데이터를 사용해 실행 간 객체를 추상화할 수 있습니다. 이는 제안된 확장 기능이지, 현재 MAccConc 사용자 공간 도구의 기능은 아닙니다.<sup>[[17]](#references)</sup>

## Harness Introspection: 얕은 fuzzer를 조기에 찾기

캠페인이 정체될 때 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **도달 가능성/커버리지 인트рос펙션**을 사용해 fuzz 대상에서 정적으로 도달 가능하지만 동적으로는 거의 또는 전혀 커버되지 않는 함수를 찾으세요. 이런 함수는 대개 다음 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 대상 진입 시점을 너무 늦추거나 앞당깁니다.
- 시드 corpus에 기능군 전체가 빠져 있습니다.
- 대상에는 하나의 지나치게 큰 “모든 작업 수행” harness 대신 **두 번째 harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일의 워크플로를 사용한다면, Fuzz Introspector는 정적 도달 가능성과 런타임 커버리지를 비교하고, 시간 제한 실행 또는 공개 corpus에서 보고서를 생성할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

보고서를 사용해 미테스트 parser 경로를 위한 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나의 큰 harness를 더 작은 진입점으로 나눌지 결정하세요.

## 그래프 우선 Fuzz 타깃 선정 및 Mutation 분류

이미 **정적 분석 결과**, **mutation testing 생존 항목**, **coverage 보고서**가 있다면, 이를 서로 독립적인 목록으로 분류하지 마세요. 먼저 **call graph**를 만들고, 노드에 **순환 복잡도**, **진입점/신뢰할 수 없는 입력으로부터의 도달 가능성**, 외부 분석 결과를 표시한 다음, 그래프를 기준으로 질문하세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 복잡도가 높은 함수 중 신뢰할 수 없는 입력에서 도달 가능한 함수는 무엇인가요?
- parser/handler에서 보안상 중요한 코드로 이어지는 경로에 어떤 mutation 생존 항목이 있나요?
- **영향 범위**가 유난히 큰 아키텍처상의 병목 함수는 무엇인가요?

이 방법은 대개 단순히 "coverage가 가장 낮은 곳"을 찾는 것보다 더 나은 fuzz 타깃을 찾아냅니다. **복잡도가 높고** 외부에서 도달 가능하다고 확인된 parser/decoder는, coverage가 낮더라도 공격자가 제어하는 경로가 없는 독립적인 내부 helper보다 더 적합한 harness 후보입니다.

### 실용적인 분류 워크플로

1. 코드베이스에서 **코드 그래프**를 만들고 함수별 복잡도/분기 지표를 추출합니다.
2. 공격자가 제어하는 입력을 받는 **진입점**을 열거합니다. 예: request handler, decoder, importer, protocol parser, CLI/file reader.
3. 진입점에서 후보 함수까지의 **경로 쿼리**를 실행해, 도달 가능한 공격 표면과 사용되지 않거나 내부 전용인 코드를 구분합니다.
4. 다음 조건을 충족하는 노드를 우선시합니다.
   - 높은 **순환 복잡도**
   - 신뢰할 수 없는 입력으로부터의 도달 가능성이 확인됨
   - 큰 **영향 범위** 또는 다수의 하위 의존 항목
   - **SARIF** 분석 결과, 감사 메모, mutation 생존 항목 등의 추가 근거
5. 점수가 가장 높은 노드부터 집중형 harness를 작성합니다. 특히 hex/Base64/IP/message decoder 같은 **parser/codec**을 우선합니다.

### Mutation 생존 항목: 동등한 변이인가, 조치가 필요한가

Mutation testing을 수행하면 생존 항목 목록에 잡음이 많이 섞이는 경우가 있습니다. 모든 생존 항목을 보안 결함으로 취급하기 전에, 그래프를 이용해 다음을 확인하세요.

- 변형된 함수가 공격자가 제어하는 진입점에서 도달 가능한가요?
- 모든 호출 경로가 변형된 검사보다 더 강한 불변 조건으로 제한되나요?
- 해당 노드가 사용되지 않는 코드나 서식 처리 로직에 있는가요, 아니면 영향이 큰 산술/parser 경로에 있는가요?

도달 불가능한 상태로 남거나 구조적으로 제약된 생존 항목은 대개 **동등 변이**입니다. **도달 가능**한 상태로 남아 **경계 조건**, **overflow/carry 경로**, **보안상 중요한 산술/parser 처리**에 영향을 주는 생존 항목은 다음 항목으로 승격해야 합니다.

- 새 fuzz harness
- 직접적인 property/invariant 테스트
- 대상별 edge-case 벡터

### 외부 분석 결과를 그래프에 연결하기

SAST 파이프라인에서 **SARIF**를 내보내는 경우, **파일 + 줄 범위**를 기준으로 분석 결과를 그래프 노드에 매핑하고 그래프를 사용해 영향 범위를 확장하세요.<sup>[[6]](#references)</sup>

- 표시된 함수의 **영향 범위**를 계산합니다.
- 해당 분석 결과가 진입점에서 이어지는 경로에 있는지 확인합니다.
- 같은 병목 지점으로 통합되는 인접 분석 결과를 묶습니다.

이 방법은 특정 함수에 fuzzing 시간을 투입할지 결정할 때 유용합니다. **도달 가능하고**, **복잡하며**, 이미 **SAST 결과**가 있는 노드는 공격 경로가 없는 단순 고복잡도 노드보다 더 나은 타깃인 경우가 많습니다.

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

중요한 방법론은 다음 요소들의 교집합입니다: **복잡도 x 노출도 x 영향도**. 그래프를 활용해 예상 보안 가치가 가장 높은 fuzz 대상을 선택한 다음, mutation에서 살아남은 항목을 바탕으로 harness에서 어떤 경계와 불변 조건을 집중적으로 테스트할지 결정하세요.<sup>[[5]](#references)</sup>

## gosentry를 사용한 Go 퍼징: 더 강력한 엔진, 타입이 지정된 입력, 차등 검사

Go 대상에 이미 기본 `testing.F` harness가 있다면, 실용적인 업그레이드 방법은 [gosentry](https://github.com/trailofbits/gosentry)를 사용해 동일한 harness를 실행하는 것입니다. gosentry는 `go test -fuzz`는 유지하면서 백엔드를 **LibAFL**로 교체한 Go 툴체인의 fork입니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

이는 native Go fuzzer가 **hard comparisons**, **typed inputs** 또는 **parser-heavy formats**에서 진행을 멈출 때 유용합니다. 방법론은 동일합니다.

- 시드에는 `f.Add(...)`를, 콜백에는 `f.Fuzz(...)`를 계속 사용합니다.
- 동일한 harness를 재사용하되, 기본 toolchain 대신 gosentry의 `go` 바이너리로 실행합니다.
- 결과 campaign은 일반적인 coverage-guided 실행으로 취급하되, LibAFL의 scheduling/mutation과 개선된 주변 detector를 활용합니다.

### 조용한 실패를 fuzzing finding으로 전환하기

Go 평가에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 **crash를 일으키지 않는 경우가 많다**는 점입니다. gosentry를 사용하면 여러 유형의 “문제가 있지만 조용한” 상태를 finding으로 전환할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용하면 선택한 logging/error 경로가 crash처럼 동작합니다. (그렇지 않으면 로그만 남기고 계속 진행하는 `log.Fatal` 스타일의 코드 경로에 유용합니다.)
- `--catch-races=true`를 사용하면 새로 발견된 queue entry를 Go race detector로 다시 실행합니다.
- `--catch-leaks=true`를 사용하면 새 queue entry를 `goleak`으로 다시 실행하고 goroutine leak이 발생하면 중단합니다.
- LibAFL의 hang 처리 기능을 사용하면 **infinite loop / 매우 느린 입력**이 timeout으로 사라지지 않고 fuzzing finding으로 남습니다.
- 기본적으로 내장 arithmetic overflow 검사를 수행하며, go-panikint 스타일 instrumentation을 통해 선택적으로 truncation 검사도 수행합니다.

이는 보안 영향이 memory corruption이 아니라 **panic 없는 parser 실패**, **concurrency bug** 또는 **DoS만 유발하는 hang**인 타깃에서 특히 유용합니다.

### 타입이 지정된 Go API를 위한 Struct-aware fuzzing

native Go fuzzing은 주로 `[]byte`, `string`, 숫자와 같은 scalar를 입력으로 받습니다. 테스트 대상 코드가 타입이 지정된 객체를 사용하는 경우, gosentry는 내부에서 계속 바이트를 변형하면서 struct, slice, array, pointer 같은 **composite value**를 직접 fuzzing할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

fuzzing 전용 fake wire format을 만들 때 이 방법을 사용하면 harness에만 있는 parsing 코드 뒤에 logic bug가 숨겨질 수 있습니다. differential 또는 grammar-based campaign에서는 harness 입력을 단일 `[]byte` 또는 `string`으로 유지하고 대신 callback 내부에서 parsing하세요.

### parser와 protocol 입력을 위한 grammar-based fuzzing

parser, format, input language의 경우 gosentry는 LibAFL 위에서 **Nautilus grammar fuzzing**을 실행할 수 있습니다. grammar는 production rule의 JSON 배열이며, harness는 일반적으로 단일 `[]byte` 또는 `string` 인수를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

방법론 메모:

- 바이트 수준 변이 입력이 대부분 초기 구문 검사에서 걸러진다면 grammar mode를 사용합니다.
- 전체 사양을 모델링하는 대신, 언어/프로토콜의 **보안 관련 하위 집합**에 초점을 맞춰 grammar를 구성합니다.
- terminal/nonterminal에 큰 경계값을 사용해 정수, 길이, 상태 머신의 경계 조건을 압박합니다.
- Grammar mode는 입력을 문법적으로 유효하게 유지하지만, 대상은 여전히 **bytes/strings**를 받으므로 파싱 및 의미 검사는 하네스가 적용된 코드 내부에서 이루어집니다.

### Differential fuzzing: 크래시만이 아니라 구현을 비교합니다

Go 생태계에서 효과적인 패턴은 **grammar 기반 differential fuzzing**입니다. 유효한 구조화 입력을 생성해 두 개의 parser, client 또는 상태 전이 엔진에 입력합니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

다음과 같은 경우를 발견 사항으로 취급하세요.

- 한 구현은 panic이 발생하지만 다른 구현은 정상적으로 거부함
- 입력을 허용하거나 거부하는 결과가 서로 다름
- 파스 트리 또는 디코딩된 객체가 서로 다름
- 상태 전이, nonce, 잔액 또는 상태 루트가 서로 다름

이는 순수 crash fuzzing으로는 놓치기 쉬운 **합의 불일치**, **파서 모호성**, **사양과 구현 간의 괴리**를 찾는 실용적인 방법입니다.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 커버리지 보고에 캠페인 코퍼스 재사용

캠페인이 끝난 후 저장된 queue 코퍼스를 재생해 별도의 코퍼스를 수동으로 내보내지 않고 Go 커버리지 보고서를 생성하세요.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

gosentry가 올바른 캐시된 campaign state를 확인할 수 있도록 **같은 패키지**에서 **같은 `-fuzz` target**으로 명령을 실행하세요.



## References

- [1] [Mutational grammar 퍼징](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing 심층 분석](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet 5년 후: 커버리지 기반 프로토콜 Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark가 코드를 그래프로 변환하는 방법](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go Fuzzing에는 툴킷의 절반이 빠져 있었습니다. 이를 해결하기 위해 툴체인을 포크했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 스냅샷을 사용한 상태 기반 네트워크 프로토콜용 고속 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [문법이 없어도 문제없다: 시스템 호출 설명 없이 Linux 커널을 Fuzzing하는 방법](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: 적응형 및 변경 가능한 스냅샷을 활용한 효율적인 Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 계측: 경로 및 호출자 커버리지](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [예측형 컨텍스트 민감 Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 빌드 및 회귀 시드 문서](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: 제어된 메모리 접근 인터리빙으로 Linux 커널 경쟁 조건 탐색](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Fuzzing을 위한 코드 커버리지](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
