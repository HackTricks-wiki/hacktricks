# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**mutational grammar fuzzing**에서는 입력을 **문법에 맞는 상태로 유지하면서** 변형합니다. coverage-guided 모드에서는 **새로운 coverage**를 유발하는 샘플만 corpus seed로 저장합니다. **언어 대상**(파서, 인터프리터, 엔진)의 경우, 한 구성 요소의 출력이 다른 구성 요소의 입력이 되는 **semantic/dataflow chain**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**실패 방식:** fuzzer가 각각 `document()`와 `generate-id()`(또는 유사한 기본 요소)를 실행하는 seed를 찾지만, **연결된 dataflow를 유지하지 못해** 버그에 더 가까운 샘플이 coverage를 늘리지 않는다는 이유로 버려집니다. **서로 의존하는 단계가 3개 이상**이면 무작위 재조합에 비용이 많이 들고 coverage 피드백도 탐색을 안내하지 못합니다.<sup>[[1]](#references)</sup>

**시사점:** 의존성이 많은 문법에서는 **mutational 단계와 generative 단계를 결합**하거나, coverage뿐 아니라 **function chaining** 패턴을 우선 생성하도록 편향하는 방안을 고려하세요.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation은 **greedy**합니다. 새로운 coverage를 발견한 샘플을 즉시 저장하며, 변경되지 않은 큰 영역이 그대로 남는 경우가 많습니다. 시간이 지나면 corpus가 구조적 다양성이 낮은 **거의 중복된 샘플**로 채워집니다. 지나치게 공격적인 minimization은 유용한 맥락을 없앨 수 있으므로, 실용적인 절충안은 **최소 token 임계값에서 멈추는** **grammar-aware minimization**입니다. 이렇게 하면 노이즈를 줄이면서 mutation에 적합한 주변 구조를 충분히 유지할 수 있습니다.<sup>[[1]](#references)</sup>

mutational fuzzing에서 실용적인 corpus 규칙은 다음과 같습니다. 거의 중복된 샘플을 많이 모으기보다 **coverage를 극대화하는 구조적으로 다양한 seed를 소수 유지**하세요. 일반적으로 다음과 같이 하면 됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **실제 환경의 샘플**(공개 corpus, crawling 결과, 캡처한 트래픽, 대상 생태계의 파일 모음)에서 시작합니다.
- 유효한 샘플을 모두 보관하는 대신 **coverage 기반 corpus minimization**으로 추립니다.
- mutation이 대부분의 주기를 관련 없는 바이트에 쓰는 대신 의미 있는 필드를 변경하도록 seed를 **충분히 작게** 유지합니다.
- harness/instrumentation을 크게 변경한 뒤에는 corpus minimization을 다시 실행합니다. reachability가 달라지면 “최적” corpus도 바뀌기 때문입니다.

## Comparison-Aware Mutation For Magic Values

fuzzer가 정체되는 흔한 이유는 문법이 아니라 **엄격한 비교**입니다. 예를 들어 magic byte, 길이 검사, enum 문자열, checksum 또는 `memcmp`, switch table, 연쇄 비교로 보호되는 parser dispatch 값이 있습니다. 순수한 무작위 mutation은 이런 값을 바이트 단위로 추측하는 데 주기를 낭비합니다.

이런 대상에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen 방식의 workflow)을 사용해 fuzzer가 실패한 비교의 피연산자를 관찰하고, 비교를 통과하는 값 쪽으로 mutation을 유도하세요.<sup>[[3]](#references)</sup>

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

- 대상이 **파일 시그니처**, **프로토콜 동사**, **타입 태그** 또는 **버전에 따라 달라지는 기능 비트** 뒤에 복잡한 로직을 두는 경우 특히 유용합니다.
- 실제 샘플, 프로토콜 사양 또는 디버그 로그에서 추출한 **사전**과 함께 사용하세요. 문법 토큰, 청크 이름, 동사, 구분 기호가 포함된 작은 사전이 대규모 범용 단어 목록보다 더 유용한 경우가 많습니다.
- 대상이 순차적으로 많은 검사를 수행한다면, 가장 먼저 나오는 “매직” 비교를 먼저 통과한 다음 결과 코퍼스를 다시 최소화하여 이후 단계가 이미 유효한 접두부에서 시작하도록 하세요.

## 파일 이름 언어를 숨기는 파일 API 퍼징

`filename`, `path` 또는 `URL`이라는 매개변수는 단순한 파일 조회가 아니라 인터프리터의 진입점일 수 있습니다. 예를 들어, CFITSIO Extended Filename Syntax (EFS)는 열린 객체를 반환하기 전에 대괄호로 묶인 선택자, 행/픽셀 표현식, 계산된 열, 히스토그램 및 변환을 평가하며, 일부 형식은 임시 복사본도 만듭니다. 공격 표면을 매핑할 때 각 열기/가져오기 API를 **리터럴 경로** 또는 **해석되는 경로**로 분류한 다음, 애플리케이션이 실제로 호출하는 프로덕션 진입점을 퍼징하세요.<sup>[[20]](#references)[[22]](#references)</sup>

이로 인해 발생할 수 있는 SSRF, 파일 복사, 프로토콜 핸들러 프리미티브와 더 안전한 리터럴 경로 API는 [SSRF/파일 프리미티브로서의 파일 이름 미니 언어](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)를 참조하세요.<sup>[[20]](#references)</sup>

### 백업 객체를 퍼징 대상 프로그램과 분리하기

문법이 파일 이름 접미부에 있다면 참조된 파일 바이트만 변경해서는 파서를 테스트할 수 없습니다. 대신 간단한 하네스에서 테스트케이스를 문자열로 읽어 해석되는 열기 API에 전달할 수 있습니다. CFITSIO 캠페인에서는 `fits_open_file()`을 읽기 전용 모드로 호출해 대부분의 EFS 파서와 평가기에 도달했습니다. 기본 경로가 계속 손상되는 대신 선택자/표현식 언어에 집중해 변경할 수 있도록 유효한 백업 파일을 별도로 준비하세요.<sup>[[22]](#references)</sup>

각기 다른 문법 계열에 도달하는 시드로 시작한 다음, 사양과 렉서/파서 소스 코드 모두에서 간결한 사전을 만드세요. 입력이 같은 구문 오류 경로에서 계속 실패해 커버리지가 정체된다면, 유효한 접두부를 보존하고 무작위 변경 시간을 늘리는 대신 구분 기호, 연산자, 키워드, 함수 이름, 대표 필드 이름을 추가하세요.<sup>[[22]](#references)</sup>

예를 들어 문법 사전을 사용해 하네스를 실행하세요:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness 부작용 방지

라이브러리의 read-only 플래그가 testcase에 부작용이 없음을 보장하지는 않습니다. filename language가 입력을 다시 쓰거나, 출력 파일을 만들거나, 임시 객체를 생성할 수 있습니다. CFITSIO 캠페인에서는 seed 파일이 처음에 파괴되고 파일 시스템 곳곳에 예상치 못한 파일이 남아 정리와 격리가 필요했습니다.<sup>[[22]](#references)</sup>

- 각 worker에 폐기 가능한 작업 디렉터리와 전용 임시 디렉터리를 제공합니다.
- 기준 backing file의 복사본을 노출하고, 대상이 corpus의 유일한 원본을 수정하지 못하게 합니다.
- 원격 backend가 의도한 대상이 아니라면 네트워크 접근을 비활성화하고, 컨테이너, mount namespace 또는 동등한 sandbox로 쓰기 가능한 경로를 제한합니다.
- 실행 또는 worker batch가 끝날 때마다 디렉터리를 초기화하고, 예상치 못한 파일 시스템 변경도 추가 finding으로 취급합니다.

### Crash-to-patch-to-fuzz 반복 과정

수천 개의 artifact가 수천 개의 patch 작업으로 이어지지 않도록 수정 전에 crash를 cluster로 묶습니다. CFITSIO 평가에서 AFLTriage는 초기 crash 집합을 몇 가지 근본 원인으로 줄였습니다. 그 결과 작성된 advisory에는 잘못된 대상 크기 검사, `realloc()` 이후의 stale pointer, 산술 오류, 안전하지 않은 parser 정리 경로 등 서로 다른 오류가 나와 있습니다.<sup>[[21]](#references)[[22]](#references)</sup>

1. 각 cluster에서 대표 입력 하나를 최소화하고 AddressSanitizer로 재현합니다.
2. 실패한 정확한 접근, 소스 위치, 할당/해제 이력, invariant가 깨진 parser 상태를 기록합니다.
3. 범위를 좁힌 후보 patch 하나를 적용하고 동일한 coverage 및 sanitizer 계측으로 다시 빌드합니다.
4. 원래 재현 입력과 **cluster에 속한 모든 입력**을 다시 실행합니다. 또한 메모리 안전성 수정으로 오류 경로의 소유권 처리가 깨질 수 있으므로 leak detection도 활성화합니다.
5. 실제 파일로 기능 테스트를 실행한 뒤 누적된 queue에서 다시 시작합니다. 바이너리 변경 후 엔진에 새 출력 디렉터리가 필요하다면 해당 queue를 다시 가져옵니다.
6. 반복합니다. 첫 번째 얕은 crash를 제거하면 기존 seed가 더 깊은 parser 상태까지 진행되는 경우가 많습니다.

LLM에 crash 입력, sanitizer 보고서, harness, 관련 소스 코드를 제공하면 2단계를 빠르게 진행하고 3단계의 초안을 작성하는 데 도움이 될 수 있지만, 제안된 patch는 여전히 신뢰할 수 없습니다. 수정을 승인할지는 모델의 설명이 아니라 sanitizer 재실행과 회귀 테스트 기준으로 결정해야 합니다.<sup>[[22]](#references)</sup>

## Edge Coverage로 구분되지 않는 경로에 더 풍부한 Feedback 제공

일반적인 edge coverage로는 같은 helper를 서로 다른 caller를 통해 실행하거나 함수 안에서 서로 다른 branch 조합을 거치는 두 실행을 구분할 수 없습니다. 공유 decoder, 프로토콜 dispatcher, interpreter helper에서는 edge에 도달하는 **경로**가 현재 상태를 결정하므로 이 점이 중요합니다. 모든 호출 문맥을 단순하게 추적하면 위험할 수도 있습니다. coverage map과 queue가 폭발적으로 커질 수 있기 때문입니다. 따라서 context-sensitive fuzzing 연구에서는 전체 call graph를 context-sensitive로 취급하기보다 가능성이 높은 문맥만 정교하게 추적할 것을 권장합니다.<sup>[[14]](#references)</sup>

최근 AFL++ 빌드는 일반 edge coverage 외에도 **Ball-Larus 함수별 경로 coverage**를 제공합니다. 이는 함수 내 각 비순환 경로에 feature를 할당합니다. loop back-edge는 제거되므로 이 feedback은 branch 조합은 구분하지만 **loop 반복 횟수는 구분하지 않습니다**. 먼저 완화된 level `1`로 시작한 다음, 경로 수가 지수적으로 증가할 수 있으므로 의심스러운 parser/state-machine 코드에만 더 엄격한 모드를 적용합니다.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

여러 보안 관련 지점에서 호출되는 helper의 경우, LTO 모드는 각 함수 경로를 바로 호출한 지점과 결합할 수 있습니다:<sup>[[13]](#references)</sup>

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

- 일반적인 edge-coverage 인스턴스를 병렬로 실행하세요. 추가 queue/map 비용으로 초당 실행 횟수가 크게 줄어들지 않을 때만 더 풍부한 피드백이 유용합니다.
- 템플릿이 많은 대형 라이브러리나 범용 유틸리티 코드가 map의 대부분을 차지한다면 `AFL_LLVM_ALLOWLIST`를 사용해 경로/호출자 계측 범위를 제한하세요.
- 비순환 경로가 지나치게 많은 함수는 AFL++가 건너뛸 수 있습니다. 컴파일 중 경고가 나타나면 allowlist를 설정하거나 덜 엄격한 level을 사용해야 한다는 신호입니다.
- Caller + path coverage는 caller depth를 하나만 지원합니다. 더 깊은 context stack과 함께 사용하지 마세요.
- Path ID는 LLVM 주요 버전 간에 달라질 수 있습니다. 캠페인 동안 toolchain을 고정하고, 빌드마다 feature ID가 동일하다고 가정해 PATH 기반 corpus를 동기화하지 마세요.
- 이 피드백은 `CMPLOG`를 보완합니다. 비교 추적은 **guard를 통과하는 값이 무엇인지** 해결하고, path/caller 피드백은 **어떤 경로와 분기 조합이 해당 지점에 도달했는지** 보존합니다.

## Stateful Fuzzing: 시퀀스가 시드다

**프로토콜**, **인증된 워크플로**, **다단계 parser**에서는 흥미로운 단위가 단일 blob이 아니라 **메시지 시퀀스**인 경우가 많습니다. 전체 transcript를 하나의 파일로 이어 붙여 무작위로 변이하면 대개 비효율적입니다. fuzzer가 모든 단계를 똑같이 변이하는데, 취약한 상태에 도달하는 후반 메시지만 변이하면 되는 경우가 많기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 방법은 **시퀀스 자체를 시드로 취급**하고, **관찰 가능한 상태**(응답 코드, 프로토콜 상태, parser 단계, 반환된 객체 유형)를 추가 피드백으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **유효한 prefix 메시지**는 그대로 유지하고, 상태 **전환을 유도하는** 메시지에 변이를 집중하세요.
- 다음 단계가 이전 응답에 의존한다면 식별자와 서버가 생성한 값을 캐시하세요.
- 직렬화된 transcript 전체를 불투명한 blob으로 변이하기보다 메시지 단위로 변이/스플라이싱하는 방식을 우선하세요.
- 프로토콜에서 의미 있는 응답 코드를 제공한다면, 이를 **저비용 상태 오라클**로 사용해 더 깊이 진행되는 시퀀스의 우선순위를 높이세요.

인증이 필요한 버그, 숨겨진 전환, “handshake 이후에만 발생하는” parser 버그가 일반적인 파일 기반 fuzzing에서 자주 누락되는 이유도 같습니다. fuzzer는 구조뿐 아니라 **순서, 상태, 종속성**도 보존해야 합니다.<sup>[[4]](#references)</sup>

### Android Binder: 다중 클라이언트 driver fuzzing

edge coverage가 높아도 IPC-driver 버그를 놓칠 수 있습니다. coverage는 **객체 소유권, 참조 횟수, 대기 중인 메시지, 정리 순서 또는 스레드 인터리빙**을 설명하지 않기 때문입니다. [Android Binder IPC 내부 구조](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 페이지에서는 driver 객체 모델을 다룹니다. 여기서는 fuzzer harness에 초점을 맞춥니다. Android Binder는 유용한 모델입니다. fuzzer가 여러 프로세스를 필요한 순서로 동일한 kernel 객체에 접근시키지 못한다면, 할당 경로와 해제 경로를 모두 실행하는 것만으로는 충분하지 않습니다.<sup>[[15]](#references)</sup>

#### 고립된 `ioctl` 버퍼가 아니라 프로토콜을 모델링하기

테스트 케이스를 **클라이언트 ID + 연산 + 구조화된 인수**로 이루어진 순서 있는 grammar로 표현하세요. Binder LKL fuzzer는 protobuf와 `libprotobuf-mutator`를 사용하며, 영구적인 context-manager 클라이언트 하나와 일반 클라이언트 두 개를 둡니다. 그런 다음 의미 기반 harness가 무작위 바이트 변이로 파괴될 관계를 보존합니다.<sup>[[15]](#references)</sup>

- 이전 연산에서 반환된 값을 캐시하세요. 예를 들어 `BC_FREE_BUFFER`는 이전 `ioctl`에서 반환된 transaction-buffer 포인터를 재사용해야 합니다.
- 유효한 기본 reply를 생성해 동기 transaction이 완료되고 이후 연산에도 도달할 수 있게 하세요.
- 자체 전송이나 동일한 대상에 대한 다중 대기 중 transaction처럼 불가능한 상태 전환은 거부하세요.
- singleton bootstrap 상태는 입력별 reset 대상에서 제외하세요. Binder는 부팅당 `BINDER_SET_CONTEXT_MGR` 등록을 하나만 허용하므로, 해당 클라이언트를 반복해서 제거하고 다시 만들면 이후 입력이 무효가 됩니다.

유용한 수명 경합 템플릿은 한 클라이언트가 객체를 전송하게 하고, 스레드 또는 프로세스 정리를 시작한 다음, 수신 클라이언트가 동시에 transaction 버퍼를 해제하도록 하는 것입니다. CVE-2020-0423 사례에서는 `BINDER_TYPE_WEAK_BINDER` 전송 후 `BINDER_THREAD_EXIT`와 `BC_FREE_BUFFER`가 경합하면, 종료 중인 스레드의 정리 경로가 계속 사용 중인 내장 `binder_work`가 해제될 수 있었습니다.<sup>[[15]](#references)</sup>

#### userspace kernel에서 제어된 인터리빙 재도입하기

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)는 실제 kernel 코드를 userspace harness에 연결하고 `lkl_syscall`을 통해 syscall 인터페이스를 제공합니다. 덕분에 하나의 프로세스에서 protobuf 상태, coverage, KASAN을 쉽게 조율할 수 있습니다. 그러나 LKL은 일반적으로 다른 kernel thread가 syscall을 중단하지 않도록 실행합니다. 경합 캠페인에서는 선택한 lock/unlock 및 수명 경계 주변에 `schedule()` 지점을 삽입한 다음, 각 yield에서 다음 클라이언트를 harness가 무작위로 선택하게 하세요. 각 지점은 스케줄링 탐색 공간을 늘리므로 꼭 필요한 곳에만 두세요. 연구자들이 설명한 무작위 scheduler는 upstream Binder fuzzer에 **포함되어 있지 않습니다**.<sup>[[15]](#references)</sup>

#### 직렬화된 회귀 시드 빌드 및 재현하기

upstream harness는 호환되는 `libprotobuf-mutator` 버전을 고정하고, `LKL_FUZZING=1`로 LKL fuzzing 계측과 KASAN을 활성화하며, Binder용으로 `MMU=1`로 `CONFIG_MMU`를 활성화합니다.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

의도적으로 취약한 리비전을 체크아웃하거나 업스트림에 문서화된 롤백 패치를 적용한 후에는, 직렬화된 시드로 애드혹 C proof of concept에서 상태 전이를 재구성하지 않고도 전체 멀티클라이언트 상태 전이를 재현할 수 있습니다:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

결과적으로 발생한 KASAN use-after-free는 seed가 취약한 수명 경로에 도달했다는 확인으로 간주하세요. 이것만으로는 커널 코드 실행이나 권한 상승에 필요한 후속 primitive가 입증되지는 않습니다.<sup>[[16]](#references)</sup>

## 단일 머신 다양성 트릭 (Jackalope 방식)

**생성형 새로움**과 **coverage 재사용**을 결합하는 실용적인 방법은 지속적으로 실행되는 서버를 대상으로 수명이 짧은 worker를 **재시작**하는 것입니다. 각 worker는 비어 있는 corpus에서 시작해 `T`초 후 동기화하고, 결합된 corpus로 다시 `T`초 동안 실행한 다음, 다시 동기화하고 종료합니다. 이렇게 하면 누적된 coverage를 활용하면서도 각 세대마다 **새로운 구조**를 만들어 낼 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty`는 각 세대마다 **새 corpus**를 강제합니다.
- `-server_update_interval T`는 **지연된 동기화**(먼저 새 입력을 찾고, 나중에 재사용)를 근사합니다.
- grammar fuzzing 모드에서는 기본적으로 **초기 서버 동기화를 건너뜁니다**(`-skip_initial_server_sync` 불필요).
- 최적의 `T`는 **target에 따라 다릅니다**. worker가 대부분의 “쉬운” coverage를 찾은 뒤 전환하는 것이 대체로 효과적입니다.

## Snapshot Fuzzing: 하네싱하기 어려운 target

테스트하려는 코드에 도달하기까지 **큰 초기화 비용**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화)이 드는 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비된 프로세스나 VM의 상태를 캡처하고, 각 테스트 케이스를 target의 입력 경로에 주입한 다음, crash/timeout까지 실행하고 snapshot을 복원합니다. 이렇게 하면 초기화나 프로토콜 접두부를 반복할 필요가 없어 **network service**, **firmware**, **인증 후 공격 표면**, **binary-only target**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 관심 있는 상태가 준비될 때까지 target을 실행합니다.
2. 그 시점의 **메모리 + 레지스터**를 snapshot으로 저장합니다.
3. 각 테스트 케이스에서 변형된 입력을 관련 guest/process buffer에 직접 씁니다.
4. crash/timeout/reset까지 실행합니다.
5. snapshot을 복원합니다. VM target의 경우 지원되면 **변경된 페이지**만 복원한 다음 반복합니다.

`recv`/`read` 이후나 패킷 역직렬화 지점처럼, 가능한 한 첫 번째 비용이 큰 파싱/디스패치 단계 가까이에 snapshot을 배치하고 target이 사용하는 입력 buffer를 기록합니다. 이는 반복 작업을 피하기 위해 snapshot을 입력 처리 단계 안쪽으로 이동하는 adaptive-placement 원칙을 따릅니다.<sup>[[11]](#references)</sup>

### 프로토콜 상태를 위한 증분 snapshot

고정 snapshot은 초기화 비용을 줄이지만, 여러 개의 유효한 메시지가 필요한 전이를 그 자체로 탐색하지는 않습니다. LibAFL-Qemu harness는 프로토콜 상태 필드에 대한 쓰기를 감시하고 상태가 바뀌면 새 snapshot을 저장할 수 있습니다. [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful)는 `tcpcb.t_state`를 감시하고, 상태와 응답 플래그를 해시해 snapshot 중복을 제거하며, 상위 snapshot을 기준으로 변경된 페이지를 저장합니다. 다음 구조화된 메시지를 변형하기 전에 상위 snapshot 체인을 통해 선택한 snapshot을 복원합니다. testcase에는 `SnapshotId`와 생성된 입력 바이트(`gen_bytes`)가 포함되고, snapshot manager는 재생에 필요한 상위 관계를 추적합니다.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu의 user-mode `SnapshotModule`은 매핑과 target 메모리를 저장하지만 CPU 레지스터는 저장하지 않으므로, 필요하면 별도로 보존해야 합니다. 설명된 manager는 하나의 root snapshot 트리만 지원하며 worker 간에 snapshot ID를 공유할 수 없습니다. 또한 multi-snapshot 모드에서는 QASAN shadow state를 직접 재사용할 수 없습니다. 오프라인 triage를 위해 별도의 계측된 프로세스에서 입력 체인을 재구성합니다. `AsanHostModule`과 `DrCovModule`을 사용할 때 `fuzzer.evaluate_input`은 필요한 `pre_exec`/`post_exec` callback을 실행하지만, `qemu.run`만으로는 실행되지 않습니다.<sup>[[27]](#references)[[28]](#references)</sup>

### 논리적 링 버퍼 overread 감지

버퍼의 *유효 데이터 개수*를 넘어 읽더라도 host allocation 내부에 머물 수 있어 일반 ASAN으로는 감지되지 않을 수 있습니다. [libslirp urgent-data 예제](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)는 unsigned byte count underflow도 일으킵니다. 소스 코드가 있다면 signed/unsigned integer-overflow instrumentation으로 이 부작용을 감지할 수 있습니다. 보고를 억제하기 전에 의도적인 TCP sequence-number wrap과 구별하세요. 더 강력한 oracle로는 custom ring allocation을 poison 처리하고, 내부 allocator가 진행됨에 따라 유효한 범위만 unpoison 처리한 뒤, 해제된 범위를 다시 poison 처리하는 방법이 제안되어 있습니다. LibAFL-Qemu는 소스 계측이 비현실적인 target을 위해 ASAN poisoning API를 제공합니다.<sup>[[27]](#references)</sup>

## MAccConc를 이용한 Linux Kernel Race 탐색

[MAccConc](https://github.com/googleprojectzero/MAccConc)는 타이밍에 민감한 Linux-kernel race를 반복 가능한 메모리 접근 스케줄로 변환합니다. 두 context의 **A-B-A** 실행을 자동으로 열거하거나, 분석가가 terminal UI/GUI에서 순서 제약을 지정할 수 있습니다. 완전한 concurrency fuzzer라기보다는 실험적인 연구 도구입니다. 현재 LLVM 23 이상과 프로젝트에서 패치한 kernel이 필요하고, command-line 도구는 테스트 thread 두 개를 지원하며, 제안된 userspace fuzzing 계층은 구현되지 않았습니다.<sup>[[17]](#references)[[18]](#references)</sup>

### Context 간 통신 지점 수집

KASAN outline callback과 패치된 KCOV memory-record 지원을 사용해 계측된 kernel을 빌드합니다. 프로젝트 README는 call stack을 사용할 수 있도록 sibling-call optimization을 비활성화하는 것도 권장합니다.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode(`asan-instrumentation-with-call-threshold=0`)는 instrumented access를 helper call로 변환합니다. MAccConc 커널 패치는 연속된 access가 병합되지 않도록 `asan-opt-same-temp`를 비활성화합니다. 전역 변수 race도 감지해야 한다면 `asan-opt-globals` 최적화도 비활성화하세요. KCOV는 생성된 record를 userspace로 전달합니다. 서로 다른 execution context의 access를 비교하고, byte 범위가 겹치며 적어도 한쪽이 write하는 쌍을 유지합니다. lifetime 전환도 후보가 되도록 `kfree()`를 write로 모델링합니다.<sup>[[17]](#references)</sup>

packet processing이나 RCU callback처럼 시작한 task의 범위를 벗어나는 작업의 경우, subsystem은 KCOV remote-coverage handle을 전파해야 합니다. Upstream remote KCOV는 opt-in 방식이며 임의의 background work에 자동으로 적용되지 않으므로, 전파가 누락되면 실제 interaction을 감지하지 못할 수 있습니다.<sup>[[17]](#references)[[19]](#references)</sup>

### 매 실행에서 동일한 동적 access 식별

할당 후 바뀔 수 있는 구체적인 heap 주소나, `memcpy()` 및 `spin_lock()` 같은 helper 내부에서 모호한 instruction 주소만을 기준으로 replay하지 마세요. MAccConc는 **count-augmented stack trace**를 사용합니다. 각 frame은 callee와 caller 내 호출 횟수를 식별하고, 마지막 요소는 memory-access instruction을 식별합니다. SanitizerCoverage의 function-entry/exit record를 통해 userspace는 이 동적 식별자를 재구성할 수 있으며, 이 식별자는 주소 변경이나 무관한 control-flow 노이즈에도 안정적으로 유지됩니다.<sup>[[17]](#references)</sup>

### 후보 쌍을 강제 schedule로 변환

패치된 `KCOV_SET_DI` ioctl은 count-augmented access 식별자를 shared-flag 동작과 연결합니다.<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 선택한 access 직전에 flag *N*을 설정합니다. |
| `DI_STACK_WAIT` | 선택한 access 직전에 flag *N*이 설정될 때까지 또는 설정된 제한 시간이 만료될 때까지 spin합니다. |
| `DI_STACK_WAKE_POST` | 선택한 access 직후에 flag *N*을 설정합니다. |

부분적인 **A-happens-before-B** 제약을 적용하려면, A에는 `DI_STACK_WAKE_POST`를, B에는 같은 flag를 사용하는 `DI_STACK_WAIT`를 지정합니다. 두 context의 schedule을 완전히 지정하려면 B를 차단한 상태로 시작한 뒤, A가 첫 번째 transfer 지점에서 B를 깨우고 대기하게 합니다. 다음 transfer에서는 B가 반대 동작을 수행합니다. 후자는 deterministic context switching처럼 동작하며, 자동 A-B-A explorer가 사용하는 방식입니다.<sup>[[17]](#references)</sup>

최소한의 campaign은 네 개의 hook(`test_setup`, 두 thread function, `test_end`)을 포함하는 test case를 shared library로 compile하고, 제약 없는 trace를 수집한 다음 A-B-A 후보를 열거하거나 의심스러운 access 주변에 수동 제약을 추가하는 것입니다.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

타임아웃은 성공적인 순서 재배치와 별도로 해석하세요. 잠금이나 초기화/게시 의존성 때문에 두 번째 컨텍스트가 injection 지점에 도달하지 못해 요청한 순서가 불가능할 수 있습니다. KASAN의 사각지대도 염두에 두세요. 직접적인 스택 접근은 범위를 벗어날 가능성이 없는 한 보통 후킹되지 않고, 기본 최적화 설정에서는 전역 변수가 제외되며, 현재 컴파일러는 ASAN과 TSAN 후크를 동시에 생성할 수 없습니다. 마지막으로, 프로토타입은 guest가 panic을 일으키면 KCOV 버퍼를 잃으므로 독립적인 crash console/oracle을 보존하세요.<sup>[[17]](#references)</sup>

향후 concurrency-guided fuzzing을 위해 입력별 또는 syscall별 메모리 접근 요약을 기록하고, 컨텍스트 간 통신 지점을 형성할 수 있는 연산을 짝지은 다음 해당 조합만 탐색하세요. VM snapshot은 전역 상태와 주소를 안정화합니다. snapshot이 없으면 할당 지점 메타데이터를 사용해 실행 간 객체를 추상화할 수 있습니다. 이는 제안된 확장 기능이지, 현재 MAccConc userspace 도구의 기능은 아닙니다.<sup>[[17]](#references)</sup>

## Harness 분석: 얕은 Fuzzer를 조기에 찾기

campaign이 정체되면 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **reachability/coverage 분석**을 사용해 fuzz target에서 정적으로 도달 가능하지만 동적으로는 거의 또는 전혀 커버되지 않는 함수를 찾으세요. 이러한 함수는 보통 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 target에 너무 늦게 또는 너무 일찍 진입합니다.
- seed corpus에 기능군 전체가 빠져 있습니다.
- target에는 하나의 지나치게 큰 “모든 작업을 처리하는” harness 대신 **두 번째 harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일의 워크플로를 사용한다면 Fuzz Introspector를 통해 정적 reachability와 runtime coverage를 비교하고, 정해진 시간 동안 실행하거나 공개 corpus를 사용해 보고서를 생성할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

보고서를 사용해 테스트되지 않은 parser 경로에 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나의 monolithic harness를 더 작은 entrypoint로 분리할지 결정하세요.

## Graph-First Fuzz Target Selection And Mutation Triage

**static-analysis findings**, **mutation-testing survivors**, **coverage reports**가 이미 있다면, 이를 서로 독립된 목록으로 triage하지 마세요. 먼저 **call graph**를 만들고, 노드에 **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, 외부 finding을 표시한 다음 graph를 바탕으로 질문하세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 어떤 high-complexity 함수가 untrusted input에서 도달 가능한가요?
- 어떤 mutation survivor가 parser/handler에서 security-critical code로 이어지는 경로에 있나요?
- 어떤 함수가 이례적으로 큰 **blast radius**를 가진 architectural choke point인가요?

이 방법은 일반적으로 "가장 낮은 coverage"만 보는 것보다 더 나은 fuzz target을 찾아냅니다. **high complexity**와 확인된 **external reachability**를 가진 parser/decoder는, coverage가 낮더라도 attacker-controlled path가 없는 고립된 internal helper보다 더 적합한 harness 후보입니다.

### Practical triage workflow

1. Codebase에서 **code graph**를 만들고 함수별 complexity/branch 지표를 추출합니다.
2. attacker-controlled input을 받는 **entrypoint**를 열거합니다. 예: request handler, decoder, importer, protocol parser, CLI/file reader.
3. 해당 entrypoint에서 후보 함수까지 **path query**를 실행해, 도달 가능한 attack surface와 dead/internal-only code를 구분합니다.
4. 다음 조건을 함께 만족하는 노드의 우선순위를 높입니다.
   - 높은 **cyclomatic complexity**
   - untrusted input에서 도달 가능하다는 확인
   - 높은 **blast radius** 또는 다수의 downstream dependent
   - **SARIF** finding, audit note, mutation survivor 등 이를 뒷받침하는 근거
5. 점수가 높은 노드부터, 특히 hex/Base64/IP/message decoder와 같은 **parser/codec**를 대상으로 집중된 harness를 작성합니다.

### Mutation survivors: equivalent vs actionable

Mutation testing은 종종 잡음이 많은 survivor 목록을 만듭니다. 모든 survivor를 security gap으로 취급하기 전에 graph를 사용해 다음을 확인하세요.

- Mutated function이 attacker-controlled entrypoint에서 도달 가능한가요?
- 모든 call path가 mutated check보다 더 강한 invariant로 제한되어 있나요?
- 해당 노드가 dead code, formatting-only logic, 또는 high-impact arithmetic/parser path 중 어디에 있나요?

도달할 수 없거나 구조적으로 제약된 survivor는 **equivalent mutant**인 경우가 많습니다. **reachable** 상태로 남아 있고 **boundary condition**, **overflow/carry path**, 또는 **security-critical arithmetic/parsing**을 다루는 survivor는 다음 항목으로 승격해야 합니다.

- 새 fuzz harness
- 직접적인 property/invariant test
- 목표를 좁힌 edge-case vector

### Correlate external findings onto the graph

SAST pipeline이 **SARIF**를 내보내는 경우, **file + line range**를 기준으로 finding을 graph node에 매핑하고 graph를 사용해 영향을 확장하세요.<sup>[[6]](#references)</sup>

- 표시된 함수의 **blast radius**를 계산합니다.
- finding이 entrypoint에서 시작하는 경로에 있는지 확인합니다.
- 인접한 finding 중 동일한 choke point로 합쳐지는 항목을 그룹화합니다.

특정 함수에 fuzzing 시간을 쓸지 결정할 때 유용합니다. **reachable**하고 **complex**하며 이미 **SAST hit**가 있는 노드는, attacker path가 없는 단순히 complex한 노드보다 더 나은 target인 경우가 많습니다.

Trailmark를 사용한 workflow 예시입니다.<sup>[[6]](#references)</sup>

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

중요한 방법론은 **복잡도 x 노출도 x 영향도**의 교차점입니다. 그래프를 사용해 예상 보안 가치가 가장 높은 fuzz 대상들을 선정한 다음, 변이 후에도 살아남은 입력을 바탕으로 하네스가 어떤 경계와 불변 조건을 집중적으로 테스트해야 하는지 결정하세요.<sup>[[5]](#references)</sup>

## 암호화 키 인코딩의 Differential fuzzing

유효한 직렬화 키 또는 표준 테스트 벡터에서 시작하세요. import 및 연산 경로에 도달하는 데 필요한 길이와 구조는 유지하면서 인코딩된 필드를 변이한 다음, 동일한 바이트를 서로 독립적인 구현에 전달하세요. 처리 여부와 오류를 비교하세요. 서명 및 암호문이 무작위화되는 경우에는 바이트 단위 비교가 아니라 정확성 오라클이 필요합니다. 서명을 검증하거나 캡슐화/역캡슐화 왕복 과정에서 공유 비밀을 비교하세요. 테스트 벡터는 알려진 사례에 대한 적합성을 확인하고, differential mutation은 그 범위를 넘어 잘못된 인코딩을 탐색합니다.<sup>[[23]](#references)[[26]](#references)</sup>

다음 키 형식에는 형식별 오라클을 사용하세요.<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA 확장 서명 키:** 키를 파싱 가능한 상태로 유지하면서 packed `s1` 또는 `s2` 계수를 `[-η, η]` 범위 밖으로 변경하세요. import 또는 서명 생성에서 이를 거부하는지, 생성된 서명이 검증되는지 확인하세요. FIPS 204는 추가적인 개인 키 검사를 의무화하지 않으므로, 허용 여부의 차이만으로 표준 위반이라고 볼 수는 없습니다. [조건부 leakage 메커니즘](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)을 참조하세요.
- **ML-KEM 키 쌍:** 필수 캡슐화 키 및 역캡슐화 입력 검사를, import된 키 쌍에 대해 선택적으로 수행하는 pairwise-consistency 검사(PCT)와 구분하세요. 공개 키로 캡슐화하고 개인 키로 역캡슐화한 다음 공유 비밀을 비교하세요. 개별 키가 입력 검사를 통과하더라도 불일치가 발생하면 암호화된 통신이 중단될 수 있습니다. API가 연산 중 입력을 검증하는지 별도 호출을 통해 검증하는지 확인하세요. libcrux는 `validate_public_key(pk)`와 `validate_private_key(sk, ct)`를 제공하지만, 이들은 PCT를 대체하지 않습니다.
- **XMSS/XMSSMT 원시 키:** 메모리 내 키를 사용한 연산만 테스트하지 말고, 매개변수 세트 전반에 걸쳐 직렬화된 **서명 및 검증 키**의 왕복 변환을 테스트하세요. XMSS와 XMSSMT는 서로 다른 4바이트 OID 네임스페이스를 사용하므로, XMSS를 먼저 시도하는 OID 전용 파서는 OID가 충돌하는 XMSSMT 키를 잘못 분류해 import를 거부할 수 있습니다. 보고된 RustCrypto 파서는 서명 위조가 아닌 상호 운용성/가용성 실패를 보여줍니다.

## gosentry를 사용한 Go Fuzzing: 더 강력한 엔진, 타입 지정 입력 및 Differential 검사

Go 대상에 이미 기본 `testing.F` 하네스가 있다면, 실용적인 업그레이드 방법은 동일한 하네스를 [gosentry](https://github.com/trailofbits/gosentry)로 실행하는 것입니다. gosentry는 `go test -fuzz`를 유지하면서 백엔드를 **LibAFL**로 교체하는 포크된 Go 툴체인입니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

이는 native Go fuzzer가 **hard comparisons**, **typed inputs** 또는 **parser-heavy formats**에서 멈출 때 유용합니다. 방법론은 동일합니다.

- 시드에는 계속 `f.Add(...)`를, 콜백에는 `f.Fuzz(...)`를 사용합니다.
- 같은 harness를 재사용하되, 기본 toolchain 대신 gosentry의 `go` 바이너리로 실행합니다.
- 결과 캠페인은 일반적인 coverage-guided 실행으로 취급하되, LibAFL의 스케줄링/변이와 향상된 주변 detector를 활용합니다.

### 조용한 실패를 fuzz finding으로 전환하기

Go 평가에서 자주 발생하는 문제는 위험한 동작이 기본적으로 **crash를 일으키지 않는다는 것**입니다. gosentry를 사용하면 여러 유형의 “나쁘지만 조용한” 상태를 finding으로 전환할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용하면 선택한 logging/error 경로가 crash처럼 동작합니다. (그렇지 않으면 로그만 남기고 계속 실행하는 `log.Fatal` 스타일의 코드 경로에 유용합니다.)
- `--catch-races=true`를 사용하면 새로 발견된 queue 항목을 Go race detector로 다시 실행합니다.
- `--catch-leaks=true`를 사용하면 새 queue 항목을 `goleak`으로 다시 실행하고 goroutine leak이 발생하면 중단합니다.
- LibAFL의 hang 처리 기능을 사용하면 **무한 루프 / 매우 느린 입력**이 timeout으로 사라지지 않고 fuzz finding으로 남습니다.
- 기본적으로 산술 오버플로를 검사하며, go-panikint 스타일의 instrumentation을 통해 선택적으로 truncation도 검사할 수 있습니다.

이는 보안 영향이 메모리 손상이 아니라 **panic 없는 parser 실패**, **concurrency bug** 또는 **DoS만 유발하는 hang**인 대상에서 특히 유용합니다.

### typed Go API를 위한 struct-aware fuzzing

Native Go fuzzing은 주로 `[]byte`, `string`, 숫자 같은 scalar를 대상으로 합니다. 테스트 대상 코드가 typed object를 받는 경우, gosentry는 내부적으로 계속 바이트를 변이하면서 **composite value**(struct, slice, array, pointer)를 직접 fuzz할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

가짜 wire format을 만들어 fuzzing에만 사용하는 경우, harness 전용 파싱 코드가 로직 버그를 가릴 수 있습니다. Differential 또는 grammar-based 캠페인에서는 harness 입력을 단일 `[]byte` 또는 `string`으로 유지하고, 대신 callback 내부에서 파싱하세요.

### 파서 및 프로토콜 입력을 위한 grammar-based fuzzing

파서, 형식 및 입력 언어의 경우 gosentry는 LibAFL 기반으로 **Nautilus grammar fuzzing**을 실행할 수 있습니다. grammar는 production rule의 JSON 배열이며, harness는 보통 단일 `[]byte` 또는 `string` 인수를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

방법론 참고 사항:

- 바이트 수준 변이로 생성한 입력이 대부분 초기 구문 검사에서 걸러진다면 grammar mode를 사용합니다.
- 전체 명세를 모델링하는 대신, 언어/프로토콜의 **보안 관련 하위 집합**에 초점을 맞춰 grammar를 구성합니다.
- 터미널/비단말에 큰 경계값을 사용해 정수, 길이, 상태 머신의 경계 조건을 테스트합니다.
- Grammar mode는 입력의 문법 유효성을 유지하지만, 대상은 여전히 **바이트/문자열**을 받으므로 파싱과 의미 검사는 하네스가 적용된 코드 안에서 수행됩니다.

### Differential fuzzing: 크래시만 비교하지 말고 구현체를 비교하기

Go 생태계에서 효과적인 패턴은 **grammar 기반 differential fuzzing**입니다. 유효한 구조화 입력을 생성해 두 개의 파서, 클라이언트 또는 상태 전이 엔진에 전달합니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

다음을 findings로 취급합니다.

- 한 구현은 panic이 발생하지만 다른 구현은 정상적으로 거부함
- 입력을 수락하거나 거부하는 결과가 서로 다름
- parse tree 또는 디코딩된 객체가 서로 다름
- state transition, nonce, balance 또는 state root가 서로 다름

이는 순수한 crash fuzzing으로는 놓치기 쉬운 **consensus mismatch**, **parser ambiguity**, **spec과 구현 간의 괴리**를 찾는 실용적인 방법입니다.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### coverage 보고에 campaign corpus 재사용하기

campaign이 끝난 후 저장된 queue corpus를 재생해, 별도의 corpus를 수동으로 내보내지 않고 Go coverage 보고서를 생성합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

같은 패키지에서 동일한 `-fuzz` 대상을 지정해 명령을 실행해야 gosentry가 올바른 캐시된 캠페인 상태를 찾습니다.

## References

- [1] [변이 기반 문법 퍼징](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ 퍼징 심층 분석](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [5년 후의 AFLNet: 커버리지 유도 프로토콜 퍼징에 관하여](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark, 코드를 그래프로 변환하다](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go 퍼징에는 도구 모음의 절반이 빠져 있었습니다. 이를 해결하기 위해 툴체인을 포크했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 스냅샷을 활용한 상태 기반 네트워크 프로토콜용 고속 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [문법이 없어도 문제없다: 시스템 호출 설명 없이 Linux 커널을 퍼징하는 방법](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: 적응형 및 변경 가능한 스냅샷을 활용한 효율적인 퍼징](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM 계측: 경로 및 호출자 커버리지](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [예측적 문맥 민감 퍼징](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder 퍼징](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 빌드 및 회귀 시드 문서](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: 제어된 메모리 접근 인터리빙으로 Linux 커널 경쟁 조건 탐색](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: 퍼징을 위한 코드 커버리지](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 확장 파일명 구문](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 권고문: CFITSIO 2025년 4분기](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO 확장 파일명 구문 퍼징: 메모리 안전성 취약점 16건과 Codex 지원 분류](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [암호학을 위한 차등 퍼징](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: 모듈 격자 기반 키 캡슐화 메커니즘 표준](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID 파싱 버그 - RustCrypto 이슈 #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [양자 내성 암호 구현 현황](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [스냅샷으로 CVE-2026-9539를 찾아내기까지](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
