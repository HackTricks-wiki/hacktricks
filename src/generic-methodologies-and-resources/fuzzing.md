# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage와 Semantics

**mutational grammar fuzzing**에서는 **grammar-valid** 상태를 유지하면서 입력을 변형합니다. Coverage-guided 모드에서는 **새로운 coverage**를 유발하는 샘플만 corpus seed로 저장합니다. **언어 대상**(parser, interpreter, engine)의 경우, 한 construct의 출력이 다른 construct의 입력이 되는 **semantic/dataflow chain**이 필요한 버그를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

**실패 유형:** fuzzer가 `document()`와 `generate-id()`(또는 유사한 primitive)를 각각 실행하는 seed를 찾지만, **연결된 dataflow를 보존하지 못해** “버그에 더 가까운” 샘플이 coverage를 추가하지 않는다는 이유로 버려집니다. **3개 이상의 종속 단계**가 있는 경우, 무작위 재조합은 비용이 많이 들고 coverage feedback도 검색을 유도하지 못합니다.<sup>[[1]](#references)</sup>

**시사점:** 종속성이 많은 grammar에서는 **mutational 단계와 generative 단계를 혼합**하거나, generation이 coverage만이 아니라 **function chaining** 패턴을 우선하도록 고려하세요.<sup>[[1]](#references)</sup>

## Corpus 다양성의 함정

Coverage-guided mutation은 **greedy** 방식입니다. 새로운 coverage를 보이는 샘플을 즉시 저장하며, 이때 변경되지 않은 큰 영역이 그대로 남는 경우가 많습니다. 시간이 지나면서 corpus에 구조적 다양성이 낮은 **거의 중복된 샘플**이 쌓입니다. 지나치게 공격적인 minimization은 유용한 context를 제거할 수 있으므로, **최소 token 임계값에 도달하면 중단하는** **grammar-aware minimization**이 실용적인 절충안입니다. 이렇게 하면 noise를 줄이면서도 mutation에 적합한 주변 구조를 충분히 유지할 수 있습니다.<sup>[[1]](#references)</sup>

mutational fuzzing에서 실용적인 corpus 원칙은 다음과 같습니다. 큰 규모의 거의 중복된 샘플 더미보다 **coverage를 극대화하는, 구조적으로 서로 다른 소수의 seed를 우선하세요**. 일반적으로 다음을 의미합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- **실제 샘플**(공개 corpus, crawling, 캡처한 traffic, 대상 생태계의 파일 모음)에서 시작합니다.
- 모든 유효한 샘플을 보관하는 대신 **coverage 기반 corpus minimization**으로 추려냅니다.
- Mutation이 의미 있는 필드에 적용되도록 seed를 **충분히 작게** 유지합니다. 무관한 byte에 대부분의 cycle을 쓰지 않도록 합니다.
- Harness나 instrumentation을 크게 변경한 뒤에는 corpus minimization을 다시 실행합니다. 도달 가능성이 바뀌면 “최적의” corpus도 달라지기 때문입니다.

## Magic Value를 위한 Comparison-Aware Mutation

fuzzer가 정체되는 흔한 이유는 syntax가 아니라 **엄격한 비교**입니다. 예를 들어 magic byte, length 검사, enum 문자열, checksum 또는 `memcmp`, switch table, 연쇄 비교문으로 보호되는 parser dispatch 값이 있습니다. 순수한 무작위 mutation은 이 값을 byte 단위로 맞히려다 cycle을 낭비합니다.

이런 대상에는 **comparison tracing**(예: AFL++ `CMPLOG` / Redqueen 스타일 workflow)을 사용하세요. 이를 통해 fuzzer가 실패한 비교의 피연산자를 관찰하고, 비교를 통과하는 값에 mutation을 집중할 수 있습니다.<sup>[[3]](#references)</sup>

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

- 대상이 **파일 시그니처**, **프로토콜 동사**, **타입 태그** 또는 **버전에 따라 달라지는 기능 비트** 뒤에 깊은 로직을 숨기는 경우 특히 유용합니다.
- 실제 샘플, 프로토콜 사양 또는 디버그 로그에서 추출한 **사전**과 함께 사용하세요. 문법 토큰, 청크 이름, 동사, 구분자가 포함된 작은 사전이 방대한 범용 단어 목록보다 더 유용한 경우가 많습니다.
- 대상이 여러 검사를 순차적으로 수행한다면, 가장 앞에 있는 “매직” 비교부터 통과시킨 다음 결과 코퍼스를 다시 최소화하여 이후 단계가 이미 유효한 접두부에서 시작하도록 하세요.

## 파일명 언어를 숨기는 파일 API 퍼징

`filename`, `path` 또는 `URL`이라는 이름의 매개변수는 단순한 파일 조회가 아니라 인터프리터의 진입점일 수 있습니다. 예를 들어 CFITSIO Extended Filename Syntax (EFS)는 열린 객체를 반환하기 전에 대괄호로 묶인 선택자, 행/픽셀 표현식, 계산된 열, 히스토그램 및 변환을 평가합니다. 일부 형식은 임시 복사본도 만듭니다. 공격 표면을 매핑할 때 각 열기/가져오기 API를 **리터럴 경로** 또는 **해석되는 경로**로 분류한 다음, 애플리케이션이 실제로 호출하는 프로덕션 진입점을 퍼징하세요.<sup>[[20]](#references)[[22]](#references)</sup>

그 결과 얻을 수 있는 SSRF, 파일 복사 및 프로토콜 핸들러 원시 기능과 더 안전한 리터럴 경로 API는 [SSRF/파일 원시 기능으로서의 파일명 미니 언어](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs)를 참조하세요.<sup>[[20]](#references)</sup>

### 백업 객체와 퍼징 대상 프로그램을 분리하기

문법이 파일명 접미부에 있다면, 참조된 파일 바이트만 변형해서는 파서를 놓치게 됩니다. 대신 작은 harness에서 테스트 케이스 하나를 문자열로 읽어 해석형 열기 API에 전달할 수 있습니다. CFITSIO 캠페인은 `fits_open_file()`을 읽기 전용 모드로 호출해 대부분의 EFS 파서와 평가기에 도달했습니다. 기본 경로를 계속 손상시키는 대신 선택자/표현식 언어에 변형을 집중할 수 있도록 유효한 백업 파일을 별도로 준비하세요.<sup>[[22]](#references)</sup>

각기 다른 문법 계열에 도달하는 시드로 시작한 다음, 사양과 lexer/parser 소스 모두에서 간결한 사전을 만드세요. 입력이 반복해서 같은 구문 오류 경로에서 실패하며 커버리지가 정체된다면, 무작위 변형 시간을 늘리는 대신 유효한 접두부를 유지하고 구분자, 연산자, 키워드, 함수 이름 및 대표적인 필드 이름을 추가하세요.<sup>[[22]](#references)</sup>

예를 들어 문법 사전을 사용해 harness를 실행합니다:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" 하네스 부작용 방지

라이브러리의 읽기 전용 플래그가 테스트케이스에 부작용이 없음을 보장하지는 않습니다. 파일명 문법이 입력을 다시 쓰거나, 출력 파일을 만들거나, 임시 객체를 구체화할 수 있습니다. CFITSIO 캠페인에서는 초기 시드 파일이 삭제되고 파일시스템 곳곳에 예상치 못한 파일이 남아 정리와 격리가 필요했습니다.<sup>[[22]](#references)</sup>

- 각 worker에 폐기 가능한 작업 디렉터리와 전용 임시 디렉터리를 제공합니다.
- 정본 backing file의 복사본을 노출합니다. 대상이 corpus의 유일한 사본을 수정하게 해서는 안 됩니다.
- 원격 backend가 대상이 아닌 한 네트워크 액세스를 비활성화하고, 컨테이너, mount namespace 또는 이에 준하는 sandbox로 쓰기 가능한 경로를 제한합니다.
- 실행 또는 worker 배치마다 디렉터리를 초기화하고, 예상치 못한 파일시스템 변경도 추가 finding으로 취급합니다.

### Crash-to-patch-to-fuzz 루프

수천 개의 artifact가 수천 개의 patch 작업이 되지 않도록 수정 전에 crash를 분류합니다. CFITSIO 평가에서 AFLTriage는 초기 crash 집합을 소수의 근본 원인으로 줄였습니다. 그 결과로 작성된 advisory에는 잘못된 대상 크기 검사, `realloc()` 이후 오래된 포인터, 산술 오류, 안전하지 않은 parser 정리 경로 등 서로 다른 실패가 나와 있습니다.<sup>[[21]](#references)[[22]](#references)</sup>

1. 각 cluster를 대표하는 입력을 최소화하고 AddressSanitizer로 재현합니다.
2. 실패한 정확한 메모리 접근, 소스 위치, 할당/해제 이력, 불변 조건을 깨뜨린 parser 상태를 기록합니다.
3. 범위를 좁힌 후보 patch 하나를 적용하고 동일한 coverage 및 sanitizer 계측을 사용해 다시 빌드합니다.
4. 원래 재현 입력과 **cluster에 속한 모든 입력**을 다시 실행합니다. 메모리 안전성 수정으로 오류 경로의 소유권 처리가 깨질 수 있으므로 leak detection도 활성화합니다.
5. 실제 파일로 기능 테스트를 실행한 다음 누적된 queue에서 재개합니다. (또는 바이너리 변경 후 엔진에서 새 output directory가 필요하다면 해당 queue를 다시 가져옵니다.)
6. 반복합니다. 첫 번째 얕은 crash를 제거하면 기존 seed가 더 깊은 parser 상태까지 진행되는 경우가 많습니다.

LLM에 crash 입력, sanitizer 보고서, 하네스, 관련 소스 코드를 제공하면 2단계를 앞당기고 3단계의 초안을 작성하는 데 도움이 될 수 있습니다. 하지만 LLM의 patch는 여전히 신뢰할 수 없는 것으로 취급해야 합니다. 수정 승인 여부는 모델의 설명이 아니라 sanitizer 재실행과 회귀 테스트 기준으로 결정합니다.<sup>[[22]](#references)</sup>

## Edge Coverage로 서로 다른 경로를 구분할 수 없을 때 더 풍부한 피드백 활용하기

일반적인 edge coverage는 같은 helper를 서로 다른 caller를 통해 실행하거나 함수 안에서 서로 다른 branch 조합을 거치는 두 실행을 구분하지 못합니다. 공유 decoder, protocol dispatcher, interpreter helper에서는 edge에 도달한 **경로**가 현재 상태를 결정하므로 이 점이 중요합니다. 모든 calling context를 무분별하게 추적하는 것도 위험합니다. coverage map과 queue가 폭증할 수 있기 때문입니다. 따라서 context-sensitive fuzzing 연구에서는 전체 call graph를 context-sensitive하게 다루기보다 유망한 context만 세분화할 것을 권장합니다.<sup>[[14]](#references)</sup>

최신 AFL++ 빌드는 일반 edge coverage 외에도 **함수별 Ball-Larus 경로 coverage**를 제공합니다. 각 함수의 비순환 경로에 feature를 할당합니다. loop back-edge는 제거되므로 이 피드백은 branch 조합은 구분하지만 **loop 반복 횟수는 구분하지 않습니다**. 완화된 level `1`에서 시작한 다음, 경로 수가 기하급수적으로 증가할 수 있으므로 의심스러운 parser/state-machine 코드에만 더 엄격한 모드를 적용합니다.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

많은 보안상 중요한 위치에서 호출되는 helper의 경우, LTO 모드는 각 함수 경로를 바로 호출 지점과 결합할 수 있습니다:<sup>[[13]](#references)</sup>

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

**캠페인 지침:** 더 풍부한 feedback은 신중하게 적용하고, coverage-map/queue 비용을 모니터링하세요.<sup>[[13]](#references)[[14]](#references)</sup>

- 일반 edge-coverage 인스턴스를 병렬로 실행하세요. 추가 queue/map 비용으로 초당 실행 횟수가 크게 줄어들지 않을 때만 더 풍부한 feedback이 유용합니다.
- 대형 템플릿 중심 라이브러리나 범용 유틸리티 코드가 map의 대부분을 차지한다면 `AFL_LLVM_ALLOWLIST`를 사용해 path/caller instrumentation 범위를 제한하세요.
- 비순환 경로가 지나치게 많은 함수는 AFL++에서 건너뛸 수 있습니다. 컴파일 중 경고가 발생하면 allowlist를 적용하거나 더 낮은 수준을 사용해야 한다는 신호입니다.
- Caller + path coverage는 caller depth를 하나만 지원합니다. 더 깊은 context stack과 함께 사용하지 마세요.
- Path ID는 LLVM 메이저 버전이 달라지면 바뀔 수 있습니다. 캠페인 동안 toolchain을 고정하고, 빌드 간 feature ID가 안정적이라고 가정해 PATH 기반 corpus를 동기화하지 마세요.
- 이 feedback은 `CMPLOG`를 보완합니다. 비교 추적은 guard를 통과하는 **값이 무엇인지** 해결하는 반면, path/caller feedback은 **어떤 경로와 분기 조합으로 해당 지점에 도달했는지** 보존합니다.

## Stateful Fuzzing: 시퀀스가 Seed

**프로토콜**, **인증된 workflow**, **다단계 parser**에서는 관심 대상이 단일 blob이 아니라 **메시지 시퀀스**인 경우가 많습니다. 전체 transcript를 하나의 파일로 이어 붙여 무작위로 변형하는 방식은 대개 비효율적입니다. 취약한 상태에 도달하는 메시지가 나중에 있더라도 fuzzer가 모든 단계를 동일하게 변형하기 때문입니다.<sup>[[4]](#references)</sup>

더 효과적인 방법은 **시퀀스 자체를 seed**로 취급하고, **관찰 가능한 상태**(응답 코드, 프로토콜 상태, parser 단계, 반환된 객체 유형)를 추가 feedback으로 사용하는 것입니다.<sup>[[4]](#references)</sup>

- **유효한 접두 메시지**는 그대로 유지하고 **전이를 유도하는** 메시지에 변형을 집중하세요.
- 다음 단계가 이전 응답에 의존한다면, 식별자와 서버가 생성한 값을 캐시하세요.
- 직렬화된 transcript 전체를 불투명한 blob처럼 변형하기보다 메시지별 변형/이어 붙이기를 사용하세요.
- 프로토콜이 의미 있는 응답 코드를 노출한다면, 이를 **저비용 상태 oracle**로 사용해 더 깊은 단계까지 진행하는 시퀀스에 우선순위를 부여하세요.

인증이 필요한 버그, 숨겨진 전이, “handshake 이후에만 발생하는” parser 버그가 일반적인 파일 방식 fuzzing에서 자주 발견되지 않는 이유도 같습니다. fuzzer는 구조뿐 아니라 **순서, 상태, 종속성**도 보존해야 합니다.<sup>[[4]](#references)</sup>

### Android Binder: 다중 클라이언트 driver fuzzing

높은 edge coverage를 달성하더라도 IPC driver 버그를 놓칠 수 있습니다. coverage는 **객체 소유권, 참조 횟수, 대기 중인 메시지, 정리 순서, thread 간 실행 순서**를 나타내지 않기 때문입니다. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) 페이지에서는 driver 객체 모델을 다루며, 이 예제에서는 fuzzer harness에 초점을 맞춥니다. Android Binder는 유용한 모델입니다. 할당 및 해제 경로 모두에 도달하는 것만으로는 충분하지 않습니다. fuzzer가 필요한 순서로 여러 프로세스가 동일한 kernel 객체에 접근하도록 할 수 있어야 합니다.<sup>[[15]](#references)</sup>

#### 격리된 `ioctl` buffer가 아니라 프로토콜을 모델링하세요

테스트 케이스를 **클라이언트 식별자 + 작업 + 구조화된 인수**로 이루어진 순서 있는 grammar로 표현하세요. Binder LKL fuzzer는 protobuf와 `libprotobuf-mutator`를 사용하며, persistent context-manager 클라이언트 하나와 일반 클라이언트 두 개를 둡니다. 그런 다음 semantic harness가 무작위 byte 변형으로 파괴될 수 있는 관계를 보존합니다.<sup>[[15]](#references)</sup>

- 이전 작업에서 반환된 값을 캐시하세요. 예를 들어 `BC_FREE_BUFFER`는 이전 `ioctl`에서 반환된 transaction-buffer 포인터를 재사용해야 합니다.
- 동기 transaction을 완료하고 이후 작업에 도달할 수 있도록 유효한 기본 응답을 생성하세요.
- 자기 자신에게 보내는 transaction이나 동일한 대상에 대한 여러 대기 중 transaction 등 불가능한 전이는 거부하세요.
- singleton bootstrap 상태는 입력별 reset 범위 밖에 두세요. Binder에서는 부팅당 `BINDER_SET_CONTEXT_MGR` 등록을 하나만 허용하므로, 해당 클라이언트를 반복해서 삭제하고 다시 생성하면 이후 입력이 유효하지 않게 됩니다.

유용한 수명 경합 템플릿은 한 클라이언트가 객체를 전달하게 하고, thread 또는 프로세스 정리를 시작한 다음, 수신 클라이언트가 transaction buffer를 동시에 해제하도록 하는 것입니다. CVE-2020-0423 예제에서는 `BINDER_TYPE_WEAK_BINDER`를 전달한 뒤 `BINDER_THREAD_EXIT`와 `BC_FREE_BUFFER`가 경합하면서, 종료 중인 thread의 정리 경로가 아직 사용 중인 내장 `binder_work`가 해제될 수 있었습니다.<sup>[[15]](#references)</sup>

#### userspace kernel에서 제어된 interleaving 재도입하기

[Linux Kernel Library (LKL)](https://github.com/lkl/linux)는 실제 kernel 코드를 userspace harness에 링크하고, `lkl_syscall`을 통해 syscall 인터페이스를 노출합니다. 덕분에 protobuf 상태, coverage, KASAN을 하나의 프로세스에서 쉽게 조정할 수 있습니다. 하지만 LKL은 일반적으로 다른 kernel thread가 끼어들지 않은 채 syscall을 실행합니다. 경합 테스트를 위해 선택한 lock/unlock 및 수명 경계 주변에 `schedule()` 지점을 삽입한 다음, 각 yield 지점에서 harness가 다음 클라이언트를 무작위로 선택하게 하세요. 각 지점은 스케줄링 탐색 공간을 늘리므로 꼭 필요한 곳에만 적용하세요. 연구자들이 설명한 randomized scheduler는 upstream Binder fuzzer에 포함되어 있지 않습니다.<sup>[[15]](#references)</sup>

#### 직렬화된 회귀 seed 빌드 및 재생하기

upstream harness는 호환되는 `libprotobuf-mutator` 버전을 고정하고, `LKL_FUZZING=1`로 LKL fuzzing instrumentation과 KASAN을 활성화하며, Binder에서 `CONFIG_MMU`를 활성화하려면 `MMU=1`을 설정합니다.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

의도적으로 취약한 리비전을 체크아웃하거나 upstream에 문서화된 롤백 패치를 적용한 후에는, 직렬화된 시드만으로 임시방편의 C PoC를 작성하지 않고도 전체 멀티클라이언트 상태 전이를 재현할 수 있다:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

생성된 seed가 취약한 lifetime 경로에 도달했다는 확인으로, 그 결과 발생한 KASAN use-after-free를 간주하세요. 이는 kernel code execution이나 privilege escalation에 필요한 후속 primitive를 입증하지는 않습니다.<sup>[[16]](#references)</sup>

## 단일 머신 다양성 트릭 (Jackalope-Style)

**생성형 novelty**와 **coverage 재사용**을 결합하는 실용적인 방법은 persistent server를 대상으로 수명이 짧은 worker를 재시작하는 것입니다. 각 worker는 빈 corpus에서 시작하고, `T`초 후 동기화한 다음, 통합된 corpus로 다시 `T`초 동안 실행하고, 한 번 더 동기화한 뒤 종료합니다. 이렇게 하면 누적된 coverage를 활용하면서도 **세대마다 새로운 구조**를 얻을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequential worker (예제 루프):**

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

- `-in empty`는 각 generation마다 **새로운 corpus**를 강제합니다.
- `-server_update_interval T`는 **지연된 동기화**(먼저 novelty를 찾고 나중에 재사용)를 근사합니다.
- grammar fuzzing 모드에서는 **초기 server 동기화가 기본적으로 생략됩니다**(`-skip_initial_server_sync` 불필요).
- 최적의 `T`는 **대상에 따라 다릅니다**. worker가 대부분의 “쉬운” coverage를 찾은 뒤 전환하는 방식이 대체로 가장 효과적입니다.

## Snapshot Fuzzing: Harness 구성이 어려운 대상을 위한 기법

테스트하려는 코드에 도달하기까지 **큰 초기화 비용**(VM 부팅, 로그인 완료, 패킷 수신, 컨테이너 파싱, 서비스 초기화)이 필요한 경우, 유용한 대안은 **snapshot fuzzing**입니다. 준비된 프로세스나 VM의 상태를 캡처하고, 각 테스트 케이스를 대상 입력 경로에 주입한 뒤, crash/timeout이 발생할 때까지 실행하고 snapshot을 복원합니다. 이 방식은 초기화나 protocol prefix를 반복해서 처리하지 않아도 되므로 **network services**, **firmware**, **post-auth attack surfaces**, **binary-only targets**에 유용합니다.<sup>[[9]](#references)[[10]](#references)</sup>

1. 대상이 흥미로운 상태에 도달할 때까지 실행합니다.
2. 그 시점의 **memory + registers**를 snapshot으로 저장합니다.
3. 각 테스트 케이스에 대해 변형된 입력을 해당 guest/process buffer에 직접 씁니다.
4. crash/timeout/reset이 발생할 때까지 실행합니다.
5. snapshot을 복원합니다. VM 대상의 경우 지원된다면 **dirty pages**만 복원한 다음 반복합니다.

snapshot은 가능한 한 첫 번째 비용이 큰 parse/dispatch 단계에 가까운 위치에 설정합니다. 예를 들어 `recv`/`read` 이후나 packet 역직렬화 시점이 이에 해당하며, 대상이 사용하는 입력 버퍼도 기록합니다. 이는 입력 처리 과정에서 snapshot을 더 깊은 지점으로 이동해 반복 작업을 피하는 adaptive-placement 원칙을 따릅니다.<sup>[[11]](#references)</sup>

## MAccConc를 이용한 Linux Kernel Race 탐색

[MAccConc](https://github.com/googleprojectzero/MAccConc)는 타이밍에 민감한 Linux-kernel race를 반복 가능한 memory-access schedule로 바꿉니다. 두 context 간의 **A-B-A** 실행을 자동으로 열거하거나, 분석자가 terminal UI/GUI에서 순서 제약을 지정할 수 있습니다. 완전한 concurrency fuzzer라기보다 실험 단계의 연구 도구입니다. 현재 LLVM 23+와 프로젝트의 patched kernel이 필요하고, command-line 도구는 두 개의 test thread를 지원하며, 제안된 userspace fuzzing layer는 아직 구현되지 않았습니다.<sup>[[17]](#references)[[18]](#references)</sup>

### Cross-context communication 지점 수집

KASAN outline callback과 patched KCOV memory-record 지원을 포함해 instrumented kernel을 빌드합니다. 프로젝트 README에서는 call stack을 계속 사용할 수 있도록 sibling-call optimization을 비활성화할 것도 권장합니다.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`)은 instrumented access를 helper call로 변환합니다. MAccConc 커널 패치는 연속된 access가 병합되지 않도록 `asan-opt-same-temp`를 비활성화합니다. 전역 변수 race도 감지해야 한다면 `asan-opt-globals` 최적화도 비활성화하세요. KCOV는 이렇게 생성된 레코드를 userspace로 전달합니다. 서로 다른 실행 컨텍스트에서 발생한 access를 비교하고, 바이트 범위가 겹치며 둘 중 적어도 하나가 쓰기인 쌍을 선별합니다. 수명 전환도 후보에 포함되도록 `kfree()`를 쓰기로 모델링하세요.<sup>[[17]](#references)</sup>

패킷 처리나 RCU callback처럼 시작한 task의 범위를 벗어나는 작업에서는 해당 subsystem이 KCOV remote-coverage handle을 전파해야 합니다. Upstream remote KCOV는 opt-in 방식이며 임의의 background 작업에서 자동으로 사용할 수 없습니다. 따라서 handle 전파가 누락되면 실제 상호작용이 감지되지 않을 수 있습니다.<sup>[[17]](#references)[[19]](#references)</sup>

### 매 실행에서 동일한 동적 access 식별하기

각 할당 이후 바뀔 수 있는 구체적인 heap 주소만으로 replay하지 마세요. `memcpy()`나 `spin_lock()` 같은 helper 내부에서는 모호한 instruction 주소만으로 replay해서도 안 됩니다. MAccConc는 **count-augmented stack trace**를 사용합니다. 각 frame은 callee와 caller 내 호출 횟수를 식별하고, 마지막 요소는 memory-access instruction을 식별합니다. SanitizerCoverage의 함수 진입/종료 레코드를 사용하면 userspace가 이 동적 식별자를 재구성할 수 있습니다. 이 식별자는 주소 변경이나 무관한 제어 흐름의 잡음에도 안정적으로 유지됩니다.<sup>[[17]](#references)</sup>

### 후보 쌍을 강제 스케줄로 변환하기

패치된 `KCOV_SET_DI` ioctl은 count-augmented access 식별자를 shared-flag 동작과 연결합니다.<sup>[[17]](#references)</sup>

| 동작 | 의미 |
| --- | --- |
| `DI_STACK_WAKE_PRE` | 선택한 access 직전에 flag *N*을 설정합니다. |
| `DI_STACK_WAIT` | 선택한 access 직전에 flag *N*이 설정되거나 구성된 제한 시간이 만료될 때까지 spin합니다. |
| `DI_STACK_WAKE_POST` | 선택한 access 직후 flag *N*을 설정합니다. |

부분적인 **A-happens-before-B** 제약을 적용하려면 같은 flag를 사용해 A에 `DI_STACK_WAKE_POST`를, B에 `DI_STACK_WAIT`를 지정합니다. 두 컨텍스트의 스케줄을 완전히 지정하려면 B를 먼저 blocked 상태로 두고, A가 첫 번째 전환 지점에서 B를 깨운 뒤 대기하게 합니다. 다음 전환 지점에서는 B가 반대 동작을 수행합니다. 후자는 결정적 context switching처럼 동작하며, 자동 A-B-A 탐색기가 사용하는 방식입니다.<sup>[[17]](#references)</sup>

최소 캠페인에서는 네 개의 hook(`test_setup`, 두 thread 함수, `test_end`)으로 구성된 테스트 케이스를 shared library로 컴파일하고, 제약이 없는 trace를 수집한 다음 A-B-A 후보를 열거하거나 의심스러운 access 주변에 수동 제약을 추가합니다.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

타임아웃은 성공적인 재정렬과 별도로 해석해야 합니다. 요청한 순서는 lock 또는 초기화/게시 의존성 때문에 두 번째 컨텍스트가 주입 지점에 도달하지 못해 불가능할 수 있습니다. KASAN의 사각지대도 고려하세요. 직접적인 스택 접근은 범위를 벗어날 가능성이 있는 경우가 아니면 보통 후킹되지 않고, 기본 최적화에서는 전역 변수가 제외되며, 현재 컴파일러는 ASAN 및 TSAN 후크를 동시에 생성할 수 없습니다. 또한 프로토타입은 게스트가 패닉하면 KCOV 버퍼를 잃으므로, 독립적인 크래시 콘솔/오라클을 유지하세요.<sup>[[17]](#references)</sup>

향후 동시성 기반 퍼징을 위해 입력별 또는 시스템 호출별 메모리 접근 요약을 기록하고, 컨텍스트 간 통신 지점을 형성할 작업을 짝지은 다음, 해당 조합만 탐색하세요. VM 스냅샷은 전역 상태와 주소를 안정화합니다. 스냅샷이 없으면 할당 위치 메타데이터로 실행 간 객체를 추상화할 수 있습니다. 이는 제안된 확장이지, 현재 MAccConc userspace 도구의 기능은 아닙니다.<sup>[[17]](#references)</sup>

## Harness 인트로스펙션: 얕은 Fuzzer 조기 발견

퍼징 캠페인이 정체되면 문제는 mutator가 아니라 **harness**인 경우가 많습니다. **도달 가능성/커버리지 인트로스펙션**을 사용해 퍼징 대상에서 정적으로 도달 가능하지만 동적으로는 거의 또는 전혀 커버되지 않는 함수를 찾으세요. 이런 함수는 보통 다음 세 가지 문제 중 하나를 나타냅니다.<sup>[[12]](#references)</sup>

- harness가 대상에 너무 늦게 또는 너무 일찍 진입합니다.
- 시드 코퍼스에 기능군 전체가 빠져 있습니다.
- 대상에는 하나의 거대한 “모든 것을 처리하는” harness 대신 **두 번째 harness**가 실제로 필요합니다.

OSS-Fuzz / ClusterFuzz 스타일의 워크플로를 사용한다면, Fuzz Introspector는 정적 도달 가능성과 런타임 커버리지를 비교하고, 일정 시간 동안 실행한 결과나 공개 코퍼스를 바탕으로 보고서를 생성할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

보고서를 바탕으로 테스트되지 않은 parser 경로를 위한 새 harness를 추가할지, 특정 기능의 corpus를 확장할지, 아니면 하나로 뭉친 harness를 더 작은 진입점으로 분리할지 결정하세요.

## 그래프 우선 퍼징 대상 선정 및 mutation triage

이미 **정적 분석 결과**, **mutation testing 생존 항목**, **coverage 보고서**가 있다면, 이를 서로 독립된 목록처럼 분류하지 마세요. 먼저 **call graph**를 만들고, 노드에 **cyclomatic complexity**, **entrypoint/비신뢰 입력 도달 가능성**, 외부 분석 결과를 표시한 다음 그래프를 기준으로 질문하세요.<sup>[[5]](#references)[[6]](#references)</sup>

- 비신뢰 입력에서 도달할 수 있는 고복잡도 함수는 무엇인가요?
- parser/handler에서 보안상 중요한 코드로 이어지는 경로에 있는 mutation 생존 항목은 무엇인가요?
- **blast radius**가 이례적으로 큰 아키텍처상 병목 지점은 어떤 함수인가요?

이 방법은 보통 "coverage가 가장 낮은 곳"만 보는 것보다 더 나은 퍼징 대상을 찾아냅니다. **복잡도가 높고** 외부에서 도달 가능한 것으로 확인된 parser/decoder는, coverage가 낮더라도 공격자가 제어하는 경로가 없는 고립된 내부 helper보다 더 적합한 harness 후보입니다.

### 실용적인 triage 워크플로

1. 코드베이스에서 **code graph**를 만들고 함수별 complexity/branch 메트릭을 추출합니다.
2. 공격자가 제어하는 입력을 받는 **entrypoint**를 열거합니다. 예: request handler, decoder, importer, protocol parser, CLI/file reader.
3. 해당 entrypoint에서 후보 함수까지 **경로 질의**를 실행해 공격 표면에서 도달 가능한 코드와 dead/internal-only 코드를 구분합니다.
4. 다음 조건을 함께 충족하는 노드의 우선순위를 높입니다.
   - 높은 **cyclomatic complexity**
   - 비신뢰 입력에서 도달 가능하다는 확인
   - 높은 **blast radius** 또는 다수의 하위 의존 함수
   - **SARIF** 결과, 감사 메모, mutation 생존 항목 등으로 뒷받침되는 증거
5. 특히 hex/Base64/IP/message decoder 같은 **parser/codec**를 중심으로, 점수가 높은 노드부터 집중형 harness를 작성합니다.

### Mutation 생존 항목: 동등한 항목과 조치 대상

Mutation testing은 잡음이 많은 생존 항목 목록을 만드는 경우가 많습니다. 모든 생존 항목을 보안 격차로 간주하기 전에 그래프를 활용해 다음을 확인하세요.

- 변형된 함수가 공격자가 제어하는 entrypoint에서 도달 가능한가요?
- 모든 호출 경로가 변형된 검사보다 더 강한 불변 조건으로 제한되나요?
- 해당 노드는 dead code, 포매팅 전용 로직, 아니면 영향이 큰 산술/parser 경로에 있나요?

도달 불가능한 상태로 남거나 구조적으로 제약되는 생존 항목은 흔히 **동등 mutant**입니다. 계속 **도달 가능**하고 **경계 조건**, **overflow/carry 경로**, **보안상 중요한 산술/파싱**에 영향을 미치는 생존 항목은 다음 대상으로 승격해야 합니다.

- 새 fuzz harness
- 직접적인 property/invariant 테스트
- 특정 edge case를 겨냥한 벡터

### 외부 분석 결과를 그래프에 연결하기

SAST 파이프라인에서 **SARIF**를 내보낸다면, **파일 + 줄 범위**를 기준으로 분석 결과를 그래프 노드에 투영하고 그래프를 활용해 영향 범위를 넓혀 살펴보세요.<sup>[[6]](#references)</sup>

- 표시된 함수의 **blast radius**를 계산합니다.
- 해당 분석 결과가 entrypoint에서 시작하는 경로에 있는지 확인합니다.
- 같은 병목 지점으로 모이는 인접 분석 결과를 그룹화합니다.

이 방법은 특정 함수에 퍼징 시간을 투자할지 결정할 때 유용합니다. **도달 가능**하고 **복잡**하며 이미 **SAST 결과**가 있는 노드는 공격 경로가 없는 단순 고복잡도 노드보다 더 나은 대상인 경우가 많습니다.

Trailmark를 사용한 워크플로 예시입니다.<sup>[[6]](#references)</sup>

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

중요한 방법론은 다음 요소의 교집합입니다. **복잡도 x 노출도 x 영향도**. 그래프를 사용해 예상 보안 가치가 가장 높은 fuzz 대상을 선택한 다음, 변이를 통과한 입력을 바탕으로 하네스가 집중적으로 테스트해야 할 경계와 불변 조건을 결정하세요.<sup>[[5]](#references)</sup>

## 암호화 키 인코딩의 차등 fuzzing

유효한 직렬화 키 또는 표준 테스트 벡터에서 시작하세요. import 및 연산 경로에 도달하는 데 필요한 길이와 구조는 유지하면서 인코딩된 필드를 변형한 다음, 동일한 바이트를 서로 독립적인 구현에 전달하세요. 수용 여부와 오류를 비교하세요. 무작위 서명과 암호문에는 바이트 단위 비교가 아니라 정확성 오라클이 필요합니다. 즉, 서명을 검증하거나 캡슐화/역캡슐화 왕복 과정에서 생성된 공유 비밀을 비교하세요. 테스트 벡터는 알려진 사례에 대한 적합성을 확인하고, 차등 변이는 그 범위를 넘어 잘못된 인코딩을 탐색합니다.<sup>[[23]](#references)[[26]](#references)</sup>

다음 키 형식에는 형식별 오라클을 사용하세요.<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA 확장 서명 키:** 키를 파싱할 수 있는 상태로 유지하면서 패킹된 `s1` 또는 `s2` 계수를 `[-η, η]` 범위 밖으로 변경하세요. import 또는 서명 과정에서 거부되는지, 생성된 서명이 검증되는지 확인하세요. FIPS 204는 추가적인 개인 키 검사를 의무화하지 않으므로, 수용 여부의 차이만으로 표준 위반이라고 볼 수는 없습니다. [조건부 누출 메커니즘](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage)을 참조하세요.
- **ML-KEM 키 쌍:** 가져온 키 쌍에 대해 필수 캡슐화 키 및 역캡슐화 입력 검사를 선택적 쌍별 일관성 검사(PCT)와 구분하세요. 공개 키로 캡슐화하고 개인 키로 역캡슐화한 다음 공유 비밀을 비교하세요. 개별 키가 입력 검사를 통과하더라도 값이 일치하지 않으면 암호화된 통신이 중단될 수 있습니다. API가 연산 중 입력을 검증하는지, 별도 호출을 통해 검증하는지 확인하세요. libcrux는 `validate_public_key(pk)`와 `validate_private_key(sk, ct)`를 제공하지만, 이들은 PCT를 대체하지 않습니다.
- **XMSS/XMSSMT 원시 키:** 메모리 내 키를 사용한 연산만 테스트하지 말고, 매개변수 세트별로 직렬화된 **서명 및 검증 키**의 왕복을 테스트하세요. XMSS와 XMSSMT는 서로 다른 4바이트 OID 네임스페이스를 사용하므로, XMSS를 먼저 시도하는 OID 전용 파서는 OID가 충돌하는 XMSSMT 키를 잘못 분류해 import를 거부할 수 있습니다. 보고된 RustCrypto 파서는 서명 위조가 아닌 상호 운용성/가용성 실패의 사례입니다.

## gosentry를 이용한 Go Fuzzing: 더 강력한 엔진, 형식화된 입력 및 차등 검사

Go 대상에 이미 네이티브 `testing.F` 하네스가 있다면, 실용적인 업그레이드 방법은 같은 하네스를 [gosentry](https://github.com/trailofbits/gosentry)로 실행하는 것입니다. gosentry는 `go test -fuzz`는 유지하면서 백엔드를 **LibAFL**로 교체하는 Go 툴체인 포크입니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

네이티브 Go fuzzer가 **어려운 비교**, **타입이 지정된 입력**, **파서 처리가 많은 형식**에서 정체될 때 유용합니다. 방법론은 동일합니다.

- 시드에는 `f.Add(...)`를, 콜백에는 `f.Fuzz(...)`를 계속 사용합니다.
- 같은 harness를 재사용하되, 기본 툴체인 대신 gosentry의 `go` 바이너리로 실행합니다.
- 결과 캠페인을 일반적인 coverage-guided 실행으로 취급하되, LibAFL 스케줄링/변이와 더 나은 주변 탐지기를 활용합니다.

### 조용한 실패를 fuzz finding으로 전환

Go 평가에서 반복적으로 발생하는 문제는 위험한 동작이 기본적으로 **crash를 일으키지 않는 경우가 많다**는 점입니다. gosentry를 사용하면 여러 유형의 “나쁘지만 조용한” 상태를 finding으로 전환할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`를 사용하면 선택한 로깅/오류 경로가 crash처럼 동작하게 할 수 있습니다(그렇지 않으면 로그만 남기고 계속 실행하는 `log.Fatal` 스타일의 코드 경로에 유용).
- `--catch-races=true`를 사용하면 새로 발견된 queue entry를 Go race detector로 다시 실행합니다.
- `--catch-leaks=true`를 사용하면 새 queue entry를 `goleak`으로 다시 실행하고 goroutine leak이 발생하면 중지합니다.
- LibAFL의 hang 처리는 **무한 루프 / 매우 느린 입력**이 timeout으로 사라지지 않고 fuzz finding으로 남도록 합니다.
- 기본적으로 내장된 산술 오버플로 검사를 수행하며, go-panikint 스타일의 instrumentation을 통해 선택적으로 truncation 검사도 할 수 있습니다.

이는 보안 영향이 메모리 손상이 아니라 **panic을 일으키지 않는 파서 실패**, **동시성 버그**, 또는 **DoS만 유발하는 hang**인 타깃에 특히 유용합니다.

### 타입이 지정된 Go API를 위한 struct-aware fuzzing

네이티브 Go fuzzing은 주로 `[]byte`, `string`, 숫자 같은 스칼라를 입력으로 기대합니다. 테스트 대상 코드가 타입이 지정된 객체를 사용한다면, gosentry는 바이트를 기반으로 변이를 계속 수행하면서 **복합 값**(struct, slice, array, pointer)을 직접 fuzz할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

이 방식은 fuzzing만을 위한 가짜 wire format을 만들 때 사용하세요. 그러면 harness 전용 파싱 코드가 로직 버그를 가릴 수 있습니다. Differential 또는 grammar-based 캠페인에서는 harness 입력을 단일 `[]byte` 또는 `string`으로 유지하고, 대신 callback 내부에서 파싱하세요.

### 파서 및 프로토콜 입력을 위한 grammar-based fuzzing

파서, 포맷, 입력 언어의 경우 gosentry는 LibAFL 위에서 **Nautilus grammar fuzzing**을 실행할 수 있습니다. 문법은 production rule로 구성된 JSON 배열이며, harness는 보통 단일 `[]byte` 또는 `string` 인수를 받아야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodology notes:

- 바이트 수준 변이가 초기 구문 검사에서 대부분 실패한다면 Grammar mode를 사용합니다.
- 전체 사양을 모델링하는 대신, 언어/프로토콜의 **보안 관련 하위 집합**에 초점을 맞춰 grammar를 구성합니다.
- terminal/nonterminal에 큰 경계값을 사용해 정수, 길이, 상태 머신의 경계 조건을 자극합니다.
- Grammar mode는 입력을 문법적으로 유효하게 유지하지만, 대상에는 여전히 **바이트/문자열**이 전달되므로 파싱과 의미 검사는 하네스가 적용된 코드 내부에서 수행됩니다.

### Differential fuzzing: 크래시만 보는 대신 구현을 비교하기

Go 생태계에서 효과적인 방식은 **grammar-based differential fuzzing**입니다. 유효한 구조화 입력을 생성해 두 개의 파서, 클라이언트 또는 상태 전이 엔진에 전달합니다.<sup>[[7]](#references)[[8]](#references)</sup>

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

- 한 구현은 panic을 일으키지만 다른 구현은 정상적으로 거부함
- 입력 수락/거부 결과가 서로 다름
- 파스 트리 또는 디코딩된 객체가 서로 다름
- 상태 전이, nonce, 잔액 또는 상태 루트가 서로 다름

이는 순수 crash fuzzing으로는 놓치기 쉬운 **합의 불일치**, **파서 모호성**, **명세와 구현 간의 괴리**를 찾는 실용적인 방법입니다.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### 커버리지 보고에 캠페인 코퍼스 재사용하기

캠페인 후 저장된 큐 코퍼스를 재생하면 별도의 코퍼스를 수동으로 내보내지 않고도 Go 커버리지 보고서를 생성할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Run 명령을 **같은 package**에서 **같은 `-fuzz` 대상**을 지정해 실행해야 gosentry가 올바른 캐시된 campaign state를 확인합니다.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [변형 문법 fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ fuzzing 심층 분석](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [5년 후의 AFLNet: 커버리지 기반 프로토콜 fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark, 코드를 그래프로 변환하다](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing에는 도구의 절반이 빠져 있었습니다. 이를 해결하기 위해 toolchain을 fork했습니다.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 스냅샷을 사용하는 상태 기반 네트워크 프로토콜용 고속 Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [문법이 없어도 문제없다: 시스템 호출 설명 없이 Linux 커널 fuzzing하기](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: 적응형 및 변경 가능한 스냅샷을 사용한 효율적인 fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: 경로 및 caller 커버리지](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [예측형 컨텍스트 민감 fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security 블로그 - Binder fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - 빌드 및 회귀 seed 문서](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: 제어된 메모리 접근 인터리빙으로 Linux 커널 race condition 탐색](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing을 위한 코드 커버리지](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO 확장 파일명 구문](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec 보안 권고: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO 확장 파일명 구문 fuzzing: 16건의 메모리 안전성 취약점과 Codex 지원 triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [암호화를 위한 differential fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: 모듈 격자 기반 키 캡슐화 메커니즘 표준](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID 파싱 버그 - RustCrypto 이슈 #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [양자내성 암호 구현 현황](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
